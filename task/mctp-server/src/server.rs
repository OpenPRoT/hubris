// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::ipc::*;
use heapless::LinearMap;
use idol_runtime::{Leased, R, W};
use mctp::{Eid, MsgIC, MsgType, Tag, TagValue};
use mctp_stack::{AppCookie, Router};
use userlib::*;
use zerocopy::IntoBytes;

// TODO: Use configuration from mctp-lib (mctp-estack)
//       see https://github.com/OpenPRoT/mctp-lib/issues/4
const MAX_PAYLOAD: usize = 1023;

pub struct Server<S: mctp_stack::Sender, const OUTSTANDING: usize> {
    pub stack: Router<S, { super::MAX_LISTENERS }, { super::MAX_REQUESTS }>,
    /// The currently outstanding recv calls
    ///
    /// Maps the handle to RecvMessage that must be replied to,
    /// once a message arrives or a timeout occurs.
    /// The timeout is stored as a deadline.
    outstanding: LinearMap<GenericHandle, (RecvMessage, u64), OUTSTANDING>,
}

impl<S: mctp_stack::Sender, const OUTSTANDING: usize> Server<S, OUTSTANDING> {
    /// Create a new MCTP server instance
    pub fn new(own_eid: mctp::Eid, now_millis: u64, outbound: S) -> Self {
        let stack = Router::new(own_eid, now_millis, outbound);
        Self {
            stack,
            outstanding: LinearMap::new(),
        }
    }

    /// Answer a request for a handle for sending messages to the given EID
    pub fn req(&mut self, msg: &RecvMessage, eid: u8) {
        match self.stack.req(mctp::Eid(eid)) {
            Ok(handle) => {
                let handle = GenericHandle(handle.0 as u32); // TODO better mapping
                sys_reply(msg.sender, 0, handle.as_bytes())
            }
            Err(e) => {
                sys_reply(msg.sender, ServerError::from(e).into(), &[]);
            }
        }
    }

    /// Answer a request for a listener handle for incoming messages of the given type
    pub fn listener(&mut self, msg: &RecvMessage, typ: u8) {
        match self.stack.listener(mctp::MsgType(typ)) {
            Ok(handle) => {
                let handle = GenericHandle(handle.0 as u32); // TODO better mapping
                sys_reply(msg.sender, 0, handle.as_bytes())
            }
            Err(e) => {
                sys_reply(msg.sender, ServerError::from(e).into(), &[]);
            }
        }
    }

    /// Reply to a request for the current EID
    pub fn get_eid(&mut self, msg: &RecvMessage) {
        sys_reply(msg.sender, 0, self.stack.get_eid().0.as_bytes());
    }

    /// Set the current EID of the stack
    pub fn set_eid(&mut self, msg: &RecvMessage, eid: u8) {
        match self.stack.set_eid(mctp::Eid(eid)) {
            Ok(()) => sys_reply(msg.sender, 0, &[]),
            Err(e) => {
                sys_reply(msg.sender, ServerError::from(e).into(), &[]);
            }
        }
    }

    /// Check for incoming messages for the handle given by the client
    ///
    /// Postpones the reply if no message is available.
    /// If called again for a handle that already has a pending recv call,
    /// try to answer and remove the handle.
    /// Won't overwrite an existing pending recv call for the given handle.
    pub fn recv(
        &mut self,
        msg: RecvMessage,
        handle: GenericHandle,
        timeout_millis: u32,
        buf: Leased<W, [u8]>,
    ) {
        // Check for a message for the given handle, if there is one, copy it into buf and reply.
        // Otherwise postpone the reply until a message arrives or a timeout occurs.
        // For this the RecvMessage must be stored.
        // On inbound message arrival, all postponed recv calls must be checked for a match.

        let cookie = AppCookie(handle.0 as usize);
        if let Some(mctp_message) = self.stack.recv(cookie) {
            send_reply(&msg, mctp_message, buf);

            // Remove any outstanding recv call for this handle, if any
            self.outstanding.remove(&handle);
            return;
        }

        let deadline = if timeout_millis != 0 {
            self.set_timer(timeout_millis)
        } else {
            0
        };

        // We don't want to update any existing entries
        if !self.outstanding.contains_key(&handle) {
            self.outstanding
                .insert(handle, (msg, deadline))
                .unwrap_lite();
        }
    }

    /// Send a message provided by the client
    ///
    /// Blocks until the message is sent or an error occurs.
    /// When responding to a request received by a listener, `eid` and `tag` have to be set.
    /// A request never sets an `eid`.
    /// We distinguish request and response by the `handle` parameter: if it is `None`, it is a response.
    /// When no `tag` is supplied for a request, a new one will be allocated.
    pub fn send(
        &mut self,
        msg: &RecvMessage,
        handle: Option<GenericHandle>,
        typ: u8,
        eid: Option<u8>,
        tag: Option<u8>,
        ic: bool,
        buf: Leased<R, [u8]>,
    ) {
        let mut msg_buf = [0; MAX_PAYLOAD];
        if msg_buf.len() < buf.len() {
            sys_reply(msg.sender, ServerError::NoSpace.into(), &[]);
        }
        if buf.read_range(0..buf.len(), &mut msg_buf).is_err() {
            todo!("client died?");
        }
        let msg_buf = &msg_buf[..buf.len()];
        let tag = if handle.is_none() {
            // All calls without a handle are responses and must use unowned tags
            // TODO erroring out if no tag is provided?
            tag.map(|x| Tag::Unowned(TagValue(x)))
        } else {
            // A call with a handle is a request and must use owned tags (or allocate a new one)
            tag.map(|x| Tag::Owned(TagValue(x)))
        };
        let res = self.stack.send(
            eid.map(Eid),
            MsgType(typ),
            tag,
            MsgIC(ic),
            AppCookie(handle.unwrap_or(GenericHandle(255)).0 as usize), // Responses need no handle, use 255 as dummy
            msg_buf,
        );

        match res {
            Ok(tag) => {
                let mut buf = [0; 8];
                let l =
                    hubpack::serialize(&mut buf, &tag.tag().0).unwrap_lite();
                sys_reply(msg.sender, 0, &buf[..l]);
            }
            Err(e) => {
                sys_reply(msg.sender, ServerError::from(e).into(), &[]);
            }
        }
    }

    /// Update the stack, check for receive calls that can be fullfilled
    ///
    /// Should be called whenever a timer interrupt occurs.
    /// Sets the timer to the next timeout required.
    pub fn update(&mut self, now_millis: u64) {
        // Crash the server if updating the stack fails (this is probably unrecoverable)
        let stack_timeout = self.stack.update(now_millis).unwrap_lite() as u32;
        self.set_timer(stack_timeout);

        let mut marked: heapless::Vec<_, OUTSTANDING> = heapless::Vec::new();

        for (handle, (msg_handle, deadline)) in self.outstanding.iter() {
            if let Some(mctp_msg) =
                self.stack.recv(AppCookie(handle.0 as usize))
            {
                let lease =
                    Leased::write_only_slice(msg_handle.sender, 0, None)
                        .unwrap_lite();
                send_reply(msg_handle, mctp_msg, lease);
                let _ = marked.push(*handle);
            }

            if *deadline != 0 && now_millis >= *deadline {
                sys_reply(msg_handle.sender, ServerError::TimedOut.into(), &[]);
                let _ = marked.push(*handle);
            }
        }
        for key in marked {
            self.outstanding.remove(&key);
        }
    }

    /// Set the system timer to expire after the given timeout returning a deadline
    ///
    /// Timer won't be set if the timeout is longer than the current one.
    fn set_timer(&self, timeout_millis: u32) -> u64 {
        let state = sys_get_timer();
        // If a deadline is set and it is sooner than the requested timeout,
        // keep it and return the deadline for the requested timeout by calulating it.
        if let Some(deadline) = state.deadline {
            if (deadline - state.now) < (timeout_millis as u64) {
                return state.now + timeout_millis as u64;
            }
        }

        // Else set the timer and return the deadline
        set_timer_relative(timeout_millis, super::notifications::TIMER_MASK)
    }

    /// Unbind a handle previously allocated by `req` or `listener`
    pub fn unbind(&mut self, msg: &RecvMessage, handle: GenericHandle) {
        let cookie = AppCookie(handle.0 as usize);
        let _ = self.stack.unbind(cookie);
        self.outstanding.remove(&handle); // should never contain the handle at this point, but just in case...
        sys_reply(msg.sender, 0, &[]);
    }
}

fn send_reply(
    msg: &RecvMessage,
    mctp_message: mctp_stack::MctpMessage<'_>,
    buf: Leased<W, [u8]>,
) {
    if mctp_message.payload.len() > buf.len() {
        sys_reply(msg.sender, ServerError::NoSpace.into(), &[]);
        return;
    }
    if buf
        .write_range(0..mctp_message.payload.len(), mctp_message.payload)
        .is_err()
    {
        todo!("client died?")
    }
    let answer = crate::ipc::RecvMetadata {
        msg_typ: mctp_message.typ.0,
        msg_ic: mctp_message.ic.0,
        msg_tag: mctp_message.tag.tag().0,
        remote_eid: mctp_message.source.0,
        size: mctp_message.payload.len() as u64,
    };

    let mut msg_buf = [0; MAX_PAYLOAD];
    let l = hubpack::serialize(&mut msg_buf, &answer).unwrap_lite();
    sys_reply(msg.sender, 0, &msg_buf[..l]);
}

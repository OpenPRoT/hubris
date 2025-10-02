//! ## High-level interface
//! Applications can use the [`Stack`] to configure the hubris mctp-server-task,
//! or to obtain [listener](MctpListener), [request](MctpReqChannel) and [response](MctpRespChannel) handles that implement
//! the standard [`mctp`] traits.
//!
//! ## IPC API
//! The raw IPC interface can be accessed through the [ipc] module.
//! It is used by the high-level interface to communicate with the server task.

#![no_std]

use mctp::{
    Eid, Error, Listener, MsgIC, MsgType, ReqChannel, RespChannel, Tag,
    TagValue,
};
use userlib::TaskId;

/// A MCTP stack backed by a hubris MCTP server.
///
/// Applications can use [`req()`](Self::req) and [`listener()`](Self::listener)
/// to optain instances of the [`mctp`] traits via IPC calls to a MCTP server task.
///
/// A stack can be obtained from a corresponding MCTP server [`TaskId`].
#[derive(Clone, Debug)]
pub struct Stack {
    ipc: ipc::client::MCTP,
}
impl From<TaskId> for Stack {
    fn from(value: TaskId) -> Self {
        Stack { ipc: value.into() }
    }
}

impl Stack {
    pub fn req(
        &self,
        eid: Eid,
        timeout_millis: Option<u32>,
    ) -> mctp::Result<MctpReqChannel<'_>> {
        let handle = self.ipc.req(eid.0)?;
        Ok(MctpReqChannel {
            stack: self,
            handle,
            eid,
            sent_tag: None,
            timeout: timeout_millis.unwrap_or(0),
        })
    }
    pub fn listener(
        &self,
        typ: MsgType,
        timeout_millis: Option<u32>,
    ) -> mctp::Result<MctpListener<'_>> {
        let handle = self.ipc.listener(typ.0)?;
        Ok(MctpListener {
            stack: self,
            handle,
            timeout: timeout_millis.unwrap_or(0),
        })
    }
    pub fn get_eid(&self) -> Eid {
        Eid(self.ipc.get_eid())
    }
    pub fn set_eid(&self, eid: Eid) -> mctp::Result<()> {
        Ok(self.ipc.set_eid(eid.0)?)
    }
}

/// A request channel
#[derive(Debug)]
pub struct MctpReqChannel<'r> {
    stack: &'r Stack,
    handle: ipc::GenericHandle,
    eid: Eid,
    sent_tag: Option<Tag>,
    /// Timeout in milliseconds
    ///
    /// 0 means no timeout.
    timeout: u32,
}
impl ReqChannel for MctpReqChannel<'_> {
    fn send_vectored(
        &mut self,
        typ: mctp::MsgType,
        integrity_check: mctp::MsgIC,
        bufs: &[&[u8]],
    ) -> mctp::Result<()> {
        if self.sent_tag.is_some() {
            return Err(Error::BadArgument);
        }
        // TODO Sending vectored bufs over IPC isn't possible out of the box.
        //      Assembling them into one slice means copying the buffers.
        //      This it not ideal but might be a sufficient for now.
        let _ = typ;
        let _ = integrity_check;
        let _ = bufs;
        Err(Error::Unsupported)
    }

    fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> mctp::Result<(mctp::MsgType, mctp::MsgIC, &'f mut [u8])> {
        let Some(Tag::Owned(tv)) = self.sent_tag else {
            return Err(Error::BadArgument);
        };
        let ipc::RecvMetadata {
            msg_typ,
            msg_ic,
            msg_tag,
            remote_eid,
            size,
        } = self.stack.ipc.recv(self.handle, self.timeout, buf)?;
        debug_assert_eq!(tv.0, msg_tag);
        debug_assert_eq!(self.eid.0, remote_eid);
        let ic = mctp::MsgIC(msg_ic);
        let typ = mctp::MsgType(msg_typ);
        Ok((typ, ic, &mut buf[..size as usize]))
    }

    fn remote_eid(&self) -> Eid {
        self.eid
    }
    fn send(&mut self, typ: mctp::MsgType, buf: &[u8]) -> mctp::Result<()> {
        if self.sent_tag.is_some() {
            return Err(Error::BadArgument);
        }
        let tv = self.stack.ipc.send(
            Some(self.handle),
            typ.0,
            None,
            None,
            false,
            buf,
        )?;
        let tag = Tag::Owned(mctp::TagValue(tv));
        self.sent_tag = Some(tag);
        Ok(())
    }
}
impl Drop for MctpReqChannel<'_> {
    fn drop(&mut self) {
        self.stack.ipc.drop(self.handle);
    }
}

/// A listener that listens for a specific message type
#[derive(Debug)]
pub struct MctpListener<'r> {
    stack: &'r Stack,
    handle: ipc::GenericHandle,
    /// Timeout in milliseconds
    ///
    /// 0 means no timeout.
    timeout: u32,
}
impl<'b> Listener for MctpListener<'b> {
    type RespChannel<'a>
        = MctpRespChannel<'b>
    where
        Self: 'a;

    fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> mctp::Result<(
        mctp::MsgType,
        mctp::MsgIC,
        &'f mut [u8],
        Self::RespChannel<'_>,
    )> {
        let ipc::RecvMetadata {
            msg_typ,
            msg_ic,
            msg_tag,
            remote_eid,
            size,
        } = self.stack.ipc.recv(self.handle, self.timeout, buf)?;

        let resp_channel = MctpRespChannel {
            stack: self.stack,
            eid: Eid(remote_eid),
            typ: MsgType(msg_typ),
            tv: TagValue(msg_tag),
        };

        Ok((
            MsgType(msg_typ),
            MsgIC(msg_ic),
            &mut buf[..size as usize],
            resp_channel,
        ))
    }
}
impl Drop for MctpListener<'_> {
    fn drop(&mut self) {
        self.stack.ipc.drop(self.handle);
    }
}

/// A response channel for an incoming MCTP message
#[derive(Debug)]
pub struct MctpRespChannel<'r> {
    stack: &'r Stack,
    eid: Eid,
    typ: MsgType,
    tv: TagValue,
}
impl<'r> RespChannel for MctpRespChannel<'r> {
    type ReqChannel = MctpReqChannel<'r>;

    fn send_vectored(
        &mut self,
        integrity_check: MsgIC,
        bufs: &[&[u8]],
    ) -> mctp::Result<()> {
        // TODO Sending vectored bufs over IPC isn't possible out of the box.
        //      Assembling them into one slice means copying the buffers.
        //      This it not ideal but might be a sufficient for now.
        let _ = integrity_check;
        let _ = bufs;
        Err(Error::Unsupported)
    }

    fn remote_eid(&self) -> Eid {
        self.eid
    }

    fn req_channel(&self) -> mctp::Result<Self::ReqChannel> {
        self.stack.req(self.eid, None)
    }

    fn send(&mut self, buf: &[u8]) -> mctp::Result<()> {
        Ok(self
            .stack
            .ipc
            .send(
                None, //no handle, since this is a response (server distinguishes by Some/None)
                self.typ.0,
                Some(self.eid.0),
                Some(self.tv.0),
                false,
                buf,
            )
            .map(|_| ())?)
    }
}

pub mod ipc {
    //! Raw IPC API and associated types
    //!
    //! Used by the [`Stack`](crate::Stack) and server implementation.
    //! Usually an application will not use this interface directly.

    use derive_idol_err::IdolError;
    use hubpack::SerializedSize;
    use serde::{Deserialize, Serialize};
    use userlib::*;

    /// Metadata returned by a successful [`recv`](client::MCTP::recv).
    #[derive(Clone, Copy, Debug, Serialize, SerializedSize, Deserialize)]
    #[repr(C)]
    pub struct RecvMetadata {
        pub msg_typ: u8,
        pub msg_ic: bool,
        pub msg_tag: u8,
        pub remote_eid: u8,
        pub size: u64,
    }

    /// Errors reported by the MCTP server
    #[derive(Clone, Copy, Debug, FromPrimitive, IdolError, counters::Count)]
    #[repr(u32)]
    #[non_exhaustive]
    pub enum ServerError {
        #[idol(server_death)]
        ServerRestarted = 1,
        InternalError = 2,
        NoSpace = 3,
        AddrInUse = 4,
        TimedOut = 5,
        BadArgument = 6,
    }

    impl From<ServerError> for mctp::Error {
        fn from(value: ServerError) -> Self {
            use mctp::Error::*;
            // this will probably map nearly 1:1 once everything is implemented
            match value {
                ServerError::InternalError => InternalError,
                ServerError::ServerRestarted => InternalError,
                ServerError::NoSpace => NoSpace,
                ServerError::AddrInUse => AddrInUse,
                ServerError::TimedOut => TimedOut,
                ServerError::BadArgument => BadArgument,
            }
        }
    }
    impl From<mctp::Error> for ServerError {
        fn from(value: mctp::Error) -> Self {
            // this will probably map nearly 1:1 once everything is implemented
            match value {
                mctp::Error::InternalError => ServerError::InternalError,
                mctp::Error::NoSpace => ServerError::NoSpace,
                mctp::Error::AddrInUse => ServerError::AddrInUse,
                mctp::Error::TimedOut => ServerError::TimedOut,
                mctp::Error::BadArgument => ServerError::BadArgument,
                _ => ServerError::InternalError,
            }
        }
    }

    /// A generic handle for a listener, request or response channel.
    #[derive(
        Clone,
        Copy,
        Debug,
        zerocopy_derive::Immutable,
        zerocopy_derive::IntoBytes,
        zerocopy_derive::FromBytes,
        zerocopy_derive::KnownLayout,
        Serialize,
        Deserialize,
        SerializedSize,
        PartialEq,
        Eq,
    )]
    #[repr(transparent)]
    pub struct GenericHandle(pub u32);

    pub mod client {
        use super::*;
        include!(concat!(env!("OUT_DIR"), "/client_stub.rs"));
    }
}

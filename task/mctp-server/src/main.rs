// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use ast1060_pac as device;
use core::cell::RefCell;
use core::ops::Deref;
use mctp_stack;
use userlib::*;

use lib_ast1060_uart::Usart;

mod serial;
mod server;
use server::Server;

/// Maximum number of concurrent requests the server can handle.
pub const MAX_REQUESTS: usize = 8;
/// Maximum number of listeners that can be registered concurrently.
pub const MAX_LISTENERS: usize = 8;
/// Maximum number of concurrent outstanding receive calls.
pub const MAX_OUTSTANDING: usize = 16;

#[export_name = "main"]
fn main() -> ! {
    let mut msg_buf = [0; ipc::INCOMING_SIZE];
    let peripherals = unsafe { device::Peripherals::steal() };

    let usart = RefCell::new(Usart::from(peripherals.uart.deref()));
    let serial_sender = serial::SerialSender::new(&usart);
    let mut serial_reader = mctp_stack::serial::MctpSerialHandler::new();

    let mut server: Server<_, MAX_OUTSTANDING> =
        Server::new(mctp::Eid(42), 0, serial_sender);

    loop {
        let msg = sys_recv_open(
            &mut msg_buf,
            notifications::UART_IRQ_MASK & notifications::TIMER_MASK,
        );
        let interrupt = usart.borrow_mut().read_interrupt_status();

        if msg.sender == TaskId::KERNEL
            && (msg.operation & notifications::UART_IRQ_MASK) != 0
        {
            let pkt =
                serial::handle_recv(interrupt, &usart, &mut serial_reader)
                    .unwrap_lite();
            server.stack.inbound(pkt).unwrap_lite();
            sys_irq_control(notifications::UART_IRQ_MASK, true);
            continue;
        }

        if msg.sender == TaskId::KERNEL
            && (msg.operation & notifications::TIMER_MASK) != 0
        {
            let state = sys_get_timer();
            server.update(state.now);
            continue;
        }

        handle_mctp_msg(&msg_buf, msg, &mut server);
    }
}

mod ipc {
    use counters::*;
    pub use mctp_api::ipc::*;

    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}

fn handle_mctp_msg<S: mctp_stack::Sender, const OUTSTANDING: usize>(
    msg_buf: &[u8],
    recv_msg: RecvMessage,
    server: &mut server::Server<S, OUTSTANDING>,
) {
    use hubpack::deserialize;
    use idol_runtime::Leased;
    use zerocopy::FromBytes;
    let Some(op) = ipc::MCTPOperation::from_u32(recv_msg.operation) else {
        // TODO check which cases and unwraps have to be handled better.
        return;
    };
    match op {
        ipc::MCTPOperation::req => {
            let eid = ipc::MCTP_req_ARGS::ref_from_bytes(msg_buf)
                .unwrap_lite()
                .eid;
            server.req(&recv_msg, eid);
        }
        ipc::MCTPOperation::listener => {
            let typ = ipc::MCTP_listener_ARGS::ref_from_bytes(msg_buf)
                .unwrap_lite()
                .typ;
            server.listener(&recv_msg, typ);
        }
        ipc::MCTPOperation::get_eid => {
            server.get_eid(&recv_msg);
        }
        ipc::MCTPOperation::set_eid => {
            let eid = ipc::MCTP_set_eid_ARGS::ref_from_bytes(msg_buf)
                .unwrap_lite()
                .eid;
            server.set_eid(&recv_msg, eid);
        }
        ipc::MCTPOperation::recv => {
            let (recv_args, _): (ipc::MCTP_recv_ARGS, _) =
                deserialize(msg_buf).unwrap_lite();
            let lease = Leased::write_only_slice(recv_msg.sender, 0, None)
                .unwrap_lite();
            server.recv(
                recv_msg,
                recv_args.handle,
                recv_args.timeout_millis,
                lease,
            );
        }
        ipc::MCTPOperation::send => {
            let (send_args, _): (ipc::MCTP_send_ARGS, _) =
                deserialize(msg_buf).unwrap_lite();
            let ic = send_args.raw_ic != 0;
            let lease =
                Leased::read_only_slice(recv_msg.sender, 0, None).unwrap_lite();
            server.send(
                &recv_msg,
                send_args.handle,
                send_args.typ,
                send_args.eid,
                send_args.tag,
                ic,
                lease,
            );
        }
        ipc::MCTPOperation::drop => {
            let handle = ipc::MCTP_drop_ARGS::ref_from_bytes(msg_buf)
                .unwrap_lite()
                .handle;
            server.unbind(&recv_msg, handle);
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/notifications.rs"));

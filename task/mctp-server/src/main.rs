// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

#[cfg(feature = "transport_serial")]
use core::cell::RefCell;
#[cfg(feature = "transport_serial")]
use core::ops::DerefMut;
use userlib::*;

#[cfg(any(feature = "transport_serial", feature = "serial_log"))]
use ast1060_uart_api::Uart;

#[cfg(feature = "transport_i2c")]
use drv_i2c_api::*;

#[cfg(feature = "transport_i2c")]
mod i2c;
#[cfg(feature = "transport_serial")]
mod serial;
mod server;
use server::Server;

/// Maximum number of concurrent requests the server can handle.
pub const MAX_REQUESTS: usize = 8;
/// Maximum number of listeners that can be registered concurrently.
pub const MAX_LISTENERS: usize = 8;
/// Maximum number of concurrent outstanding receive calls.
pub const MAX_OUTSTANDING: usize = 16;
/// The initial EID assigned to the MCTP server.
pub const INITIAL_EID: u8 = 42;
/// The maximum number of peers supported for I2C transport.
pub const I2C_MAX_EIDS: u8 = 16;
/// Own static I2C address for I2C transport.
/// This should be made configurable in the future,
/// or be assigned via SMBus ARP.
pub const I2C_OWN_ADDR: u8 = 0x12;

#[cfg(all(feature = "transport_serial", feature = "serial_log"))]
compile_error!("Features 'transport_serial' and 'serial_log' cannot be enabled at the same time.");

#[cfg(any(feature = "transport_serial", feature = "serial_log"))]
task_slot!(UART, uart_driver);

#[cfg(feature = "transport_i2c")]
task_slot!(I2C, i2c_driver);

#[export_name = "main"]
fn main() -> ! {
    let mut msg_buf = [0; ipc::INCOMING_SIZE];

    // Initialize logging to serial first thing if enabled
    #[cfg(feature = "serial_log")]
    ast1060_uart_log::init(
        Uart::new(UART.get_task_id()).unwrap_lite(),
        log::Level::Info,
    )
    .unwrap_lite();

    // Setup MCTP server over serial transport if enabled
    #[cfg(feature = "transport_serial")]
    let usart = RefCell::new(Uart::new(UART.get_task_id()).unwrap_lite());
    #[cfg(feature = "transport_serial")]
    let mut server: Server<_, MAX_OUTSTANDING> = {
        let serial_sender = serial::SerialSender::new(&usart);
        let usart = &mut usart.borrow_mut();
        usart
            .enable_rx_notification(notifications::RX_DATA_BIT)
            .unwrap_lite();
        Server::new(mctp::Eid(INITIAL_EID), 0, serial_sender)
    };
    #[cfg(feature = "transport_serial")]
    let mut serial_reader = mctp_stack::serial::MctpSerialHandler::new();

    // Setup MCTP server over I2C transport if enabled
    #[cfg(feature = "transport_i2c")]
    let i2c_recv = I2cDevice::new(
        I2C.get_task_id(),
        Controller::I2C1,
        PortIndex(0),
        None,
        0x00, // Addr not used for slave mode
    );
    #[cfg(feature = "transport_i2c")]
    let mut server: Server<_, MAX_OUTSTANDING> = {
        let i2c_sender = i2c::I2cSender::new(I2C.get_task_id());
        i2c_recv.configure_slave_address(I2C_OWN_ADDR).unwrap_lite();
        i2c_recv.enable_slave_receive().unwrap_lite();
        i2c_recv.enable_slave_notification(notifications::I2C_SLAVE_MASK).unwrap_lite();
        Server::new(mctp::Eid(INITIAL_EID), 0, i2c_sender)
    };

    let state = sys_get_timer();
    server.update(state.now);

    log::info!("MCTP server started.");

    #[cfg(feature = "transport_serial")]
    let notification_mask =
        notifications::RX_DATA_MASK | notifications::TIMER_MASK;
    #[cfg(feature = "transport_i2c")]
    let notification_mask = notifications::TIMER_MASK | notifications::I2C_SLAVE_MASK;
    loop {
        let msg = sys_recv_open(&mut msg_buf, notification_mask);

        #[cfg(feature = "transport_serial")]
        handle_serial_transport(&msg, &mut server, &usart, &mut serial_reader);

        #[cfg(feature = "transport_i2c")]
        handle_i2c_transport(&msg, &mut server, &i2c_recv);

        if msg.sender == TaskId::KERNEL
            && (msg.operation & notifications::TIMER_MASK) != 0
        {
            let state = sys_get_timer();
            server.update(state.now);
            continue;
        }

        if msg.sender != TaskId::KERNEL {
            handle_mctp_msg(&msg_buf, msg, &mut server);
        }
    }
}

#[cfg(feature = "transport_serial")]
fn handle_serial_transport<S: mctp_stack::Sender, const OUTSTANDING: usize>(
    msg: &RecvMessage,
    server: &mut server::Server<S, OUTSTANDING>,
    uart: &RefCell<Uart>,
    serial_reader: &mut mctp_stack::serial::MctpSerialHandler,
) {
    if msg.sender == TaskId::KERNEL
        && (msg.operation & notifications::RX_DATA_MASK) != 0
    {
        let usart = &mut uart.borrow_mut();
        let pkt = serial_reader.recv(&mut usart.deref_mut());
        match server.stack.inbound(pkt.unwrap_lite()) {
            Ok(_) => {}
            Err(_) => return,
        };
        let state = sys_get_timer();
        server.update(state.now);
    }
}

#[cfg(feature = "transport_i2c")]
fn handle_i2c_transport<S: mctp_stack::Sender, const OUTSTANDING: usize>(
    msg: &RecvMessage,
    server: &mut server::Server<S, OUTSTANDING>,
    i2c: &I2cDevice,
) {
    if msg.sender == TaskId::KERNEL
        && (msg.operation & notifications::I2C_SLAVE_MASK) != 0
    {
        // Drain all available messages following BKM pattern
        loop {
            match i2c.get_slave_message() {
                Ok(slave_msg) => {
                    // Process the I2C slave message - extract data slice
                    let data = &slave_msg.data[..slave_msg.data_length as usize];
                    match server.stack.inbound(data) {
                        Ok(_) => {}
                        Err(_) => continue,
                    };
                }
                Err(ResponseCode::NoSlaveMessage) => {
                    // All messages drained, exit loop
                    break;
                }
                Err(_) => {
                    // Unexpected error, exit loop
                    break;
                }
            }
        }
        let state = sys_get_timer();
        server.update(state.now);
    }
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

    let msg_buf = &msg_buf[..recv_msg.message_len];
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

mod ipc {
    use counters::*;
    pub use mctp_api::ipc::*;

    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}

include!(concat!(env!("OUT_DIR"), "/notifications.rs"));

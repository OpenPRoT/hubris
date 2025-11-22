//! Mock I2C Server - Embedded Binary
//!
//! This is the embedded binary entry point for the mock I2C server driver.
//! 
//! This implementation uses manual IPC handling (like the UART driver) to support
//! timer notifications for injecting test slave messages asynchronously.

#![no_std]
#![no_main]

use drv_i2c_api::*;
use drv_i2c_types::{traits::I2cHardware, Op, ResponseCode, SlaveMessage};

use userlib::{LeaseAttributes, sys_recv_open, sys_reply, sys_borrow_info, 
              sys_borrow_read, sys_borrow_write, sys_post, set_timer_relative, 
              TaskId, RecvMessage, FromPrimitive};
use ringbuf::*;

mod mock_driver;
use mock_driver::MockI2cDriver;

#[derive(Copy, Clone, PartialEq, Count)]
enum Trace {
    None,
    Transaction { controller: u8, addr: u8, len: usize },
    SlaveConfigured { controller: u8, addr: u8 },
    SlaveMessage { controller: u8, addr: u8, len: usize },
    #[count(skip)]
    Panic { controller: u8, status: u32 },
}

counted_ringbuf!(Trace, 64, Trace::None);

// Timer configuration for injecting test slave messages
const TIMER_INTERVAL_MS: u32 = 100;  // Generate test message every 100ms
const TIMER_NOTIF: u32 = 0x0001;      // Timer notification bit

#[export_name = "main"]
fn main() -> ! {
    // Create Mock I2C driver on the stack for IPC testing
    let mut driver = MockI2cDriver::new();
    
    // State for notification-driven slave message injection
    let mut notification_client: Option<(TaskId, u32)> = None;
    let mut timer_armed: bool = false;

    // Message buffer for IPC
    let mut buffer = [0u8; 4];

    loop {
        let msginfo = sys_recv_open(&mut buffer, TIMER_NOTIF);
        
        // Handle timer notification - inject slave message
        if msginfo.sender == TaskId::KERNEL {
            if msginfo.operation & TIMER_NOTIF != 0 {
                if let Some((client_task, notif_mask)) = notification_client {
                    // Inject a test slave message
                    if driver.inject_slave_message().is_ok() {
                        // Notify the client that a message is available
                        sys_post(client_task, notif_mask);
                    }
                    
                    // Re-arm timer for next message if still enabled
                    if timer_armed {
                        set_timer_relative(TIMER_INTERVAL_MS, TIMER_NOTIF);
                    }
                }
            }
            continue;
        }
        
        // Decode operation
        let op = match Op::from_u32(msginfo.operation) {
            Some(op) => op,
            None => {
                sys_reply(msginfo.sender, 1, &[]); // Bad operation
                continue;
            }
        };
        
        // Handle IPC operation
        handle_operation(op, &msginfo, &mut buffer, &mut driver, &mut notification_client, &mut timer_armed);
    }
}

fn handle_operation(
    op: Op,
    msginfo: &RecvMessage,
    buffer: &mut [u8],
    driver: &mut MockI2cDriver,
    notification_client: &mut Option<(TaskId, u32)>,
    timer_armed: &mut bool,
) {
    match op {
        Op::WriteRead | Op::WriteReadBlock => {
            handle_write_read(op, msginfo, buffer, driver);
        }
        Op::ConfigureSlaveAddress => {
            handle_configure_slave_address(msginfo, buffer, driver);
        }
        Op::EnableSlaveReceive => {
            handle_enable_slave_receive(msginfo, buffer, driver);
        }
        Op::DisableSlaveReceive => {
            handle_disable_slave_receive(msginfo, buffer, driver);
        }
        Op::EnableSlaveNotification => {
            handle_enable_slave_notification(msginfo, buffer, notification_client, timer_armed);
        }
        Op::DisableSlaveNotification => {
            handle_disable_slave_notification(msginfo, notification_client, timer_armed);
        }
        Op::GetSlaveMessage => {
            handle_get_slave_message(msginfo, buffer, driver);
        }
    }
}

fn handle_write_read(
    op: Op,
    msginfo: &RecvMessage,
    buffer: &[u8],
    driver: &mut MockI2cDriver,
) {
    let lease_count = msginfo.lease_count;
    
    if lease_count < 2 || lease_count % 2 != 0 {
        sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
        return;
    }
    
    // Extract marshal payload from buffer
    if msginfo.message_len < 4 {
        sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
        return;
    }
    
    let payload: [u8; 4] = [buffer[0], buffer[1], buffer[2], buffer[3]];
    let (addr, controller, _port, _mux) = match Marshal::unmarshal(&payload) {
        Ok(vals) => vals,
        Err(e) => {
            sys_reply(msginfo.sender, e as u32, &[]);
            return;
        }
    };
    
    let mut total = 0;
    
    // Iterate over write/read pairs
    for i in (0..lease_count).step_by(2) {
        // Get write buffer info
        let winfo = match sys_borrow_info(msginfo.sender, i) {
            Some(info) => info,
            None => {
                sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
                return;
            }
        };
        
        if !winfo.attributes.contains(LeaseAttributes::READ) {
            sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
            return;
        }
        
        // Get read buffer info
        let rinfo = match sys_borrow_info(msginfo.sender, i + 1) {
            Some(info) => info,
            None => {
                sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
                return;
            }
        };
        
        if winfo.len == 0 && rinfo.len == 0 {
            sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
            return;
        }
        
        if winfo.len > 255 || rinfo.len > 255 {
            sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
            return;
        }
        
        // Read write data from lease
        let mut write_data = [0u8; 255];
        for pos in 0..winfo.len {
            let (rc, _) = sys_borrow_read(msginfo.sender, i, pos, &mut write_data[pos..pos+1]);
            if rc != 0 {
                sys_reply(msginfo.sender, rc, &[]);
                return;
            }
        }
        
        // Prepare read buffer
        let mut read_buffer = [0u8; 255];
        let read_slice = &mut read_buffer[..rinfo.len];
        
        // Perform the I2C transaction
        let bytes_read = if op == Op::WriteReadBlock {
            match driver.write_read_block(controller, addr, &write_data[..winfo.len], read_slice) {
                Ok(n) => n,
                Err(e) => {
                    sys_reply(msginfo.sender, e as u32, &[]);
                    return;
                }
            }
        } else {
            match driver.write_read(controller, addr, &write_data[..winfo.len], read_slice) {
                Ok(n) => n,
                Err(e) => {
                    sys_reply(msginfo.sender, e as u32, &[]);
                    return;
                }
            }
        };
        
        // Write read data back to lease
        for pos in 0..bytes_read.min(rinfo.len) {
            let (rc, _) = sys_borrow_write(msginfo.sender, i + 1, pos, &read_slice[pos..pos+1]);
            if rc != 0 {
                sys_reply(msginfo.sender, rc, &[]);
                return;
            }
        }
        
        total += bytes_read;
    }
    
    sys_reply(msginfo.sender, 0, &total.to_le_bytes());
}

fn handle_configure_slave_address(
    msginfo: &RecvMessage,
    buffer: &[u8],
    driver: &mut MockI2cDriver,
) {
    if msginfo.message_len < 4 {
        sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
        return;
    }
    
    let payload: [u8; 4] = [buffer[0], buffer[1], buffer[2], buffer[3]];
    let (slave_address, controller, port, _segment) = match Marshal::unmarshal(&payload) {
        Ok(vals) => vals,
        Err(e) => {
            sys_reply(msginfo.sender, e as u32, &[]);
            return;
        }
    };
    
    use drv_i2c_types::SlaveConfig;
    let config = match SlaveConfig::new(controller, port, slave_address) {
        Ok(c) => c,
        Err(_) => {
            sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
            return;
        }
    };
    
    match driver.configure_slave_mode(controller, &config) {
        Ok(()) => sys_reply(msginfo.sender, 0, &[]),
        Err(e) => sys_reply(msginfo.sender, e as u32, &[]),
    }
}

fn handle_enable_slave_receive(
    msginfo: &RecvMessage,
    buffer: &[u8],
    driver: &mut MockI2cDriver,
) {
    if msginfo.message_len < 4 {
        sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
        return;
    }
    
    let payload: [u8; 4] = [buffer[0], buffer[1], buffer[2], buffer[3]];
    let (_address, controller, _port, _segment) = match Marshal::unmarshal(&payload) {
        Ok(vals) => vals,
        Err(e) => {
            sys_reply(msginfo.sender, e as u32, &[]);
            return;
        }
    };
    
    match driver.enable_slave_receive(controller) {
        Ok(()) => sys_reply(msginfo.sender, 0, &[]),
        Err(e) => sys_reply(msginfo.sender, e as u32, &[]),
    }
}

fn handle_disable_slave_receive(
    msginfo: &RecvMessage,
    buffer: &[u8],
    driver: &mut MockI2cDriver,
) {
    if msginfo.message_len < 4 {
        sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
        return;
    }
    
    let payload: [u8; 4] = [buffer[0], buffer[1], buffer[2], buffer[3]];
    let (_address, controller, _port, _segment) = match Marshal::unmarshal(&payload) {
        Ok(vals) => vals,
        Err(e) => {
            sys_reply(msginfo.sender, e as u32, &[]);
            return;
        }
    };
    
    match driver.disable_slave_receive(controller) {
        Ok(()) => sys_reply(msginfo.sender, 0, &[]),
        Err(e) => sys_reply(msginfo.sender, e as u32, &[]),
    }
}

fn handle_enable_slave_notification(
    msginfo: &RecvMessage,
    buffer: &[u8],
    notification_client: &mut Option<(TaskId, u32)>,
    timer_armed: &mut bool,
) {
    if msginfo.message_len < 4 {
        sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
        return;
    }
    
    // Check for lease with notification mask
    if msginfo.lease_count < 1 {
        sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
        return;
    }
    
    let lease_info = match sys_borrow_info(msginfo.sender, 0) {
        Some(info) => info,
        None => {
            sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
            return;
        }
    };
    
    if lease_info.len < 4 {
        sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
        return;
    }
    
    // Read notification mask from lease (u32, 4 bytes)
    let mut mask_bytes = [0u8; 4];
    for i in 0..4 {
        let (rc, _) = sys_borrow_read(msginfo.sender, 0, i, &mut mask_bytes[i..i+1]);
        if rc != 0 {
            sys_reply(msginfo.sender, rc, &[]);
            return;
        }
    }
    let notif_mask = u32::from_le_bytes(mask_bytes);
    
    // Store client info and start timer
    *notification_client = Some((msginfo.sender, notif_mask));
    *timer_armed = true;
    set_timer_relative(TIMER_INTERVAL_MS, TIMER_NOTIF);
    
    sys_reply(msginfo.sender, 0, &[]);
}

fn handle_disable_slave_notification(
    msginfo: &RecvMessage,
    notification_client: &mut Option<(TaskId, u32)>,
    timer_armed: &mut bool,
) {
    // Clear notification state and stop timer
    *notification_client = None;
    *timer_armed = false;
    
    sys_reply(msginfo.sender, 0, &[]);
}

fn handle_get_slave_message(
    msginfo: &RecvMessage,
    buffer: &[u8],
    driver: &mut MockI2cDriver,
) {
    if msginfo.message_len < 4 {
        sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
        return;
    }
    
    let payload: [u8; 4] = [buffer[0], buffer[1], buffer[2], buffer[3]];
    let (_address, controller, _port, _segment) = match Marshal::unmarshal(&payload) {
        Ok(vals) => vals,
        Err(e) => {
            sys_reply(msginfo.sender, e as u32, &[]);
            return;
        }
    };
    
    // Check that we have a lease for returning the message
    if msginfo.lease_count < 1 {
        sys_reply(msginfo.sender, ResponseCode::BadArg as u32, &[]);
        return;
    }
    
    // Try to get a message from the driver
    let mut messages = [SlaveMessage::default(); 1];
    match driver.poll_slave_messages(controller, &mut messages) {
        Ok(1) => {
            // Message available - write to lease
            let slave_msg = &messages[0];
            
            // Write: source_address (1 byte) + data_length (1 byte) + data
            let mut write_buf = [0u8; 257]; // max: 2 + 255
            write_buf[0] = slave_msg.source_address;
            write_buf[1] = slave_msg.data_length;
            write_buf[2..2 + slave_msg.data_length as usize]
                .copy_from_slice(&slave_msg.data[..slave_msg.data_length as usize]);
            
            let total_len = 2 + slave_msg.data_length as usize;
            for i in 0..total_len {
                let (rc, _) = sys_borrow_write(msginfo.sender, 0, i, &write_buf[i..i+1]);
                if rc != 0 {
                    sys_reply(msginfo.sender, rc, &[]);
                    return;
                }
            }
            
            sys_reply(msginfo.sender, 0, &total_len.to_le_bytes());
        }
        Ok(0) => {
            // No message available
            sys_reply(msginfo.sender, ResponseCode::NoSlaveMessage as u32, &[]);
        }
        Ok(_) => {
            // Unexpected count
            sys_reply(msginfo.sender, ResponseCode::BadResponse as u32, &[]);
        }
        Err(e) => {
            sys_reply(msginfo.sender, e as u32, &[]);
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/notifications.rs"));

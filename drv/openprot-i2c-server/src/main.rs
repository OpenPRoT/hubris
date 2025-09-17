//! Mock I2C Server - Embedded Binary
//!
//! This is the embedded binary entry point for the mock I2C server driver.

#![no_std]
#![no_main]

use drv_i2c_api::*;
use drv_i2c_types::{traits::I2cHardware, Op, ResponseCode};

use userlib::{hl, LeaseAttributes};
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

#[export_name = "main"]
fn main() -> ! {
    // Create Mock I2C driver on the stack for IPC testing
    let mut driver = MockI2cDriver::new();
    
    // Optional: Configure driver for specific test scenarios
    // Example: driver.set_device_response(Controller::I2C0, 0x50, &[0x12, 0x34]).ok();

    // Field messages
    let mut buffer = [0; 4];

    loop {
        hl::recv_without_notification(&mut buffer, |op, msg| match op {
            Op::WriteRead | Op::WriteReadBlock => {
                let lease_count = msg.lease_count();

                let (payload, caller) = msg
                    .fixed::<[u8; 4], usize>()
                    .ok_or(ResponseCode::BadArg)?;

                if lease_count < 2 || lease_count % 2 != 0 {
                    return Err(ResponseCode::BadArg);
                }

                // For mock mode, we use the standard marshal format but ignore complex topology
                let (addr, controller, _port, _mux) = Marshal::unmarshal(payload)?;

                let mut total = 0;

                // Iterate over write/read pairs
                for i in (0..lease_count).step_by(2) {
                    let wbuf = caller.borrow(i);
                    let winfo = wbuf.info().ok_or(ResponseCode::BadArg)?;

                    if !winfo.attributes.contains(LeaseAttributes::READ) {
                        return Err(ResponseCode::BadArg);
                    }

                    let rbuf = caller.borrow(i + 1);
                    let rinfo = rbuf.info().ok_or(ResponseCode::BadArg)?;

                    if winfo.len == 0 && rinfo.len == 0 {
                        return Err(ResponseCode::BadArg);
                    }

                    if winfo.len > 255 || rinfo.len > 255 {
                        // Keep the 255 limit as per IPC protocol
                        return Err(ResponseCode::BadArg);
                    }

                    // Read write data from lease
                    let mut write_data = [0u8; 255];
                    for pos in 0..winfo.len {
                        write_data[pos] = wbuf.read_at(pos).ok_or(ResponseCode::BadArg)?;
                    }

                    // Prepare read buffer
                    let mut read_buffer = [0u8; 255];
                    let read_slice = &mut read_buffer[..rinfo.len];

                    // Perform the I2C transaction
                    let bytes_read = if op == Op::WriteReadBlock {
                        driver.write_read_block(
                            controller,
                            addr,
                            &write_data[..winfo.len],
                            read_slice,
                        )?
                    } else {
                        driver.write_read(
                            controller,
                            addr,
                            &write_data[..winfo.len],
                            read_slice,
                        )?
                    };

                    // Write read data back to lease
                    for pos in 0..bytes_read.min(rinfo.len) {
                        rbuf.write_at(pos, read_slice[pos]).ok_or(ResponseCode::BadArg)?;
                    }

                    total += bytes_read;
                }

                caller.reply(total);
                Ok(())
            }
            Op::ConfigureSlaveAddress => {
                // Use the same marshal format as WriteRead operations
                let (payload, caller) = msg
                    .fixed::<[u8; 4], usize>()
                    .ok_or(ResponseCode::BadArg)?;

                let (slave_address, controller, port, _segment) = Marshal::unmarshal(payload)?;
                
                // Create slave configuration  
                let config = SlaveConfig::new(controller, port, slave_address)
                    .map_err(|_| ResponseCode::BadArg)?;
                
                // Configure slave mode on hardware
                driver.configure_slave_mode(controller, &config)?;
                
                caller.reply(0usize);
                Ok(())
            }
            Op::EnableSlaveReceive => {
                // Use the same marshal format as WriteRead operations
                let (payload, caller) = msg
                    .fixed::<[u8; 4], usize>()
                    .ok_or(ResponseCode::BadArg)?;

                let (_address, controller, _port, _segment) = Marshal::unmarshal(payload)?;
                
                driver.enable_slave_receive(controller)?;
                caller.reply(0usize);
                Ok(())
            }
            Op::DisableSlaveReceive => {
                // Use the same marshal format as WriteRead operations
                let (payload, caller) = msg
                    .fixed::<[u8; 4], usize>()
                    .ok_or(ResponseCode::BadArg)?;

                let (_address, controller, _port, _segment) = Marshal::unmarshal(payload)?;
                
                driver.disable_slave_receive(controller)?;
                caller.reply(0usize);
                Ok(())
            }
            Op::CheckSlaveBuffer => {
                // Use the same marshal format as WriteRead operations
                let (payload, caller) = msg
                    .fixed::<[u8; 4], usize>()
                    .ok_or(ResponseCode::BadArg)?;

                let (_address, controller, _port, _segment) = Marshal::unmarshal(payload)?;
                
                // Check for slave messages - for now just return count
                // A full implementation would need to handle message data formatting
                let temp_messages: [u8; 0] = []; // Empty for mock
                let count = temp_messages.len();
                
                caller.reply(count);
                Ok(())
            }
        });
    }
}

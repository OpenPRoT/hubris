// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! I2C Client Test Task
//!
//! This task exercises all available I2C IPC operations to validate the
//! mock I2C server implementation. It tests both master mode operations
//! and slave mode operations for comprehensive protocol validation.

#![no_std]
#![no_main]

use drv_i2c_api::{I2cDevice, ResponseCode, Controller, PortIndex};
use userlib::*;
use ringbuf::*;

task_slot!(I2C, i2c);
task_slot!(UART, uart_driver);

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    None,
    TestStart(u32),
    TestComplete(u32),
    MasterOpResult(u32, bool), // operation_id, success
    SlaveOpResult(u32, bool),  // operation_id, success
    Error(u32),
}

ringbuf!(Trace, 16, Trace::None);

/// I2C device configuration for testing
const TEST_CONTROLLER: Controller = Controller::I2C0;
const TEST_PORT: PortIndex = PortIndex(0); 
const TEST_DEVICE_ADDR: u8 = 0x50;
const TEST_SLAVE_ADDR: u8 = 0x42;

#[export_name = "main"]
fn main() -> ! {
    let i2c_task = I2C.get_task_id();
    
    // Send startup banner
    uart_send(b"\r\n=== I2C Client Test Task Started ===\r\n");
    uart_send(b"Testing all I2C IPC operations...\r\n\r\n");
    
    let device = I2cDevice::new(i2c_task, TEST_CONTROLLER, TEST_PORT, None, TEST_DEVICE_ADDR, "i2c-client");

    loop {
        // Run comprehensive I2C tests
        uart_send(b"--- Starting Master Mode Tests ---\r\n");
        run_master_mode_tests(&device);
        uart_send(b"Master mode tests completed.\r\n\r\n");
        
        uart_send(b"--- Starting Slave Mode Tests ---\r\n");
        run_slave_mode_tests(&device);
        uart_send(b"Slave mode tests completed.\r\n\r\n");
        
        uart_send(b"Test cycle complete. Waiting 5 seconds...\r\n\r\n");
        
        // Wait before next test cycle
        hl::sleep_for(5000);
    }
}

/// Test all master mode operations
fn run_master_mode_tests(device: &I2cDevice) {
    ringbuf_entry!(Trace::TestStart(1));
    
    // Test 1: Basic read_reg operation
    uart_send(b"  Test 1: read_reg... ");
    let read_result: Result<u8, ResponseCode> = device.read_reg(0x10u8);
    uart_send(if read_result.is_ok() { b"PASS\r\n" } else { b"FAIL\r\n" });
    ringbuf_entry!(Trace::MasterOpResult(1, read_result.is_ok()));
    
    // Test 2: read_reg_into operation  
    uart_send(b"  Test 2: read_reg_into... ");
    let mut buffer = [0u8; 4];
    let read_into_result = device.read_reg_into(0x20u8, &mut buffer);
    uart_send(if read_into_result.is_ok() { b"PASS\r\n" } else { b"FAIL\r\n" });
    ringbuf_entry!(Trace::MasterOpResult(2, read_into_result.is_ok()));
    
    // Test 3: read_block operation
    uart_send(b"  Test 3: read_block... ");
    let mut block_buffer = [0u8; 16];
    let block_result = device.read_block(0x30u8, &mut block_buffer);
    uart_send(if block_result.is_ok() { b"PASS\r\n" } else { b"FAIL\r\n" });
    ringbuf_entry!(Trace::MasterOpResult(3, block_result.is_ok()));
    
    // Test 4: Basic write operation
    uart_send(b"  Test 4: write... ");
    let write_data = [0x01, 0x02, 0x03, 0x04];
    let write_result = device.write(&write_data);
    uart_send(if write_result.is_ok() { b"PASS\r\n" } else { b"FAIL\r\n" });
    ringbuf_entry!(Trace::MasterOpResult(4, write_result.is_ok()));
    
    // Test 5: write_read_reg operation (requires write buffer)
    uart_send(b"  Test 5: write_read_reg... ");
    let write_data_for_read = [0x01];
    let write_read_result: Result<u16, ResponseCode> = device.write_read_reg(0x40u8, &write_data_for_read);
    uart_send(if write_read_result.is_ok() { b"PASS\r\n" } else { b"FAIL\r\n" });
    ringbuf_entry!(Trace::MasterOpResult(5, write_read_result.is_ok()));
    
    // Test 6: write_read_block operation (requires output buffer)
    uart_send(b"  Test 6: write_read_block... ");
    let mut wr_block_buffer = [0u8; 8];
    let wr_block_result = device.write_read_block(0x50u8, &write_data_for_read, &mut wr_block_buffer);
    uart_send(if wr_block_result.is_ok() { b"PASS\r\n" } else { b"FAIL\r\n" });
    ringbuf_entry!(Trace::MasterOpResult(6, wr_block_result.is_ok()));
    
    // Test 7: write_write operation (dual write)
    uart_send(b"  Test 7: write_write... ");
    let write1_data = [0xAA];
    let write2_data = [0xBB, 0xCC];
    let write_write_result = device.write_write(&write1_data, &write2_data);
    uart_send(if write_write_result.is_ok() { b"PASS\r\n" } else { b"FAIL\r\n" });
    ringbuf_entry!(Trace::MasterOpResult(7, write_write_result.is_ok()));
    
    // Test 8: write_write_read_reg operation (complex combo - requires three buffers)
    uart_send(b"  Test 8: write_write_read_reg... ");
    let wwr_result: Result<u32, ResponseCode> = device.write_write_read_reg(0x60u8, &write1_data, &write2_data);
    uart_send(if wwr_result.is_ok() { b"PASS\r\n" } else { b"FAIL\r\n" });
    ringbuf_entry!(Trace::MasterOpResult(8, wwr_result.is_ok()));
    
    ringbuf_entry!(Trace::TestComplete(1));
}

/// Test all slave mode operations for MCTP protocol support
fn run_slave_mode_tests(device: &I2cDevice) {
    ringbuf_entry!(Trace::TestStart(2));
    
    // Test 1: Configure slave address
    uart_send(b"  Test 1: configure_slave_address... ");
    let config_result = device.configure_slave_address(TEST_SLAVE_ADDR);
    uart_send(if config_result.is_ok() { b"PASS\r\n" } else { b"FAIL\r\n" });
    ringbuf_entry!(Trace::SlaveOpResult(1, config_result.is_ok()));
    
    // Test 2: Enable slave receive mode
    uart_send(b"  Test 2: enable_slave_receive... ");
    let enable_result = device.enable_slave_receive();
    uart_send(if enable_result.is_ok() { b"PASS\r\n" } else { b"FAIL\r\n" });
    ringbuf_entry!(Trace::SlaveOpResult(2, enable_result.is_ok()));
    
    // Test 3: Check slave buffer (should work even if no messages)
    uart_send(b"  Test 3: check_slave_buffer... ");
    let mut slave_buffer = [0u8; 64];
    let check_result = device.check_slave_buffer(&mut slave_buffer);
    uart_send(if check_result.is_ok() { b"PASS\r\n" } else { b"FAIL\r\n" });
    ringbuf_entry!(Trace::SlaveOpResult(3, check_result.is_ok()));
    
    // Test 4: Disable slave receive mode
    uart_send(b"  Test 4: disable_slave_receive... ");
    let disable_result = device.disable_slave_receive();
    uart_send(if disable_result.is_ok() { b"PASS\r\n" } else { b"FAIL\r\n" });
    ringbuf_entry!(Trace::SlaveOpResult(4, disable_result.is_ok()));
    
    ringbuf_entry!(Trace::TestComplete(2));
}

/// Send text to UART for debugging output
fn uart_send(text: &[u8]) {
    let uart_task = UART.get_task_id();
    
    const OP_WRITE: u16 = 1;
    let (code, _) = sys_send(uart_task, OP_WRITE, &[], &mut [], &[Lease::from(text)]);
    assert_eq!(0, code);
}
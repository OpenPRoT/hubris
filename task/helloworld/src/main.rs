// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use ast1060_uart_api::Uart;
use embedded_io::{Read, Write};
use userlib::*;

task_slot!(UART, uart_driver);

#[export_name = "main"]
fn main() -> ! {
    let mut uart = Uart::new(UART.get_task_id()).unwrap_lite();
    uart.write_fmt(format_args!("Hello World!\n")).unwrap_lite();

    // Enable RX notifications.
    // Print errors and continue (blocking the task with recv).
    let _ = uart
        .enable_rx_notification(notifications::RX_DATA_BIT)
        .inspect_err(|e| {
            uart.write_fmt(format_args!(
                "enable_rx_notification failed: {e:?}\n"
            ))
            .unwrap_lite();
        });
    let mut buf = [0; 32];
    loop {
        sys_recv_notification(notifications::RX_DATA_MASK);
        let n = uart.read(&mut buf).unwrap_lite();
        uart.write_all(&buf[..n]).unwrap_lite();
    }
}

include!(concat!(env!("OUT_DIR"), "/notifications.rs"));

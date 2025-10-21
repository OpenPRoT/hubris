// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use ast1060_uart_api::{Uart, UartError};
use embedded_io::{Read, Write};
use userlib::*;
use zerocopy::FromBytes;

task_slot!(UART, uart_driver);

#[export_name = "main"]
fn main() -> ! {
    let mut uart = Uart::new(UART.get_task_id()).unwrap_lite();
    uart.write_fmt(format_args!("Hello World!\n")).unwrap_lite();
    let mut buf = [0; 32];
    loop {
        hl::sleep_for(1);
        let n = uart.read(&mut buf).unwrap_lite();
        uart.write_all(&buf[..n]).unwrap_lite();
    }
}

fn uart_send(text: &[u8]) {
    let peer = UART.get_task_id();

    const OP_WRITE: u16 = 1;
    let (code, _) =
        sys_send(peer, OP_WRITE, &[], &mut [], &[Lease::from(text)]);
    assert_eq!(0, code);
}

fn uart_read<'a>(text: &'a mut [u8]) -> &'a [u8] {
    let peer = UART.get_task_id();
    const OP_READ: u16 = 2;

    let mut response = [0u8; 4];
    let (code, n) = sys_send(
        peer,
        OP_READ,
        &[],
        &mut response,
        &mut [Lease::from(&mut *text)],
    );
    // check for success or overflow
    if (code == 0 || code == 5) && n == 4 {
        let n = u32::ref_from_bytes(&response[..n]).unwrap_lite();
        &text[..*n as usize]
    } else {
        &[]
    }
}

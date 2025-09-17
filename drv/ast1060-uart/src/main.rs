// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A driver for the LPC55 U(S)ART.
//!
//! This driver is currently configured to run at 9600. We could potentially
//! run faster but 9600 works so nicely with the clocks...
//!
//! # IPC protocol
//!
//! ## `write` (1)
//!
//! Sends the contents of lease #0. Returns when completed.

#![no_std]
#![no_main]

use core::ops::Deref;
use ast1060_pac as device;
use lib_ast1060_uart::{Usart, Write, Read, InterruptDecoding};
use userlib::*;
use zerocopy::{IntoBytes, IntoByteSliceMut, IntoByteSlice};

// task_slot!(SYSCON, syscon_driver);

#[repr(u16)]
pub enum OpCode {
    Write = 1,
    Read = 2,
}

impl TryFrom<u32> for OpCode {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(OpCode::Write),
            2 => Ok(OpCode::Read),
            _ => Err(()),
        }
    }
}

const OP_WRITE: u32 = 1;
const OP_READ: u32 = 2;

#[repr(u32)]
pub enum ResponseCode {
    Success = 0,
    BadOp = 1,
    BadArg = 2,
    Busy = 3,
}

struct Transmit {
    task: TaskId,
    len: usize,
    pos: usize,
}

#[export_name = "main"]
fn main() -> ! {
    // Turn the actual peripheral on so that we can interact with it.
    turn_on_uart();

    let peripherals = unsafe { device::Peripherals::steal() };
    let usart = peripherals.uart;

    let mut usart = Usart::from(usart.deref());

    // USART side yet, so this won't trigger notifications yet.
    sys_irq_control(notifications::UART_IRQ_MASK, true);

    // Field messages.
    let mut tx: Option<Transmit> = None;
    let mut reg;
    let mut rx_buf = [0u8; 128];
    let mut rx_idx = 0;

    loop {
        let msginfo = sys_recv_open(&mut [], notifications::UART_IRQ_MASK);
        if msginfo.sender == TaskId::KERNEL {
            if msginfo.operation & 1 != 0 {
                // Handling an interrupt. To allow for spurious interrupts,
                // check the individual conditions we care about, and
                // unconditionally re-enable the IRQ at the end of the handler.
                let interrupt = usart.read_interrupt_status();

                match interrupt {
                    InterruptDecoding::ModemStatusChange => {
                        // Modem status change
                        reg = usart.read_modem_status();
                    }
                    InterruptDecoding::TxEmpty => {
                        // UART THR Empty
                        if let Some(txs) = tx.as_mut() {
                            // TX register empty. Time to send something.
                            if step_transmit(&mut usart, txs) {
                                tx = None;
                                // This is a write to clear register
                                usart.clear_tx_idle_interrupt();
                            }

                        }

                    }
                    InterruptDecoding::RxDataAvailable => {
                        // Receive data available
                        reg = usart.read() 
                            .unwrap_or_else(|_| {
                                // If we get an error, we just return 0.
                                0
                            });
                        rx_buf[rx_idx % 32] = reg;
                        rx_idx += 1;
                    }
                    InterruptDecoding::LineStatusChange => {
                        // Receive line status change
                        reg = usart.read_line_status();
                    }
                    InterruptDecoding::CharacterTimeout => {
                        // Character timeout
                        reg = usart.read()
                            .unwrap_or_else(|_| {
                                // If we get an error, we just return 0.
                                0
                            });
                        // usart.write(reg);
                        rx_buf[rx_idx % 32] = reg;
                        rx_idx += 1;
                    }
                    _ => {

                    }
                }

                sys_irq_control(notifications::UART_IRQ_MASK, true);
            }
        } else {
            match OpCode::try_from(msginfo.operation) {
                Ok(OpCode::Write) => {
                    // Deny incoming writes if we're already running one.
                    if tx.is_some() {
                        sys_reply(
                            msginfo.sender,
                            ResponseCode::Busy as u32,
                            &[],
                        );
                        continue;
                    }

                    // Check the lease count and characteristics.
                    if msginfo.lease_count != 1 {
                        sys_reply(
                            msginfo.sender,
                            ResponseCode::BadArg as u32,
                            &[],
                        );
                        continue;
                    }

                    let len = match sys_borrow_info(msginfo.sender, 0) {
                        None => {
                            sys_reply(
                                msginfo.sender,
                                ResponseCode::BadArg as u32,
                                &[],
                            );
                            continue;
                        }
                        Some(info)
                            if !info
                                .attributes
                                .contains(LeaseAttributes::READ) =>
                        {
                            sys_reply(
                                msginfo.sender,
                                ResponseCode::BadArg as u32,
                                &[],
                            );
                            continue;
                        }
                        Some(info) => info.len,
                    };

                    // Okay! Begin a transfer!
                    tx = Some(Transmit {
                        task: msginfo.sender,
                        pos: 0,
                        len,
                    });

                    usart.set_tx_idle_interrupt();

                    // We'll do the rest as interrupts arrive.
                }
                Ok(OpCode::Read) => {
                    // Deny incoming reads.
                    if rx_idx == 0 {
                        sys_reply(
                            msginfo.sender,
                            ResponseCode::BadArg as u32,
                            &[],
                        );
                        continue;
                    } else if msginfo.lease_count == 1 {
                        let response = [0u8; 4];
                        sys_irq_control(notifications::UART_IRQ_MASK, false);
                        sys_borrow_write(
                            msginfo.sender,
                            0,
                            0,
                            rx_buf[..rx_idx.min(32)].into_byte_slice(),
                        );
                        sys_irq_control(notifications::UART_IRQ_MASK, true);
                        sys_reply(
                            msginfo.sender,
                            ResponseCode::Success as u32,
                            &response,
                        );
                        rx_idx = 0;
                    }
                }
                _ => sys_reply(msginfo.sender, ResponseCode::BadOp as u32, &[]),
            }
        }
    }
}

fn turn_on_uart() {
}

fn step_transmit(usart: &mut Usart<'_>, txs: &mut Transmit) -> bool {
    let mut byte = 0u8;
    let (rc, len) = sys_borrow_read(txs.task, 0, txs.pos, byte.as_mut_bytes());
    if rc != 0 || len != 1 {
        sys_reply(txs.task, ResponseCode::BadArg as u32, &[]);
        true
    } else {
        // Stuff byte into transmitter.
        match usart.write(byte) {
            Ok(_) => {
                txs.pos += 1;
                if txs.pos == txs.len {
                    sys_reply(txs.task, ResponseCode::Success as u32, &[]);
                    true
                } else {
                    false
                }
            }
            Err(nb::Error::WouldBlock) => false,
            Err(nb::Error::Other(e)) => {
                panic!("write to Usart failed: {:?}", e)
            }
        }
    }
}

// include!(concat!(env!("OUT_DIR"), "/pin_config.rs"));

include!(concat!(env!("OUT_DIR"), "/notifications.rs"));

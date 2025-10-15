// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A driver for the AST1060 UART.
//!
//! # IPC protocol
//!
//! ## `write` (1)
//!
//! Sends the contents of lease #0. Returns when completed.
//!
//! ## `read` (2)
//!
//! Copies available RX data into lease #0.

#![no_std]
#![no_main]

use ast1060_pac as device;
use core::ops::Deref;
use embedded_hal::serial::{Read, Write};
use lib_ast1060_uart::{InterruptDecoding, Usart};
use userlib::*;
use zerocopy::{IntoByteSlice, IntoBytes};

const RX_BUF_SIZE: usize = 128;

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

#[repr(u32)]
pub enum ResponseCode {
    Success = 0,
    BadOp = 1,
    BadArg = 2,
    Busy = 3,
    Overflow = 4,
}

struct Transmit {
    task: TaskId,
    len: usize,
    pos: usize,
}

#[export_name = "main"]
fn main() -> ! {
    let peripherals = unsafe { device::Peripherals::steal() };
    let usart = peripherals.uart;

    let mut usart = Usart::from(usart.deref());

    sys_irq_control(notifications::UART_IRQ_MASK, true);

    // Field messages.
    let mut tx: Option<Transmit> = None;
    let mut reg;
    let mut rx_buf = [0u8; RX_BUF_SIZE];
    let mut rx_idx = 0;

    loop {
        let msginfo = sys_recv_open(&mut [], notifications::UART_IRQ_MASK);
        if msginfo.sender == TaskId::KERNEL {
            if msginfo.operation & notifications::UART_IRQ_MASK != 0 {
                // Handling an interrupt. To allow for spurious interrupts,
                // check the individual conditions we care about, and
                // unconditionally re-enable the IRQ at the end of the handler.
                let interrupt = usart.read_interrupt_status();

                match interrupt {
                    InterruptDecoding::ModemStatusChange => {
                        // Modem status change
                        usart.read_modem_status();
                    }
                    InterruptDecoding::TxEmpty => {
                        // UART THR Empty
                        if let Some(txs) = tx.as_mut() {
                            // TX register empty. Time to send something.
                            if step_transmit(&mut usart, txs) {
                                tx = None;
                                // Disable interrupt when transmission is finished.
                                usart.clear_tx_idle_interrupt();
                            }
                        }
                    }
                    InterruptDecoding::RxDataAvailable => {
                        // Receive data available
                        reg = usart.read().unwrap_or_else(|_| {
                            // If we get an error, we just return 0.
                            0
                        });
                        rx_buf[rx_idx % RX_BUF_SIZE] = reg;
                        rx_idx += 1;
                    }
                    InterruptDecoding::LineStatusChange => {
                        // Receive line status change
                        usart.read_line_status();
                    }
                    InterruptDecoding::CharacterTimeout => {
                        // Character timeout
                        reg = usart.read().unwrap_or_else(|_| {
                            // If we get an error, we just return 0.
                            0
                        });
                        rx_buf[rx_idx % RX_BUF_SIZE] = reg;
                        rx_idx += 1;
                    }
                    _ => {}
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

                    tx = Some(Transmit {
                        task: msginfo.sender,
                        pos: 0,
                        len,
                    });

                    usart.set_tx_idle_interrupt();
                    // Transmit once immediately in case we're already idle.
                    // Otherwise we might never get a tx idle IRQ.
                    if usart.is_tx_idle() {
                        if let Some(txs) = tx.as_mut() {
                            // TX register empty. Time to send something.
                            if step_transmit(&mut usart, txs) {
                                tx = None;
                                // Disable interrupt when transmission is finished.
                                usart.clear_tx_idle_interrupt();
                            }
                        }
                    }
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
                        sys_irq_control(notifications::UART_IRQ_MASK, false);
                        sys_borrow_write(
                            msginfo.sender,
                            0,
                            0,
                            rx_buf[..rx_idx.min(RX_BUF_SIZE)].into_byte_slice(),
                        );
                        sys_irq_control(notifications::UART_IRQ_MASK, true);
                        sys_reply(
                            msginfo.sender,
                            ResponseCode::Success as u32,
                            &[],
                        );
                        rx_idx = 0;
                    }
                }
                _ => sys_reply(msginfo.sender, ResponseCode::BadOp as u32, &[]),
            }
        }
    }
}

/// Attempt to step the transmitter forward by one byte.
///
/// Return `true` when the transmission is complete (or reading from the borrow failed).
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

include!(concat!(env!("OUT_DIR"), "/notifications.rs"));

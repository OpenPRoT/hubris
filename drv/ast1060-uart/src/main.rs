// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A driver for the AST1060 UART.
//!
//! See the `ast1060_uart_api` crate for IPC API documentation.

#![no_std]
#![no_main]

use ast1060_pac as device;
use ast1060_uart_api::ipc::*;
use core::ops::Deref;
use embedded_hal::serial::{Read, Write};
use heapless::Deque;
use lib_ast1060_uart::{InterruptDecoding, Usart};
use userlib::*;
use zerocopy::IntoBytes;

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
    let mut rx_buf: Deque<u8, RX_BUF_SIZE> = Deque::new();
    let mut overflow = false;
    let mut notify_rx_data: Option<(TaskId, u8)> = None;

    loop {
        let mut recv_buf = [0; 1];
        let msginfo =
            sys_recv_open(&mut recv_buf, notifications::UART_IRQ_MASK);
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
                        // Receive all data available
                        let buffer_len = rx_buf.len();
                        while let Ok(byte) = usart.read() {
                            if rx_buf.push_back(byte).is_err() {
                                overflow = true;
                            }
                            if rx_buf.len() > buffer_len {
                                if let Some((task, notification_bit)) =
                                    notify_rx_data
                                {
                                    // Notify the task that data is available.
                                    sys_post(task, 1 << notification_bit);
                                }
                            }
                        }
                    }
                    InterruptDecoding::LineStatusChange => {
                        // Receive line status change
                        usart.read_line_status();
                    }
                    InterruptDecoding::CharacterTimeout => {
                        // Character timeout
                        // Receive all data available
                        let buffer_len = rx_buf.len();
                        while let Ok(byte) = usart.read() {
                            if rx_buf.push_back(byte).is_err() {
                                overflow = true;
                            }
                        }
                        if rx_buf.len() > buffer_len {
                            if let Some((task, notification_bit)) =
                                notify_rx_data
                            {
                                // Notify the task that data is available.
                                sys_post(task, 1 << notification_bit);
                            }
                        }
                    }
                    _ => {}
                }
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
                    if rx_buf.is_empty() {
                        sys_reply(
                            msginfo.sender,
                            ResponseCode::WouldBlock as u32,
                            &[],
                        );
                        continue;
                    } else if msginfo.lease_count == 1 {
                        let (a, b) = rx_buf.as_slices();

                        let (rc, n1) =
                            sys_borrow_write(msginfo.sender, 0, 0, a);
                        if rc != 0 {
                            sys_reply(
                                msginfo.sender,
                                ResponseCode::BadArg as u32,
                                &[],
                            );
                            continue;
                        }

                        if n1 != a.len() {
                            // Could not write all `a` data, return now.
                            // (Also don't forget to pop it from the buffer.)
                            let rc = if overflow {
                                overflow = false;
                                ResponseCode::Overflow as u32
                            } else {
                                ResponseCode::Success as u32
                            };
                            sys_reply(
                                msginfo.sender,
                                rc,
                                (n1 as u32).as_bytes(),
                            );
                            for _ in 0..n1 {
                                rx_buf.pop_front();
                            }
                            continue;
                        }

                        // All `a` data written, try to write `b` data.

                        let (rc, n2) =
                            sys_borrow_write(msginfo.sender, 0, n1, b);
                        if rc != 0 {
                            sys_reply(
                                msginfo.sender,
                                ResponseCode::BadArg as u32,
                                &[],
                            );
                            continue;
                        }
                        let rc = if overflow {
                            overflow = false;
                            ResponseCode::Overflow as u32
                        } else {
                            ResponseCode::Success as u32
                        };
                        sys_reply(
                            msginfo.sender,
                            rc,
                            (n1 as u32 + n2 as u32).as_bytes(),
                        );
                        if n2 == b.len() {
                            rx_buf.clear();
                        } else {
                            // Could not write all `b` data, pop only n bytes.
                            for _ in 0..(n1 + n2) {
                                rx_buf.pop_front();
                            }
                        }
                    }
                }
                Ok(OpCode::EnableRxNotification) => {
                    notify_rx_data = Some((msginfo.sender, recv_buf[0]));
                    sys_reply(
                        msginfo.sender,
                        ResponseCode::Success as u32,
                        &[],
                    );
                }
                Ok(OpCode::DisableRxNotification) => {
                    notify_rx_data = None;
                    sys_reply(
                        msginfo.sender,
                        ResponseCode::Success as u32,
                        &[],
                    );
                }
                _ => sys_reply(msginfo.sender, ResponseCode::BadOp as u32, &[]),
            }
        }
        sys_irq_control(notifications::UART_IRQ_MASK, true);
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

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ast1060_uart_api::Uart;
use core::{cell::RefCell, ops::DerefMut};
use embedded_io::Write;
use mctp::Result;
use userlib::*;

pub struct SerialSender<'a> {
    pub usart: &'a RefCell<Uart>,
    serial_handler: mctp_stack::serial::MctpSerialHandler,
}

impl<'a> mctp_stack::Sender for SerialSender<'a> {
    fn send_vectored(
        &mut self,
        mut fragmenter: mctp_stack::fragment::Fragmenter,
        payload: &[&[u8]],
    ) -> Result<mctp::Tag> {
        loop {
            let mut pkt = [0u8; mctp_stack::serial::MTU_MAX];
            let r = fragmenter.fragment_vectored(payload, &mut pkt);

            match r {
                mctp_stack::fragment::SendOutput::Packet(p) => {
                    self.serial_handler
                        .send_sync(p, &mut self.usart.borrow_mut().deref_mut())
                        .unwrap_lite();
                    self.usart.borrow_mut().flush().unwrap_lite();
                }
                mctp_stack::fragment::SendOutput::Complete { tag, .. } => {
                    break Ok(tag)
                }
                mctp_stack::fragment::SendOutput::Error { err, .. } => {
                    break Err(err)
                }
            }
        }
    }

    fn get_mtu(&self) -> usize {
        mctp_stack::serial::MTU_MAX
    }
}

impl<'a> SerialSender<'a> {
    /// Create a new SerialSender instance with the neccessary serial setup code.
    pub fn new(uart: &'a RefCell<Uart>) -> Self {
        Self {
            usart: uart,
            serial_handler: mctp_stack::serial::MctpSerialHandler::new(),
        }
    }
}

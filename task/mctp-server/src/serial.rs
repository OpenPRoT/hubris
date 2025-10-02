use core::{cell::RefCell, ops::DerefMut};
use embedded_io::Write;
use mctp::Result;
use mctp_stack;
use userlib::*;

use super::notifications;

use lib_ast1060_uart::{InterruptDecoding, Usart};

pub struct SerialSender<'a> {
    pub usart: &'a RefCell<Usart<'a>>,
    serial_handler: mctp_stack::serial::MctpSerialHandler,
}

impl<'a> mctp_stack::Sender for SerialSender<'a> {
    fn send(
        &mut self,
        mut fragmenter: mctp_stack::fragment::Fragmenter,
        payload: &[u8],
    ) -> Result<mctp::Tag> {
        loop {
            let mut pkt = [0u8; mctp_stack::serial::MTU_MAX];
            let r = fragmenter.fragment(payload, &mut pkt);

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
    pub fn new(uart: &'a RefCell<Usart<'a>>) -> Self {
        sys_irq_control(notifications::UART_IRQ_MASK, true);

        Self {
            usart: uart,
            serial_handler: mctp_stack::serial::MctpSerialHandler::new(),
        }
    }
}

pub fn handle_uart_interrupt<'a>(
    interrupt: InterruptDecoding,
    usart: &RefCell<Usart<'_>>,
    serial_reader: &'a mut mctp_stack::serial::MctpSerialHandler,
) -> Option<Result<&'a [u8]>> {
    let usart = &mut usart.borrow_mut();
    match interrupt {
        InterruptDecoding::RxDataAvailable
        | InterruptDecoding::CharacterTimeout => {
            usart.clear_rx_data_available_interrupt();
            let ret = serial_reader.recv(&mut usart.deref_mut());
            usart.set_rx_data_available_interrupt();
            return Some(ret);
        }
        InterruptDecoding::ModemStatusChange => {
            usart.read_modem_status();
        }
        InterruptDecoding::TxEmpty => usart.clear_tx_idle_interrupt(),
        InterruptDecoding::LineStatusChange => {
            usart.read_line_status();
        }
        _ => return Some(Err(mctp::Error::RxFailure)),
    }
    None
}

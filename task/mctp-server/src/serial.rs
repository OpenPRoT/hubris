// mctp-baremetal
use core::{cell::RefCell, ops::DerefMut};
use mctp::Result;
use mctp_stack;
use userlib::*;

use super::notifications;

// use cortex_m_rt::entry;

// #[cfg(feature = "jtag-halt")]
// use core::ptr::{self, addr_of};

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
        // peripherals.scu.scu000().modify(|_, w| w);
        // peripherals.scu.scu41c().modify(|_, w| {
        //     // Set the JTAG pinmux to 0x1f << 25
        //     w.enbl_armtmsfn_pin()
        //         .bit(true)
        //         .enbl_armtckfn_pin()
        //         .bit(true)
        //         .enbl_armtrstfn_pin()
        //         .bit(true)
        //         .enbl_armtdifn_pin()
        //         .bit(true)
        //         .enbl_armtdofn_pin()
        //         .bit(true)
        // });

        // USART side yet, so this won't trigger notifications yet.
        sys_irq_control(notifications::UART_IRQ_MASK, true);

        Self {
            usart: uart,
            serial_handler: mctp_stack::serial::MctpSerialHandler::new(),
        }
    }
}

pub fn handle_recv<'a>(
    interrupt: InterruptDecoding,
    usart: &RefCell<Usart<'_>>,
    serial_reader: &'a mut mctp_stack::serial::MctpSerialHandler,
) -> Result<&'a [u8]> {
    let usart = &mut usart.borrow_mut();
    match interrupt {
        InterruptDecoding::RxDataAvailable
        | InterruptDecoding::CharacterTimeout => {
            serial_reader.recv(&mut usart.deref_mut())
        }
        _ => Err(mctp::Error::RxFailure),
    }
}

// #[cfg(feature = "jtag-halt")]
// fn jtag_halt() {
//     static mut HALT: u32 = 1;

//     // This is a hack to halt the CPU in JTAG mode.
//     // It writes a value to a volatile memory location
//     // Break by jtag and set val to zero to continue.
//     loop {
//         let val;
//         unsafe {
//             val = ptr::read_volatile(addr_of!(HALT));
//         }

//         if val == 0 {
//             break;
//         }
//     }
// }

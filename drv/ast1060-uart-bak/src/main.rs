// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A driver for the STM32F4 U(S)ART.
//!
//! # IPC protocol
//!
//! ## `write` (1)
//!
//! Sends the contents of lease #0. Returns when completed.

#![no_std]
#![no_main]

use aspeed_ddk::uart::{Config, UartController};
use ast1060_pac::{Peripherals, uart};
use ast1060_pac::generic::Periph;
use embedded_hal::delay::DelayNs;
use userlib::*;
use zerocopy::IntoBytes;

task_slot!(RCC, rcc_driver);

#[derive(Copy, Clone, Debug, FromPrimitive)]
enum Operation {
    Write = 1,
}

#[repr(u32)]
enum ResponseCode {
    BadArg = 2,
    Busy = 3,
}

// TODO: it is super unfortunate to have to write this by hand, but deriving
// ToPrimitive makes us check at runtime whether the value fits
impl From<ResponseCode> for u32 {
    fn from(rc: ResponseCode) -> Self {
        rc as u32
    }
}

struct Transmit {
    caller: hl::Caller<()>,
    len: usize,
    pos: usize,
}

#[export_name = "main"]
fn main() -> ! {
    // Turn the actual peripheral on so that we can interact with it.
    turn_on_uart();

    // From thin air, pluck a pointer to the USART register block.
    //
    // Safety: this is needlessly unsafe in the API. The USART is essentially a
    // static, and we access it through a & reference so aliasing is not a
    // concern. Were it literally a static, we could just reference it.
    let peripherals = unsafe { Peripherals::steal() };
    let uart_ptr = peripherals.uart;
    let mut delay = DummyDelay;
    let uart = UartController::new(uart_ptr, &mut delay);

    // Work out our baud rate divisor.
    const BAUDRATE: u32 = 115_200;

    // Config UART Controller
    unsafe {
        uart.init(&Config {
            baud_rate: BAUDRATE,
            word_length: aspeed_ddk::uart::WordLength::Eight as u8,
            parity: aspeed_ddk::uart::Parity::None,
            stop_bits: aspeed_ddk::uart::StopBits::One,
            clock: 24_000_000,
        });
    }

    // The UART has clock and is out of reset, but isn't actually on until we:
    // usart.cr1.write(|w| w.ue().enabled());


    // Enable the transmitter.
    // usart.cr1.modify(|_, w| w.te().enabled());

    // Turn on our interrupt. We haven't enabled any interrupt sources at the
    // USART side yet, so this won't trigger notifications yet.
    sys_irq_control(notifications::UART_IRQ_MASK, true);

    // Field messages.
    let mut tx: Option<Transmit> = None;

    loop {
        hl::recv(
            // Buffer (none required)
            &mut [],
            // Notification mask
            notifications::UART_IRQ_MASK,
            // State to pass through to whichever closure below gets run
            &mut tx,
            // Notification handler
            |txref, bits| {
                if bits & 1 != 0 {
                    // Handling an interrupt. To allow for spurious interrupts,
                    // check the individual conditions we care about, and
                    // unconditionally re-enable the IRQ at the end of the handler.

                    let txe = uart_ptr.uartlsr().read().bits() & 0x40;
                    if txe != 0 {
                        // TX register empty. Do we need to send something?
                        step_transmit(&uart_ptr, txref);
                    }

                    sys_irq_control(notifications::UART_IRQ_MASK, true);
                }
            },
            // Message handler
            |txref, op, msg| match op {
                Operation::Write => {
                    // Validate lease count and buffer sizes first.
                    let ((), caller) =
                        msg.fixed_with_leases(1).ok_or(ResponseCode::BadArg)?;

                    // Deny incoming writes if we're already running one.
                    if txref.is_some() {
                        return Err(ResponseCode::Busy);
                    }

                    let borrow = caller.borrow(0);
                    let info = borrow.info().ok_or(ResponseCode::BadArg)?;
                    // Provide feedback to callers if they fail to provide a
                    // readable lease (otherwise we'd fail accessing the borrow
                    // later, which is a defection case and we won't reply at
                    // all).
                    if !info.attributes.contains(LeaseAttributes::READ) {
                        return Err(ResponseCode::BadArg);
                    }

                    // Okay! Begin a transfer!
                    *txref = Some(Transmit {
                        caller,
                        pos: 0,
                        len: info.len,
                    });

                    // OR the TX register empty signal into the USART interrupt.
                    // uart.cr1.modify(|_, w| w.txeie().enabled());
                    let ier = uart_ptr.uartier().read().bits();
                    unsafe {
                        uart_ptr.uartier().write(|w| {
                            w.bits(ier | 0x02) // Enable TXE interrupt
                        });
                    }

                    // We'll do the rest as interrupts arrive.
                    Ok(())
                }
            },
        );
    }
}

fn turn_on_uart() {
/*
    let rcc_driver = RCC.get_task_id();

    const ENABLE_CLOCK: u16 = 1;
    let pnum = 113; // see bits in APB1ENR
    let (code, _) = userlib::sys_send(
        rcc_driver,
        ENABLE_CLOCK,
        pnum.as_bytes(),
        &mut [],
        &[],
    );
    assert_eq!(code, 0);

    const LEAVE_RESET: u16 = 4;
    let (code, _) = userlib::sys_send(
        rcc_driver,
        LEAVE_RESET,
        pnum.as_bytes(),
        &mut [],
        &[],
    );
    assert_eq!(code, 0);
*/

}

fn step_transmit(
    // usart: &device::usart1::RegisterBlock,
    uart_ptr: &Periph<uart::RegisterBlock, 0x7e78_4000>,
    tx: &mut Option<Transmit>,
) {
    // Clearer than just using replace:
    fn end_transmission(
        uart_ptr: &Periph<uart::RegisterBlock, 0x7e78_4000>,
        state: &mut Option<Transmit>,
    ) -> hl::Caller<()> {
        // uart.cr1.modify(|_, w| w.txeie().disabled());
        uart_ptr.uartier().modify(|_, w| {
            // Disable TXE interrupt
            w.bits(w.bits() & !0x02)
        });
        state.take().unwrap().caller
    }

    let txs = if let Some(txs) = tx { txs } else { return };

    if let Some(byte) = txs.caller.borrow(0).read_at::<u8>(txs.pos) {
        // Stuff byte into transmitter.
        txs.pos += 1;
        if txs.pos == txs.len {
            end_transmission(uart_ptr, tx).reply(());
        }
    } else {
        end_transmission(uart_ptr, tx).reply_fail(ResponseCode::BadArg);
    }
}

#[derive(Clone, Default)]
struct DummyDelay;

impl DelayNs for DummyDelay {
    fn delay_ns(&mut self, ns: u32) {
        for _ in 0..ns {
            cortex_m::asm::nop();
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/notifications.rs"));

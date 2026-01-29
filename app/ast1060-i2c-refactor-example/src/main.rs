// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! AST1060 I2C Refactored Driver Example Application
//!
//! This application serves as a build container for testing the refactored
//! I2C driver (drv-ast1060-i2c-refactor) which delegates to the portable
//! aspeed-ddk i2c_core implementation.

#![no_std]
#![no_main]

// We have to do this if we don't otherwise use it to ensure its vector table
// gets linked in.

use aspeed_ddk::i2c_core::init_i2c_global;
use aspeed_ddk::pinctrl::{Pinctrl, PINCTRL_I2C2};
use ast1060_pac::Peripherals;
use cortex_m_rt::entry;

#[cfg(feature = "jtag-halt")]
use core::ptr::{self, addr_of};

/// AST1060 EVB Clock Configuration
///
/// The AST1060 uses an internal oscillator with a fixed 1 GHz HPLL
/// (High-Performance PLL) as its base clock. Unlike AST2500/2600 which
/// use external 25 MHz crystals, the AST1060 operates with a fixed
/// internal clock configuration.
///
/// Clock Hierarchy:
/// ```text
/// +------------+-------------+---------------------------+
/// | Clock      | Frequency   | Source                    |
/// +------------+-------------+---------------------------+
/// | HPLL       | 1 GHz       | Internal PLL (default)    |
/// | CPU (M4F)  | 200 MHz     | HPLL ÷ 5                  |
/// | AHB        | 200 MHz     | Same as CPU               |
/// | APB        | 50 MHz      | HPLL ÷ 20 (or AHB ÷ 4)    |
/// +------------+-------------+---------------------------+
/// ```
///
/// For I2C, the APB clock (50 MHz) feeds into the I2C global register
/// I2CG10, which provides four base clocks for different I2C speeds:
/// - base_clk1: 20 MHz  → Fast-plus (1 MHz)
/// - base_clk2: 10 MHz  → Fast (400 kHz)
/// - base_clk3: 2.77 MHz → Standard (100 kHz)
/// - base_clk4: Recovery timeout
///
/// Reference: ASPEED AST1060 Datasheet, ARM Cortex-M4F @ 200 MHz
const CPU_FREQ_HZ: u32 = 200_000_000;    // 200 MHz

/// Cycles per millisecond for the kernel timer
const CYCLES_PER_MS: u32 = CPU_FREQ_HZ / 1000; // 200,000

#[entry]
fn main() -> ! {
    let peripherals = unsafe { Peripherals::steal() };
    
    // Configure JTAG pins for debugging
    peripherals.scu.scu41c().modify(|_, w| {
        w.enbl_armtmsfn_pin()
            .bit(true)
            .enbl_armtckfn_pin()
            .bit(true)
            .enbl_armtrstfn_pin()
            .bit(true)
            .enbl_armtdifn_pin()
            .bit(true)
            .enbl_armtdofn_pin()
            .bit(true)
    });

    // =========================================================================
    // I2C Hardware Pre-Configuration
    // =========================================================================
    // Initialize I2C global registers (reset, clock dividers) using aspeed-ddk
    init_i2c_global();
    
    // Configure I2C2 pin mux (this app uses I2C2 per app.toml)
    Pinctrl::apply_pinctrl_group(PINCTRL_I2C2);

    #[cfg(feature = "jtag-halt")]
    jtag_halt();

    unsafe { kern::startup::start_kernel(CYCLES_PER_MS) }
}

#[cfg(feature = "jtag-halt")]
fn jtag_halt() {
    static mut HALT: u32 = 1;

    // This is a hack to halt the CPU in JTAG mode.
    // It writes a value to a volatile memory location
    // Break by jtag and set val to zero to continue.
    loop {
        let val;
        unsafe {
            val = core::ptr::read_volatile(core::ptr::addr_of!(HALT));
        }

        if val == 0 {
            break;
        }
    }
}

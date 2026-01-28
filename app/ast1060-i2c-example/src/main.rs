// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

// We have to do this if we don't otherwise use it to ensure its vector table
// gets linked in.

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
    // Configure I2C clocks and pins before the kernel starts.
    // The I2C driver will read these settings from hardware registers.
    // =========================================================================
    configure_i2c_hardware(&peripherals);

    #[cfg(feature = "jtag-halt")]
    jtag_halt();

    unsafe { kern::startup::start_kernel(CYCLES_PER_MS) }
}

/// Configure I2C global clocks and pin mux
///
/// This must be called before the kernel starts to ensure I2C hardware
/// is properly configured. The I2C driver will read clock settings from
/// hardware and use the pre-configured pins.
fn configure_i2c_hardware(peripherals: &Peripherals) {
    // -------------------------------------------------------------------------
    // Step 1: Reset I2C/SMBus controller via SCU
    // -------------------------------------------------------------------------
    // SCU050 bit 2: Assert reset for I2C/SMBus controller
    peripherals.scu.scu050().write(|w| w.rst_i2csmbus_ctrl().set_bit());
    
    // Small delay for reset to take effect
    for _ in 0..1000 {
        core::hint::spin_loop();
    }
    
    // SCU054: Clear reset (de-assert)
    // Writing 1 to bit 2 clears the reset
    peripherals.scu.scu054().write(|w| unsafe { w.bits(0x4) });
    
    // Small delay for reset release
    for _ in 0..1000 {
        core::hint::spin_loop();
    }

    // -------------------------------------------------------------------------
    // Step 2: Configure I2C global clock settings
    // -------------------------------------------------------------------------
    // Access I2C global registers directly (address 0x7e7b0000)
    let i2cg = unsafe { &*ast1060_pac::I2cglobal::ptr() };
    
    // I2CG0C: Global control register
    // - clk_divider_mode_sel: Use new clock divider mode
    // - reg_definition_sel: Use new register definitions
    // - slave_pkt_mode_rxbuf_empty_action: Clock stretch when RX buffer empty
    i2cg.i2cg0c().write(|w| {
        w.clk_divider_mode_sel()
            .set_bit()
            .reg_definition_sel()
            .set_bit()
            .select_the_action_when_slave_pkt_mode_rxbuf_empty()
            .set_bit()
    });

    // I2CG10: Base clock dividers
    // These dividers create the base clocks used by all I2C controllers
    // Value: 0x6222_0803
    //   base_clk4 (recovery): 0x62 → 50M / ((98+2)/2) = 1 MHz
    //   base_clk3 (100kHz):   0x22 → 50M / ((34+2)/2) = 2.77 MHz
    //   base_clk2 (400kHz):   0x08 → 50M / ((8+2)/2) = 10 MHz
    //   base_clk1 (1MHz):     0x03 → 50M / ((3+2)/2) = 20 MHz
    i2cg.i2cg10().write(|w| unsafe { w.bits(0x6222_0803) });

    // -------------------------------------------------------------------------
    // Step 3: Configure I2C pin mux
    // -------------------------------------------------------------------------
    // This app uses I2C2 (per app.toml: uses = ["scu", "i2c_global", "i2c2", "i2c_buffer2"])
    // Configure the pins for I2C2 in SCU418
    //
    // Pin mapping (AST1060):
    //   I2C0-1: SCU414 bits 28-31
    //   I2C2-7: SCU418 bits 0-11
    //   I2C8-13: SCU41C bits (varies, check datasheet)
    configure_i2c_pins(peripherals);
}

/// Configure I2C pin multiplexing
///
/// Sets up the SCU registers to route I2C signals to the physical pins.
/// Only configures the controllers actually used by this application.
fn configure_i2c_pins(peripherals: &Peripherals) {
    // I2C2: SCU418[0:1] = SCL2/SDA2
    // Set bits 0 and 1 to enable I2C2 function on these pins
    peripherals.scu.scu418().modify(|r, w| unsafe {
        w.bits(r.bits() | (0b11 << 0))
    });
    
    // If using additional I2C controllers, configure them here:
    //
    // I2C0: SCU414[28:29]
    // peripherals.scu.scu414().modify(|r, w| unsafe {
    //     w.bits(r.bits() | (0b11 << 28))
    // });
    //
    // I2C1: SCU414[30:31]
    // peripherals.scu.scu414().modify(|r, w| unsafe {
    //     w.bits(r.bits() | (0b11 << 30))
    // });
    //
    // I2C3: SCU418[2:3]
    // peripherals.scu.scu418().modify(|r, w| unsafe {
    //     w.bits(r.bits() | (0b11 << 2))
    // });
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

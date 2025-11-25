//! AST1060 I2C Driver for Hubris
//!
//! This driver provides I2C controller support for the ASPEED AST1060 SoC.
//! It supports:
//! - Byte mode (1 byte transfers)
//! - Buffer mode (up to 32 byte transfers)
//! - Master mode operations (read, write, write-read)
//! - Optional slave/target mode (with `slave` feature)
//! - 14 I2C controllers (I2C0-I2C13)

#![no_std]

mod constants;
mod controller;
mod error;
mod master;
mod mux;
mod recovery;
mod timing;
mod transfer;

#[cfg(feature = "slave")]
mod slave;

pub use constants::*;
pub use controller::*;
pub use error::*;
pub use master::*;
pub use mux::*;
pub use recovery::*;
pub use timing::*;
pub use transfer::*;

#[cfg(feature = "slave")]
pub use slave::*;

use drv_i2c_api::{Controller, PortIndex};
use drv_i2c_types::PinSet;

/// I2C controller configuration
pub struct I2cController<'a> {
    pub controller: Controller,
    pub registers: &'a ast1060_pac::i2c::RegisterBlock,
    pub buff_registers: &'a ast1060_pac::i2cbuff::RegisterBlock,
    pub notification: Option<u32>,
}

/// I2C pin configuration
pub struct I2cPins {
    pub controller: Controller,
    pub port: PortIndex,
    pub scl: PinSet,
    pub sda: PinSet,
    pub function: u8,  // Alternate function number
}

/// I2C configuration
#[derive(Debug, Clone, Copy)]
pub struct I2cConfig {
    pub xfer_mode: I2cXferMode,
    pub speed: I2cSpeed,
    pub multi_master: bool,
    pub smbus_timeout: bool,
    pub smbus_alert: bool,
    pub timing_config: Option<TimingConfig>,
}

impl Default for I2cConfig {
    fn default() -> Self {
        Self {
            xfer_mode: I2cXferMode::BufferMode,
            speed: I2cSpeed::Fast,
            multi_master: false,
            smbus_timeout: false,
            smbus_alert: false,
            timing_config: None,
        }
    }
}

/// Transfer mode selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cXferMode {
    /// Byte-by-byte mode (1 byte at a time)
    ByteMode,
    /// Buffer mode (up to 32 bytes via hardware buffer)
    BufferMode,
    // Note: DMA mode intentionally excluded for initial version
}

/// I2C bus speed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cSpeed {
    /// Standard mode: 100 kHz
    Standard,
    /// Fast mode: 400 kHz
    Fast,
    /// Fast-plus mode: 1 MHz
    FastPlus,
}

/// Timing configuration (optional, auto-calculated if not provided)
#[derive(Debug, Clone, Copy)]
pub struct TimingConfig {
    pub scl_high_ns: u32,
    pub scl_low_ns: u32,
    pub sda_hold_ns: u32,
    pub sda_setup_ns: u32,
}

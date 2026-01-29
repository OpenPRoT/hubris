//! Safe wrapper for AST1060 I2C peripherals
//!
//! This module handles peripheral ownership and provides safe access
//! to the 14 I2C controllers on the AST1060.

use ast1060_pac::{i2c::RegisterBlock, i2cbuff::RegisterBlock as BuffRegisterBlock};

/// Safe wrapper for AST1060 I2C peripherals
///
/// Owns the PAC peripherals and provides safe access to all 14 I2C controllers.
/// In Hubris, each task exclusively owns its peripherals via kernel memory protection.
pub struct I2cPeripherals {
    peripherals: ast1060_pac::Peripherals,
}

impl I2cPeripherals {
    /// Create a new I2C peripherals wrapper
    ///
    /// # Safety
    ///
    /// Must only be called once. Caller must ensure no other code
    /// accesses I2C peripherals concurrently.
    #[must_use]
    pub unsafe fn new() -> Self {
        Self {
            peripherals: ast1060_pac::Peripherals::steal(),
        }
    }

    /// Get references to a specific I2C controller's registers and buffer
    ///
    /// Returns `None` if the controller ID is out of range (>13).
    ///
    /// # Arguments
    ///
    /// * `id` - Controller number (0-13)
    #[must_use]
    pub fn controller_and_buffer(
        &self,
        id: u8,
    ) -> Option<(&RegisterBlock, &BuffRegisterBlock)> {
        Some(match id {
            0 => (&self.peripherals.i2c, &self.peripherals.i2cbuff),
            1 => (&self.peripherals.i2c1, &self.peripherals.i2cbuff1),
            2 => (&self.peripherals.i2c2, &self.peripherals.i2cbuff2),
            3 => (&self.peripherals.i2c3, &self.peripherals.i2cbuff3),
            4 => (&self.peripherals.i2c4, &self.peripherals.i2cbuff4),
            5 => (&self.peripherals.i2c5, &self.peripherals.i2cbuff5),
            6 => (&self.peripherals.i2c6, &self.peripherals.i2cbuff6),
            7 => (&self.peripherals.i2c7, &self.peripherals.i2cbuff7),
            8 => (&self.peripherals.i2c8, &self.peripherals.i2cbuff8),
            9 => (&self.peripherals.i2c9, &self.peripherals.i2cbuff9),
            10 => (&self.peripherals.i2c10, &self.peripherals.i2cbuff10),
            11 => (&self.peripherals.i2c11, &self.peripherals.i2cbuff11),
            12 => (&self.peripherals.i2c12, &self.peripherals.i2cbuff12),
            13 => (&self.peripherals.i2c13, &self.peripherals.i2cbuff13),
            _ => return None,
        })
    }

    /// Get reference to the I2C global registers
    #[must_use]
    pub fn i2c_global(&self) -> &ast1060_pac::i2cglobal::RegisterBlock {
        &self.peripherals.i2cglobal
    }

    /// Get reference to the SCU (for pinmux if needed)
    #[must_use]
    pub fn scu(&self) -> &ast1060_pac::scu::RegisterBlock {
        &self.peripherals.scu
    }
}

//! I2cHardware trait implementation for AST1060
//!
//! This module implements the `I2cHardware` trait from `drv-i2c-types`,
//! delegating all hardware operations to `aspeed-ddk::i2c_core`.
//!
//! **Implementation Pattern**: Following `drv-ast1060-i2c/src/server_driver.rs`,
//! we create `I2cController` and `Ast1060I2c` inline within each trait method
//! to avoid lifetime issues.
//!
//! **Performance Optimization**: Uses `Ast1060I2c::from_initialized()` instead
//! of `new()` to avoid redundant hardware re-initialization on every operation.
//! The app's `main.rs` must initialize the I2C hardware before the kernel starts.

use crate::peripherals::I2cPeripherals;
use aspeed_ddk::i2c_core::{
    Ast1060I2c, I2cConfig, I2cController, I2cError, I2cSpeed as CoreSpeed,
    SlaveConfig as CoreSlaveConfig,
};
use drv_i2c_types::{traits::I2cHardware, traits::I2cSpeed, Controller, ResponseCode, SlaveConfig};

/// AST1060 I2C driver implementing the Hubris I2cHardware trait
///
/// This is a thin adapter that:
/// - Owns AST1060 peripherals safely
/// - Maps Hubris types to i2c_core types
/// - Delegates all hardware operations to i2c_core
///
/// # Hardware Initialization
///
/// This driver assumes I2C hardware is pre-initialized by the app's `main.rs`
/// before the kernel starts. It uses `Ast1060I2c::from_initialized()` for
/// lightweight per-operation wrappers (~50x faster than full init).
///
/// Required app initialization:
/// - I2C global registers (I2CG0C, I2CG10)
/// - Controller reset and enable (I2CC00)
/// - Timing configuration
/// - Pin mux configuration
pub struct Ast1060I2cDriver {
    peripherals: I2cPeripherals,
}

impl Ast1060I2cDriver {
    /// Create a new driver instance
    ///
    /// Takes ownership of the I2C peripherals. In Hubris, each task
    /// exclusively owns its peripherals via kernel memory protection.
    #[must_use]
    pub fn new(peripherals: I2cPeripherals) -> Self {
        Self { peripherals }
    }

    /// Get references to a specific controller's registers
    fn get_controller(
        &self,
        controller: Controller,
    ) -> Result<
        (
            &ast1060_pac::i2c::RegisterBlock,
            &ast1060_pac::i2cbuff::RegisterBlock,
        ),
        ResponseCode,
    > {
        self.peripherals
            .controller_and_buffer(controller as u8)
            .ok_or(ResponseCode::BadArg)
    }
}

/// Map i2c_core errors to Hubris ResponseCode
fn map_error(e: I2cError) -> ResponseCode {
    match e {
        I2cError::NoAcknowledge => ResponseCode::NoDevice,
        I2cError::Bus => ResponseCode::BusLocked,
        I2cError::ArbitrationLoss => ResponseCode::BusLocked,
        I2cError::Timeout => ResponseCode::BusLockedMux,
        I2cError::Overrun => ResponseCode::BadArg,
        I2cError::Invalid => ResponseCode::BadArg,
        I2cError::Busy => ResponseCode::BusLocked,
        I2cError::InvalidAddress => ResponseCode::BadArg,
        I2cError::SlaveError => ResponseCode::BadArg,
        I2cError::BusRecoveryFailed => ResponseCode::BusLocked,
        I2cError::Abnormal => ResponseCode::BadArg,
    }
}

impl I2cHardware for Ast1060I2cDriver {
    type Error = ResponseCode;

    fn write_read(
        &mut self,
        controller: Controller,
        addr: u8,
        write_data: &[u8],
        read_buffer: &mut [u8],
    ) -> Result<usize, ResponseCode> {
        let (regs, buffs) = self.get_controller(controller)?;

        // Create I2C controller reference - inline to avoid lifetime issues
        let ctrl = I2cController {
            controller: aspeed_ddk::i2c_core::Controller::new(controller as u8)
                .ok_or(ResponseCode::BadArg)?,
            registers: regs,
            buff_registers: buffs,
        };

        // Create lightweight I2C instance (hardware pre-initialized by app main.rs)
        let config = I2cConfig::default();
        let mut i2c = Ast1060I2c::from_initialized(&ctrl, config);

        // Perform write-read operation
        if !write_data.is_empty() && !read_buffer.is_empty() {
            i2c.write_read(addr, write_data, read_buffer)
                .map_err(map_error)?;
            Ok(read_buffer.len())
        } else if !write_data.is_empty() {
            i2c.write(addr, write_data).map_err(map_error)?;
            Ok(0)
        } else if !read_buffer.is_empty() {
            i2c.read(addr, read_buffer).map_err(map_error)?;
            Ok(read_buffer.len())
        } else {
            Ok(0)
        }
    }

    fn write_read_block(
        &mut self,
        controller: Controller,
        addr: u8,
        write_data: &[u8],
        read_buffer: &mut [u8],
    ) -> Result<usize, ResponseCode> {
        // For AST1060, block mode is the same as regular write_read
        // The driver automatically chunks large transfers
        self.write_read(controller, addr, write_data, read_buffer)
    }

    fn configure_slave_mode(
        &mut self,
        controller: Controller,
        config: &SlaveConfig,
    ) -> Result<(), ResponseCode> {
        let (regs, buffs) = self.get_controller(controller)?;

        let ctrl = I2cController {
            controller: aspeed_ddk::i2c_core::Controller::new(controller as u8)
                .ok_or(ResponseCode::BadArg)?,
            registers: regs,
            buff_registers: buffs,
        };

        let i2c_config = I2cConfig::default();
        let mut i2c = Ast1060I2c::from_initialized(&ctrl, i2c_config);

        // Convert SlaveConfig to i2c_core slave config
        let slave_cfg =
            CoreSlaveConfig::new(config.address).map_err(|_| ResponseCode::BadArg)?;

        i2c.configure_slave(&slave_cfg).map_err(map_error)?;

        Ok(())
    }

    fn enable_slave_receive(&mut self, controller: Controller) -> Result<(), ResponseCode> {
        let (regs, buffs) = self.get_controller(controller)?;

        let ctrl = I2cController {
            controller: aspeed_ddk::i2c_core::Controller::new(controller as u8)
                .ok_or(ResponseCode::BadArg)?,
            registers: regs,
            buff_registers: buffs,
        };

        let i2c_config = I2cConfig::default();
        let mut i2c = Ast1060I2c::from_initialized(&ctrl, i2c_config);

        // Re-enable slave mode and interrupts (after a previous disable)
        i2c.enable_slave();
        Ok(())
    }

    fn disable_slave_receive(&mut self, controller: Controller) -> Result<(), ResponseCode> {
        let (regs, buffs) = self.get_controller(controller)?;

        let ctrl = I2cController {
            controller: aspeed_ddk::i2c_core::Controller::new(controller as u8)
                .ok_or(ResponseCode::BadArg)?,
            registers: regs,
            buff_registers: buffs,
        };

        let i2c_config = I2cConfig::default();
        let mut i2c = Ast1060I2c::from_initialized(&ctrl, i2c_config);

        i2c.disable_slave();
        Ok(())
    }

    fn configure_timing(
        &mut self,
        controller: Controller,
        speed: I2cSpeed,
    ) -> Result<(), Self::Error> {
        let core_speed = match speed {
            I2cSpeed::Standard => CoreSpeed::Standard,
            I2cSpeed::Fast => CoreSpeed::Fast,
            I2cSpeed::FastPlus => CoreSpeed::FastPlus,
            I2cSpeed::HighSpeed => return Err(ResponseCode::BadArg), // Not supported
        };

        let (regs, buffs) = self.get_controller(controller)?;

        let ctrl = I2cController {
            controller: aspeed_ddk::i2c_core::Controller::new(controller as u8)
                .ok_or(ResponseCode::BadArg)?,
            registers: regs,
            buff_registers: buffs,
        };

        let config = I2cConfig {
            speed: core_speed,
            ..I2cConfig::default()
        };

        // Re-initialize with new timing configuration
        // Note: configure_timing intentionally uses new() because we need
        // to write new timing values to hardware registers
        let mut i2c = Ast1060I2c::from_initialized(&ctrl, config);
        i2c.init_hardware(&config).map_err(map_error)
    }

    fn reset_bus(&mut self, controller: Controller) -> Result<(), Self::Error> {
        let (regs, buffs) = self.get_controller(controller)?;

        let ctrl = I2cController {
            controller: aspeed_ddk::i2c_core::Controller::new(controller as u8)
                .ok_or(ResponseCode::BadArg)?,
            registers: regs,
            buff_registers: buffs,
        };

        let i2c_config = I2cConfig::default();
        let mut i2c = Ast1060I2c::from_initialized(&ctrl, i2c_config);

        i2c.recover_bus().map_err(map_error)
    }

    fn enable_controller(&mut self, controller: Controller) -> Result<(), Self::Error> {
        let (regs, buffs) = self.get_controller(controller)?;

        let ctrl = I2cController {
            controller: aspeed_ddk::i2c_core::Controller::new(controller as u8)
                .ok_or(ResponseCode::BadArg)?,
            registers: regs,
            buff_registers: buffs,
        };

        let i2c_config = I2cConfig::default();
        // enable_controller must init hardware, so we use new() which calls init_hardware()
        let _i2c = Ast1060I2c::new(&ctrl, i2c_config).map_err(map_error)?;

        Ok(())
    }

    fn disable_controller(&mut self, _controller: Controller) -> Result<(), Self::Error> {
        // AST1060 doesn't need explicit disable - hardware auto-releases bus
        Ok(())
    }

    fn check_slave_data(&self, controller: Controller) -> bool {
        if let Some((regs, buffs)) = self.peripherals.controller_and_buffer(controller as u8) {
            if let Some(ctrl_id) = aspeed_ddk::i2c_core::Controller::new(controller as u8) {
                let ctrl = I2cController {
                    controller: ctrl_id,
                    registers: regs,
                    buff_registers: buffs,
                };

                let i2c_config = I2cConfig::default();
                let i2c = Ast1060I2c::from_initialized(&ctrl, i2c_config);
                return i2c.slave_has_data();
            }
        }
        false
    }

    fn clear_slave_interrupts(&self, controller: Controller) {
        // Note: clear_slave_interrupts is private in i2c_core
        // The slave_read clears the interrupt automatically
        let _ = controller;
    }

    fn read_slave_data(
        &mut self,
        controller: Controller,
        buffer: &mut [u8],
    ) -> Result<(u8, usize), ResponseCode> {
        let (regs, buffs) = self.get_controller(controller)?;

        let ctrl = I2cController {
            controller: aspeed_ddk::i2c_core::Controller::new(controller as u8)
                .ok_or(ResponseCode::BadArg)?,
            registers: regs,
            buff_registers: buffs,
        };

        let i2c_config = I2cConfig::default();
        let mut i2c = Ast1060I2c::from_initialized(&ctrl, i2c_config);

        // Read from slave buffer - i2c_core returns just length
        let len = i2c.slave_read(buffer).map_err(map_error)?;

        // Source address would need to be tracked separately; return 0 for now
        Ok((0, len))
    }
}

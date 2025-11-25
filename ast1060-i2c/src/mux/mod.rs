//! I2C multiplexer support

mod pca9545;
mod pca9548;

pub use pca9545::Pca9545;
pub use pca9548::Pca9548;

use crate::*;

/// I2C multiplexer driver trait
pub trait I2cMuxDriver {
    /// Configure the mux
    fn configure(
        &self,
        mux: &I2cMux<'_>,
        i2c: &mut Ast1060I2c<'_>,
    ) -> Result<(), I2cError>;
    
    /// Set active segment
    fn set_segment(
        &self,
        mux: &I2cMux<'_>,
        i2c: &mut Ast1060I2c<'_>,
        segment: drv_i2c_api::Segment,
    ) -> Result<(), I2cError>;
    
    /// Reset the mux (disable all segments)
    fn reset(
        &self,
        mux: &I2cMux<'_>,
        i2c: &mut Ast1060I2c<'_>,
    ) -> Result<(), I2cError>;
}

/// I2C multiplexer configuration
pub struct I2cMux<'a> {
    pub controller: drv_i2c_api::Controller,
    pub port: drv_i2c_api::PortIndex,
    pub id: drv_i2c_api::Mux,
    pub address: u8,
    pub driver: &'a dyn I2cMuxDriver,
    pub gpio_reset: Option<drv_i2c_types::PinSet>,
}

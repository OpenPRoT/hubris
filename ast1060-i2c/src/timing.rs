//! Timing configuration for I2C

use crate::*;
use ast1060_pac::i2c::RegisterBlock;

/// Configure I2C timing based on speed
pub fn configure_timing(
    regs: &RegisterBlock,
    config: &I2cConfig,
) -> Result<(), I2cError> {
    let base_clk = match config.speed {
        I2cSpeed::Standard => 1,   // 100 kHz - use base_clk3
        I2cSpeed::Fast => 2,        // 400 kHz - use base_clk2
        I2cSpeed::FastPlus => 3,    // 1 MHz - use base_clk1
    };
    
    // Set AC timing register based on speed
    unsafe {
        regs.i2cc04().write(|w| {
            w.bits(base_clk)
        });
    }
    
    Ok(())
}

/// Calculate timing values for custom speeds (if needed)
pub fn calculate_timing(
    bus_clk_hz: u32,
    target_speed_hz: u32,
) -> Result<TimingConfig, I2cError> {
    if target_speed_hz == 0 || target_speed_hz > I2C_FAST_PLUS_MODE_HZ {
        return Err(I2cError::Invalid);
    }
    
    // Calculate SCL period
    let scl_period_ns = 1_000_000_000 / target_speed_hz;
    
    // Standard I2C timing ratios
    let scl_high_ns = scl_period_ns / 2;
    let scl_low_ns = scl_period_ns / 2;
    let sda_hold_ns = scl_period_ns / 8;
    let sda_setup_ns = scl_period_ns / 8;
    
    Ok(TimingConfig {
        scl_high_ns,
        scl_low_ns,
        sda_hold_ns,
        sda_setup_ns,
    })
}

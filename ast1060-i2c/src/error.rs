//! Error types for AST1060 I2C driver

use drv_i2c_api::ResponseCode;

/// I2C error type
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum I2cError {
    /// Data overrun
    Overrun,
    /// No acknowledge from device
    NoAcknowledge,
    /// Operation timeout
    Timeout,
    /// Bus recovery failed
    BusRecoveryFailed,
    /// Bus error
    Bus,
    /// Bus busy
    Busy,
    /// Invalid parameter
    Invalid,
    /// Abnormal condition
    Abnormal,
    /// Arbitration loss (multi-master)
    ArbitrationLoss,
    /// Slave mode error
    SlaveError,
    /// Invalid address
    InvalidAddress,
}

impl From<I2cError> for ResponseCode {
    fn from(err: I2cError) -> Self {
        match err {
            I2cError::NoAcknowledge => ResponseCode::NoDevice,
            I2cError::Timeout => ResponseCode::Timeout,
            I2cError::Bus | I2cError::Busy | I2cError::BusRecoveryFailed => {
                ResponseCode::BusLocked
            }
            I2cError::ArbitrationLoss => ResponseCode::BusError,
            I2cError::Overrun | I2cError::Invalid | I2cError::Abnormal => {
                ResponseCode::BadTransferSize
            }
            I2cError::SlaveError | I2cError::InvalidAddress => ResponseCode::BadArg,
        }
    }
}

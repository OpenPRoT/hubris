// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Common types for the I2C server client API
//!
//! This crate works on both the host and embedded system, so it can be used in
//! host-side tests.
//!
//! # Implementation Notes
//!
//! ## Slave Mode Extensions for MCTP Support
//!
//! The I2C server has been extended to support slave mode operations to enable
//! protocols like MCTP (Management Component Transport Protocol) that require
//! peer-to-peer communication. This extension allows the I2C controller to both
//! initiate transactions as a master and respond to incoming transactions as a slave.
//!
//! ### Design Rationale
//!
//! - **Polling-Based Approach**: Slave message retrieval uses polling rather than
//!   notifications to avoid the complexity of asynchronous callbacks and potential
//!   buffer overflow scenarios in a resource-constrained embedded environment.
//!
//! - **Per-Port Configuration**: Slave addresses are configured per controller/port
//!   combination, allowing multiple I2C peripherals to operate independently with
//!   different slave addresses if needed.
//!
//! - **Fixed Buffer Size**: Messages use a fixed 255-byte buffer to match typical
//!   I2C transaction limits and simplify memory management without dynamic allocation.
//!
//! - **Serialization Requirements**: Types used in IPC messages must implement 
//!   `SerializedSize`, `Serialize`, and `Deserialize` for Hubris IPC communication. 
//!   Newtypes like `PortIndex` inherit these requirements when used in serializable 
//!   contexts (e.g., as fields in `SlaveConfig`).
//!
//! - **Large Array Serialization**: Arrays larger than 32 elements require the 
//!   `serde-big-array` crate and `#[serde(with = "BigArray")]` attribute. This 
//!   follows the established Hubris pattern used in `host-sp-messages` and other 
//!   crates for handling buffers that exceed serde's built-in array size limits.
//!
//! ### Usage Pattern
//!
//! 1. Configure slave address: `ConfigureSlaveAddress`
//! 2. Enable slave receive: `EnableSlaveReceive`
//! 3. Poll for messages: `CheckSlaveBuffer`
//! 4. Process received messages
//! 5. Disable when done: `DisableSlaveReceive`
//!
//! This pattern supports protocols like PLDM-over-MCTP-over-I2C where devices
//! need to both send and receive management messages.

#![no_std]

use hubpack::SerializedSize;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use derive_idol_err::IdolError;
use enum_kinds::EnumKind;

pub mod traits;

#[derive(FromPrimitive, Eq, PartialEq)]
pub enum Op {
    WriteRead = 1,

    /// In a `WriteReadBlock` operation, only the **final read** is an SMBus
    /// block operation.
    ///
    /// All writes and all other read operations are normal (non-block)
    /// operations.
    ///
    /// We don't need a special way to perform block writes, because they can be
    /// constructed by the caller without cooperation from the driver.
    /// Specifically, the caller can construct the array `[reg, size, data[0],
    /// data[1], ...]` and pass it to a normal `WriteRead` operation.
    ///
    /// If we encounter a device which requires multiple block reads in a row
    /// without interruption, this logic would not work, but that would be a
    /// very strange device indeed.
    WriteReadBlock = 2,

    /// Configure the I2C controller to act as a slave device with the specified
    /// address. This enables the controller to respond to incoming I2C 
    /// transactions from other masters on the bus.
    ///
    /// The payload should contain:
    /// - `[0]`: Slave address (7-bit)
    /// - `[1]`: Controller index
    /// - `[2]`: Port index
    /// - `[3]`: Reserved (0)
    ///
    /// This operation is required for protocols like MCTP that need peer-to-peer
    /// communication where devices can both initiate and respond to transactions.
    ConfigureSlaveAddress = 3,

    /// Enable slave receive mode for the specified controller/port combination.
    /// After this operation, the controller will begin buffering incoming 
    /// messages sent to its configured slave address(es).
    ///
    /// This must be called after `ConfigureSlaveAddress` to begin receiving
    /// slave messages.
    EnableSlaveReceive = 4,

    /// Disable slave receive mode for the specified controller/port. After this
    /// operation, the controller will stop responding to slave transactions
    /// and will not buffer incoming messages.
    DisableSlaveReceive = 5,

    /// Check for received slave messages and retrieve them from the internal
    /// buffer. Returns the number of messages retrieved and their data.
    ///
    /// The caller should provide a sufficient buffer to receive multiple
    /// messages. Each message is formatted as:
    /// - `[0]`: Source address (7-bit address of the master that sent this)
    /// - `[1]`: Message length
    /// - `[2..N]`: Message data
    ///
    /// Returns the total number of bytes written to the buffer, or 0 if no
    /// messages are available.
    CheckSlaveBuffer = 6,
}

/// The response code returned from the I2C server.  These response codes pretty
/// specific, not because the caller is expected to necessarily handle them
/// differently, but to give upstack software some modicum of context
/// surrounding the error.
#[derive(
    Copy,
    Clone,
    Debug,
    EnumKind,
    FromPrimitive,
    Eq,
    PartialEq,
    IdolError,
    Serialize,
    Deserialize,
    SerializedSize,
    counters::Count,
)]
#[enum_kind(ResponseCodeU8, derive(counters::Count))]
#[repr(u32)]
pub enum ResponseCode {
    /// Bad response from server
    BadResponse = 1,
    /// Bad argument sent to server
    BadArg,
    /// Indicated I2C device is invalid
    NoDevice,
    /// Indicated I2C controller is invalid
    BadController,
    /// Device address is reserved
    ReservedAddress,
    /// Indicated port is invalid
    BadPort,
    /// Device does not have indicated register
    NoRegister,
    /// Indicated mux is an invalid mux identifier
    BadMux,
    /// Indicated segment is an invalid segment identifier
    BadSegment,
    /// Indicated mux does not exist on this controller
    MuxNotFound,
    /// Indicated segment does not exist on this controller
    SegmentNotFound,
    /// Segment disconnected during operation
    SegmentDisconnected,
    /// Mux disconnected during operation
    MuxDisconnected,
    /// No device at address used for mux in-band management
    MuxMissing,
    /// Register used for mux in-band management is invalid
    BadMuxRegister,
    /// I2C bus was spontaneously reset during operation
    BusReset,
    /// I2C bus was reset during a mux in-band management operation
    BusResetMux,
    /// I2C bus locked up and was reset
    BusLocked,
    /// I2C bus locked up during in-band management operation and was reset
    BusLockedMux,
    /// I2C controller appeared to be busy and was reset
    ControllerBusy,
    /// I2C bus error
    BusError,
    /// Bad device state of unknown origin
    BadDeviceState,
    /// Requested operation is not supported
    OperationNotSupported,
    /// Illegal number of leases
    IllegalLeaseCount,
    /// Too much data -- or not enough buffer
    TooMuchData,
    /// Slave address is already in use by another configuration
    SlaveAddressInUse,
    /// Slave mode is not supported on this controller/port combination
    SlaveNotSupported,
    /// Slave receive is not enabled for this controller/port
    SlaveNotEnabled,
    /// Slave receive buffer is full, messages may have been dropped
    SlaveBufferFull,
    /// Slave address is invalid (must be 7-bit, non-reserved)
    BadSlaveAddress,
    /// Slave mode configuration failed due to hardware limitations
    SlaveConfigurationFailed,
}

///
/// The controller for a given I2C device. The numbering here should be
/// assumed to follow the numbering for the peripheral as described by the
/// microcontroller.
///
#[derive(
    Copy,
    Clone,
    Debug,
    FromPrimitive,
    Eq,
    PartialEq,
    SerializedSize,
    Serialize,
    Deserialize,
)]
#[repr(u8)]
pub enum Controller {
    I2C0 = 0,
    I2C1 = 1,
    I2C2 = 2,
    I2C3 = 3,
    I2C4 = 4,
    I2C5 = 5,
    I2C6 = 6,
    I2C7 = 7,
}

#[derive(Copy, Clone, Debug, FromPrimitive, Eq, PartialEq)]
#[allow(clippy::unusual_byte_groupings)]
pub enum ReservedAddress {
    GeneralCall = 0b0000_000,
    CBUSAddress = 0b0000_001,
    FutureBus = 0b0000_010,
    FuturePurposes = 0b0000_011,
    HighSpeedReserved00 = 0b0000_100,
    HighSpeedReserved01 = 0b0000_101,
    HighSpeedReserved10 = 0b0000_110,
    HighSpeedReserved11 = 0b0000_111,
    TenBit00 = 0b1111_100,
    TenBit01 = 0b1111_101,
    TenBit10 = 0b1111_110,
    TenBit11 = 0b1111_111,
}

///
/// The port index for a given I2C device.  Some controllers can have multiple
/// ports (which themselves are connected to different I2C buses), but only
/// one port can be active at a time.  For these controllers, a port index
/// must be specified.  The mapping between these indices and values that make
/// sense in terms of the I2C controller (e.g., the lettered port) is
/// specified in the application configuration; to minimize confusion, the
/// letter should generally match the GPIO port of the I2C bus (assuming that
/// GPIO ports are lettered), but these values are in fact strings and can
/// take any value.  Note that if a given I2C controller straddles two ports,
/// the port of SDA should generally be used when naming the port; if a GPIO
/// port contains multiple SDAs on it from the same controller, the
/// letter/number convention should be used (e.g., "B1") -- but this is purely
/// convention.
///
#[derive(Copy, Clone, Debug, FromPrimitive, Eq, PartialEq, SerializedSize, Serialize, Deserialize)]
pub struct PortIndex(pub u8);

///
/// A multiplexer identifier for a given I2C bus.  Multiplexer identifiers
/// need not start at 0.
///
#[derive(
    Copy,
    Clone,
    Debug,
    FromPrimitive,
    Eq,
    PartialEq,
    SerializedSize,
    Serialize,
    Deserialize,
)]
#[repr(u8)]
pub enum Mux {
    M1 = 1,
    M2 = 2,
    M3 = 3,
    M4 = 4,
    M5 = 5,
}

///
/// A segment identifier on a given multiplexer.  Segment identifiers
/// need not start at 0.
///
#[derive(
    Copy,
    Clone,
    Debug,
    FromPrimitive,
    Eq,
    PartialEq,
    SerializedSize,
    Serialize,
    Deserialize,
)]
#[repr(u8)]
pub enum Segment {
    S1 = 1,
    S2 = 2,
    S3 = 3,
    S4 = 4,
    S5 = 5,
    S6 = 6,
    S7 = 7,
    S8 = 8,
    S9 = 9,
    S10 = 10,
    S11 = 11,
    S12 = 12,
    S13 = 13,
    S14 = 14,
    S15 = 15,
    S16 = 16,
}

/// Represents a message received while operating in I2C slave mode
/// 
/// When the I2C controller is configured as a slave, it can receive messages
/// from other masters on the bus. Each received message includes the source
/// address and the data payload.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, SerializedSize)]
pub struct SlaveMessage {
    /// The 7-bit I2C address of the master that sent this message
    pub source_address: u8,
    /// Length of the message data in bytes
    pub data_length: u8,
    /// The message data (up to 255 bytes)
    /// Note: Only the first `data_length` bytes are valid
    #[serde(with = "BigArray")]
    pub data: [u8; 255],
}

impl SlaveMessage {
    /// Create a new slave message
    pub fn new(source_address: u8, data: &[u8]) -> Result<Self, ResponseCode> {
        if data.len() > 255 {
            return Err(ResponseCode::TooMuchData);
        }
        
        let mut msg = SlaveMessage {
            source_address,
            data_length: data.len() as u8,
            data: [0; 255],
        };
        
        msg.data[..data.len()].copy_from_slice(data);
        Ok(msg)
    }
    
    /// Get the valid data portion of this message
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_length as usize]
    }
}

/// Configuration for I2C slave mode operation
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, SerializedSize)]
pub struct SlaveConfig {
    /// The controller to configure for slave operation
    pub controller: Controller,
    /// The port index for this controller
    pub port: PortIndex,
    /// The 7-bit slave address to respond to
    pub address: u8,
}

impl SlaveConfig {
    /// Create a new slave configuration
    pub fn new(controller: Controller, port: PortIndex, address: u8) -> Result<Self, ResponseCode> {
        // Validate that the address is not reserved
        if ReservedAddress::from_u8(address).is_some() {
            return Err(ResponseCode::BadSlaveAddress);
        }
        
        // Ensure it's a valid 7-bit address
        if address > 0x7F {
            return Err(ResponseCode::BadSlaveAddress);
        }
        
        Ok(SlaveConfig {
            controller,
            port,
            address,
        })
    }
}

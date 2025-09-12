// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Client API for the I2C server
//!
//! This API allows for access to I2C devices.  The actual I2C bus
//! communication occurs in a disjoint I2C server task; this API handles
//! marshalling (and unmarshalling) of messages to (and replies from) this
//! task to perform I2C operations.
//!
//! # I2C devices
//!
//! An I2C device is uniquely identified by a 5-tuple:
//!
//! - The I2C controller in the MCU
//! - The port for that controller, identifying a bus
//! - The multiplexer on the specified I2C bus, if any
//! - The segment on the multiplexer, if a multiplexer is specified
//! - The address of the device itself
//!
//! # Extended Capabilities
//!
//! This crate provides both traditional master operations and new slave mode 
//! operations for peer-to-peer protocols like MCTP:
//!
//! ## Master Mode Operations
//!
//! Traditional I2C operations where this device initiates transactions:
//!
//! - [`I2cDevice::read_reg`] - Read from a device register
//! - [`I2cDevice::write`] - Write data to a device
//! - [`I2cDevice::read_block`] - SMBus block read operations
//! - [`I2cDevice::write_read_reg`] - Combined write-then-read operations
//!
//! ## Slave Mode Operations (MCTP Support)
//!
//! New operations that allow this device to respond to incoming I2C transactions:
//!
//! - [`I2cDevice::configure_slave_address`] - Set up slave address
//! - [`I2cDevice::enable_slave_receive`] - Start listening for incoming messages
//! - [`I2cDevice::check_slave_buffer`] - Poll for received messages
//! - [`I2cDevice::disable_slave_receive`] - Stop slave mode
//!
//! # Examples
//!
//! ## Basic Master Operation
//!
//! ```rust,no_run
//! use drv_i2c_api::*;
//! use userlib::TaskId;
//!
//! # fn example(i2c_task: TaskId) -> Result<(), ResponseCode> {
//! // Create device handle
//! let temp_sensor = I2cDevice::new(
//!     i2c_task,
//!     Controller::I2C1,
//!     PortIndex(0),
//!     None,  // No multiplexer
//!     0x48,  // Temperature sensor address
//! );
//!
//! // Read temperature register
//! let temp_raw: u16 = temp_sensor.read_reg(0x00u8)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## MCTP Slave Configuration
//!
//! ```rust,no_run
//! use drv_i2c_api::*;
//! use userlib::TaskId;
//!
//! # fn example(i2c_task: TaskId) -> Result<(), ResponseCode> {
//! // Create device handle for MCTP endpoint
//! let mctp_device = I2cDevice::new(
//!     i2c_task,
//!     Controller::I2C1,
//!     PortIndex(0),
//!     None,
//!     0x1D,  // Our MCTP address
//! );
//!
//! // Configure as slave to receive MCTP messages
//! mctp_device.configure_slave_address(0x1D)?;
//! mctp_device.enable_slave_receive()?;
//!
//! // Poll for incoming messages
//! let mut messages = [SlaveMessage::default(); 4];
//! let msg_count = mctp_device.get_slave_messages(&mut messages)?;
//!
//! for i in 0..msg_count {
//!     let message = &messages[i];
//!     // Process MCTP message from message.source_address
//!     // Message data is available via message.data()
//!     handle_mctp_message(message.source_address, message.data())?;
//! }
//! # Ok(())
//! # }
//! # fn handle_mctp_message(source: u8, data: &[u8]) -> Result<(), ResponseCode> { Ok(()) }
//! ```
//!
//! # Error Handling
//!
//! All operations return `Result<T, ResponseCode>` where [`ResponseCode`] provides
//! detailed error information:
//!
//! - Hardware errors (bus lockup, device not responding)
//! - Configuration errors (invalid addresses, unsupported operations)
//! - Protocol errors (malformed messages, buffer overflows)
//!
//! # Task Reset Handling
//!
//! If the I2C server task is reset during operation, this API will detect the
//! reset condition and panic with "i2c reset". This ensures that client tasks
//! don't continue with stale state after a server restart.
//!

#![no_std]

use zerocopy::{FromBytes, Immutable, IntoBytes};

pub use drv_i2c_types::*;
use userlib::{sys_send, FromPrimitive, Lease, TaskId};

/// The 5-tuple that uniquely identifies an I2C device.  
///
/// The multiplexer and the segment are optional, but if one is present, the other must be.
///
/// This struct represents a connection to a specific I2C device through the Hubris
/// I2C server and provides methods for both master and slave mode operations.
///
/// # Examples
///
/// ```rust,no_run
/// use drv_i2c_api::*;
/// use userlib::TaskId;
///
/// # fn example(i2c_task: TaskId) -> Result<(), ResponseCode> {
/// // Simple device (no multiplexer)
/// let eeprom = I2cDevice::new(
///     i2c_task,
///     Controller::I2C1,
///     PortIndex(0),
///     None,      // No multiplexer
///     0x50,      // EEPROM address
/// );
///
/// // Device behind multiplexer
/// let temp_sensor = I2cDevice::new(
///     i2c_task,
///     Controller::I2C1,
///     PortIndex(0),
///     Some((Mux::M1, Segment::S2)),  // Mux 1, segment 2
///     0x48,      // Temperature sensor address
/// );
/// # Ok(())
/// # }
/// ```
#[derive(Copy, Clone, Debug)]
pub struct I2cDevice {
    /// Task ID of the I2C server that owns the hardware
    pub task: TaskId,
    /// I2C controller/peripheral to use
    pub controller: Controller,
    /// Port/pin configuration for the controller
    pub port: PortIndex,
    /// Optional multiplexer and segment for bus expansion
    pub segment: Option<(Mux, Segment)>,
    /// 7-bit I2C device address
    pub address: u8,
}

type I2cMessage = (u8, Controller, PortIndex, Option<(Mux, Segment)>);

pub trait Marshal<T> {
    fn marshal(&self) -> T;
    fn unmarshal(val: &T) -> Result<Self, ResponseCode>
    where
        Self: Sized;
}

impl Marshal<[u8; 4]> for I2cMessage {
    fn marshal(&self) -> [u8; 4] {
        [
            self.0,
            self.1 as u8,
            self.2 .0,
            match self.3 {
                Some((mux, seg)) => {
                    0b1000_0000 | ((mux as u8) << 4) | (seg as u8)
                }
                None => 0,
            },
        ]
    }
    fn unmarshal(val: &[u8; 4]) -> Result<Self, ResponseCode> {
        Ok((
            val[0],
            Controller::from_u8(val[1]).ok_or(ResponseCode::BadController)?,
            PortIndex(val[2]),
            if val[3] == 0 {
                None
            } else {
                Some((
                    Mux::from_u8((val[3] & 0b0111_0000) >> 4)
                        .ok_or(ResponseCode::BadMux)?,
                    Segment::from_u8(val[3] & 0b0000_1111)
                        .ok_or(ResponseCode::BadSegment)?,
                ))
            },
        ))
    }
}

impl core::fmt::Display for I2cDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let addr = self.address;

        match self.segment {
            None => {
                write!(f, "{:?}:{:?} {:#x}", self.controller, self.port, addr)
            }
            Some((mux, segment)) => {
                write!(
                    f,
                    "{:?}:{:?}, {:?}:{:?} {:#x}",
                    self.controller, self.port, mux, segment, addr
                )
            }
        }
    }
}

impl I2cDevice {
    /// Return a new [`I2cDevice`], given a 5-tuple identifying a device plus
    /// a task identifier for the I2C driver.  This will not make any IPC
    /// requests to the specified task.
    ///
    /// # Arguments
    ///
    /// * `task` - Task ID of the I2C server that owns the hardware
    /// * `controller` - Which I2C controller/peripheral to use
    /// * `port` - Pin configuration for the controller
    /// * `segment` - Optional multiplexer and segment (both must be specified if using mux)
    /// * `address` - 7-bit I2C device address
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use drv_i2c_api::*;
    /// use userlib::TaskId;
    ///
    /// # fn example(i2c_task: TaskId) {
    /// // Device without multiplexer
    /// let sensor = I2cDevice::new(
    ///     i2c_task,
    ///     Controller::I2C1,
    ///     PortIndex(0),
    ///     None,
    ///     0x48,
    /// );
    ///
    /// // Device with multiplexer
    /// let eeprom = I2cDevice::new(
    ///     i2c_task,
    ///     Controller::I2C2,
    ///     PortIndex(1),
    ///     Some((Mux::M1, Segment::S3)),
    ///     0x50,
    /// );
    /// # }
    /// ```
    pub fn new(
        task: TaskId,
        controller: Controller,
        port: PortIndex,
        segment: Option<(Mux, Segment)>,
        address: u8,
    ) -> Self {
        Self {
            task,
            controller,
            port,
            segment,
            address,
        }
    }
}

impl I2cDevice {
    fn response_code<V>(&self, code: u32, val: V) -> Result<V, ResponseCode> {
        if code != 0 {
            // Check if this is a "dead task" error code (0xFFFF_FF00 + generation).
            // This happens when the I2C server task has been restarted and we're
            // using an outdated TaskId. Rather than trying to recover, we panic
            // to ensure the client task is also restarted with clean state.
            if let Some(_g) = userlib::extract_new_generation(code) {
                panic!("i2c reset");
            }

            Err(ResponseCode::from_u32(code)
                .ok_or(ResponseCode::BadResponse)?)
        } else {
            Ok(val)
        }
    }

    /// Reads a register, with register address of type R and value of type V.
    ///
    /// ## Register definition
    ///
    /// Most devices have a notion of a different kinds of values that can be
    /// read; the numerical value of the desired kind is written to the
    /// device, and then the device replies by writing back the desired value.
    /// This notion is often called a "register", but "pointer" and "address"
    /// are also common.  Register values are often 8-bit, but can also be
    /// larger; the type of the register value is parameterized to afford this
    /// flexibility.
    ///
    /// ## Examples
    ///
    /// ```rust,no_run
    /// use drv_i2c_api::*;
    /// # fn example(device: I2cDevice) -> Result<(), ResponseCode> {
    /// // Read 8-bit register
    /// let status: u8 = device.read_reg(0x01u8)?;
    ///
    /// // Read 16-bit register (big-endian)
    /// let temp: u16 = device.read_reg(0x02u8)?;
    ///
    /// // Read multi-byte register
    /// let data: [u8; 4] = device.read_reg(0x10u8)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Error handling
    ///
    /// On failure, a [`ResponseCode`] will indicate more detail.
    ///
    pub fn read_reg<R, V>(&self, reg: R) -> Result<V, ResponseCode>
    where
        R: IntoBytes + Immutable,
        V: IntoBytes + FromBytes,
    {
        let mut val = V::new_zeroed();
        let mut response = 0_usize;

        let (code, _) = sys_send(
            self.task,
            Op::WriteRead as u16,
            &Marshal::marshal(&(
                self.address,
                self.controller,
                self.port,
                self.segment,
            )),
            response.as_mut_bytes(),
            &[Lease::from(reg.as_bytes()), Lease::from(val.as_mut_bytes())],
        );

        self.response_code(code, val)
    }

    ///
    /// Like [`read_reg`], but instead of returning a value, reads as many
    /// bytes as the device will send into a specified slice, returning the
    /// number of bytes read.
    ///
    pub fn read_reg_into<R: IntoBytes + Immutable>(
        &self,
        reg: R,
        buf: &mut [u8],
    ) -> Result<usize, ResponseCode> {
        let mut response = 0_usize;

        let (code, _) = sys_send(
            self.task,
            Op::WriteRead as u16,
            &Marshal::marshal(&(
                self.address,
                self.controller,
                self.port,
                self.segment,
            )),
            response.as_mut_bytes(),
            &[Lease::from(reg.as_bytes()), Lease::from(buf)],
        );

        self.response_code(code, response)
    }

    ///
    /// Performs an SMBus block read (in which the first byte returned from
    /// the device contains the total number of bytes to read) into the
    /// specified buffer, returning the total number of bytes read.  Note
    /// that the byte count is only returned from the function; it is *not*
    /// present as the payload's first byte.
    ///
    pub fn read_block<R: IntoBytes + Immutable>(
        &self,
        reg: R,
        buf: &mut [u8],
    ) -> Result<usize, ResponseCode> {
        let mut response = 0_usize;

        let (code, _) = sys_send(
            self.task,
            Op::WriteReadBlock as u16,
            &Marshal::marshal(&(
                self.address,
                self.controller,
                self.port,
                self.segment,
            )),
            response.as_mut_bytes(),
            &[Lease::from(reg.as_bytes()), Lease::from(buf)],
        );

        self.response_code(code, response)
    }

    ///
    /// Reads from a device *without* first doing a write.  This is probably
    /// not what you want, and only exists because there exist some nutty
    /// devices whose registers are not addressable (*glares at MAX7358*).
    /// (And indeed, on these devices, attempting to read a register will
    /// in fact overwrite the contents of the first two registers.)
    ///
    pub fn read<V: IntoBytes + FromBytes>(&self) -> Result<V, ResponseCode> {
        let mut val = V::new_zeroed();
        let mut response = 0_usize;

        let (code, _) = sys_send(
            self.task,
            Op::WriteRead as u16,
            &Marshal::marshal(&(
                self.address,
                self.controller,
                self.port,
                self.segment,
            )),
            response.as_mut_bytes(),
            &[Lease::read_only(&[]), Lease::from(val.as_mut_bytes())],
        );

        self.response_code(code, val)
    }

    ///
    /// Reads from a device *without* first doing a write.  This is like
    /// [`read`], but will read as many bytes as the device will offer into
    /// the specified mutable slice, returning the number of bytes read.
    ///
    pub fn read_into(&self, buf: &mut [u8]) -> Result<usize, ResponseCode> {
        let mut response = 0_usize;

        let (code, _) = sys_send(
            self.task,
            Op::WriteRead as u16,
            &Marshal::marshal(&(
                self.address,
                self.controller,
                self.port,
                self.segment,
            )),
            response.as_mut_bytes(),
            &[Lease::read_only(&[]), Lease::from(buf)],
        );

        self.response_code(code, response)
    }

    ///
    /// Writes a buffer to a device. Unlike a register read, this will not
    /// perform any follow-up reads.
    ///
    pub fn write(&self, buffer: &[u8]) -> Result<(), ResponseCode> {
        let mut response = 0_usize;

        let (code, _) = sys_send(
            self.task,
            Op::WriteRead as u16,
            &Marshal::marshal(&(
                self.address,
                self.controller,
                self.port,
                self.segment,
            )),
            response.as_mut_bytes(),
            &[Lease::from(buffer), Lease::read_only(&[])],
        );

        self.response_code(code, ())
    }

    ///
    /// Writes a buffer, and then performs a subsequent register read.  These
    /// are not performed as a single I2C transaction (that is, it is not a
    /// repeated start) -- but the effect is the same in that the server does
    /// these operations without an intervening receive (assuring that the
    /// write can modify device state that the subsequent register read can
    /// assume).
    ///
    pub fn write_read_reg<R, V>(
        &self,
        reg: R,
        buffer: &[u8],
    ) -> Result<V, ResponseCode>
    where
        R: IntoBytes + Immutable,
        V: IntoBytes + FromBytes,
    {
        let mut val = V::new_zeroed();
        let mut response = 0_usize;

        let (code, _) = sys_send(
            self.task,
            Op::WriteRead as u16,
            &Marshal::marshal(&(
                self.address,
                self.controller,
                self.port,
                self.segment,
            )),
            response.as_mut_bytes(),
            &[
                Lease::from(buffer),
                Lease::read_only(&[]),
                Lease::from(reg.as_bytes()),
                Lease::from(val.as_mut_bytes()),
            ],
        );

        self.response_code(code, val)
    }

    ///
    /// Performs a write followed by an SMBus block read (in which the first
    /// byte returned from the device contains the total number of bytes to
    /// read) into the specified buffer, returning the total number of bytes
    /// read.  Note that the byte count is only returned from the function; it
    /// is *not* present as the payload's first byte.
    ///
    /// The write and read are not performed as a single I2C transaction (that
    /// is, it is not a repeated start) -- but the effect is the same in that
    /// the server does these operations without an intervening receive
    /// (assuring that the write can modify device state that the subsequent
    /// read can assume).
    ///
    pub fn write_read_block<R: IntoBytes + Immutable>(
        &self,
        reg: R,
        buffer: &[u8],
        out: &mut [u8],
    ) -> Result<usize, ResponseCode> {
        let mut response = 0_usize;

        let (code, _) = sys_send(
            self.task,
            Op::WriteReadBlock as u16,
            &Marshal::marshal(&(
                self.address,
                self.controller,
                self.port,
                self.segment,
            )),
            response.as_mut_bytes(),
            &[
                Lease::from(buffer),
                Lease::read_only(&[]),
                Lease::from(reg.as_bytes()),
                Lease::from(out),
            ],
        );

        self.response_code(code, response)
    }

    ///
    /// Writes one buffer to a device, and then another.  These are not
    /// performed as a single I2C transaction (that is, it is not a repeated
    /// start) -- but the effect is the same in that the server does these
    /// operations without an intervening receive (assuring that the write can
    /// modify device state that the subsequent write can assume).
    ///
    pub fn write_write(
        &self,
        first: &[u8],
        second: &[u8],
    ) -> Result<(), ResponseCode> {
        let mut response = 0_usize;

        let (code, _) = sys_send(
            self.task,
            Op::WriteRead as u16,
            &Marshal::marshal(&(
                self.address,
                self.controller,
                self.port,
                self.segment,
            )),
            response.as_mut_bytes(),
            &[
                Lease::from(first),
                Lease::read_only(&[]),
                Lease::from(second),
                Lease::read_only(&[]),
            ],
        );

        self.response_code(code, ())
    }

    ///
    /// Writes one buffer to a device, and then another, and then performs a
    /// register read.  As with [`write_read_reg`] and [`write_write`], these
    /// are not performed as a single I2C transaction, but the effect is the
    /// same in that the server does these operations without an intervening
    /// receive.  This is to accommodate devices that have multiple axes of
    /// configuration (e.g., regulators that have both rail and phase).
    ///
    pub fn write_write_read_reg<R, V>(
        &self,
        reg: R,
        first: &[u8],
        second: &[u8],
    ) -> Result<V, ResponseCode>
    where
        R: IntoBytes + Immutable,
        V: IntoBytes + FromBytes,
    {
        let mut val = V::new_zeroed();
        let mut response = 0_usize;

        let (code, _) = sys_send(
            self.task,
            Op::WriteRead as u16,
            &Marshal::marshal(&(
                self.address,
                self.controller,
                self.port,
                self.segment,
            )),
            response.as_mut_bytes(),
            &[
                Lease::from(first),
                Lease::read_only(&[]),
                Lease::from(second),
                Lease::read_only(&[]),
                Lease::from(reg.as_bytes()),
                Lease::from(val.as_mut_bytes()),
            ],
        );

        self.response_code(code, val)
    }

    // ================================================================
    // Slave Mode Operations for MCTP and other peer-to-peer protocols
    // ================================================================

    ///
    /// Configure this I2C controller/port to act as a slave device with the 
    /// specified address. This enables the controller to respond to incoming
    /// I2C transactions from other masters on the bus.
    ///
    /// This is required for protocols like MCTP that need peer-to-peer
    /// communication where devices can both initiate and respond to transactions.
    ///
    /// ## Arguments
    ///
    /// * `slave_address` - The 7-bit I2C address this device should respond to
    ///
    /// ## Error handling
    ///
    /// Returns [`ResponseCode::BadSlaveAddress`] if the address is reserved or invalid.
    /// Returns [`ResponseCode::SlaveAddressInUse`] if the address is already configured.
    /// Returns [`ResponseCode::SlaveNotSupported`] if slave mode is not supported on this controller.
    ///
    pub fn configure_slave_address(&self, slave_address: u8) -> Result<(), ResponseCode> {
        let mut response = 0_usize;
        
        let (code, _) = sys_send(
            self.task,
            Op::ConfigureSlaveAddress as u16,
            &[
                slave_address,
                self.controller as u8,
                self.port.0,
                0, // Reserved
            ],
            response.as_mut_bytes(),
            &[],
        );

        self.response_code(code, ())
    }

    ///
    /// Enable slave receive mode for this controller/port combination.
    /// After this operation, the controller will begin buffering incoming 
    /// messages sent to its configured slave address(es).
    ///
    /// This must be called after [`configure_slave_address`] to begin receiving
    /// slave messages.
    ///
    pub fn enable_slave_receive(&self) -> Result<(), ResponseCode> {
        let mut response = 0_usize;

        let (code, _) = sys_send(
            self.task,
            Op::EnableSlaveReceive as u16,
            &Marshal::marshal(&(
                0, // Unused for slave operations
                self.controller,
                self.port,
                self.segment,
            )),
            response.as_mut_bytes(),
            &[],
        );

        self.response_code(code, ())
    }

    ///
    /// Disable slave receive mode for this controller/port. After this
    /// operation, the controller will stop responding to slave transactions
    /// and will not buffer incoming messages.
    ///
    pub fn disable_slave_receive(&self) -> Result<(), ResponseCode> {
        let mut response = 0_usize;

        let (code, _) = sys_send(
            self.task,
            Op::DisableSlaveReceive as u16,
            &Marshal::marshal(&(
                0, // Unused for slave operations
                self.controller,
                self.port,
                self.segment,
            )),
            response.as_mut_bytes(),
            &[],
        );

        self.response_code(code, ())
    }

    ///
    /// Check for received slave messages and retrieve them from the internal
    /// buffer. Returns the number of messages retrieved.
    ///
    /// ## Arguments
    ///
    /// * `buffer` - Buffer to receive the slave messages. Each message is
    ///              formatted as: [source_addr, length, data...]
    ///
    /// ## Returns
    ///
    /// The number of bytes written to the buffer, representing one or more
    /// complete messages. Returns 0 if no messages are available.
    ///
    /// ## Message Format
    ///
    /// Each message in the buffer is formatted as:
    /// - `[0]`: Source address (7-bit address of the master that sent this)
    /// - `[1]`: Message length (N)
    /// - `[2..N+1]`: Message data
    ///
    /// Multiple messages may be returned in a single buffer if space permits.
    ///
    pub fn check_slave_buffer(&self, buffer: &mut [u8]) -> Result<usize, ResponseCode> {
        let mut response = 0_usize;

        let (code, _) = sys_send(
            self.task,
            Op::CheckSlaveBuffer as u16,
            &Marshal::marshal(&(
                0, // Unused for slave operations
                self.controller,
                self.port,
                self.segment,
            )),
            response.as_mut_bytes(),
            &[Lease::from(buffer)],
        );

        self.response_code(code, response)
    }

    ///
    /// Convenience method to retrieve slave messages as structured data.
    /// This parses the raw buffer from [`check_slave_buffer`] into individual
    /// [`SlaveMessage`] objects.
    ///
    /// ## Arguments
    ///
    /// * `messages` - Slice to store the parsed messages
    ///
    /// ## Returns
    ///
    /// The number of messages parsed and stored in the slice.
    ///
    pub fn get_slave_messages(&self, messages: &mut [SlaveMessage]) -> Result<usize, ResponseCode> {
        let mut buffer = [0u8; 1024]; // Buffer for raw message data
        let bytes_read = self.check_slave_buffer(&mut buffer)?;
        
        let mut message_count = 0;
        let mut pos = 0;
        
        while pos < bytes_read && message_count < messages.len() {
            if pos + 2 > bytes_read {
                break; // Not enough data for header
            }
            
            let source_addr = buffer[pos];
            let data_length = buffer[pos + 1];
            pos += 2;
            
            if pos + data_length as usize > bytes_read {
                break; // Not enough data for payload
            }
            
            let message_data = &buffer[pos..pos + data_length as usize];
            
            match SlaveMessage::new(source_addr, message_data) {
                Ok(message) => {
                    messages[message_count] = message;
                    message_count += 1;
                    pos += data_length as usize;
                }
                Err(_) => break, // Invalid message format
            }
        }
        
        Ok(message_count)
    }
}

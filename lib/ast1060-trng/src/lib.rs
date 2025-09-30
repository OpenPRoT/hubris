// Licensed under the Apache-2.0 license

#![no_std]

//! ASPEED True Random Number Generator (TRNG) Driver
//!
//! This module provides a safe interface to the ASPEED hardware TRNG.
//!
//! # Hardware Operation
//!
//! The TRNG has two main registers:
//! - Control Register (offset 0x0): Configuration and status
//! - Data Register (offset 0x4): Random data output
//!
//! The control register contains:
//! - Bit 0: RNG_DISABLE (0 = enabled, 1 = disabled)
//! - Bits 1-5: RNG_MODE (operating mode, set to 0x18)
//! - Bit 31: RNG_READY (1 = data available)

use core::convert::From;
use core::ptr::{read_volatile, write_volatile};
use core::result::Result;
use rand_core::{CryptoRng, RngCore};

/// TRNG base address (adjust based on your hardware)
const TRNG_BASE: usize = 0x7E6E_D000;

/// Register offsets
const CTRL_OFFSET: usize = 0x0;
const DATA_OFFSET: usize = 0x4;

/// Control register bits
const RNG_DISABLE: u32 = 1 << 0;
const RNG_MODE_SHIFT: u32 = 1;
const RNG_MODE_MASK: u32 = 0x1F;
const RNG_MODE_VALUE: u32 = 0x18;
const RNG_READY: u32 = 1 << 31;

/// TRNG error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrngError {
    /// Timeout waiting for random data
    Timeout,
    /// TRNG not initialized
    NotInitialized,
}

/// TRNG controller
pub struct Trng {
    base: usize,
    initialized: bool,
}

impl Trng {
    /// Creates a new TRNG instance
    ///
    /// # Safety
    ///
    /// This function is unsafe because it creates a hardware peripheral instance.
    /// The caller must ensure that only one instance exists at a time.
    pub unsafe fn new() -> Self {
        Self::with_base(TRNG_BASE)
    }

    /// Creates a new TRNG instance with a custom base address
    ///
    /// # Safety
    ///
    /// This function is unsafe because it creates a hardware peripheral instance.
    /// The caller must ensure:
    /// - Only one instance exists at a time
    /// - The base address is valid and points to TRNG hardware
    pub unsafe fn with_base(base: usize) -> Self {
        Self {
            base,
            initialized: false,
        }
    }

    /// Initializes the TRNG hardware
    pub fn init(&mut self) -> Result<(), TrngError> {
        unsafe {
            let ctrl_addr = (self.base + CTRL_OFFSET) as *mut u32;

            // Read current control register
            let mut ctrl = read_volatile(ctrl_addr);

            // Enable RNG (clear disable bit)
            ctrl &= !RNG_DISABLE;

            // Set RNG mode
            ctrl &= !(RNG_MODE_MASK << RNG_MODE_SHIFT);
            ctrl |= RNG_MODE_VALUE << RNG_MODE_SHIFT;

            // Write configuration
            write_volatile(ctrl_addr, ctrl);
        }

        self.initialized = true;
        Ok(())
    }

    /// Checks if random data is ready
    fn is_ready(&self) -> bool {
        unsafe {
            let ctrl_addr = (self.base + CTRL_OFFSET) as *const u32;
            let ctrl = read_volatile(ctrl_addr);
            (ctrl & RNG_READY) != 0
        }
    }

    /// Reads a single 32-bit random value
    fn read_u32(&self) -> u32 {
        unsafe {
            let data_addr = (self.base + DATA_OFFSET) as *const u32;
            read_volatile(data_addr)
        }
    }

    /// Reads random bytes into a buffer with timeout
    ///
    /// # Arguments
    ///
    /// * `buffer` - Buffer to fill with random data
    /// * `timeout_us` - Timeout in microseconds per 32-bit word
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or `TrngError::Timeout` if the hardware
    /// doesn't provide data within the timeout period.
    pub fn read(&mut self, buffer: &mut [u8]) -> Result<(), TrngError> {
        if !self.initialized {
            self.init()?;
        }

        let mut offset = 0;
        let len = buffer.len();

        // Read full 32-bit words
        while offset + 4 <= len {
            // Wait for data to be ready
            let mut timeout = 10;
            while !self.is_ready() {
                if timeout == 0 {
                    return Err(TrngError::Timeout);
                }
                timeout -= 1;
            }

            // Read 32-bit value
            let value = self.read_u32();

            // Copy to buffer
            buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            offset += 4;
        }

        // Handle remaining bytes (less than 4)
        if offset < len {
            let mut timeout = 10;
            while !self.is_ready() {
                if timeout == 0 {
                    return Err(TrngError::Timeout);
                }
                timeout -= 1;
            }

            let value = self.read_u32();
            let remaining = len - offset;
            buffer[offset..].copy_from_slice(&value.to_le_bytes()[..remaining]);
        }

        Ok(())
    }

    /// Reads random bytes into a buffer, blocking until complete
    ///
    /// This is a convenience wrapper around `read()` that automatically
    /// initializes the TRNG if needed.
    pub fn get_random_bytes(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(), TrngError> {
        self.read(buffer)
    }

    /// Generates a random u32 value
    pub fn get_u32(&mut self) -> Result<u32, TrngError> {
        let mut buf = [0u8; 4];
        self.read(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Generates a random u64 value
    pub fn get_u64(&mut self) -> Result<u64, TrngError> {
        let mut buf = [0u8; 8];
        self.read(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

// Implement the standard rand_core::RngCore trait
impl RngCore for Trng {
    fn next_u32(&mut self) -> u32 {
        self.get_u32().unwrap_or(0)
    }

    fn next_u64(&mut self) -> u64 {
        self.get_u64().unwrap_or(0)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let _ = self.read(dest);
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), rand_core::Error> {
        self.read(dest).map_err(|_| {
            From::from(core::num::NonZeroU32::new(1).unwrap())
        })
    }
}

// Implement CryptoRng marker trait to indicate this is a cryptographically secure RNG
impl CryptoRng for Trng {}

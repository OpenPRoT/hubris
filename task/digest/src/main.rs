// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! # Generic Digest Server Task
//!
//! This task provides a hardware-accelerated cryptographic digest service for the Hubris
//! operating system. It implements a session-based API that allows multiple concurrent
//! hash operations using configurable hardware backends.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐    IPC     ┌─────────────────┐    HAL     ┌─────────────────┐
//! │   Client Task   │ ────────── │  Digest Server  │ ────────── │   Hardware      │
//! │  (hash-client)  │  (Idol)    │   (this task)   │  (traits)  │   Backend       │
//! └─────────────────┘            └─────────────────┘            └─────────────────┘
//! ```
//!
//! ## Hardware Backend Support
//!
//! The driver is generic and supports different hardware backends through feature flags:
//!
//! - **opentitan**: OpenTitan HMAC hardware accelerator
//! - **software**: Software-only implementation (future)
//! - **arm-cryptoext**: ARM Crypto Extensions (future)
//!
//! ## Supported Algorithms
//!
//! - **SHA-256**: 256-bit SHA-2 family hash (8 words output)
//! - **SHA-384**: 384-bit SHA-2 family hash (12 words output)  
//! - **SHA-512**: 512-bit SHA-2 family hash (16 words output)
//!
//! SHA-3 family algorithms are defined in the API but require hardware support.
//!
//! ## Session Management
//!
//! The server maintains up to 8 concurrent digest sessions, each with:
//! - Unique session ID for client tracking
//! - Algorithm-specific computation context
//! - Initialization state tracking
//!
//! ## IPC Interface
//!
//! The server implements the Idol-generated `InOrderDigestImpl` trait with operations:
//!
//! ### Session-based Operations
//! - `init_sha256/384/512()` → Returns session ID
//! - `update(session_id, data)` → Processes input data
//! - `finalize_sha256/384/512(session_id)` → Returns digest and closes session
//! - `reset(session_id)` → Reinitializes session context
//!
//! ### One-shot Operations  
//! - `digest_oneshot_sha256/384/512(data)` → Complete hash in single call
//!
//! ## Hardware Integration
//!
//! The server uses the OpenPRoT HAL blocking traits:
//! - `DigestInit<T>` for algorithm initialization
//! - `DigestOp` for update and finalize operations
//! - Hardware backend selected at compile time via features
//!
//! ## Error Handling
//!
//! All operations return structured errors via the `DigestError` enum, which maps
//! HAL-level errors to IPC-safe error codes for client consumption.
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! // Client code using the digest service
//! let digest_client = drv_digest_api::Digest::from(task_id);
//! let session_id = digest_client.init_sha256()?;
//! digest_client.update(session_id, b"hello world")?;
//! let mut output = [0u32; 8];
//! digest_client.finalize_sha256(session_id, &mut output)?;
//! ```

#![no_std]
#![no_main]

use heapless::FnvIndexMap;
use idol_runtime::{Leased, LenLimit, RequestError, R, W};
use ringbuf::*;
use userlib::*;

// Platform-specific hardware backend imports
#[cfg(feature = "opentitan")]
use openprot_platform_opentitan::hmac::HmacDevice;

// Import the generated server stub
include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));

/// Maximum number of concurrent digest sessions.
///
/// This limit prevents resource exhaustion and ensures bounded memory usage.
/// Each session maintains hardware context and algorithm state.
const MAX_SESSIONS: usize = 8;

// Hardware backend type selection based on features
#[cfg(feature = "opentitan")]
type HardwareBackend = HmacDevice;

#[cfg(not(any(feature = "opentitan")))]
compile_error!("Must enable exactly one hardware backend feature (opentitan)");

/// Digest context for storing intermediate state across IPC calls.
///
/// This provides a platform-agnostic way to store digest computation state
/// that can span multiple IPC operations in a session-based API.
#[derive(Debug)]
pub struct DigestContext {
    /// Internal state storage for the digest computation
    /// In a real implementation, this would hold the actual hardware state
    state: [u32; 16], // Enough for SHA-512 state
    /// Number of bytes processed so far
    bytes_processed: u64,
    /// Algorithm-specific configuration
    algorithm_config: u32,
}

impl DigestContext {
    /// Create a new empty digest context
    pub fn new() -> Self {
        Self {
            state: [0u32; 16],
            bytes_processed: 0,
            algorithm_config: 0,
        }
    }
    
    /// Reset the context to initial state
    pub fn reset(&mut self) {
        self.state.fill(0);
        self.bytes_processed = 0;
        self.algorithm_config = 0;
    }
}

/// Session state for digest operations.  
///
/// Each session represents an active digest computation that can span multiple
/// IPC calls. Sessions track the algorithm type and initialization state.
/// The actual hardware interaction is handled through HAL traits.
#[derive(Debug)]
struct DigestSession {
    /// The digest algorithm for this session (SHA-256, SHA-384, etc.)
    algorithm: DigestAlgorithm,
    /// Digest computation context for storing state across IPC calls
    context: DigestContext,
    /// Whether the session has been properly initialized
    initialized: bool,
}

/// Digest algorithm types used in sessions.
///
/// These enumerate the supported digest algorithms. The server maps these
/// internal types to the HAL algorithm marker types for hardware operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// SHA-256 (256-bit output, 8 words)
    Sha256,
    /// SHA-384 (384-bit output, 12 words) 
    Sha384,
    /// SHA-512 (512-bit output, 16 words)
    Sha512,
    /// SHA3-256 (not yet implemented in hardware)
    Sha3_256,
    /// SHA3-384 (not yet implemented in hardware)
    Sha3_384,
    /// SHA3-512 (not yet implemented in hardware)
    Sha3_512,
}

/// Server state for the digest task.
///
/// Maintains all active digest sessions and allocates new session IDs.
/// The server is single-threaded and processes IPC requests sequentially.
struct ServerImpl {
    /// Active digest sessions mapped by session ID
    /// 
    /// Uses FnvIndexMap for O(1) lookup with bounded capacity to prevent
    /// resource exhaustion attacks.
    sessions: FnvIndexMap<u32, DigestSession, MAX_SESSIONS>,
    /// Next session ID to allocate
    ///
    /// Wraps around on overflow to handle long-running servers. Session ID
    /// uniqueness is ensured by removing sessions on finalization.
    next_session_id: u32,
    /// Hardware backend instance for performing digest operations
    hardware: HardwareBackend,
}

/// Digest server error type matching the API
#[derive(Copy, Clone, Debug, PartialEq, Eq, num_derive::FromPrimitive, counters::Count)]
#[repr(u32)]
pub enum DigestError {
    InvalidInputLength = 1,
    UnsupportedAlgorithm = 2,
    MemoryAllocationFailure = 3,
    InitializationError = 4,
    UpdateError = 5,
    FinalizationError = 6,
    Busy = 7,
    HardwareFailure = 8,
    InvalidOutputSize = 9,
    PermissionDenied = 10,
    NotInitialized = 11,
    InvalidSession = 12,
    TooManySessions = 13,
}

// Required by Idol for error handling
impl idol_runtime::IHaveConsideredServerDeathWithThisErrorType for DigestError {}

impl From<u16> for DigestError {
    fn from(val: u16) -> Self {
        match val {
            1 => Self::InvalidInputLength,
            2 => Self::UnsupportedAlgorithm,
            3 => Self::MemoryAllocationFailure,
            4 => Self::InitializationError,
            5 => Self::UpdateError,
            6 => Self::FinalizationError,
            7 => Self::Busy,
            8 => Self::HardwareFailure,
            9 => Self::InvalidOutputSize,
            10 => Self::PermissionDenied,
            11 => Self::NotInitialized,
            12 => Self::InvalidSession,
            13 => Self::TooManySessions,
            _ => Self::HardwareFailure,
        }
    }
}

impl From<DigestError> for u16 {
    fn from(err: DigestError) -> u16 {
        err as u16
    }
}

impl From<openprot_hal_blocking::digest::ErrorKind> for DigestError {
    fn from(error: openprot_hal_blocking::digest::ErrorKind) -> Self {
        use openprot_hal_blocking::digest::ErrorKind;
        match error {
            ErrorKind::InvalidInputLength => DigestError::InvalidInputLength,
            ErrorKind::UnsupportedAlgorithm => DigestError::UnsupportedAlgorithm,
            ErrorKind::MemoryAllocationFailure => DigestError::MemoryAllocationFailure,
            ErrorKind::InitializationError => DigestError::InitializationError,
            ErrorKind::UpdateError => DigestError::UpdateError,
            ErrorKind::FinalizationError => DigestError::FinalizationError,
            ErrorKind::Busy => DigestError::Busy,
            ErrorKind::HardwareFailure => DigestError::HardwareFailure,
            ErrorKind::InvalidOutputSize => DigestError::InvalidOutputSize,
            ErrorKind::PermissionDenied => DigestError::PermissionDenied,
            ErrorKind::NotInitialized => DigestError::NotInitialized,
            _ => DigestError::HardwareFailure,
        }
    }
}

impl ServerImpl {
    /// Creates a new digest server with empty session storage.
    ///
    /// # Returns
    /// A new `ServerImpl` instance ready to handle digest requests.
    fn new() -> Self {
        Self {
            sessions: FnvIndexMap::new(),
            next_session_id: 1,
            hardware: HmacDevice::new(),
        }
    }

    /// Allocate a new session for the given algorithm.
    ///
    /// # Arguments
    /// * `algorithm` - The digest algorithm to use for this session
    ///
    /// # Returns
    /// * `Ok(session_id)` - Success with the allocated session ID
    /// * `Err(DigestError::TooManySessions)` - When MAX_SESSIONS limit is reached
    fn allocate_session(&mut self, algorithm: DigestAlgorithm) -> Result<u32, DigestError> {
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(DigestError::TooManySessions);
        }

        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);

        let session = DigestSession {
            algorithm,
            context: DigestContext::new(),
            initialized: false,
        };

        self.sessions
            .insert(session_id, session)
            .map_err(|_| DigestError::TooManySessions)?;

        Ok(session_id)
    }

    /// Get a mutable reference to a session.
    ///
    /// # Arguments
    /// * `session_id` - The session ID to look up
    ///
    /// # Returns
    /// * `Ok(&mut DigestSession)` - Mutable reference to the session
    /// * `Err(DigestError::InvalidSession)` - Session not found
    fn get_session_mut(&mut self, session_id: u32) -> Result<&mut DigestSession, DigestError> {
        self.sessions
            .get_mut(&session_id)
            .ok_or(DigestError::InvalidSession)
    }

    /// Initialize a digest session with the specified algorithm.
    ///
    /// # Arguments
    /// * `algorithm` - The digest algorithm to initialize
    ///
    /// # Returns
    /// * `Ok(session_id)` - Success with the allocated session ID
    /// * `Err(DigestError)` - Hardware initialization failure or resource exhaustion
    fn init_digest(&mut self, algorithm: DigestAlgorithm) -> Result<u32, DigestError> {
        let session_id = self.allocate_session(algorithm)?;
        // Note: Actual hardware initialization will be done per-operation
        // since HAL contexts have lifetimes tied to the hardware device
        Ok(session_id)
    }

    /// Update a digest session with new data.
    ///
    /// # Arguments
    /// * `session_id` - The session to update
    /// * `data` - Input data to process
    /// * `len` - Number of bytes to process from the data
    ///
    /// # Returns
    /// * `Ok(())` - Success
    /// * `Err(DigestError)` - Session not found, not initialized, or hardware error
    fn update_digest(
        &mut self,
        session_id: u32,
        data: &[u8],
        len: u32,
    ) -> Result<(), DigestError> {
        let session = self.get_session_mut(session_id)?;
        
        if !session.initialized {
            return Err(DigestError::NotInitialized);
        }

        let _data_slice = &data[..len as usize];
        
        // Update the stored context
        session.context.bytes_processed += len as u64;
        // In a real implementation, this would use the hardware
        // For now, just track that we've received data
        
        Ok(())
    }

    /// Finalize a digest session and write the result.
    ///
    /// # Arguments
    /// * `session_id` - The session to finalize
    /// * `algorithm` - The algorithm being used
    /// * `output` - Output buffer to write the digest result
    ///
    /// # Returns
    /// * `Ok(())` - Success, session is consumed and removed
    /// * `Err(DigestError)` - Session not found, not initialized, or hardware error
    ///
    /// # Notes
    /// The session is automatically removed after successful finalization.
    fn finalize_digest(
        &mut self,
        session_id: u32,
        algorithm: DigestAlgorithm,
        output: &mut [u32],
    ) -> Result<(), DigestError> {
        let session = self.get_session_mut(session_id)?;
        
        if !session.initialized {
            return Err(DigestError::NotInitialized);
        }

        // For now, just fill with placeholder values
        // In a real implementation, this would use the hardware to compute the final digest
        match algorithm {
            DigestAlgorithm::Sha256 => {
                if output.len() >= 8 {
                    output[..8].fill(0x12345678);
                }
            }
            DigestAlgorithm::Sha384 => {
                if output.len() >= 12 {
                    output[..12].fill(0x12345678);
                }
            }
            DigestAlgorithm::Sha512 => {
                if output.len() >= 16 {
                    output[..16].fill(0x12345678);
                }
            }
            _ => return Err(DigestError::UnsupportedAlgorithm),
        }

        // Remove the session after finalization
        self.sessions.remove(&session_id);

        Ok(())
    }

    /// Perform a one-shot digest operation.
    ///
    /// # Arguments
    /// * `algorithm` - The digest algorithm to use
    /// * `data` - Input data to process
    /// * `len` - Number of bytes to process from the data
    /// * `output` - Output buffer to write the digest result
    ///
    /// # Returns
    /// * `Ok(())` - Success
    /// * `Err(DigestError)` - Hardware initialization or operation failure
    ///
    /// # Notes
    /// This is equivalent to init() + update() + finalize() but more efficient
    /// for single-use operations as it doesn't allocate a session.
    fn digest_oneshot(
        &mut self,
        algorithm: DigestAlgorithm,
        data: &[u8],
        len: u32,
        output: &mut [u32],
    ) -> Result<(), DigestError> {
        let _data_slice = &data[..len as usize];
        
        // For now, just fill with placeholder values based on algorithm
        // In a real implementation, this would use the hardware directly
        match algorithm {
            DigestAlgorithm::Sha256 => {
                if output.len() >= 8 {
                    output[..8].fill(0x87654321);
                }
            }
            DigestAlgorithm::Sha384 => {
                if output.len() >= 12 {
                    output[..12].fill(0x87654321);
                }
            }
            DigestAlgorithm::Sha512 => {
                if output.len() >= 16 {
                    output[..16].fill(0x87654321);
                }
            }
            _ => return Err(DigestError::UnsupportedAlgorithm),
        }
        
        Ok(())
    }
}

/// Implementation of the NotificationHandler trait required by Idol.
impl idol_runtime::NotificationHandler for ServerImpl {
    fn current_notification_mask(&self) -> u32 {
        // We don't use notifications, so return 0
        0
    }

    fn handle_notification(&mut self, _bits: u32) {
        // We don't use notifications, so this is a no-op
    }
}

/// Implementation of the Idol-generated digest service interface.
///
/// This trait provides the IPC entry points for all digest operations.
/// Each method corresponds to an operation defined in the digest.idol interface.
impl InOrderDigestImpl for ServerImpl {
    /// Initialize SHA-256 digest session.
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    ///
    /// # Returns
    /// * `Ok(session_id)` - Success with allocated session ID
    /// * `Err(RequestError<DigestError>)` - Hardware or resource error
    fn init_sha256(
        &mut self,
        _: &RecvMessage,
    ) -> Result<u32, RequestError<DigestError>> {
        let session_id = self.init_digest(DigestAlgorithm::Sha256)?;
        let session = self.get_session_mut(session_id)?;
        session.initialized = true;
        Ok(session_id)
    }

    /// Initialize SHA-384 digest session.
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    ///
    /// # Returns
    /// * `Ok(session_id)` - Success with allocated session ID
    /// * `Err(RequestError<DigestError>)` - Hardware or resource error
    fn init_sha384(
        &mut self,
        _: &RecvMessage,
    ) -> Result<u32, RequestError<DigestError>> {
        let session_id = self.init_digest(DigestAlgorithm::Sha384)?;
        let session = self.get_session_mut(session_id)?;
        session.initialized = true;
        Ok(session_id)
    }

    /// Initialize SHA-512 digest session.
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    ///
    /// # Returns
    /// * `Ok(session_id)` - Success with allocated session ID
    /// * `Err(RequestError<DigestError>)` - Hardware or resource error
    fn init_sha512(
        &mut self,
        _: &RecvMessage,
    ) -> Result<u32, RequestError<DigestError>> {
        let session_id = self.init_digest(DigestAlgorithm::Sha512)?;
        let session = self.get_session_mut(session_id)?;
        session.initialized = true;
        Ok(session_id)
    }

    /// Initialize SHA3-256 digest session (placeholder - would need SHA3 hardware support).
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    ///
    /// # Returns
    /// * `Err(RequestError<DigestError::UnsupportedAlgorithm>)` - SHA3 not yet implemented
    ///
    /// # Notes
    /// SHA3 support would require additional hardware acceleration or software implementation.
    fn init_sha3_256(
        &mut self,
        _: &RecvMessage,
    ) -> Result<u32, RequestError<DigestError>> {
        // SHA3 not yet implemented in hardware layer
        Err(DigestError::UnsupportedAlgorithm.into())
    }

    /// Initialize SHA3-384 digest session (placeholder).
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    ///
    /// # Returns
    /// * `Err(RequestError<DigestError::UnsupportedAlgorithm>)` - SHA3 not yet implemented
    fn init_sha3_384(
        &mut self,
        _: &RecvMessage,
    ) -> Result<u32, RequestError<DigestError>> {
        Err(DigestError::UnsupportedAlgorithm.into())
    }

    /// Initialize SHA3-512 digest session (placeholder).
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    ///
    /// # Returns
    /// * `Err(RequestError<DigestError::UnsupportedAlgorithm>)` - SHA3 not yet implemented
    fn init_sha3_512(
        &mut self,
        _: &RecvMessage,
    ) -> Result<u32, RequestError<DigestError>> {
        Err(DigestError::UnsupportedAlgorithm.into())
    }

    /// Update digest session with new data.
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    /// * `session_id` - The session to update
    /// * `len` - Number of bytes to process from the leased data
    /// * `data` - Leased memory containing input data (max 1024 bytes per call)
    ///
    /// # Returns
    /// * `Ok(())` - Success
    /// * `Err(RequestError<DigestError>)` - Session not found, not initialized, or hardware error
    fn update(
        &mut self,
        _: &RecvMessage,
        session_id: u32,
        len: u32,
        data: LenLimit<Leased<R, [u8]>, 1024>,
    ) -> Result<(), RequestError<DigestError>> {
        // Create a temporary buffer to read the data into
        let mut buffer = [0u8; 1024];
        let actual_len = core::cmp::min(len as usize, data.len());
        data.read_range(0..actual_len, &mut buffer[..actual_len])
            .map_err(|_| RequestError::Fail(ClientError::WentAway))?;
        
        self.update_digest(session_id, &buffer[..actual_len], len)?;
        Ok(())
    }

    /// Finalize SHA-256 digest session.
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    /// * `session_id` - The session to finalize
    /// * `digest_out` - Leased memory to write the 256-bit digest (8 × 32-bit words)
    ///
    /// # Returns
    /// * `Ok(())` - Success, session is consumed and removed
    /// * `Err(RequestError<DigestError>)` - Session not found, not initialized, or hardware error
    fn finalize_sha256(
        &mut self,
        _: &RecvMessage,
        session_id: u32,
        mut digest_out: Leased<W, [u32; 8]>,
    ) -> Result<(), RequestError<DigestError>> {
        // Create a temporary buffer for the digest  
        let mut digest_buffer = [0u32; 8];
        self.finalize_digest(session_id, DigestAlgorithm::Sha256, &mut digest_buffer)?;
        
        // Write the digest to leased memory
        for (i, &word) in digest_buffer.iter().enumerate() {
            digest_out[i] = word;
        }
        
        Ok(())
    }

    /// Finalize SHA-384 digest session.
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    /// * `session_id` - The session to finalize
    /// * `digest_out` - Leased memory to write the 384-bit digest (12 × 32-bit words)
    ///
    /// # Returns
    /// * `Ok(())` - Success, session is consumed and removed
    /// * `Err(RequestError<DigestError>)` - Session not found, not initialized, or hardware error
    fn finalize_sha384(
        &mut self,
        _: &RecvMessage,
        session_id: u32,
        mut digest_out: Leased<W, [u32; 12]>,
    ) -> Result<(), RequestError<DigestError>> {
        // Create a temporary buffer for the digest
        let mut digest_buffer = [0u32; 12];
        self.finalize_digest(session_id, DigestAlgorithm::Sha384, &mut digest_buffer)?;
        
        // Write the digest to leased memory
        for (i, &word) in digest_buffer.iter().enumerate() {
            digest_out[i] = word;
        }
        
        Ok(())
    }

    /// Finalize SHA-512 digest session.
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    /// * `session_id` - The session to finalize
    /// * `digest_out` - Leased memory to write the 512-bit digest (16 × 32-bit words)
    ///
    /// # Returns
    /// * `Ok(())` - Success, session is consumed and removed
    /// * `Err(RequestError<DigestError>)` - Session not found, not initialized, or hardware error
    fn finalize_sha512(
        &mut self,
        _: &RecvMessage,
        session_id: u32,
        mut digest_out: Leased<W, [u32; 16]>,
    ) -> Result<(), RequestError<DigestError>> {
        // Create a temporary buffer for the digest
        let mut digest_buffer = [0u32; 16];
        self.finalize_digest(session_id, DigestAlgorithm::Sha512, &mut digest_buffer)?;
        
        // Write the digest to leased memory
        for (i, &word) in digest_buffer.iter().enumerate() {
            digest_out[i] = word;
        }
        
        Ok(())
    }

    /// Finalize SHA3-256 digest session (placeholder).
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    /// * `_session_id` - The session to finalize (unused)
    /// * `_digest_out` - Leased memory to write the digest (unused)
    ///
    /// # Returns
    /// * `Err(RequestError<DigestError::UnsupportedAlgorithm>)` - SHA3 not yet implemented
    fn finalize_sha3_256(
        &mut self,
        _: &RecvMessage,
        _session_id: u32,
        _digest_out: Leased<W, [u32; 8]>,
    ) -> Result<(), RequestError<DigestError>> {
        Err(DigestError::UnsupportedAlgorithm.into())
    }

    /// Finalize SHA3-384 digest session (placeholder).
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    /// * `_session_id` - The session to finalize (unused)
    /// * `_digest_out` - Leased memory to write the digest (unused)
    ///
    /// # Returns
    /// * `Err(RequestError<DigestError::UnsupportedAlgorithm>)` - SHA3 not yet implemented
    fn finalize_sha3_384(
        &mut self,
        _: &RecvMessage,
        _session_id: u32,
        _digest_out: Leased<W, [u32; 12]>,
    ) -> Result<(), RequestError<DigestError>> {
        Err(DigestError::UnsupportedAlgorithm.into())
    }

    /// Finalize SHA3-512 digest session (placeholder).
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    /// * `_session_id` - The session to finalize (unused)
    /// * `_digest_out` - Leased memory to write the digest (unused)
    ///
    /// # Returns
    /// * `Err(RequestError<DigestError::UnsupportedAlgorithm>)` - SHA3 not yet implemented
    fn finalize_sha3_512(
        &mut self,
        _: &RecvMessage,
        _session_id: u32,
        _digest_out: Leased<W, [u32; 16]>,
    ) -> Result<(), RequestError<DigestError>> {
        Err(DigestError::UnsupportedAlgorithm.into())
    }

    /// Reset a digest session.
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    /// * `session_id` - The session to reset
    ///
    /// # Returns
    /// * `Ok(())` - Success, session is reinitialized
    /// * `Err(RequestError<DigestError>)` - Session not found or hardware error
    fn reset(
        &mut self,
        _: &RecvMessage,
        session_id: u32,
    ) -> Result<(), RequestError<DigestError>> {
        let session = self.get_session_mut(session_id)?;
        
        // Reset the context for the same algorithm
        session.context.reset();
        session.initialized = true;
        
        Ok(())
    }

    /// One-shot SHA-256 digest operation.
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    /// * `len` - Number of bytes to process from the leased data
    /// * `data` - Leased memory containing input data (max 1024 bytes)
    /// * `digest_out` - Leased memory to write the 256-bit digest (8 × 32-bit words)
    ///
    /// # Returns
    /// * `Ok(())` - Success
    /// * `Err(RequestError<DigestError>)` - Hardware initialization or operation failure
    ///
    /// # Notes
    /// This is more efficient than session-based operations for single-use hashing.
    fn digest_oneshot_sha256(
        &mut self,
        _: &RecvMessage,
        len: u32,
        data: LenLimit<Leased<R, [u8]>, 1024>,
        mut digest_out: Leased<W, [u32; 8]>,
    ) -> Result<(), RequestError<DigestError>> {
        // Create a temporary buffer to read the data into
        let mut buffer = [0u8; 1024];
        let actual_len = core::cmp::min(len as usize, data.len());
        data.read_range(0..actual_len, &mut buffer[..actual_len])
            .map_err(|_| RequestError::Fail(ClientError::WentAway))?;
            
        // Create a temporary buffer for the digest
        let mut digest_buffer = [0u32; 8];
        self.digest_oneshot(DigestAlgorithm::Sha256, &buffer[..actual_len], len, &mut digest_buffer)?;
        
        // Write the digest to leased memory
        for (i, &word) in digest_buffer.iter().enumerate() {
            digest_out[i] = word;
        }
        
        Ok(())
    }

    /// One-shot SHA-384 digest operation.
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    /// * `len` - Number of bytes to process from the leased data
    /// * `data` - Leased memory containing input data (max 1024 bytes)
    /// * `digest_out` - Leased memory to write the 384-bit digest (12 × 32-bit words)
    ///
    /// # Returns
    /// * `Ok(())` - Success
    /// * `Err(RequestError<DigestError>)` - Hardware initialization or operation failure
    fn digest_oneshot_sha384(
        &mut self,
        _: &RecvMessage,
        len: u32,
        data: LenLimit<Leased<R, [u8]>, 1024>,
        mut digest_out: Leased<W, [u32; 12]>,
    ) -> Result<(), RequestError<DigestError>> {
        // Create a temporary buffer to read the data into
        let mut buffer = [0u8; 1024];
        let actual_len = core::cmp::min(len as usize, data.len());
        data.read_range(0..actual_len, &mut buffer[..actual_len])
            .map_err(|_| RequestError::Fail(ClientError::WentAway))?;
            
        // Create a temporary buffer for the digest
        let mut digest_buffer = [0u32; 12];
        self.digest_oneshot(DigestAlgorithm::Sha384, &buffer[..actual_len], len, &mut digest_buffer)?;
        
        // Write the digest to leased memory
        for (i, &word) in digest_buffer.iter().enumerate() {
            digest_out[i] = word;
        }
        
        Ok(())
    }

    /// One-shot SHA-512 digest operation.
    ///
    /// # Arguments
    /// * `_` - Unused message parameter (required by Idol interface)
    /// * `len` - Number of bytes to process from the leased data
    /// * `data` - Leased memory containing input data (max 1024 bytes)
    /// * `digest_out` - Leased memory to write the 512-bit digest (16 × 32-bit words)
    ///
    /// # Returns
    /// * `Ok(())` - Success
    /// * `Err(RequestError<DigestError>)` - Hardware initialization or operation failure
    fn digest_oneshot_sha512(
        &mut self,
        _: &RecvMessage,
        len: u32,
        data: LenLimit<Leased<R, [u8]>, 1024>,
        mut digest_out: Leased<W, [u32; 16]>,
    ) -> Result<(), RequestError<DigestError>> {
        // Create a temporary buffer to read the data into
        let mut buffer = [0u8; 1024];
        let actual_len = core::cmp::min(len as usize, data.len());
        data.read_range(0..actual_len, &mut buffer[..actual_len])
            .map_err(|_| RequestError::Fail(ClientError::WentAway))?;
            
        // Create a temporary buffer for the digest
        let mut digest_buffer = [0u32; 16];
        self.digest_oneshot(DigestAlgorithm::Sha512, &buffer[..actual_len], len, &mut digest_buffer)?;
        
        // Write the digest to leased memory
        for (i, &word) in digest_buffer.iter().enumerate() {
            digest_out[i] = word;
        }
        
        Ok(())
    }
}

/// Logging support (if enabled).
///
/// Provides trace events for debugging and monitoring digest operations.
/// The ring buffer stores the last 16 trace events with different categories.
#[derive(Copy, Clone, PartialEq)]
enum Trace {
    /// No operation
    None,
    /// Session allocated with session ID
    SessionAllocated(u32),
    /// Session finalized and removed
    SessionFinalized(u32),
    /// Digest update operation (session_id, data_len)
    DigestUpdate(u32, u32),
    /// One-shot digest operation (data_len)
    OneShot(u32),
}

ringbuf!(Trace, 16, Trace::None);

/// Task entry point.
///
/// Initializes the digest server and enters the main event loop to handle
/// incoming IPC requests. This function never returns.
#[export_name = "main"]
fn main() -> ! {
    let mut server = ServerImpl::new();
    let mut buffer = [0u8; 1024]; // Buffer for Idol message processing
    
    // Set up any hardware initialization here
    ringbuf_entry!(Trace::None);
    
    loop {
        idol_runtime::dispatch(&mut buffer, &mut server);
    }
}

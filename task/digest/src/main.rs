// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! # Digest Server Task
//!
//! This task provides a hardware-accelerated cryptographic digest service for the Hubris
//! operating system. It implements a session-based API that allows multiple concurrent
//! hash operations using OpenTitan's HMAC hardware accelerator.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐    IPC     ┌─────────────────┐    HAL     ┌─────────────────┐
//! │   Client Task   │ ────────── │  Digest Server  │ ────────── │ OpenTitan HMAC  │
//! │  (hash-client)  │  (Idol)    │   (this task)   │  (traits)  │   Hardware      │
//! └─────────────────┘            └─────────────────┘            └─────────────────┘
//! ```
//!
//! ## Supported Algorithms
//!
//! - **SHA-256**: 256-bit SHA-2 family hash (8 words output)
//! - **SHA-384**: 384-bit SHA-2 family hash (12 words output)  
//! - **SHA-512**: 512-bit SHA-2 family hash (16 words output)
//!
//! SHA-3 family algorithms are defined in the API but not yet implemented in hardware.
//!
//! ## Session Management
//!
//! The server maintains up to 8 concurrent digest sessions, each with:
//! - Unique session ID for client tracking
//! - Algorithm-specific hardware context
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
//! - Hardware-specific implementations in `openprot_platform_baremetal::opentitan`
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
use openprot_hal_blocking::digest::{DigestInit, DigestOp, Sha2_256, Sha2_384, Sha2_512};
use openprot_platform_baremetal::opentitan::{Hmac, Hasher};
use ringbuf::*;
use userlib::*;

// Import the generated server stub
include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));

/// Maximum number of concurrent digest sessions.
///
/// This limit prevents resource exhaustion and ensures bounded memory usage.
/// Each session maintains hardware context and algorithm state.
const MAX_SESSIONS: usize = 8;

/// Session state for digest operations.  
///
/// Each session represents an active digest computation that can span multiple
/// IPC calls. Sessions track the algorithm type, hardware device instance,
/// and initialization state.
#[derive(Debug)]
struct DigestSession {
    /// The digest algorithm for this session (SHA-256, SHA-384, etc.)
    algorithm: DigestAlgorithm,
    /// Hardware HMAC device instance (None if session is defunct)
    hmac_device: Option<Hmac>,
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
            hmac_device: Some(Hmac::new()),
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
    /// # Type Parameters
    /// * `T` - The digest algorithm implementation from the HAL
    ///
    /// # Arguments
    /// * `algorithm` - The digest algorithm to initialize
    ///
    /// # Returns
    /// * `Ok(session_id)` - Success with the allocated session ID
    /// * `Err(DigestError)` - Hardware initialization failure or resource exhaustion
    fn init_digest<T>(&mut self, algorithm: DigestAlgorithm) -> Result<u32, DigestError> 
    where
        T: DigestInit + DigestOp,
    {
        let session_id = self.allocate_session(algorithm)?;
        let session = self.get_session_mut(session_id)?;

        // Initialize the digest context for the specific algorithm
        T::init(&mut session.context).map_err(DigestError::from)?;
        session.initialized = true;

        Ok(session_id)
    }

    /// Update a digest session with new data.
    ///
    /// # Type Parameters
    /// * `T` - The digest algorithm implementation from the HAL
    ///
    /// # Arguments
    /// * `session_id` - The session to update
    /// * `data` - Leased memory containing input data
    /// * `len` - Number of bytes to process from the leased data
    ///
    /// # Returns
    /// * `Ok(())` - Success
    /// * `Err(DigestError)` - Session not found, not initialized, or hardware error
    fn update_digest<T>(
        &mut self,
        session_id: u32,
        data: &Leased<R, [u8]>,
        len: u32,
    ) -> Result<(), DigestError>
    where
        T: DigestOp,
    {
        let session = self.get_session_mut(session_id)?;
        
        if !session.initialized {
            return Err(DigestError::NotInitialized);
        }

        let data_slice = &data[..len as usize];
        T::update(&mut session.context, data_slice).map_err(DigestError::from)?;

        Ok(())
    }

    /// Finalize a digest session and write the result.
    ///
    /// # Type Parameters
    /// * `T` - The digest algorithm implementation from the HAL
    /// * `N` - The output size in 32-bit words (algorithm-dependent)
    ///
    /// # Arguments
    /// * `session_id` - The session to finalize
    /// * `digest_out` - Leased memory to write the digest result
    ///
    /// # Returns
    /// * `Ok(())` - Success, session is consumed and removed
    /// * `Err(DigestError)` - Session not found, not initialized, or hardware error
    ///
    /// # Notes
    /// The session is automatically removed after successful finalization.
    fn finalize_digest<T, const N: usize>(
        &mut self,
        session_id: u32,
        digest_out: &Leased<W, [u32; N]>,
    ) -> Result<(), DigestError>
    where
        T: DigestOp,
    {
        let session = self.get_session_mut(session_id)?;
        
        if !session.initialized {
            return Err(DigestError::NotInitialized);
        }

        let mut output = [0u32; N];
        T::finalize(&mut session.context, &mut output).map_err(DigestError::from)?;
        
        digest_out.copy_from_slice(&output);

        // Remove the session after finalization
        self.sessions.remove(&session_id);

        Ok(())
    }

    /// Perform a one-shot digest operation.
    ///
    /// # Type Parameters
    /// * `T` - The digest algorithm implementation from the HAL
    /// * `N` - The output size in 32-bit words (algorithm-dependent)
    ///
    /// # Arguments
    /// * `data` - Leased memory containing input data
    /// * `len` - Number of bytes to process from the leased data
    /// * `digest_out` - Leased memory to write the digest result
    ///
    /// # Returns
    /// * `Ok(())` - Success
    /// * `Err(DigestError)` - Hardware initialization or operation failure
    ///
    /// # Notes
    /// This is equivalent to init() + update() + finalize() but more efficient
    /// for single-use operations as it doesn't allocate a session.
    fn digest_oneshot<T, const N: usize>(
        &mut self,
        data: &Leased<R, [u8]>,
        len: u32,
        digest_out: &Leased<W, [u32; N]>,
    ) -> Result<(), DigestError>
    where
        T: DigestInit + DigestOp,
    {
        let mut context = DigestContext::new();
        
        // Initialize
        T::init(&mut context).map_err(DigestError::from)?;
        
        // Update with data
        let data_slice = &data[..len as usize];
        T::update(&mut context, data_slice).map_err(DigestError::from)?;
        
        // Finalize
        let mut output = [0u32; N];
        T::finalize(&mut context, &mut output).map_err(DigestError::from)?;
        
        digest_out.copy_from_slice(&output);
        
        Ok(())
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
        Ok(self.init_digest::<Sha2_256>(DigestAlgorithm::Sha256)?)
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
        Ok(self.init_digest::<Sha2_384>(DigestAlgorithm::Sha384)?)
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
        Ok(self.init_digest::<Sha2_512>(DigestAlgorithm::Sha512)?)
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
        data: Leased<R, [u8], LenLimit<1024>>,
    ) -> Result<(), RequestError<DigestError>> {
        let session = self.sessions.get(&session_id).ok_or(DigestError::InvalidSession)?;
        
        match session.algorithm {
            DigestAlgorithm::Sha256 => {
                self.update_digest::<Sha2_256>(session_id, &data, len)?;
            }
            DigestAlgorithm::Sha384 => {
                self.update_digest::<Sha2_384>(session_id, &data, len)?;
            }
            DigestAlgorithm::Sha512 => {
                self.update_digest::<Sha2_512>(session_id, &data, len)?;
            }
            _ => return Err(DigestError::UnsupportedAlgorithm.into()),
        }
        
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
        digest_out: Leased<W, [u32; 8]>,
    ) -> Result<(), RequestError<DigestError>> {
        self.finalize_digest::<Sha2_256, 8>(session_id, &digest_out)?;
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
        digest_out: Leased<W, [u32; 12]>,
    ) -> Result<(), RequestError<DigestError>> {
        self.finalize_digest::<Sha2_384, 12>(session_id, &digest_out)?;
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
        digest_out: Leased<W, [u32; 16]>,
    ) -> Result<(), RequestError<DigestError>> {
        self.finalize_digest::<Sha2_512, 16>(session_id, &digest_out)?;
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
        
        // Re-initialize the context for the same algorithm
        match session.algorithm {
            DigestAlgorithm::Sha256 => {
                Sha2_256::init(&mut session.context).map_err(DigestError::from)?;
            }
            DigestAlgorithm::Sha384 => {
                Sha2_384::init(&mut session.context).map_err(DigestError::from)?;
            }
            DigestAlgorithm::Sha512 => {
                Sha2_512::init(&mut session.context).map_err(DigestError::from)?;
            }
            _ => return Err(DigestError::UnsupportedAlgorithm.into()),
        }
        
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
        data: Leased<R, [u8], LenLimit<1024>>,
        digest_out: Leased<W, [u32; 8]>,
    ) -> Result<(), RequestError<DigestError>> {
        self.digest_oneshot::<Sha2_256, 8>(&data, len, &digest_out)?;
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
        data: Leased<R, [u8], LenLimit<1024>>,
        digest_out: Leased<W, [u32; 12]>,
    ) -> Result<(), RequestError<DigestError>> {
        self.digest_oneshot::<Sha2_384, 12>(&data, len, &digest_out)?;
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
        data: Leased<R, [u8], LenLimit<1024>>,
        digest_out: Leased<W, [u32; 16]>,
    ) -> Result<(), RequestError<DigestError>> {
        self.digest_oneshot::<Sha2_512, 16>(&data, len, &digest_out)?;
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
    
    // Set up any hardware initialization here
    ringbuf_entry!(Trace::None);
    
    loop {
        idol_runtime::dispatch(&mut server);
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! API crate for the OpenPRoT ECDSA server.
//!
//! This crate provides types and constants for ECDSA-384 cryptographic operations
//! in the OpenPRoT security framework.

#![no_std]

use derive_idol_err::IdolError;
use userlib::{FromPrimitive, sys_send};
pub use userlib::TaskId;

/// Errors that can occur during ECDSA operations
#[derive(
    Copy, Clone, Debug, FromPrimitive, Eq, PartialEq, IdolError, counters::Count, 
    serde::Deserialize, serde::Serialize, hubpack::SerializedSize,
)]
#[repr(u8)]
pub enum EcdsaError {
    /// Invalid key ID provided
    InvalidKeyId = 1,
    
    /// Key not found
    KeyNotFound = 2,
    
    /// Invalid signature format or length
    InvalidSignature = 3,
    
    /// Invalid hash length for the algorithm
    InvalidHashLength = 4,
    
    /// Signature verification failed
    VerificationFailed = 5,
    
    /// Hardware security module error
    HsmError = 6,
    
    /// Buffer too small for the operation
    BufferTooSmall = 7,
    
    /// Cryptographic hardware not available
    HardwareNotAvailable = 8,
    
    /// Key is not suitable for the requested operation
    InvalidKeyType = 9,
    
    /// Internal error in cryptographic implementation
    InternalError = 10,

    #[idol(server_death)]
    ServerRestarted,
}

impl From<idol_runtime::ServerDeath> for EcdsaError {
    fn from(_: idol_runtime::ServerDeath) -> Self {
        Self::ServerRestarted
    }
}

include!(concat!(env!("OUT_DIR"), "/client_stub.rs"));
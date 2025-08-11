// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! API crate for Digest server.

#![no_std]

use derive_idol_err::IdolError;
use userlib::{sys_send, FromPrimitive};

/// Digest algorithm sizes in 32-bit words
pub const SHA256_WORDS: usize = 8;   // 256 bits / 32 bits = 8 words
pub const SHA384_WORDS: usize = 12;  // 384 bits / 32 bits = 12 words  
pub const SHA512_WORDS: usize = 16;  // 512 bits / 32 bits = 16 words
pub const SHA3_256_WORDS: usize = 8; // 256 bits / 32 bits = 8 words
pub const SHA3_384_WORDS: usize = 12; // 384 bits / 32 bits = 12 words
pub const SHA3_512_WORDS: usize = 16; // 512 bits / 32 bits = 16 words

/// Digest algorithm identifiers
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    FromPrimitive,
)]
#[repr(u32)]
pub enum DigestAlgorithm {
    Sha256 = 0,
    Sha384 = 1,
    Sha512 = 2,
    Sha3_256 = 3,
    Sha3_384 = 4,
    Sha3_512 = 5,
}

/// A generic digest output container that mirrors the HAL trait.
///
/// This structure represents the output of a cryptographic digest operation.
/// It uses a const generic parameter `N` to specify the number of 32-bit words
/// in the digest output, allowing it to accommodate different digest sizes.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
#[repr(C)]
pub struct DigestOutput<const N: usize> {
    /// The digest value as an array of 32-bit words
    pub value: [u32; N],
}

/// Type aliases for specific digest outputs
pub type Sha256Digest = DigestOutput<SHA256_WORDS>;
pub type Sha384Digest = DigestOutput<SHA384_WORDS>;
pub type Sha512Digest = DigestOutput<SHA512_WORDS>;
pub type Sha3_256Digest = DigestOutput<SHA3_256_WORDS>;
pub type Sha3_384Digest = DigestOutput<SHA3_384_WORDS>;
pub type Sha3_512Digest = DigestOutput<SHA3_512_WORDS>;

/// Errors that can be produced from the digest server API.
///
/// This enumeration mirrors the ErrorKind from the HAL trait but is adapted
/// for use in the Hubris IPC context.
#[derive(
    Copy, Clone, Debug, FromPrimitive, Eq, PartialEq, IdolError, counters::Count,
)]
#[repr(u32)]
pub enum DigestError {
    /// The input data length is not valid for the hash function.
    InvalidInputLength = 1,
    
    /// The specified hash algorithm is not supported by the hardware or software implementation.
    UnsupportedAlgorithm = 2,
    
    /// Failed to allocate memory for the hash computation.
    MemoryAllocationFailure = 3,
    
    /// Failed to initialize the hash computation context.
    InitializationError = 4,
    
    /// Error occurred while updating the hash computation with new data.
    UpdateError = 5,
    
    /// Error occurred while finalizing the hash computation.
    FinalizationError = 6,
    
    /// The hardware accelerator is busy and cannot process the hash computation.
    Busy = 7,
    
    /// General hardware failure during hash computation.
    HardwareFailure = 8,
    
    /// The specified output size is not valid for the hash function.
    InvalidOutputSize = 9,
    
    /// Insufficient permissions to access the hardware or perform the hash computation.
    PermissionDenied = 10,
    
    /// The hash computation context has not been initialized.
    NotInitialized = 11,
    
    /// Invalid session ID provided.
    InvalidSession = 12,
    
    /// Maximum number of concurrent sessions exceeded.
    TooManySessions = 13,

    /// Server restarted
    #[idol(server_death)]
    ServerRestarted = 100,
}

/// Helper trait to convert digest outputs to byte arrays
pub trait DigestAsBytes {
    /// Convert the digest to a byte array
    fn as_bytes(&self) -> &[u8];
}

impl<const N: usize> DigestAsBytes for DigestOutput<N> {
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: [u32; N] has the same layout as [u8; N*4] when using zerocopy
        unsafe {
            core::slice::from_raw_parts(
                self.value.as_ptr() as *const u8,
                N * 4,
            )
        }
    }
}

// Include the generated client stub
include!(concat!(env!("OUT_DIR"), "/client_stub.rs"));

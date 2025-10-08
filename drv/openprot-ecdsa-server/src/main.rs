// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! OpenPRoT ECDSA Server
//!
//! This server provides ECDSA-384 cryptographic operations for the OpenPRoT
//! security framework, including digital signature generation and verification
//! using P-384 elliptic curve cryptography.
//!
//! # Overview
//!
//! The server supports two main operational modes based on compile-time features:
//!
//! ## Hardware Mode (`ast1060-verifier` feature)
//! - **AST1060 Hardware**: Uses dedicated cryptographic processor
//! - **Verification Only**: Hardware-accelerated signature verification
//! - **Production Ready**: Optimized for security and performance
//! - **Server Type**: `VerifierOnlyServer<AspeedEcdsa<SimpleDelay>>`
//!
//! ## Development Mode (default)
//! - **Placeholder Implementation**: Software-based testing implementations
//! - **Full Functionality**: Both signing and verification (non-cryptographic)
//! - **Development/Testing**: Perfect for integration testing and development
//! - **Server Type**: `FullServer<PlaceholderSigner, PlaceholderVerifier>`
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  OpenPRoT ECDSA Server                      │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Feature: ast1060-verifier    │  Default (no features)      │
//! │  ┌─────────────────────────┐  │  ┌─────────────────────────┐ │
//! │  │  VerifierOnlyServer     │  │  │     FullServer          │ │
//! │  │  ├─ AspeedEcdsa (HW)    │  │  │  ├─ PlaceholderSigner   │ │
//! │  │  └─ No Signing          │  │  │  └─ PlaceholderVerifier │ │
//! │  └─────────────────────────┘  │  └─────────────────────────┘ │
//! ├─────────────────────────────────────────────────────────────┤
//! │              idol_runtime::dispatch Message Loop             │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    OpenPRoT HAL Blocking                     │
//! │              P384 • EcdsaVerify • EcdsaSign                  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Supported Operations
//!
//! | Operation          | Hardware Mode | Development Mode |
//! |--------------------|---------------|------------------|
//! | `ecdsa384_verify`  | ✅ Hardware   | ✅ Placeholder   |
//! | `ecdsa384_sign`    | ❌ Not Available | ✅ Placeholder |
//!
//! # Key Features
//!
//! - **Zero-Copy Operations**: Uses `zerocopy` crate for efficient serialization
//! - **Memory Safety**: Proper error handling with no panics in embedded environment
//! - **Hardware Abstraction**: Clean separation between hardware and software implementations
//! - **Feature-Gated Compilation**: Conditional compilation based on target hardware
//! - **Comprehensive Documentation**: Full rustdoc coverage for all public APIs
//!
//! # Usage Examples
//!
//! ## Building for Hardware
//! ```bash
//! cargo xtask dist app/ast1060-ecdsa-test/app.toml --features ast1060-verifier
//! ```
//!
//! ## Building for Development
//! ```bash
//! cargo xtask dist app/ast1060-ecdsa-test/app.toml
//! ```
//!
//! # Dependencies
//!
//! - **openprot-hal-blocking**: Core ECDSA traits and P384 curve support
//! - **zerocopy**: Zero-copy serialization for performance
//! - **idol-runtime**: Message dispatching and service framework
//! - **drv-ast1060-ecdsa**: Hardware driver (when `ast1060-verifier` feature enabled)
//! - **ast1060-pac**: Hardware register access (when `ast1060-verifier` feature enabled)
//!
//! # Security Considerations
//!
//! - Hardware mode provides cryptographically secure operations
//! - Development mode uses placeholder implementations (not cryptographically secure)
//! - All input validation follows OpenPRoT security requirements
//! - Memory operations use safe abstractions to prevent vulnerabilities

#![no_std]
#![no_main]

use crate::placeholder::P384PrivateKey;
use openprot_hal_blocking::digest::Digest;
use openprot_hal_blocking::ecdsa::{
    EcdsaSign, EcdsaVerify, P384PublicKey, P384Signature, P384,
};
use zerocopy::IntoBytes;

use drv_openprot_ecdsa_api::EcdsaError;
use idol_runtime::{Leased, LenLimit, NotificationHandler, RequestError, R, W};
use userlib::RecvMessage;

/// Performs ECDSA-384 signature verification using P-384 elliptic curve cryptography.
///
/// This function provides the core verification logic that can be shared between
/// different server implementations (`VerifierOnlyServer` and `FullServer`).
///
/// # Arguments
///
/// * `verifier` - A mutable reference to any type implementing `EcdsaVerify<P384>`
/// * `hash` - A 48-byte SHA-384 hash digest to verify against
/// * `signature` - A 96-byte ECDSA signature (48 bytes r + 48 bytes s)
/// * `public_key` - A 96-byte P-384 public key (48 bytes x + 48 bytes y coordinates)
///
/// # Returns
///
/// * `Ok(true)` - Signature verification succeeded
/// * `Ok(false)` - Signature verification failed (invalid signature)
/// * `Err(RequestError<EcdsaError>)` - Parameter validation or processing error
///
/// # Errors
///
/// Returns `EcdsaError::InvalidParameters` if:
/// - Hash length is not exactly 48 bytes (SHA-384 requirement)
/// - Signature length is not exactly 96 bytes (P-384 requirement)  
/// - Public key length is not exactly 96 bytes (P-384 uncompressed format)
/// - Input data cannot be read from leased memory
/// - Public key or signature cannot be deserialized using zerocopy
///
/// # Implementation Details
///
/// 1. **Input Validation**: Verifies all input lengths match P-384 requirements
/// 2. **Memory Safety**: Uses leased memory reads with proper error handling
/// 3. **Zero-Copy Deserialization**: Uses zerocopy traits for efficient parsing
/// 4. **Digest Conversion**: Converts SHA-384 bytes to P-384 digest format
/// 5. **Hardware Dispatch**: Delegates to the provided verifier implementation
///
/// The function is designed to work with both hardware verifiers (AST1060) and
/// placeholder implementations for testing and development.
fn verify_ecdsa384<V>(
    verifier: &mut V,
    hash: LenLimit<Leased<R, [u8]>, 48>,
    signature: LenLimit<Leased<R, [u8]>, 96>,
    public_key: LenLimit<Leased<R, [u8]>, 96>,
) -> Result<bool, RequestError<EcdsaError>>
where
    V: EcdsaVerify<P384, PublicKey = P384PublicKey, Signature = P384Signature>,
{
    // Validate input lengths
    if hash.len() != 48 || signature.len() != 96 || public_key.len() != 96 {
        return Err(RequestError::Runtime(EcdsaError::InvalidParameters));
    }

    // Read inputs from leases
    let mut hash_buf = [0u8; 48];
    let mut pubkey_buf = [0u8; 96];
    let mut sig_buf = [0u8; 96];

    hash.read_range(0..48, &mut hash_buf)
        .map_err(|_| RequestError::Runtime(EcdsaError::InvalidParameters))?;
    public_key
        .read_range(0..96, &mut pubkey_buf)
        .map_err(|_| RequestError::Runtime(EcdsaError::InvalidParameters))?;
    signature
        .read_range(0..96, &mut sig_buf)
        .map_err(|_| RequestError::Runtime(EcdsaError::InvalidParameters))?;

    // Convert hash to digest format
    let mut digest_words = [0u32; 12];
    for (i, chunk) in hash_buf.chunks_exact(4).enumerate() {
        digest_words[i] =
            u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    // Deserialize public key and signature
    let pubkey: P384PublicKey =
        match zerocopy::FromBytes::read_from_bytes(&pubkey_buf[..]) {
            Ok(key) => key,
            Err(_) => {
                return Err(RequestError::Runtime(
                    EcdsaError::InvalidParameters,
                ))
            }
        };

    let signature_obj: P384Signature =
        match zerocopy::FromBytes::read_from_bytes(&sig_buf[..]) {
            Ok(sig) => sig,
            Err(_) => {
                return Err(RequestError::Runtime(
                    EcdsaError::InvalidParameters,
                ))
            }
        };

    // Dispatch to the verifier
    let digest = Digest::new(digest_words);
    match verifier.verify(&pubkey, digest, &signature_obj) {
        Ok(()) => Ok(true),  // Verification succeeded
        Err(_) => Ok(false), // Verification failed
    }
}

/// Placeholder implementations for testing and development
mod placeholder;

/// A verification-only ECDSA server implementation.
///
/// This server provides ECDSA-384 signature verification capabilities using P-384
/// elliptic curve cryptography, but does not support signature generation operations.
/// It's designed for use cases where only verification is needed, such as:
///
/// - Certificate validation
/// - Firmware signature verification  
/// - Authentication token validation
/// - Read-only cryptographic operations
///
/// # Generic Parameters
///
/// * `V` - Any type implementing `EcdsaVerify<P384>` for signature verification
///
/// # Supported Operations
///
/// - ✅ `ecdsa384_verify()` - Verifies P-384 ECDSA signatures
/// - ❌ `ecdsa384_sign()` - Returns `HardwareNotAvailable` error
///
struct VerifierOnlyServer<V>
where
    V: EcdsaVerify<P384, PublicKey = P384PublicKey, Signature = P384Signature>,
{
    verifier: V,
}

struct FullServer<S, V>
where
    S: EcdsaSign<P384, PrivateKey = P384PrivateKey, Signature = P384Signature>,
    V: EcdsaVerify<P384, PublicKey = P384PublicKey, Signature = P384Signature>,
{
    signer: S,
    verifier: V,
}

impl<V> VerifierOnlyServer<V>
where
    V: EcdsaVerify<P384, PublicKey = P384PublicKey, Signature = P384Signature>,
{
    #[allow(dead_code)] 
    fn new(verifier: V) -> Self {
        Self { verifier }
    }
}

impl<S, V> FullServer<S, V>
where
    S: EcdsaSign<P384, PrivateKey = P384PrivateKey, Signature = P384Signature>,
    V: EcdsaVerify<P384, PublicKey = P384PublicKey, Signature = P384Signature>,
{
    #[allow(dead_code)] 
    fn new(signer: S, verifier: V) -> Self {
        Self { signer, verifier }
    }
}

impl<V> idl::InOrderOpenPRoTEcdsaImpl for VerifierOnlyServer<V>
where
    V: EcdsaVerify<P384, PublicKey = P384PublicKey, Signature = P384Signature>,
{
    fn ecdsa384_sign(
        &mut self,
        _msg: &RecvMessage,
        _key_id: u32,
        _hash: LenLimit<Leased<R, [u8]>, 48>,
        _signature: LenLimit<Leased<W, [u8]>, 96>,
    ) -> Result<(), RequestError<EcdsaError>> {
        // This server doesn't support signing
        Err(RequestError::Runtime(EcdsaError::HardwareNotAvailable))
    }

    fn ecdsa384_verify(
        &mut self,
        _msg: &RecvMessage,
        hash: LenLimit<Leased<R, [u8]>, 48>,
        signature: LenLimit<Leased<R, [u8]>, 96>,
        public_key: LenLimit<Leased<R, [u8]>, 96>,
    ) -> Result<bool, RequestError<EcdsaError>> {
        verify_ecdsa384(&mut self.verifier, hash, signature, public_key)
    }
}

impl<V> NotificationHandler for VerifierOnlyServer<V>
where
    V: EcdsaVerify<P384, PublicKey = P384PublicKey, Signature = P384Signature>,
{
    fn current_notification_mask(&self) -> u32 {
        // No notifications needed for now
        0
    }

    fn handle_notification(&mut self, _bits: u32) {
        // No notifications to handle
    }
}

// Implementation for FullServer with both signing and verification
impl<S, V> idl::InOrderOpenPRoTEcdsaImpl for FullServer<S, V>
where
    S: EcdsaSign<P384, PrivateKey = P384PrivateKey, Signature = P384Signature>,
    V: EcdsaVerify<P384, PublicKey = P384PublicKey, Signature = P384Signature>,
{
    fn ecdsa384_sign(
        &mut self,
        _msg: &RecvMessage,
        _key_id: u32,
        hash: LenLimit<Leased<R, [u8]>, 48>,
        signature: LenLimit<Leased<W, [u8]>, 96>,
    ) -> Result<(), RequestError<EcdsaError>> {
        // Validate hash parameter - must be exactly 48 bytes for SHA-384
        if hash.len() != 48 {
            return Err(RequestError::Runtime(EcdsaError::InvalidParameters));
        }

        // Validate signature output buffer - must be exactly 96 bytes for P384
        if signature.len() != 96 {
            return Err(RequestError::Runtime(EcdsaError::InvalidParameters));
        }

        let mut hash_buf = [0u8; 48];
        hash.read_range(0..48, &mut hash_buf).map_err(|_| {
            RequestError::Runtime(EcdsaError::InvalidParameters)
        })?;

        // Convert hash to P384 digest format (48 bytes = 12 u32 words for SHA-384)
        let mut digest_words = [0u32; 12];
        for (i, chunk) in hash_buf.chunks_exact(4).enumerate() {
            digest_words[i] =
                u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let digest = Digest::new(digest_words);

        // TODO: In a real implementation, this would:
        // 1. Load the private key for key_id from secure storage
        // 2. Validate the private key is suitable for signing
        // 3. Use a proper hardware RNG
        // 4. Dispatch to the signer with proper RNG

        // For now, use placeholder signer directly
        let private_key = P384PrivateKey::new([1u8; 48]); // Placeholder key

        // TODO: Use actual signer when RNG issues are resolved
        // match self.signer.sign(&private_key, digest, &mut rng) {
        //     Ok(sig) => { /* serialize sig to signature lease */ }
        //     Err(_) => return Err(RequestError::Runtime(EcdsaError::InternalError))
        // }

        // For now, create placeholder signature directly
        let placeholder_r = [0u8; 48];
        let mut placeholder_s = [1u8; 48];
        placeholder_s[47] = 42; // Make it slightly non-trivial

        let signature_obj = P384Signature::new(placeholder_r, placeholder_s);

        // Use zero-copy serialization
        let signature_bytes = signature_obj.as_bytes();

        signature
            .write_range(0..96, signature_bytes)
            .map_err(|_| RequestError::Runtime(EcdsaError::InternalError))?;

        Ok(())
    }

    fn ecdsa384_verify(
        &mut self,
        _msg: &RecvMessage,
        hash: LenLimit<Leased<R, [u8]>, 48>,
        signature: LenLimit<Leased<R, [u8]>, 96>,
        public_key: LenLimit<Leased<R, [u8]>, 96>,
    ) -> Result<bool, RequestError<EcdsaError>> {
        verify_ecdsa384(&mut self.verifier, hash, signature, public_key)
    }
}

impl<S, V> NotificationHandler for FullServer<S, V>
where
    S: EcdsaSign<P384, PrivateKey = P384PrivateKey, Signature = P384Signature>,
    V: EcdsaVerify<P384, PublicKey = P384PublicKey, Signature = P384Signature>,
{
    fn current_notification_mask(&self) -> u32 {
        0
    }

    fn handle_notification(&mut self, _bits: u32) {
        // No notifications to handle
    }
}

/// AST1060 hardware backend implementation for ECDSA operations.
///
/// This module provides hardware-specific implementations for the AST1060
/// cryptographic processor, including hardware initialization and delay
/// implementations required for the ECDSA verification operations.
///
/// # Features
///
/// This module is only available when the `ast1060-verifier` feature is enabled:
///
/// ```toml
/// [features]
/// ast1060-verifier = ["drv-ast1060-ecdsa", "ast1060-pac", "embedded-hal-1"]
/// ```
///
/// # Hardware Requirements
///
/// - AST1060 cryptographic processor
/// - Proper peripheral access and initialization
/// - Hardware delay implementation for timing-sensitive operations
#[cfg(feature = "ast1060-verifier")]
mod ast1060_backend {
    use ast1060_pac as device;
    use drv_ast1060_ecdsa::AspeedEcdsa;
    use embedded_hal_1::delay::DelayNs;

    /// Simple delay implementation using busy waiting for AST1060 operations.
    ///
    /// This provides the timing delays required by the AST1060 hardware during
    /// ECDSA operations. It uses busy waiting (spin loops) which is appropriate
    /// for embedded systems where precise timing is more important than CPU efficiency.
    ///
    /// # Implementation Notes
    ///
    /// - Uses `core::hint::spin_loop()` for efficient busy waiting
    /// - Approximate conversion from nanoseconds to loop iterations
    /// - Suitable for embedded bare-metal environments
    /// - No dependency on system timers or interrupts
    pub struct SimpleDelay;

    impl DelayNs for SimpleDelay {
        /// Delays execution for the specified number of nanoseconds.
        ///
        /// # Arguments
        ///
        /// * `ns` - The number of nanoseconds to delay
        ///
        /// # Implementation
        ///
        /// Converts nanoseconds to approximate loop iterations and performs
        /// busy waiting using `core::hint::spin_loop()` for optimal performance.
        fn delay_ns(&mut self, ns: u32) {
            // Convert nanoseconds to a reasonable loop count
            // This is a very rough approximation for busy waiting
            let loops = ns / 10;
            for _ in 0..loops {
                core::hint::spin_loop();
            }
        }
    }

    /// Creates a new AST1060 ECDSA implementation with proper hardware initialization.
    ///
    /// This function performs the necessary setup to create a working ECDSA verifier
    /// using the AST1060 hardware cryptographic processor.
    ///
    /// # Returns
    ///
    /// A configured `AspeedEcdsa<SimpleDelay>` instance ready for ECDSA verification operations.
    ///
    /// # Safety
    ///
    /// This function uses `unsafe` to steal peripheral access, following the same
    /// pattern as other AST1060 drivers in the system. The caller must ensure:
    /// - No other code is accessing the same peripherals
    /// - Proper system initialization has occurred
    /// - Hardware is in a valid state for ECDSA operations
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[cfg(feature = "ast1060-verifier")]
    /// # {
    /// let ecdsa_verifier = ast1060_backend::create_ecdsa_impl();
    /// let server = VerifierOnlyServer::new(ecdsa_verifier);
    /// # }
    /// ```
    pub fn create_ecdsa_impl() -> AspeedEcdsa<SimpleDelay> {
        // Use steal() to access peripherals like ast1060-uart does
        let peripherals = unsafe { ast1060_pac::Peripherals::steal() };
        let secure = peripherals.secure;

        let delay = SimpleDelay;
        AspeedEcdsa::new(secure, delay)
    }
}

/// Main entry point for the OpenPRoT ECDSA Server.
///
/// This function initializes and runs the appropriate ECDSA server implementation
/// based on compile-time feature flags. It provides two main configurations:
///
/// # Hardware Configuration (`ast1060-verifier` feature enabled)
///
/// When built with the `ast1060-verifier` feature, this creates a verification-only
/// server using the AST1060 hardware cryptographic processor:
///
/// - **Hardware Backend**: AST1060 cryptographic processor
/// - **Capabilities**: ECDSA-384 signature verification only
/// - **Performance**: Hardware-accelerated cryptographic operations
/// - **Use Case**: Production environments requiring fast, secure verification
///
/// # Placeholder Configuration (default)
///
/// When built without hardware features, this creates a full-featured server
/// using placeholder implementations for both signing and verification:
///
/// - **Software Backend**: Placeholder implementations for testing
/// - **Capabilities**: Both ECDSA-384 signing and verification (non-cryptographic)
/// - **Performance**: Fast placeholder operations for development
/// - **Use Case**: Development, testing, and integration scenarios
///
/// # Server Lifecycle
///
/// 1. **Initialization**: Creates appropriate verifier/signer implementations
/// 2. **Server Creation**: Instantiates the correct server type
/// 3. **Service Loop**: Runs an infinite loop processing incoming requests
/// 4. **Request Dispatch**: Uses `idol_runtime::dispatch` for message handling
///
/// # Error Handling
///
/// The server is designed to never return from the main function. All errors
/// are handled within the request processing loop and returned as appropriate
/// error responses to clients.
#[export_name = "main"]
fn main() -> ! {
    #[cfg(feature = "ast1060-verifier")]
    {
        // Use AST1060 hardware verifier only (no signing capability)
        let verifier = ast1060_backend::create_ecdsa_impl();

        let mut server = VerifierOnlyServer::new(verifier);

        let mut incoming = [0u8; idl::INCOMING_SIZE];
        loop {
            idol_runtime::dispatch(&mut incoming, &mut server);
        }
    }

    #[cfg(not(feature = "ast1060-verifier"))]
    {
        let signer = crate::placeholder::PlaceholderSigner;
        let verifier = crate::placeholder::PlaceholderVerifier;
        let mut server = FullServer::new(signer, verifier);

        let mut incoming = [0u8; idl::INCOMING_SIZE];
        loop {
            idol_runtime::dispatch(&mut incoming, &mut server);
        }
    }
}

// Include the generated server stub
mod idl {
    use super::EcdsaError;

    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}

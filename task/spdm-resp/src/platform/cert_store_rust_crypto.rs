//! Certificate store platform implementation for SPDM
//!
//! This module provides a demonstration certificate store implementation that supports
//! ECDSA P-384 signing operations for SPDM (Security Protocol and Data Model) operations.
//!
//! # Features
//!
//! - ECDSA P-384 digital signature generation
//! - Demo certificate chain management
//! - Cryptographic key management using RustCrypto libraries
//!
//! # Security Notice
//!
//! This implementation uses fixed demo keys and is intended for demonstration and
//! development purposes only. Do not use in production environments without replacing
//! the key generation and certificate management with secure implementations.

use spdm_lib::cert_store::{CertStoreError, SpdmCertStore};
use spdm_lib::protocol::certs::{CertificateInfo, KeyUsageMask};
use spdm_lib::protocol::AsymAlgo;
use spdm_lib::cert_store::CertStoreResult;

use ecdsa::elliptic_curve::generic_array::GenericArray;
use ecdsa::signature::Signer;
use ecdsa::{Signature, SigningKey};
use p384::NistP384;

use sha2::Digest;
use sha2::Sha384;

use crate::platform::certs::STATIC_ROOT_CA_CERT;

// Static certificate chain buffer to avoid stack allocation
static mut DEMO_CERT_CHAIN: [u8; DemoCertStore::MAX_CERT_CHAIN_SIZE] = [0u8; DemoCertStore::MAX_CERT_CHAIN_SIZE];
static mut DEMO_CERT_CHAIN_LEN: usize = 0;
/// Demonstration certificate store implementation for SPDM operations.
///
/// This certificate store provides basic SPDM certificate management and ECDSA P-384
/// signing capabilities. It maintains a single signing key for demonstration purposes.
///
/// # Examples
///
/// ```rust
/// let cert_store = DemoCertStore::new();
/// assert_eq!(cert_store.slot_count(), 1);
/// assert!(cert_store.is_provisioned(0));
/// ```
///
/// # Security
///
/// This implementation uses fixed demo cryptographic material and should only be
/// used for development and testing. Production deployments require secure key
/// generation and certificate provisioning.
pub struct DemoCertStore {
    /// ECDSA P-384 signing key for digital signature operations
    signing_key: Option<SigningKey<NistP384>>,
}

impl DemoCertStore {
// Recommended limits
    const MAX_CERT_CHAIN_SIZE: usize = 16_384; // 16 KB
    const MAX_CERT_COUNT: usize = 10;          // Max certificates in chain
    const MAX_SINGLE_CERT_SIZE: usize = 4_096; // 4 KB per certificate    
    /// Creates a new demonstration certificate store.
    ///
    /// This initializes the certificate store with a demo ECDSA P-384 signing key.
    /// The key is generated from fixed demo material and should not be used in
    /// production environments.
    ///
    /// # Returns
    ///
    /// A new `DemoCertStore` instance ready for SPDM operations.
    pub fn new() -> Self {
        Self {
            signing_key: Self::generate_demo_key(),
        }
    }

    /// Generates a demonstration ECDSA P-384 signing key.
    ///
    /// # Security Warning
    ///
    /// This method uses fixed key material for demonstration purposes only.
    /// In production, keys should be:
    /// - Generated using cryptographically secure random number generators
    /// - Stored in secure hardware (HSM, TPM, secure enclave)
    /// - Never hardcoded in source code
    ///
    /// # Returns
    ///
    /// An optional signing key. Returns `None` if key generation fails.
    fn generate_demo_key() -> Option<SigningKey<NistP384>> {
        // In a real implementation, this would load a persistent key
        // For demo purposes, we'll use a fixed key derived from a known value

        // Demo key material (32 bytes) - DO NOT use in production!
        let demo_key_bytes: [u8; 48] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
            0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
            0x2d, 0x2e, 0x2f, 0x30,
        ];

        SigningKey::from_bytes(&GenericArray::from_slice(&demo_key_bytes)).ok()
    }
}

impl SpdmCertStore for DemoCertStore {
    fn key_pair_id(&self, slot_id: u8) -> Option<u8> {
        if slot_id == 0 { Some(1) } else { None }
    }
    /// Returns the number of certificate slots available.
    ///
    /// This demo implementation provides a single certificate slot.
    ///
    /// # Returns
    ///
    /// The number of available certificate slots (always 1 for demo).
    fn slot_count(&self) -> u8 {
        1
    }

    /// Checks if a certificate slot is provisioned with a valid certificate.
    ///
    /// # Parameters
    ///
    /// * `_slot` - The certificate slot number to check
    ///
    /// # Returns
    ///
    /// `true` if the slot is provisioned, `false` otherwise.
    /// This demo implementation always returns `true` for slot 0.
    fn is_provisioned(&self, _slot: u8) -> bool {
        true
    }

    /// Returns the length of the certificate chain for the specified algorithm and slot.
    ///
    /// # Parameters
    ///
    /// * `_algo` - The asymmetric algorithm type
    /// * `_slot` - The certificate slot number
    ///
    /// # Returns
    ///
    /// The certificate chain length in bytes, or an error if the operation fails.
    /// This demo implementation returns 0 (no certificate chain data).
    fn cert_chain_len(
        &mut self,
        _algo: AsymAlgo,
        _slot: u8,
    ) -> Result<usize, CertStoreError> {
    // SAFETY: Only safe if single-threaded or otherwise synchronized
    unsafe { Ok(DEMO_CERT_CHAIN_LEN) }
    }

    /// Retrieves certificate chain data from the specified slot.
    ///
    /// # Parameters
    ///
    /// * `_slot` - The certificate slot number
    /// * `_algo` - The asymmetric algorithm type
    /// * `_offset` - Byte offset within the certificate chain
    /// * `_out` - Output buffer for certificate data
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or an error if the operation fails.
    /// This demo implementation returns 0 (no certificate data).
    fn get_cert_chain<'a>(
        &mut self,
        slot_id: u8,
        _asym_algo: AsymAlgo,
        offset: usize,
        cert_portion: &'a mut [u8],
    ) -> CertStoreResult<usize> {
        if slot_id != 0 {
            return Err(CertStoreError::InvalidSlotId);
        }
        // SAFETY: Only safe if single-threaded or otherwise synchronized
        unsafe {
            if offset >= DEMO_CERT_CHAIN_LEN {
                return Ok(0);
            }
            let remaining = DEMO_CERT_CHAIN_LEN - offset;
            let copy_len = remaining.min(cert_portion.len());
            cert_portion[..copy_len]
                .copy_from_slice(&DEMO_CERT_CHAIN[offset..offset + copy_len]);
            Ok(copy_len)
        }
    }

    /// Retrieves the root certificate hash for the specified slot and algorithm.
    ///
    /// # Parameters
    ///
    /// * `slot` - The certificate slot number
    /// * `_algo` - The asymmetric algorithm type
    /// * `cert_hash` - Output buffer for the 48-byte SHA-384 hash
    ///
    /// # Returns
    ///
    /// `Ok(())` if successful, or a `CertStoreError` if the operation fails.
    /// This demo implementation does not populate the hash (leaves buffer unchanged).
    fn root_cert_hash(
        &mut self,
        slot: u8,
        _algo: AsymAlgo,
        cert_hash: &mut [u8; 48],
    ) -> Result<(), CertStoreError> {
        if slot != 0 {
            return Err(CertStoreError::InvalidSlotId);
        }

        // Calculate proper SHA-384 hash of the root certificate
        let mut hasher = Sha384::new();
        hasher.update(STATIC_ROOT_CA_CERT);
        let hash_result = hasher.finalize();
        cert_hash.copy_from_slice(&hash_result);
        Ok(())
    }

    /// Signs a hash using the private key from the specified slot.
    ///
    /// This method performs ECDSA P-384 signing on the provided hash using the
    /// demo signing key. The signature is returned in the output buffer.
    ///
    /// # Parameters
    ///
    /// * `_slot` - The certificate slot number (ignored in demo)
    /// * `hash` - The 48-byte hash to sign (typically SHA-384)
    /// * `out` - Output buffer for the 96-byte ECDSA P-384 signature (48 bytes r + 48 bytes s)
    ///
    /// # Returns
    ///
    /// `Ok(())` if signing succeeds, or `CertStoreError::PlatformError` if:
    /// - No signing key is available
    /// - The signing operation fails
    /// - The signature doesn't fit in the output buffer
    ///
    /// # Security
    ///
    /// This demo implementation uses a fixed signing key. Production implementations
    /// should use securely stored private keys and proper key management.
    fn sign_hash(
        &self,
        _slot: u8,
        hash: &[u8; 48],
        out: &mut [u8; 96],
    ) -> Result<(), CertStoreError> {
        // Use ECDSA P-384 signing
        if let Some(signing_key) = &self.signing_key {
            // Sign the hash
            let signature: Signature<NistP384> = signing_key
                .try_sign(hash)
                .map_err(|_| CertStoreError::PlatformError)?;

            // Convert signature to bytes (96 bytes for P-384: 48 bytes r + 48 bytes s)
            let sig_bytes = signature.to_bytes();

            if sig_bytes.len() <= out.len() {
                out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
                // Zero-fill any remaining bytes
                if sig_bytes.len() < out.len() {
                    out[sig_bytes.len()..].fill(0);
                }
                Ok(())
            } else {
                Err(CertStoreError::BufferTooSmall)
            }
        } else {
            Err(CertStoreError::PlatformError)
        }
    }


    /// Returns certificate information for the specified slot.
    ///
    /// # Parameters
    ///
    /// * `_slot` - The certificate slot number
    ///
    /// # Returns
    ///
    /// Optional certificate information. This demo implementation returns `None`
    /// indicating no certificate information is available.
    fn cert_info(&self, slot: u8) -> Option<CertificateInfo> {
        // Only slot 0 is provisioned
        if slot != 0 {
            return None;
        }
        let mut cert_info = CertificateInfo(0);
        cert_info.set_cert_model(1);
        Some(cert_info)
    }

    /// Returns the key usage mask for the specified slot.
    ///
    /// The key usage mask indicates what cryptographic operations the key can perform
    /// (e.g., digital signature, key encipherment, etc.).
    ///
    /// # Parameters
    ///
    /// * `_slot` - The certificate slot number
    ///
    /// # Returns
    ///
    /// indicating no key usage restrictions are specified.
    fn key_usage_mask(&self, slot_id: u8) -> Option<KeyUsageMask> {
        if slot_id != 0 {
            return None;
        }

        let mut key_usage = KeyUsageMask::default();
        key_usage.set_challenge_usage(1);
        key_usage.set_measurement_usage(1);
        Some(key_usage)
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! OpenPRoT ECDSA Server
//!
//! This server provides ECDSA-384 cryptographic operations for the OpenPRoT
//! security framework, including digital signature generation and verification
//! using P-384 elliptic curve cryptography.

#![no_std]
#![no_main]

 use openprot_hal_blocking::ecdsa::{EcdsaVerify, ErrorType, EcdsaSign, PrivateKey};
 use openprot_hal_blocking::digest::DigestAlgorithm;
 use zeroize::{Zeroize, ZeroizeOnDrop};

use openprot_hal_blocking::ecdsa::{P384, PublicKey, SerializablePublicKey, SerializableSignature, Signature, ErrorKind};
use openprot_hal_blocking::digest::Digest;
use zerocopy::IntoBytes;

use drv_openprot_ecdsa_api::EcdsaError;
use idol_runtime::{
    LenLimit, Leased, NotificationHandler, RequestError, R, W,
};
use userlib::RecvMessage;

/// P384 Serializable Public Key Implementation
mod p384_key {
    use super::*;
    use zerocopy::{IntoBytes, FromBytes, Immutable};
    
    /// A serializable public key for the P384 elliptic curve.
    /// 
    /// This implementation provides both coordinate access and serialization
    /// capabilities for P384 public keys, supporting the standard 96-byte
    /// uncompressed format (48 bytes each for x and y coordinates).
    #[derive(Clone, Debug, IntoBytes, FromBytes, Immutable)]
    #[repr(C)]
    pub struct P384PublicKey {
        /// X coordinate (48 bytes for P384)
        x: [u8; 48],
        /// Y coordinate (48 bytes for P384)  
        y: [u8; 48],
    }

    impl P384PublicKey {
        /// Create a new P384 public key from raw coordinates
        pub fn new(x: [u8; 48], y: [u8; 48]) -> Self {
            Self { x, y }
        }

        /// Create from raw coordinates (x || y, 96 bytes total)
        pub fn from_raw_coordinates(bytes: &[u8]) -> Result<Self, EcdsaError> {
            if bytes.len() != 96 {
                return Err(EcdsaError::InvalidParameters);
            }

            let mut x = [0u8; 48];
            let mut y = [0u8; 48];
            x.copy_from_slice(&bytes[0..48]);
            y.copy_from_slice(&bytes[48..96]);

            Ok(Self::new(x, y))
        }

        /// Export to raw coordinates format (x || y)
        pub fn to_raw_coordinates(&self) -> [u8; 96] {
            let mut result = [0u8; 96];
            result[0..48].copy_from_slice(&self.x);
            result[48..96].copy_from_slice(&self.y);
            result
        }

        /// Get X coordinate
        pub fn x(&self) -> &[u8; 48] {
            &self.x
        }

        /// Get Y coordinate
        pub fn y(&self) -> &[u8; 48] {
            &self.y
        }
    }

    impl PublicKey<P384> for P384PublicKey {
        fn coordinates(&self, x_out: &mut <P384 as openprot_hal_blocking::ecdsa::Curve>::Scalar, y_out: &mut <P384 as openprot_hal_blocking::ecdsa::Curve>::Scalar) {
            // P384::Scalar is [u8; 48], so we can copy directly
            *x_out = self.x;
            *y_out = self.y;
        }

        fn from_coordinates(x: <P384 as openprot_hal_blocking::ecdsa::Curve>::Scalar, y: <P384 as openprot_hal_blocking::ecdsa::Curve>::Scalar) -> Result<Self, ErrorKind> {
            Ok(Self::new(x, y))
        }
    }

    impl SerializablePublicKey<P384> for P384PublicKey {}

    /// A serializable signature for the P384 elliptic curve.
    ///
    /// This implementation provides both signature validation and serialization
    /// capabilities for P384 ECDSA signatures, supporting the standard 96-byte
    /// format (48 bytes each for r and s components).
    #[derive(Clone, Debug, IntoBytes, FromBytes, Immutable)]
    #[repr(C)]
    pub struct P384Signature {
        /// R component (48 bytes for P384)
        r: [u8; 48],
        /// S component (48 bytes for P384)
        s: [u8; 48],
    }

    impl P384Signature {
        /// Create a new P384 signature from r and s components
        pub fn new(r: [u8; 48], s: [u8; 48]) -> Self {
            Self { r, s }
        }
    }

    impl Signature<P384> for P384Signature {
        fn from_coordinates(r: <P384 as openprot_hal_blocking::ecdsa::Curve>::Scalar, s: <P384 as openprot_hal_blocking::ecdsa::Curve>::Scalar) -> Result<Self, ErrorKind> {
            // TODO: Add proper signature validation here
            // For now, we accept any r,s values but in a real implementation
            // we should validate that 1 ≤ r,s < curve_order
            Ok(Self::new(r, s))
        }

        fn coordinates(&self, r_out: &mut <P384 as openprot_hal_blocking::ecdsa::Curve>::Scalar, s_out: &mut <P384 as openprot_hal_blocking::ecdsa::Curve>::Scalar) {
            // P384::Scalar is [u8; 48], so we can copy directly
            *r_out = self.r;
            *s_out = self.s;
        }
    }

    impl SerializableSignature<P384> for P384Signature {}
}

////////////////////////////////////////////////////////////////////////////////

/// ECDSA Server implementation variants
enum ServerImpl<S, V> 
where 
    S: EcdsaSign<P384>,
    V: EcdsaVerify<P384>,
{
    /// Verification-only server (no signing capabilities)
    VerifierOnly { verifier: V },
    /// Full server with both signing and verification capabilities  
    SignerVerifier { signer: S, verifier: V },
}

impl<S, V> ServerImpl<S, V> 
where 
    S: EcdsaSign<P384>,
    V: EcdsaVerify<P384>,
{
    /// Create a server with both signing and verification capabilities
    fn new_with_signing(signer: S, verifier: V) -> Self {
        Self::SignerVerifier { signer, verifier }
    }
    
    /// Create a verification-only server (no signing capabilities)
    fn new_verification_only(verifier: V) -> Self {
        Self::VerifierOnly { verifier }
    }
}


impl<S, V> idl::InOrderOpenPRoTEcdsaImpl for ServerImpl<S, V> 
where 
    S: EcdsaSign<P384>,
    V: EcdsaVerify<P384>,
{
    fn ecdsa384_sign(
        &mut self,
        _msg: &RecvMessage,
        _key_id: u32,
        hash: LenLimit<Leased<R, [u8]>, 48>,
        signature: LenLimit<Leased<W, [u8]>, 96>,
    ) -> Result<(), RequestError<EcdsaError>> {

        // Check if we have signing capability
        match self {
            Self::VerifierOnly { .. } => {
                // This server instance doesn't support signing
                return Err(RequestError::Runtime(EcdsaError::HardwareNotAvailable));
            }
            Self::SignerVerifier { signer, .. } => {
                // TODO: Implement ECDSA-384 signing using the signer
                // 1. Validate key_id exists and is suitable for signing
                // 2. Validate hash is exactly 48 bytes (SHA-384)
                // 3. Load private key from secure storage
                // 4. Perform ECDSA-384 signature generation using signer
                // 5. Write signature to output lease
                
                // Validate hash parameter - must be exactly 48 bytes for SHA-384
                if hash.len() != 48 {
                    return Err(RequestError::Runtime(EcdsaError::InvalidParameters));
                }
                
                // Validate signature output buffer - must be exactly 96 bytes for P384
                if signature.len() != 96 {
                    return Err(RequestError::Runtime(EcdsaError::InvalidParameters));
                }
                
                let mut hash_buf = [0u8; 48];
                hash.read_range(0..48, &mut hash_buf)
                    .map_err(|_| RequestError::Runtime(EcdsaError::InvalidParameters))?;

                // Convert hash to P384 digest format (48 bytes = 12 u32 words for SHA-384)
                let mut digest_words = [0u32; 12];
                for (i, chunk) in hash_buf.chunks_exact(4).enumerate() {
                    digest_words[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                }
                let _digest = Digest::new(digest_words);
                
                // TODO: Replace with actual implementation using signer
                // For now, create a placeholder signature using the Signature trait method
                // In a real implementation, this would:
                // 1. Load the private key for key_id
                // 2. Use the signer to generate ECDSA signature components (r, s)
                // 3. Construct a P384Signature using Signature<P384>::from_coordinates()
                
                let placeholder_r = [0u8; 48];
                let placeholder_s = [1u8; 48];
                
                let signature_obj = match p384_key::P384Signature::from_coordinates(placeholder_r, placeholder_s) {
                    Ok(sig) => sig,
                    Err(_) => return Err(RequestError::Runtime(EcdsaError::InternalError))
                };
                
                // Use zero-copy serialization with SerializableSignature
                // Since P384Signature implements IntoBytes, we can serialize directly
                let signature_bytes = signature_obj.as_bytes();
                
                signature.write_range(0..96, signature_bytes)
                    .map_err(|_| RequestError::Runtime(EcdsaError::InternalError))?;
                
                // TODO: Remove this placeholder return once real implementation is complete
                Err(RequestError::Runtime(EcdsaError::InternalError))
            }
        }
    }

    fn ecdsa384_verify(
        &mut self,
        _msg: &RecvMessage,
        hash: LenLimit<Leased<R, [u8]>, 48>,
        signature: LenLimit<Leased<R, [u8]>, 96>,
        public_key: LenLimit<Leased<R, [u8]>, 96>,
    ) -> Result<bool, RequestError<EcdsaError>> {
        // Validate input lengths - must be exactly the expected sizes
        if hash.len() != 48 {
            return Err(RequestError::Runtime(EcdsaError::InvalidParameters));
        }
        if signature.len() != 96 {
            return Err(RequestError::Runtime(EcdsaError::InvalidParameters));
        }
        if public_key.len() != 96 {
            return Err(RequestError::Runtime(EcdsaError::InvalidParameters));
        }
        
        // Read inputs from leases - these will fail gracefully if inputs are too short
        let mut hash_buf = [0u8; 48];
        let mut pubkey_buf = [0u8; 96];  // Raw x||y coordinates, 96 bytes
        let mut sig_buf = [0u8; 96];     // Raw r||s signature, 96 bytes
        
        hash.read_range(0..48, &mut hash_buf)
            .map_err(|_| RequestError::Runtime(EcdsaError::InvalidParameters))?;
        public_key.read_range(0..96, &mut pubkey_buf)
            .map_err(|_| RequestError::Runtime(EcdsaError::InvalidParameters))?;
        signature.read_range(0..96, &mut sig_buf)
            .map_err(|_| RequestError::Runtime(EcdsaError::InvalidParameters))?;

        // Convert hash to P384 digest format (48 bytes = 12 u32 words for SHA-384)
        let mut digest_words = [0u32; 12];
        for (i, chunk) in hash_buf.chunks_exact(4).enumerate() {
            digest_words[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let _digest = Digest::new(digest_words);
        
        // Get the verifier from either variant
        let _verifier = match self {
            Self::VerifierOnly { verifier } => verifier,
            Self::SignerVerifier { verifier, .. } => verifier,
        };
        
        // TODO: Replace with actual implementation using verifier
        // Use zero-copy deserialization with SerializablePublicKey
        // Since P384PublicKey implements IntoBytes + FromBytes, we can deserialize directly
        let _pubkey: p384_key::P384PublicKey = match zerocopy::FromBytes::read_from_bytes(&pubkey_buf[..]) {
            Ok(key) => key,
            Err(_) => return Err(RequestError::Runtime(EcdsaError::InvalidParameters))
        };

        // Use zero-copy deserialization with SerializableSignature  
        // Since P384Signature implements IntoBytes + FromBytes, we can deserialize directly
        let _signature_obj: p384_key::P384Signature = match zerocopy::FromBytes::read_from_bytes(&sig_buf[..]) {
            Ok(sig) => sig,
            Err(_) => return Err(RequestError::Runtime(EcdsaError::InvalidParameters))
        };

        // Now we have concrete types constructed using zero-copy deserialization:
        // - _pubkey: P384PublicKey via zerocopy::FromBytes
        // - _signature_obj: P384Signature via zerocopy::FromBytes  
        // - _digest: Digest for the hash

        // TODO: Implement actual ECDSA verification using the verifier trait
        // This would typically look like:
        // let verification_result = _verifier.verify(&_digest, &_signature_obj, &_pubkey)?;
        // Ok(verification_result)
        
        // For now, return an error indicating not implemented
        Err(RequestError::Runtime(EcdsaError::HardwareNotAvailable))
    }
}

impl<S, V> NotificationHandler for ServerImpl<S, V> 
where 
    S: EcdsaSign<P384>,
    V: EcdsaVerify<P384>,
{
    fn current_notification_mask(&self) -> u32 {
        // No notifications needed for now
        0
    }

    fn handle_notification(&mut self, _bits: u32) {
        // No notifications to handle
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Placeholder ECDSA Verifier Implementation
/// 
/// This is a concrete type that implements the EcdsaVerify trait for P384.
/// It provides a minimal working implementation for testing and development.
struct PlaceholderVerifier;

impl ErrorType for PlaceholderVerifier {
    type Error = core::convert::Infallible;
}

impl EcdsaVerify<P384> for PlaceholderVerifier {
    type PublicKey = p384_key::P384PublicKey;
    type Signature = p384_key::P384Signature;
    
    fn verify(
        &mut self,
        _public_key: &Self::PublicKey,
        _digest: <<P384 as openprot_hal_blocking::ecdsa::Curve>::DigestType as DigestAlgorithm>::Digest,
        _signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        // Placeholder implementation - always "succeeds" 
        // In a real implementation, this would:
        // 1. Extract the r,s components from the signature
        // 2. Extract the x,y coordinates from the public key  
        // 3. Perform the ECDSA verification algorithm on P384 curve
        // 4. Return Ok(()) if verification passes, Err(error) if it fails
        Ok(())
    }
}

/// P384 Private Key Implementation
/// 
/// This concrete type implements both Zeroize and PrivateKey<P384> traits
/// as required by the OpenPRoT framework.
#[derive(Zeroize, ZeroizeOnDrop)]
#[repr(C)]
struct P384PrivateKey {
    /// Private scalar value (48 bytes for P384)
    scalar: [u8; 48],
}

impl P384PrivateKey {
    /// Create a new private key from scalar bytes
    pub fn new(scalar: [u8; 48]) -> Self {
        Self { scalar }
    }
}

impl PrivateKey<P384> for P384PrivateKey {
    fn validate(&self) -> Result<(), ErrorKind> {
        // TODO: Add proper private key validation
        // For now, accept any 48-byte value as valid
        // In a real implementation, validate that:
        // 1 ≤ scalar < curve_order
        Ok(())
    }
}

/// Placeholder ECDSA Signer Implementation
/// 
/// This is a concrete type that implements the EcdsaSign trait for P384.
/// It provides a minimal working implementation for testing and development.
struct PlaceholderSigner;

impl ErrorType for PlaceholderSigner {
    type Error = core::convert::Infallible;
}

impl EcdsaSign<P384> for PlaceholderSigner {
    type PrivateKey = P384PrivateKey; // Use our concrete private key type
    type Signature = p384_key::P384Signature;
    
    fn sign<R>(
        &mut self,
        _private_key: &Self::PrivateKey,
        _digest: <<P384 as openprot_hal_blocking::ecdsa::Curve>::DigestType as DigestAlgorithm>::Digest,
        _rng: &mut R,
    ) -> Result<Self::Signature, Self::Error> {
        // Placeholder implementation - returns a dummy signature
        // In a real implementation, this would:
        // 1. Validate the private key
        // 2. Use the digest and private key to generate ECDSA signature components (r, s)
        // 3. Use random number generator for signature generation
        // 4. Return the computed signature
        
        // Create a deterministic placeholder signature for testing
        let placeholder_r = [0u8; 48];
        let mut placeholder_s = [1u8; 48];
        placeholder_s[47] = 42; // Make it slightly non-trivial
        
        Ok(p384_key::P384Signature::new(placeholder_r, placeholder_s))
    }
}

////////////////////////////////////////////////////////////////////////////////

#[export_name = "main"]
fn main() -> ! {
    // TODO: Replace with actual cryptographic backend
    // Create a server with both signing and verification capabilities using placeholder implementations
    let signer = PlaceholderSigner;
    let verifier = PlaceholderVerifier;
    let mut server: ServerImpl<PlaceholderSigner, PlaceholderVerifier> = 
        ServerImpl::new_with_signing(signer, verifier);
    
    let mut incoming = [0u8; idl::INCOMING_SIZE];
    loop {
        idol_runtime::dispatch(&mut incoming, &mut server);
    }
}

// Include the generated server stub
mod idl {
    use super::EcdsaError;
    
    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}
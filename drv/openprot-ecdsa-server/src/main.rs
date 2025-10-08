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

use openprot_hal_blocking::ecdsa::{EcdsaVerify, EcdsaSign, P384, Signature};
use openprot_hal_blocking::digest::Digest;
use zerocopy::IntoBytes;

use drv_openprot_ecdsa_api::EcdsaError;
use idol_runtime::{
    LenLimit, Leased, NotificationHandler, RequestError, R, W,
};
use userlib::RecvMessage;

/// P384 Serializable Public Key Implementation
mod p384_key;

/// Placeholder implementations for testing and development
mod placeholder;

////////////////////////////////////////////////////////////////////////////////

/// ECDSA Server implementation variants
enum ServerImpl<S, V> 
where 
    S: EcdsaSign<P384>,
    V: EcdsaVerify<P384, PublicKey = p384_key::P384PublicKey, Signature = p384_key::P384Signature>,
{
    /// Verification-only server (no signing capabilities)
    VerifierOnly { verifier: V },
    /// Full server with both signing and verification capabilities  
    SignerVerifier { signer: S, verifier: V },
}

impl<S, V> ServerImpl<S, V> 
where 
    S: EcdsaSign<P384>,
    V: EcdsaVerify<P384, PublicKey = p384_key::P384PublicKey, Signature = p384_key::P384Signature>,
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
    V: EcdsaVerify<P384, PublicKey = p384_key::P384PublicKey, Signature = p384_key::P384Signature>,
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
        
        // Get the verifier from either variant
        let verifier = match self {
            Self::VerifierOnly { verifier } => verifier,
            Self::SignerVerifier { verifier, .. } => verifier,
        };
        
        // TODO: Replace with actual implementation using verifier
        // Use zero-copy deserialization with SerializablePublicKey
        // Since P384PublicKey implements IntoBytes + FromBytes, we can deserialize directly
        let pubkey: p384_key::P384PublicKey = match zerocopy::FromBytes::read_from_bytes(&pubkey_buf[..]) {
            Ok(key) => key,
            Err(_) => return Err(RequestError::Runtime(EcdsaError::InvalidParameters))
        };

        // Use zero-copy deserialization with SerializableSignature  
        // Since P384Signature implements IntoBytes + FromBytes, we can deserialize directly
        let signature_obj: p384_key::P384Signature = match zerocopy::FromBytes::read_from_bytes(&sig_buf[..]) {
            Ok(sig) => sig,
            Err(_) => return Err(RequestError::Runtime(EcdsaError::InvalidParameters))
        };

        // Now we have concrete types constructed using zero-copy deserialization:
        // - pubkey: P384PublicKey via zerocopy::FromBytes
        // - signature_obj: P384Signature via zerocopy::FromBytes  
        // - digest: Digest for the hash

        // Dispatch to the placeholder verifier
        let digest = Digest::new(digest_words);
        match verifier.verify(&pubkey, digest, &signature_obj) {
            Ok(()) => Ok(true),  // Verification succeeded
            Err(_) => Ok(false), // Verification failed (PlaceholderVerifier uses Infallible, so this won't happen)
        }
    }
}

impl<S, V> NotificationHandler for ServerImpl<S, V> 
where 
    S: EcdsaSign<P384>,
    V: EcdsaVerify<P384, PublicKey = p384_key::P384PublicKey, Signature = p384_key::P384Signature>,
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
////////////////////////////////////////////////////////////////////////////////

#[export_name = "main"]
fn main() -> ! {
    // TODO: Replace with actual cryptographic backend
    // Create a server with both signing and verification capabilities using placeholder implementations
    let signer = placeholder::PlaceholderSigner;
    let verifier = placeholder::PlaceholderVerifier;
    let mut server: ServerImpl<placeholder::PlaceholderSigner, placeholder::PlaceholderVerifier> = 
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
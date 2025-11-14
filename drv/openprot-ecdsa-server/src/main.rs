// Copyright 2024 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! OpenPRoT ECDSA Server
//!
//! This server provides ECDSA-384 cryptographic operations for the OpenPRoT
//! security framework, including digital signature generation and verification
//! using P-384 elliptic curve cryptography.

#![no_std]
#![no_main]

use openprot_hal_blocking::digest::Digest;
use openprot_hal_blocking::ecdsa::{
    EcdsaSign, EcdsaVerify, PublicKey, Signature, P384,
};

use drv_openprot_ecdsa_api::EcdsaError;
use idol_runtime::{Leased, LenLimit, NotificationHandler, RequestError, R, W};
use userlib::RecvMessage;

////////////////////////////////////////////////////////////////////////////////

/// ECDSA Server implementation variants
enum ServerImpl<S, V> {
    /// Verification-only server (no signing capabilities)
    VerifierOnly { verifier: V },
    /// Full server with both signing and verification capabilities  
    SignerVerifier { signer: S, verifier: V },
}

impl<S, V> ServerImpl<S, V> {
    /// Create a server with both signing and verification capabilities
    fn new_with_signing(signer: S, verifier: V) -> Self {
        Self::SignerVerifier { signer, verifier }
    }

    /// Create a verification-only server (no signing capabilities)
    fn new_verification_only(verifier: V) -> Self {
        Self::VerifierOnly { verifier }
    }
}

impl<S, V> idl::InOrderOpenPRoTEcdsaImpl for ServerImpl<S, V> {
    fn ecdsa384_sign(
        &mut self,
        _msg: &RecvMessage,
        _key_id: u32,
        hash: LenLimit<Leased<R, [u8]>, 48>,
        _signature: LenLimit<Leased<W, [u8]>, 96>,
    ) -> Result<(), RequestError<EcdsaError>> {
        // Check if we have signing capability
        match self {
            Self::VerifierOnly { .. } => {
                // This server instance doesn't support signing
                return Err(RequestError::Runtime(
                    EcdsaError::HardwareNotAvailable,
                ));
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
                    return Err(RequestError::Runtime(
                        EcdsaError::InvalidParameters,
                    ));
                }

                let mut hash_buf = [0u8; 48];
                hash.read_range(0..48, &mut hash_buf).map_err(|_| {
                    RequestError::Runtime(EcdsaError::InvalidParameters)
                })?;

                // TODO: Replace with actual implementation using signer
                // For now, return an error indicating not implemented
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
        let mut pubkey_buf = [0u8; 96]; // Raw x||y coordinates, 96 bytes
        let mut sig_buf = [0u8; 96]; // Raw r||s signature, 96 bytes

        hash.read_range(0..48, &mut hash_buf).map_err(|_| {
            RequestError::Runtime(EcdsaError::InvalidParameters)
        })?;
        public_key.read_range(0..96, &mut pubkey_buf).map_err(|_| {
            RequestError::Runtime(EcdsaError::InvalidParameters)
        })?;
        signature.read_range(0..96, &mut sig_buf).map_err(|_| {
            RequestError::Runtime(EcdsaError::InvalidParameters)
        })?;

        // Convert hash to P384 digest format (48 bytes = 12 u32 words for SHA-384)
        let mut digest_words = [0u32; 12];
        for (i, chunk) in hash_buf.chunks_exact(4).enumerate() {
            digest_words[i] =
                u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let digest = Digest::new(digest_words);

        // Get the verifier from either variant
        let verifier = match self {
            Self::VerifierOnly { verifier } => verifier,
            Self::SignerVerifier { verifier, .. } => verifier,
        };

        // TODO: Replace with actual implementation using verifier
        // For now, return an error indicating not implemented
        Err(RequestError::Runtime(EcdsaError::HardwareNotAvailable))
    }
}

impl<S, V> NotificationHandler for ServerImpl<S, V> {
    fn current_notification_mask(&self) -> u32 {
        // No notifications needed for now
        0
    }

    fn handle_notification(&mut self, _bits: u32) {
        // No notifications to handle
    }
}

////////////////////////////////////////////////////////////////////////////////

#[export_name = "main"]
fn main() -> ! {
    // TODO: Replace with actual cryptographic backend
    // For now, create a verification-only server with a placeholder verifier
    struct PlaceholderVerifier;

    let mut server: ServerImpl<(), PlaceholderVerifier> =
        ServerImpl::new_verification_only(PlaceholderVerifier);

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

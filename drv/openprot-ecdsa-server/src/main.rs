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

use drv_openprot_ecdsa_api::EcdsaError;
use idol_runtime::{
    LenLimit, Leased, NotificationHandler, RequestError, R, W,
};
use userlib::RecvMessage;

////////////////////////////////////////////////////////////////////////////////

struct ServerImpl {
    // TODO: Add cryptographic backend (HSM, software crypto, etc.)
}

impl ServerImpl {
    fn new() -> Self {
        Self {}
    }
}

impl idl::InOrderOpenPRoTEcdsaImpl for ServerImpl {
    fn ecdsa384_sign(
        &mut self,
        _msg: &RecvMessage,
        key_id: u32,
        hash: LenLimit<Leased<R, [u8]>, 48>,
        signature: LenLimit<Leased<W, [u8]>, 96>,
    ) -> Result<(), RequestError<EcdsaError>> {

        // TODO: Implement ECDSA-384 signing
        // 1. Validate key_id exists and is suitable for signing
        // 2. Validate hash is exactly 48 bytes (SHA-384)
        // 3. Load private key from secure storage
        // 4. Perform ECDSA-384 signature generation
        // 5. Encode signature in DER-encoded ASN.1 format
        // 6. Write signature to output lease
        // 7. Return actual signature length
        
        let mut hash_buf = [0u8; 48];
        hash.read_range(0..48, &mut hash_buf).map_err(|_| RequestError::Runtime(EcdsaError::InternalError))?;
        
        // TODO: Replace with actual implementation
        // For now, return an error indicating not implemented
        Err(RequestError::Runtime(EcdsaError::HardwareNotAvailable))
    }

    fn ecdsa384_verify(
        &mut self,
        _msg: &RecvMessage,
        hash: LenLimit<Leased<R, [u8]>, 48>,
        signature: LenLimit<Leased<R, [u8]>, 96>,
        public_key: LenLimit<Leased<R, [u8]>, 96>,
    ) -> Result<bool, RequestError<EcdsaError>> {
        // TODO: Implement ECDSA-384 verification
        // 1. Validate hash is exactly 48 bytes (SHA-384)
        // 2. Validate public key is in uncompressed SEC1 format (97 bytes)
        // 3. Validate signature is in DER-encoded ASN.1 format
        // 4. Parse public key from SEC1 format
        // 5. Parse signature from DER format
        // 6. Perform ECDSA-384 signature verification
        // 7. Return verification result
        
        let mut hash_buf = [0u8; 48];
        let mut sig_buf = [0u8; 104];
        let mut pubkey_buf = [0u8; 97];
        
        hash.read_range(0..48, &mut hash_buf).map_err(|_| RequestError::Runtime(EcdsaError::InternalError))?;
        signature.read_range(0..signature.len(), &mut sig_buf[0..signature.len()]).map_err(|_| RequestError::Runtime(EcdsaError::InternalError))?;
        public_key.read_range(0..97, &mut pubkey_buf).map_err(|_| RequestError::Runtime(EcdsaError::InternalError))?;
        
        // Validate public key format (uncompressed SEC1: 0x04 + 48 bytes x + 48 bytes y)
        if pubkey_buf[0] != 0x04 {
            return Err(RequestError::Runtime(EcdsaError::InvalidKeyType));
        }
        
        // TODO: Replace with actual implementation
        // For now, return an error indicating not implemented
        Err(RequestError::Runtime(EcdsaError::HardwareNotAvailable))
    }
}

impl NotificationHandler for ServerImpl {
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
    let mut server = ServerImpl::new();
    
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
//! RustCrypto-specific helper functions for HMAC operations
//! 
//! This module provides safe wrappers around RustCrypto operations,
//! eliminating the need for unsafe transmutations or complex trait bounds.

use openprot_hal_blocking::mac::owned::{MacInit, MacOp};
use openprot_hal_blocking::mac::{HmacSha2_256, HmacSha2_384, HmacSha2_512};
use openprot_platform_rustcrypto::controller::{RustCryptoController, SecureOwnedKey, CryptoError};

/// Errors that can occur during RustCrypto HMAC operations
#[derive(Debug, Clone, PartialEq)]
pub enum HmacError {
    InvalidKeyLength,
    HardwareFailure,
}

impl From<CryptoError> for HmacError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::InvalidKeyLength => HmacError::InvalidKeyLength,
            _ => HmacError::HardwareFailure,
        }
    }
}

/// Initialize an HMAC-SHA256 context with the given key
pub fn init_hmac_sha256(
    controller: RustCryptoController,
    key: &[u8],
) -> Result<openprot_platform_rustcrypto::controller::MacContext256, HmacError> {
    let secure_key = SecureOwnedKey::new(key)?;
    MacInit::init(controller, HmacSha2_256, secure_key)
        .map_err(|_| HmacError::HardwareFailure)
}

/// Initialize an HMAC-SHA384 context with the given key
pub fn init_hmac_sha384(
    controller: RustCryptoController,
    key: &[u8],
) -> Result<openprot_platform_rustcrypto::controller::MacContext384, HmacError> {
    let secure_key = SecureOwnedKey::new(key)?;
    MacInit::init(controller, HmacSha2_384, secure_key)
        .map_err(|_| HmacError::HardwareFailure)
}

/// Initialize an HMAC-SHA512 context with the given key
pub fn init_hmac_sha512(
    controller: RustCryptoController,
    key: &[u8],
) -> Result<openprot_platform_rustcrypto::controller::MacContext512, HmacError> {
    let secure_key = SecureOwnedKey::new(key)?;
    MacInit::init(controller, HmacSha2_512, secure_key)
        .map_err(|_| HmacError::HardwareFailure)
}

/// Update an HMAC-SHA256 context with data
pub fn update_hmac_sha256(
    context: openprot_platform_rustcrypto::controller::MacContext256,
    data: &[u8],
) -> Result<openprot_platform_rustcrypto::controller::MacContext256, HmacError> {
    context.update(data)
        .map_err(|_| HmacError::HardwareFailure)
}

/// Update an HMAC-SHA384 context with data
pub fn update_hmac_sha384(
    context: openprot_platform_rustcrypto::controller::MacContext384,
    data: &[u8],
) -> Result<openprot_platform_rustcrypto::controller::MacContext384, HmacError> {
    context.update(data)
        .map_err(|_| HmacError::HardwareFailure)
}

/// Update an HMAC-SHA512 context with data
pub fn update_hmac_sha512(
    context: openprot_platform_rustcrypto::controller::MacContext512,
    data: &[u8],
) -> Result<openprot_platform_rustcrypto::controller::MacContext512, HmacError> {
    context.update(data)
        .map_err(|_| HmacError::HardwareFailure)
}

/// Finalize an HMAC-SHA256 context and return the MAC
pub fn finalize_hmac_sha256(
    context: openprot_platform_rustcrypto::controller::MacContext256,
) -> Result<([u8; 32], RustCryptoController), HmacError> {
    context.finalize()
        .map_err(|_| HmacError::HardwareFailure)
}

/// Finalize an HMAC-SHA384 context and return the MAC
pub fn finalize_hmac_sha384(
    context: openprot_platform_rustcrypto::controller::MacContext384,
) -> Result<([u8; 48], RustCryptoController), HmacError> {
    context.finalize()
        .map_err(|_| HmacError::HardwareFailure)
}

/// Finalize an HMAC-SHA512 context and return the MAC
pub fn finalize_hmac_sha512(
    context: openprot_platform_rustcrypto::controller::MacContext512,
) -> Result<([u8; 64], RustCryptoController), HmacError> {
    context.finalize()
        .map_err(|_| HmacError::HardwareFailure)
}

/// One-shot HMAC-SHA256 computation
pub fn hmac_sha256_oneshot(
    controller: RustCryptoController,
    key: &[u8],
    data: &[u8],
) -> Result<([u8; 32], RustCryptoController), HmacError> {
    let context = init_hmac_sha256(controller, key)?;
    let context = update_hmac_sha256(context, data)?;
    finalize_hmac_sha256(context)
}

/// One-shot HMAC-SHA384 computation
pub fn hmac_sha384_oneshot(
    controller: RustCryptoController,
    key: &[u8],
    data: &[u8],
) -> Result<([u8; 48], RustCryptoController), HmacError> {
    let context = init_hmac_sha384(controller, key)?;
    let context = update_hmac_sha384(context, data)?;
    finalize_hmac_sha384(context)
}

/// One-shot HMAC-SHA512 computation
pub fn hmac_sha512_oneshot(
    controller: RustCryptoController,
    key: &[u8],
    data: &[u8],
) -> Result<([u8; 64], RustCryptoController), HmacError> {
    let context = init_hmac_sha512(controller, key)?;
    let context = update_hmac_sha512(context, data)?;
    finalize_hmac_sha512(context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_oneshot() {
        let controller = RustCryptoController::new();
        let key = b"test key";
        let data = b"test data";

        let result = hmac_sha256_oneshot(controller, key, data);
        assert!(result.is_ok());

        let (mac, _controller) = result.unwrap();
        assert_eq!(mac.len(), 32);
        assert_ne!(mac, [0u8; 32]); // Should contain actual MAC data
    }

    #[test]
    fn test_hmac_sha384_oneshot() {
        let controller = RustCryptoController::new();
        let key = b"test key";
        let data = b"test data";

        let result = hmac_sha384_oneshot(controller, key, data);
        assert!(result.is_ok());

        let (mac, _controller) = result.unwrap();
        assert_eq!(mac.len(), 48);
        assert_ne!(mac, [0u8; 48]); // Should contain actual MAC data
    }

    #[test]
    fn test_hmac_sha512_oneshot() {
        let controller = RustCryptoController::new();
        let key = b"test key";
        let data = b"test data";

        let result = hmac_sha512_oneshot(controller, key, data);
        assert!(result.is_ok());

        let (mac, _controller) = result.unwrap();
        assert_eq!(mac.len(), 64);
        assert_ne!(mac, [0u8; 64]); // Should contain actual MAC data
    }

    #[test]
    fn test_streaming_hmac_sha256() {
        let controller = RustCryptoController::new();
        let key = b"test key";

        let context = init_hmac_sha256(controller, key).unwrap();
        let context = update_hmac_sha256(context, b"test ").unwrap();
        let context = update_hmac_sha256(context, b"data").unwrap();
        let (mac, _controller) = finalize_hmac_sha256(context).unwrap();

        assert_eq!(mac.len(), 32);
        assert_ne!(mac, [0u8; 32]); // Should contain actual MAC data
    }

    #[test]
    fn test_invalid_key_length() {
        let controller = RustCryptoController::new();
        let oversized_key = [0u8; 200]; // Too large for SecureOwnedKey::MAX_KEY_SIZE

        let result = init_hmac_sha256(controller, &oversized_key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), HmacError::InvalidKeyLength);
    }
}
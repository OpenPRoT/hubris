//! P384 Serializable Key and Signature Implementation
//!
//! This module provides concrete implementations of the OpenPRoT serializable
//! key and signature traits for the P384 elliptic curve, supporting zero-copy
//! serialization and deserialization.

use openprot_hal_blocking::ecdsa::{P384, PublicKey, SerializablePublicKey, SerializableSignature, Signature, ErrorKind};
use zerocopy::{IntoBytes, FromBytes, Immutable};
use drv_openprot_ecdsa_api::EcdsaError;

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
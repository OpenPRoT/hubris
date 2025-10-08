//! P384 Serializable Key and Signature Implementation
//!
//! This module provides concrete implementations of the OpenPRoT serializable
//! key and signature traits for the P384 elliptic curve, supporting zero-copy
//! serialization and deserialization.
#![no_std]

use openprot_hal_blocking::ecdsa::{P384, PublicKey, P384PublicKey, P384Signature, SerializablePublicKey, SerializableSignature, Signature, ErrorKind};
use zerocopy::{IntoBytes, FromBytes, Immutable};


pub mod verifier;

// Re-export the main verifier types for other crates to use
pub use verifier::{AspeedEcdsa, AspeedEcdsaError};



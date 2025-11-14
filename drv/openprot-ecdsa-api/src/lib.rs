// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 Advanced Micro Devices, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! API crate for the OpenPRoT ECDSA server.
//!
//! This crate provides types and constants for ECDSA-384 cryptographic operations
//! in the OpenPRoT security framework.

#![no_std]

use derive_idol_err::IdolError;
use userlib::{FromPrimitive, sys_send};
pub use userlib::TaskId;

/// Errors that can occur during ECDSA operations
#[derive(
    Copy, Clone, Debug, FromPrimitive, Eq, PartialEq, IdolError, counters::Count, 
    serde::Deserialize, serde::Serialize, hubpack::SerializedSize,
)]
#[repr(u8)]
pub enum EcdsaError {
    /// Invalid key ID provided
    InvalidKeyId = 1,
    
    /// Key not found
    KeyNotFound = 2,
    
    /// Invalid parameters (length, format, or content)
    InvalidParameters = 3,
    
    /// Signature verification failed
    VerificationFailed = 4,
    
    /// Cryptographic hardware not available
    HardwareNotAvailable = 5,
    
    /// Key is not suitable for the requested operation
    InvalidKeyType = 6,
    
    /// Internal error in cryptographic implementation
    InternalError = 7,

    #[idol(server_death)]
    ServerRestarted,
}

impl From<idol_runtime::ServerDeath> for EcdsaError {
    fn from(_: idol_runtime::ServerDeath) -> Self {
        Self::ServerRestarted
    }
}

include!(concat!(env!("OUT_DIR"), "/client_stub.rs"));
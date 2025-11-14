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

#![no_std]
#![no_main]

//! HMAC Client Task
//!
//! This task demonstrates the usage of HMAC operations through the digest API.
//! It performs various HMAC operations and validates the results.

use userlib::*;
use drv_digest_api::{Digest, DigestError};
use counters::{count, counters, Count};
use ringbuf::{ringbuf, ringbuf_entry};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

task_slot!(DIGEST, digest_server);

// Events for tracking HMAC test operations
#[derive(Count, Copy, Clone)]
enum Event {
    TestsStarted,
    TestsPassed,
    TestsFailed,
    Sha256Tests,
    Sha384Tests,
    Sha512Tests,
}

counters!(Event);

// Trace events for debugging
#[derive(Copy, Clone, PartialEq)]
enum Trace {
    None,
    TestStart(u32),     // Test starting (algorithm ID)
    TestPass(u32),      // Test passed (algorithm ID)
    TestFail(u32),      // Test failed (algorithm ID)
    Mismatch(u32),      // Hash mismatch (algorithm ID)
}

ringbuf!(Trace, 16, Trace::None);

#[export_name = "main"]
fn main() -> ! {
    let digest_task = DIGEST.get_task_id();
    let digest_client = Digest::from(digest_task);
    
    let mut test_round = 0u32;
    
    loop {
        test_round = test_round.wrapping_add(1);
        count!(Event::TestsStarted);
        
        let mut all_tests_passed = true;
        
        // Test HMAC-SHA256
        if let Err(_) = test_hmac_sha256(&digest_client, test_round) {
            ringbuf_entry!(Trace::TestFail(0x3256));
            all_tests_passed = false;
        }
        
        // Test HMAC-SHA384
        if let Err(_) = test_hmac_sha384(&digest_client, test_round) {
            ringbuf_entry!(Trace::TestFail(0x3384));
            all_tests_passed = false;
        }
        
        // Test HMAC-SHA512
        if let Err(_) = test_hmac_sha512(&digest_client, test_round) {
            ringbuf_entry!(Trace::TestFail(0x3512));
            all_tests_passed = false;
        }
        
        if all_tests_passed {
            count!(Event::TestsPassed);
            ringbuf_entry!(Trace::TestPass(0x4000));
        } else {
            count!(Event::TestsFailed);
            ringbuf_entry!(Trace::TestFail(0x4001));
        }
        
        // Wait a bit before next test round
        hl::sleep_for(1000);
    }
}

#[inline(never)]
pub fn test_hmac_sha256(digest_client: &Digest, _round: u32) -> Result<(), DigestError> {
    count!(Event::Sha256Tests);
    ringbuf_entry!(Trace::TestStart(0x5256));
    
    // Test data
    let key = b"test_key_256";
    let data = b"Hello, HMAC-SHA256!";
    
    // Test session-based HMAC
    let session_id = digest_client.init_hmac_sha256(key.len() as u32, key)?;
    digest_client.update(session_id, data.len() as u32, data)?;
    
    let mut hmac_output = [0u32; 8];
    digest_client.finalize_hmac_sha256(session_id, &mut hmac_output)?;
    
    // Software verification using RustCrypto
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    let expected = mac.finalize().into_bytes();
    
    let mut expected_words = [0u32; 8];
    for (i, chunk) in expected.chunks_exact(4).enumerate() {
        expected_words[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    
    if hmac_output != expected_words {
        ringbuf_entry!(Trace::Mismatch(0x6256));
        return Err(DigestError::HmacVerificationFailed);
    }
    
    ringbuf_entry!(Trace::TestPass(0x9256));
    Ok(())
}

#[inline(never)]
pub fn test_hmac_sha384(digest_client: &Digest, _round: u32) -> Result<(), DigestError> {
    count!(Event::Sha384Tests);
    ringbuf_entry!(Trace::TestStart(0x5384));
    
    let key = b"test_key_384_longer_for_better_security";
    let data = b"Hello, HMAC-SHA384 with longer message!";
    
    let mut hmac_output = [0u32; 12]; // SHA384 output is 12 u32 words
    digest_client.hmac_oneshot_sha384(
        key.len() as u32,
        data.len() as u32,
        key,
        data,
        &mut hmac_output,
    )?;
    
    // Software verification
    let mut mac = Hmac::<Sha384>::new_from_slice(key).unwrap();
    mac.update(data);
    let expected = mac.finalize().into_bytes();
    
    let mut expected_words = [0u32; 12];
    for (i, chunk) in expected.chunks_exact(4).enumerate() {
        expected_words[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    
    if hmac_output != expected_words {
        ringbuf_entry!(Trace::Mismatch(0x6384));
        return Err(DigestError::HmacVerificationFailed);
    }
    
    ringbuf_entry!(Trace::TestPass(0x9384));
    Ok(())
}

#[inline(never)]
pub fn test_hmac_sha512(digest_client: &Digest, _round: u32) -> Result<(), DigestError> {
    count!(Event::Sha512Tests);
    ringbuf_entry!(Trace::TestStart(0x5512));
    
    let key = b"test_key_512_even_longer_key_for_maximum_security_testing_purposes_here";
    let data = b"Hello, HMAC-SHA512 with an even longer message for comprehensive testing!";
    
    let mut hmac_output = [0u32; 16]; // SHA512 output is 16 u32 words
    digest_client.hmac_oneshot_sha512(
        key.len() as u32,
        data.len() as u32,
        key,
        data,
        &mut hmac_output,
    )?;
    
    // Software verification
    let mut mac = Hmac::<Sha512>::new_from_slice(key).unwrap();
    mac.update(data);
    let expected = mac.finalize().into_bytes();
    
    let mut expected_words = [0u32; 16];
    for (i, chunk) in expected.chunks_exact(4).enumerate() {
        expected_words[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    
    if hmac_output != expected_words {
        ringbuf_entry!(Trace::Mismatch(0x6512));
        return Err(DigestError::HmacVerificationFailed);
    }
    
    ringbuf_entry!(Trace::TestPass(0x9512));
    Ok(())
}

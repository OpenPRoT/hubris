// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Hash Client Task
//!
//! This task demonstrates how to use the digest-api to request hash services
//! from a hash accelerator driver in Hubris. It shows examples of computing
//! various hash algorithms and handling different use cases.

#![no_std]
#![no_main]

use drv_digest_api::{DigestError, Digest};
use userlib::task_slot;

task_slot!(DIGEST_DRIVER, digest_driver);

/// Hash client task main function
/// 
/// This task demonstrates various hash operations using the digest driver.
/// It serves as an example for other tasks that need cryptographic hashing.
#[export_name = "main"]
pub fn main() -> ! {
    // Get a handle to the digest driver using Idol client
    let digest_client = Digest::from(DIGEST_DRIVER.get_task_id());
    
    loop {
        // Demonstrate SHA-256 hashing
        if let Err(e) = demo_sha256(&digest_client) {
            // Log error (in a real system, you'd use proper logging)
            // For now, we'll just continue
            let _ = e;
        }
        
        // Demonstrate SHA-384 hashing
        if let Err(e) = demo_sha384(&digest_client) {
            let _ = e;
        }
        
        // Demonstrate SHA-512 hashing
        if let Err(e) = demo_sha512(&digest_client) {
            let _ = e;
        }
        
        // Demonstrate streaming hash for large data
        if let Err(e) = demo_streaming_hash(&digest_client) {
            let _ = e;
        }
        
        // Demonstrate one-shot hashing
        if let Err(e) = demo_oneshot_hash(&digest_client) {
            let _ = e;
        }
        
        // Sleep for a while before next demonstration
        userlib::hl::sleep_for(5000); // 5 seconds
    }
}

/// Demonstrate SHA-256 hash computation
fn demo_sha256(digest_client: &Digest) -> Result<(), DigestError> {
    // Test data
    let test_data = b"Hello, Hubris world!";
    
    // Create a new digest session for SHA-256
    let session_id = digest_client.init_sha256()?;
    
    // Update the hash with our test data
    digest_client.update(session_id, test_data.len() as u32, test_data)?;
    
    // Finalize and get the digest
    let mut digest_output = [0u32; 8];
    digest_client.finalize_sha256(session_id, &mut digest_output)?;
    
    // In a real application, you'd use the digest for something useful
    // For demonstration, we'll just verify it's not all zeros
    let is_valid = digest_output.iter().any(|&word| word != 0);
    
    if is_valid {
        // Hash computed successfully
        // In a real system, you might log this or use it for verification
    }
    
    Ok(())
}

/// Demonstrate SHA-384 hash computation
fn demo_sha384(digest_client: &Digest) -> Result<(), DigestError> {
    let test_data = b"SHA-384 test data for Hubris digest driver";
    
    let session_id = digest_client.init_sha384()?;
    digest_client.update(session_id, test_data.len() as u32, test_data)?;
    
    let mut digest_output = [0u32; 12];
    digest_client.finalize_sha384(session_id, &mut digest_output)?;
    
    // Verify digest was computed
    let is_valid = digest_output.iter().any(|&word| word != 0);
    if is_valid {
        // Success
    }
    
    Ok(())
}

/// Demonstrate SHA-512 hash computation
fn demo_sha512(digest_client: &Digest) -> Result<(), DigestError> {
    let test_data = b"SHA-512 provides the largest digest size in the SHA-2 family";
    
    let session_id = digest_client.init_sha512()?;
    digest_client.update(session_id, test_data.len() as u32, test_data)?;
    
    let mut digest_output = [0u32; 16];
    digest_client.finalize_sha512(session_id, &mut digest_output)?;
    
    // Verify digest was computed
    let is_valid = digest_output.iter().any(|&word| word != 0);
    if is_valid {
        // Success
    }
    
    Ok(())
}

/// Demonstrate streaming hash computation for large data
fn demo_streaming_hash(digest_client: &Digest) -> Result<(), DigestError> {
    // Simulate hashing a large file by streaming chunks
    let session_id = digest_client.init_sha256()?;
    
    // Hash multiple chunks of data
    let chunks: &[&[u8]] = &[
        b"This is chunk 1 of a large data stream.",
        b"This is chunk 2 with more data to hash.",
        b"This is chunk 3 continuing the stream.",
        b"This is the final chunk 4 of our data.",
    ];
    
    for chunk in chunks.iter() {
        digest_client.update(session_id, chunk.len() as u32, chunk)?;
    }
    
    let mut digest_output = [0u32; 8];
    digest_client.finalize_sha256(session_id, &mut digest_output)?;
    
    // Verify the streaming hash worked
    let is_valid = digest_output.iter().any(|&word| word != 0);
    if is_valid {
        // Streaming hash successful
    }
    
    Ok(())
}

/// Demonstrate one-shot hash computation
fn demo_oneshot_hash(digest_client: &Digest) -> Result<(), DigestError> {
    let test_data = b"One-shot hash example data";
    
    // Use one-shot API for simple cases
    let mut digest_output = [0u32; 8];
    digest_client.digest_oneshot_sha256(
        test_data.len() as u32,
        test_data,
        &mut digest_output
    )?;
    
    // Verify the one-shot hash worked
    let is_valid = digest_output.iter().any(|&word| word != 0);
    if is_valid {
        // One-shot hash successful
    }
    
    Ok(())
}

/// Example of SPDM attestation workflow using digest service
/// This demonstrates a real-world use case for the digest API
fn demo_spdm_attestation(digest_client: &Digest) -> Result<(), DigestError> {
    // Simulate SPDM device attestation process
    
    // 1. Hash device certificate chain
    let cert_data = b"DEVICE_CERTIFICATE_CHAIN_DATA";
    let cert_session = digest_client.init_sha256()?;
    digest_client.update(cert_session, cert_data.len() as u32, cert_data)?;
    
    let mut cert_hash = [0u32; 8];
    digest_client.finalize_sha256(cert_session, &mut cert_hash)?;
    
    // 2. Hash measurement data
    let measurement_data = b"DEVICE_MEASUREMENT_DATA";
    let measurement_session = digest_client.init_sha256()?;
    digest_client.update(measurement_session, measurement_data.len() as u32, measurement_data)?;
    
    let mut measurement_hash = [0u32; 8];
    digest_client.finalize_sha256(measurement_session, &mut measurement_hash)?;
    
    // 3. Combine hashes for final attestation
    let combined_session = digest_client.init_sha256()?;
    
    // Hash the certificate hash
    let cert_bytes = unsafe {
        core::slice::from_raw_parts(
            cert_hash.as_ptr() as *const u8,
            cert_hash.len() * 4
        )
    };
    digest_client.update(combined_session, cert_bytes.len() as u32, cert_bytes)?;
    
    // Hash the measurement hash
    let measurement_bytes = unsafe {
        core::slice::from_raw_parts(
            measurement_hash.as_ptr() as *const u8,
            measurement_hash.len() * 4
        )
    };
    digest_client.update(combined_session, measurement_bytes.len() as u32, measurement_bytes)?;
    
    // Final attestation hash
    let mut attestation_hash = [0u32; 8];
    digest_client.finalize_sha256(combined_session, &mut attestation_hash)?;
    
    // In a real system, this attestation hash would be signed and sent to the verifier
    let is_valid = attestation_hash.iter().any(|&word| word != 0);
    if is_valid {
        // Attestation hash computed successfully
    }
    
    Ok(())
}

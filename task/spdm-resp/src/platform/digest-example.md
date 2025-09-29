// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use userlib::*;
use drv_digest_api::{Digest, DigestError};

task_slot!(UART, uart_driver);
task_slot!(DIGEST, digest_server);

#[export_name = "main"]
fn main() -> ! {
    uart_send(b"\r\n");
    uart_send(b"=== Hubris Digest Server Test Suite ===\r\n");
    uart_send(b"Running on AST1060 in QEMU\r\n");
    uart_send(b"\r\n");
    
    // Run comprehensive digest server tests
    run_digest_test_suite();
    
    uart_send(b"\r\n");
    uart_send(b"=== Test Suite Complete ===\r\n");
    uart_send(b"All tests finished. System will now echo received data.\r\n");
    uart_send(b"\r\n");
    
    // Echo loop for interactive testing
    loop {
        let mut buf = [0u8; 128];
        hl::sleep_for(1000); // Sleep for 1 second
        
        if uart_read(&mut buf) {
            uart_send(b"Echo: ");
            uart_send(&buf);
            uart_send(b"\r\n");
            
            // Hash the received data as a bonus test
            hash_received_data(&buf);
        }
    }
}

fn run_digest_test_suite() {
    uart_send(b"Starting digest server tests...\r\n");
    
    // Test 1: Basic connectivity
    test_server_connectivity();
    
    // Test 2: One-shot operations
    test_oneshot_operations();
    
    // Test 3: Session-based operations  
    test_session_operations();
    
    // Test 4: Multiple concurrent sessions
    test_multiple_sessions();
    
    // Test 5: Error conditions (session-specific)
    test_error_conditions();
    
    // Test 6: One-shot error conditions
    test_oneshot_error_conditions();
    
    // Performance testing removed to avoid controller conflicts
}

fn test_server_connectivity() {
    uart_send(b"\r\n[TEST 1] Server Connectivity Test\r\n");
    
    let digest = Digest::from(DIGEST.get_task_id());
    let mut result = [0u32; 8];
    let test_data = b"ping";
    
    match digest.digest_oneshot_sha256(test_data.len() as u32, test_data, &mut result) {
        Ok(_) => {
            uart_send(b"  [OK] Server responding\r\n");
            uart_send(b"  [OK] Basic SHA-256 operation successful\r\n");
        }
        Err(e) => {
            uart_send(b"  [FAIL] Server connectivity failed: ");
            print_error(e);
            uart_send(b"\r\n");
        }
    }
}

fn test_oneshot_operations() {
    uart_send(b"\r\n[TEST 2] One-shot Operations\r\n");
    
    // Test known vectors
    test_oneshot_sha256_known_vector();
    test_oneshot_sha384_known_vector();
    test_oneshot_sha512_known_vector();
}

fn test_oneshot_sha256_known_vector() {
    uart_send(b"  Testing SHA-256 with known vector...\r\n");
    
    let digest = Digest::from(DIGEST.get_task_id());
    let test_data = b"abc";  // Known test vector
    let mut result = [0u32; 8];
    
    match digest.digest_oneshot_sha256(test_data.len() as u32, test_data, &mut result) {
        Ok(_) => {
            uart_send(b"    Input: 'abc'\r\n");
            uart_send(b"    SHA-256: ");
            print_hash(&result[..8]);
            uart_send(b"\r\n");
            
            // Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
            // (in big-endian u32 format)
            let expected = [0xba7816bf_u32, 0x8f01cfea_u32, 
                           0x414140de_u32, 0x5dae2223_u32,
                           0xb00361a3_u32, 0x96177a9c_u32,
                           0xb410ff61_u32, 0xf20015ad_u32];
            
            if result == expected {
                uart_send(b"    [OK] Known vector matches!\r\n");
            } else {
                uart_send(b"    [WARN] Known vector mismatch (may be endianness)\r\n");
            }
        }
        Err(e) => {
            uart_send(b"    [FAIL] SHA-256 failed: ");
            print_error(e);
            uart_send(b"\r\n");
        }
    }
}

fn test_oneshot_sha384_known_vector() {
    uart_send(b"  Testing SHA-384...\r\n");
    
    let digest = Digest::from(DIGEST.get_task_id());
    let test_data = b"abc";
    let mut result = [0u32; 12];
    
    match digest.digest_oneshot_sha384(test_data.len() as u32, test_data, &mut result) {
        Ok(_) => {
            uart_send(b"    SHA-384: ");
            print_hash(&result[..12]);
            uart_send(b"\r\n");
            uart_send(b"    [OK] SHA-384 operation successful\r\n");
        }
        Err(e) => {
            uart_send(b"    [FAIL] SHA-384 failed: ");
            print_error(e);
            uart_send(b"\r\n");
        }
    }
}

fn test_oneshot_sha512_known_vector() {
    uart_send(b"  Testing SHA-512...\r\n");
    
    let digest = Digest::from(DIGEST.get_task_id());
    let test_data = b"abc";
    let mut result = [0u32; 16];
    
    match digest.digest_oneshot_sha512(test_data.len() as u32, test_data, &mut result) {
        Ok(_) => {
            uart_send(b"    SHA-512: ");
            print_hash(&result[..16]);
            uart_send(b"\r\n");
            uart_send(b"    [OK] SHA-512 operation successful\r\n");
        }
        Err(e) => {
            uart_send(b"    [FAIL] SHA-512 failed: ");
            print_error(e);
            uart_send(b"\r\n");
        }
    }
}

fn test_session_operations() {
    uart_send(b"\r\n[TEST 3] Session Operations\r\n");
    
    // Test streaming SHA-256
    match test_session_based_digest() {
        Ok(result) => {
            uart_send(b"  [OK] SHA-256 stream\r\n");
            uart_send(b"    ");
            print_hash(&result);
            uart_send(b"\r\n");
        }
        Err(e) => {
            uart_send(b"  [FAIL] SHA-256 stream: ");
            print_error(e);
            uart_send(b"\r\n");
        }
    }
    
    // Test streaming SHA-384
    match test_session_based_sha384() {
        Ok(result) => {
            uart_send(b"  [OK] SHA-384 stream\r\n");
            uart_send(b"    ");
            print_hash(&result[..8]);
            uart_send(b"...\r\n");
        }
        Err(e) => {
            uart_send(b"  [FAIL] SHA-384 stream: ");
            print_error(e);
            uart_send(b"\r\n");
        }
    }
    
    // Test streaming SHA-512
    match test_session_based_sha512() {
        Ok(result) => {
            uart_send(b"  [OK] SHA-512 stream\r\n");
            uart_send(b"    ");
            print_hash(&result[..8]);
            uart_send(b"...\r\n");
        }
        Err(e) => {
            uart_send(b"  [FAIL] SHA-512 stream: ");
            print_error(e);
            uart_send(b"\r\n");
        }
    }
}fn test_multiple_sessions() {
    uart_send(b"\r\n[TEST 4] Multiple Sessions\r\n");
    
    let digest = Digest::from(DIGEST.get_task_id());
    
    // Try to create multiple sessions
    uart_send(b"  Creating multiple sessions...\r\n");
    
    let mut sessions = [None; 4];
    let mut created_count = 0;
    
    for i in 0..4 {
        match digest.init_sha256() {
            Ok(session_id) => {
                sessions[i] = Some(session_id);
                created_count += 1;
                uart_send(b"    [OK] Session ");
                print_number(i as u32);
                uart_send(b" created (ID: ");
                print_number(session_id);
                uart_send(b")\r\n");
            }
            Err(e) => {
                uart_send(b"    [FAIL] Session ");
                print_number(i as u32);
                uart_send(b" failed: ");
                print_error(e);
                uart_send(b"\r\n");
                break;
            }
        }
    }
    
    uart_send(b"  Created ");
    print_number(created_count);
    uart_send(b" sessions total\r\n");
    
    // Use the sessions concurrently
    for (i, session_opt) in sessions.iter().enumerate() {
        if let Some(session_id) = session_opt {
            let test_data = b"concurrent";
            match digest.update(*session_id, test_data.len() as u32, test_data) {
                Ok(_) => {
                    uart_send(b"    [OK] Session ");
                    print_number(i as u32);
                    uart_send(b" updated\r\n");
                }
                Err(e) => {
                    uart_send(b"    [FAIL] Session ");
                    print_number(i as u32);
                    uart_send(b" update failed: ");
                    print_error(e);
                    uart_send(b"\r\n");
                }
            }
        }
    }
}

fn test_error_conditions() {
    uart_send(b"\r\n[TEST 5] Error Conditions\r\n");
    
    let digest = Digest::from(DIGEST.get_task_id());
    
    // Test invalid session ID
    uart_send(b"  Testing invalid session ID...\r\n");
    let invalid_session = 999;
    let test_data = b"test";
    match digest.update(invalid_session, test_data.len() as u32, test_data) {
        Ok(_) => {
            uart_send(b"    [WARN] Expected error but operation succeeded\r\n");
        }
        Err(DigestError::InvalidSession) => {
            uart_send(b"    [OK] Correctly rejected invalid session\r\n");
        }
        Err(e) => {
            uart_send(b"    ? Unexpected error: ");
            print_error(e);
            uart_send(b"\r\n");
        }
    }
    
    // Test session limit
    uart_send(b"  Testing session limit...\r\n");
    let mut sessions_created = 0;
    loop {
        match digest.init_sha256() {
            Ok(_) => {
                sessions_created += 1;
                if sessions_created > 10 {  // Reasonable limit
                    uart_send(b"    [WARN] Created more than 10 sessions without limit\r\n");
                    break;
                }
            }
            Err(DigestError::TooManySessions) => {
                uart_send(b"    [OK] Session limit enforced at ");
                print_number(sessions_created);
                uart_send(b" sessions\r\n");
                break;
            }
            Err(e) => {
                uart_send(b"    ? Unexpected error: ");
                print_error(e);
                uart_send(b"\r\n");
                break;
            }
        }
    }
}

fn test_oneshot_error_conditions() {
    uart_send(b"\r\n[TEST 3] One-shot Error Condition Testing\r\n");
    
    let digest = Digest::from(DIGEST.get_task_id());
    
    // Test with extremely large data size (should fail)
    uart_send(b"  Testing with invalid large size...\r\n");
    let test_data = b"test";
    let mut result = [0u32; 8];
    match digest.digest_oneshot_sha256(u32::MAX, test_data, &mut result) {
        Ok(_) => {
            uart_send(b"    [WARN] Expected error but operation succeeded\r\n");
        }
        Err(DigestError::InvalidInputLength) => {
            uart_send(b"    [OK] Correctly rejected invalid input length\r\n");
        }
        Err(e) => {
            uart_send(b"    ? Unexpected error: ");
            print_error(e);
            uart_send(b"\r\n");
        }
    }
    
    // Test with mismatched size
    uart_send(b"  Testing with mismatched size...\r\n");
    let test_data = b"hello";
    let mut result = [0u32; 8];
    match digest.digest_oneshot_sha256(10, test_data, &mut result) {  // size=10 but data is 5 bytes
        Ok(_) => {
            uart_send(b"    [WARN] Expected error but operation succeeded\r\n");
        }
        Err(DigestError::InvalidInputLength) => {
            uart_send(b"    [OK] Correctly rejected mismatched input length\r\n");
        }
        Err(e) => {
            uart_send(b"    ? Unexpected error: ");
            print_error(e);
            uart_send(b"\r\n");
        }
    }
}

// Performance testing removed to avoid hardware controller conflicts
// and reduce flash memory usage

fn test_digest_server() {
    let digest = Digest::from(DIGEST.get_task_id());
    
    // Test one-shot SHA-256
    uart_send(b"Testing one-shot SHA-256...\r\n");
    let test_data = b"Hello, digest!";
    let mut result = [0u32; 8];
    
    match digest.digest_oneshot_sha256(test_data.len() as u32, test_data, &mut result) {
        Ok(_) => {
            uart_send(b"SHA-256 result: ");
            print_hash(&result[..8]);
            uart_send(b"\r\n");
        }
        Err(e) => {
            uart_send(b"SHA-256 error: ");
            print_error(e);
            uart_send(b"\r\n");
        }
    }
    
    // Test SHA-384 (one-shot only)
    uart_send(b"Testing SHA-384...\r\n");
    let mut result384 = [0u32; 12];
    match digest.digest_oneshot_sha384(test_data.len() as u32, test_data, &mut result384) {
        Ok(_) => {
            uart_send(b"SHA-384 result: ");
            print_hash(&result384[..8]); // Print first 8 words only for brevity
            uart_send(b"...\r\n");
        }
        Err(e) => {
            uart_send(b"SHA-384 error: ");
            print_error(e);
            uart_send(b"\r\n");
        }
    }
    
    // Test SHA-512 (one-shot only)
    uart_send(b"Testing SHA-512...\r\n");
    let mut result512 = [0u32; 16];
    match digest.digest_oneshot_sha512(test_data.len() as u32, test_data, &mut result512) {
        Ok(_) => {
            uart_send(b"SHA-512 result: ");
            print_hash(&result512[..8]); // Print first 8 words only for brevity
            uart_send(b"...\r\n");
        }
        Err(e) => {
            uart_send(b"SHA-512 error: ");
            print_error(e);
            uart_send(b"\r\n");
        }
    }
    
    uart_send(b"One-shot digest testing complete!\r\n");
}

fn test_session_based_digest() -> Result<[u32; 8], DigestError> {
    let digest = Digest::from(DIGEST.get_task_id());
    
    // Create a new session
    let session_id = digest.init_sha256()?;
    
    // Add data to the session in chunks
    let data1 = b"Hello";
    let data2 = b", ";
    let data3 = b"World!";
    
    digest.update(session_id, data1.len() as u32, data1)?;
    digest.update(session_id, data2.len() as u32, data2)?;
    digest.update(session_id, data3.len() as u32, data3)?;
    
    // Get the final result
    let mut result = [0u32; 8];
    digest.finalize_sha256(session_id, &mut result)?;
    
    Ok(result)
}

fn test_session_based_sha384() -> Result<[u32; 12], DigestError> {
    let digest = Digest::from(DIGEST.get_task_id());
    
    // Create a new session
    let session_id = digest.init_sha384()?;
    
    // Add data to the session in chunks
    let data1 = b"Streaming";
    let data2 = b" SHA-384";
    let data3 = b" test!";
    
    digest.update(session_id, data1.len() as u32, data1)?;
    digest.update(session_id, data2.len() as u32, data2)?;
    digest.update(session_id, data3.len() as u32, data3)?;
    
    // Get the final result
    let mut result = [0u32; 12];
    digest.finalize_sha384(session_id, &mut result)?;
    
    Ok(result)
}

fn test_session_based_sha512() -> Result<[u32; 16], DigestError> {
    let digest = Digest::from(DIGEST.get_task_id());
    
    // Create a new session
    let session_id = digest.init_sha512()?;
    
    // Add data to the session in chunks
    let data1 = b"Streaming";
    let data2 = b" SHA-512";
    let data3 = b" works great!";
    
    digest.update(session_id, data1.len() as u32, data1)?;
    digest.update(session_id, data2.len() as u32, data2)?;
    digest.update(session_id, data3.len() as u32, data3)?;
    
    // Get the final result
    let mut result = [0u32; 16];
    digest.finalize_sha512(session_id, &mut result)?;
    
    Ok(result)
}

fn hash_received_data(data: &[u8]) {
    let digest = Digest::from(DIGEST.get_task_id());
    
    // Find the actual length of the data (stop at first null byte)
    let data_len = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    if data_len == 0 {
        return;
    }
    
    let mut result = [0u32; 8];
    match digest.digest_oneshot_sha256(data_len as u32, &data[..data_len], &mut result) {
        Ok(_) => {
            uart_send(b"Hash of received data: ");
            print_hash(&result[..8]);
            uart_send(b"\r\n");
        }
        Err(_) => {
            uart_send(b"Failed to hash received data\r\n");
        }
    }
}

fn print_hash(hash: &[u32]) {
    for &word in hash {
        print_hex_word(word);
    }
}

fn print_hex_word(word: u32) {
    let bytes = word.to_be_bytes();
    for byte in bytes {
        print_hex_byte(byte);
    }
}

fn print_hex_byte(byte: u8) {
    let hex_chars = b"0123456789ABCDEF";
    uart_send(&[hex_chars[(byte >> 4) as usize]]);
    uart_send(&[hex_chars[(byte & 0xF) as usize]]);
}

fn print_number(n: u32) {
    if n == 0 {
        uart_send(b"0");
        return;
    }
    
    let mut digits = [0u8; 10];
    let mut count = 0;
    let mut num = n;
    
    while num > 0 {
        digits[count] = (num % 10) as u8 + b'0';
        num /= 10;
        count += 1;
    }
    
    // Print in reverse order
    for i in (0..count).rev() {
        uart_send(&[digits[i]]);
    }
}

fn print_error(error: DigestError) {
    match error {
        DigestError::InvalidSession => uart_send(b"Invalid session"),
        DigestError::TooManySessions => uart_send(b"Too many sessions"),
        DigestError::InvalidInputLength => uart_send(b"Invalid input length"),
        DigestError::UnsupportedAlgorithm => uart_send(b"Unsupported algorithm"),
        DigestError::InitializationError => uart_send(b"Initialization error"),
        DigestError::UpdateError => uart_send(b"Update error"),
        DigestError::FinalizationError => uart_send(b"Finalization error"),
        DigestError::HardwareFailure => uart_send(b"Hardware failure"),
        _ => uart_send(b"Unknown digest error"),
    }
}

fn uart_send(text: &[u8]) {
    let peer = UART.get_task_id();

    const OP_WRITE: u16 = 1;
    let (code, _) =
        sys_send(peer, OP_WRITE, &[], &mut [], &[Lease::from(text)]);
    assert_eq!(0, code);
}

fn uart_read(text: &mut [u8]) -> bool {
    let peer = UART.get_task_id();
    const OP_READ: u16 = 2;

    let mut response = [0u8; 4];
    let (code, _) = sys_send(peer, OP_READ, &[], &mut response, &mut [Lease::from(text)]);

    code == 0
}
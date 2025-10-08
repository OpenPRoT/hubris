// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ECDSA Test Task
//!
//! This task tests the OpenPRoT ECDSA server by performing basic
//! cryptographic operations.

#![no_std]
#![no_main]

use drv_openprot_ecdsa_api::{EcdsaError, OpenPRoTEcdsa};
use userlib::{task_slot, hl, sys_send, Lease, UnwrapLite};

task_slot!(ECDSA_SERVER, ecdsa_server);
task_slot!(UART, uart_driver);

fn uart_send(text: &[u8]) {
    let peer = UART.get_task_id();
    const OP_WRITE: u16 = 1;
    let (code, _) = sys_send(peer, OP_WRITE, &[], &mut [], &[Lease::from(text)]);
    assert_eq!(0, code);
}

fn print(msg: &str) {
    uart_send(msg.as_bytes());
    uart_send(b"\r\n");
}

#[export_name = "main"]
fn main() -> ! {
    // Wait for other tasks to start
    hl::sleep_for(1000);
    
    print("ECDSA Test Task starting...");
    
    let ecdsa = OpenPRoTEcdsa::from(ECDSA_SERVER.get_task_id());
    
    // Simple test: try to sign a hash
    let test_hash = [0u8; 48]; // SHA-384 sized hash
    let mut signature_buf = [0u8; 96]; // P-384 signature: 48 bytes r + 48 bytes s
    
    print("Testing ECDSA signing...");
    match ecdsa.ecdsa384_sign(1, &test_hash, &mut signature_buf) {
        Ok(_) => print("✓ ECDSA signing succeeded"),
        Err(EcdsaError::HardwareNotAvailable) => print("⚠ ECDSA signing not available (verification-only server)"),
        Err(_) => print("✗ ECDSA signing failed"),
    }
    
    // Simple test: try to verify a signature
    let test_pubkey = [0u8; 96]; // P-384 public key: 48 bytes x + 48 bytes y (raw coordinates)
    let test_signature = [0u8; 96]; // P-384 signature: 48 bytes r + 48 bytes s (raw components)
    
    print("Testing ECDSA verification...");
    match ecdsa.ecdsa384_verify(&test_hash, &test_signature, &test_pubkey) {
        Ok(valid) => {
            if valid {
                print("✓ ECDSA verification succeeded (signature valid)");
            } else {
                print("✓ ECDSA verification succeeded (signature invalid)");
            }
        },
        Err(EcdsaError::HardwareNotAvailable) => print("⚠ ECDSA verification not available"),
        Err(_) => print("✗ ECDSA verification failed"),
    }
    
    print("ECDSA tests completed");
    
    // Main task loop
    loop {
        hl::sleep_for(10000);
        print("ECDSA test task alive");
    }
}
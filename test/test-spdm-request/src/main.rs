use std::{env::var, time::Duration};

use mctp::*;
use mctp_linux::*;

const DEFAULT_REMOTE_EID: u8 = 42;  // SPDM responder EID
const SPDM_MSG_TYPE: u8 = 5;        // SPDM message type
const TIMEOUT_SECS: u64 = 10;

/// SPDM test application that sends SPDM requests to the responder
/// Set REMOTE_EID environment variable to change target (default: 42)
fn main() {
    let eid: u8 = var("REMOTE_EID")
        .map(|e| e.parse().unwrap_or(DEFAULT_REMOTE_EID))
        .unwrap_or(DEFAULT_REMOTE_EID);

    println!("Creating MCTP connection to SPDM responder at EID {}", eid);

    let mut req = MctpLinuxReq::new(mctp::Eid(eid), None).unwrap();
    req.as_socket()
        .set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))
        .unwrap();

    // SPDM GET_VERSION request (simplest SPDM command)
    // Format: [SPDM version, request code, param1, param2]
    let spdm_get_version = [
        0x10,  // SPDM version 1.0
        0x84,  // GET_VERSION request code
        0x00,  // Param1 (reserved)
        0x00,  // Param2 (reserved)
    ];

    println!("Sending SPDM GET_VERSION request...");
    println!("Request data: {:02x?}", spdm_get_version);

    req.send(mctp::MsgType(SPDM_MSG_TYPE), &spdm_get_version).unwrap();

    println!("Sent SPDM message to EID {}", eid);

    let mut buf = [0; 1024];  // Larger buffer for SPDM responses
    match req.recv(&mut buf) {
        Ok((_, _, resp)) => {
            println!("Received SPDM response ({} bytes): {:02x?}", resp.len(), resp);
            
            if resp.len() >= 4 {
                let version = resp[0];
                let response_code = resp[1];
                let param1 = resp[2];
                let param2 = resp[3];
                
                println!("SPDM Response parsed:");
                println!("  Version: 0x{:02x}", version);
                println!("  Response code: 0x{:02x}", response_code);
                println!("  Param1: 0x{:02x}", param1);
                println!("  Param2: 0x{:02x}", param2);
                
                if response_code == 0x04 {  // VERSION response
                    println!("✓ Received valid SPDM VERSION response!");
                } else {
                    println!("⚠ Unexpected response code: 0x{:02x}", response_code);
                }
            }
        }
        Err(e) => {
            println!("Error receiving response: {:?}", e);
            println!("This might indicate the SPDM responder is not responding or there's a transport issue");
        }
    }
}
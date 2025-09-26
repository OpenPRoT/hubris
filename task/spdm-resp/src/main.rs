// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! SPDM Responder Task
//!
//! This task implements an SPDM (Security Protocol and Data Model) responder
//! that receives SPDM requests over MCTP and responds according to the SPDM
//! specification. It uses the external spdm-lib for protocol implementation.

#![no_std]
#![no_main]

extern crate alloc;
use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

use mctp::RespChannel;
use mctp::{Eid, Listener, MsgType};
use mctp_api::Stack;
use userlib::*;
use spdm_lib::platform::transport::{SpdmTransport, TransportResult, TransportError};
use spdm_lib::codec::MessageBuf;

/// MCTP-based SPDM Transport implementation
/// This is a minimal stub since our architecture handles transport through the MCTP listener
pub struct MctpSpdmTransport <'a, T: Listener>{
    listener: &'a T,
}

impl <'a, T: Listener> MctpSpdmTransport <'a, T> {
    pub fn new(listener: &'a T) -> Self {
        Self { listener }
    }
}

impl<'a, T: Listener> SpdmTransport for MctpSpdmTransport<'a, T> {
    fn send_request(&mut self, _dest_eid: u8, _req: &mut MessageBuf) -> TransportResult<()> {
        // For a responder, we don't typically send requests
        Err(TransportError::ResponseNotExpected)
    }

    fn receive_response(&mut self, _rsp: &mut MessageBuf) -> TransportResult<()> {
        // For a responder, we don't typically receive responses
        Err(TransportError::ResponseNotExpected)
    }

    fn receive_request(&mut self, _req: &mut MessageBuf) -> TransportResult<()> {
        // MCTP receive is handled by the listener in the main loop
        // This method is not used in our async architecture
        Err(TransportError::ReceiveError)
    }

    fn send_response(&mut self, _resp: &mut MessageBuf) -> TransportResult<()> {
        // Response sending is handled directly in the main loop via response_channel
        // This transport is just a stub to satisfy the SPDM library interface
        Ok(())
    }

    fn max_message_size(&self) -> TransportResult<usize> {
        Ok(SPDM_BUFFER_SIZE)
    }

    fn header_size(&self) -> usize {
        0 // MCTP header is handled by the MCTP layer
    }
}

// SPDM uses MCTP Message Type 5 according to DMTF specifications
const SPDM_MSG_TYPE: MsgType = MsgType(5);

// SPDM responder endpoint ID - should be configurable
const SPDM_RESPONDER_EID: Eid = Eid(42);

// Buffer size for SPDM messages (can be large due to certificates)
const SPDM_BUFFER_SIZE: usize = 4096;

task_slot!(MCTP, mctp_server);

#[export_name = "main"]
fn main() -> ! {
    // Initialize the heap allocator
    const HEAP_SIZE: usize = 8192; // 8KB heap
    static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
    unsafe { ALLOCATOR.lock().init(HEAP.as_mut_ptr(), HEAP_SIZE) };

    // Connect to MCTP server task
    let mctp_stack = Stack::from(MCTP.get_task_id());

    // Set our SPDM responder endpoint ID
    if let Err(e) = mctp_stack.set_eid(SPDM_RESPONDER_EID) {
        // Log error and panic - EID setup is critical
        panic!("Failed to set SPDM responder EID: {:?}", e);
    }

    // Create listener for SPDM messages (Message Type 5)
    let mut listener = match mctp_stack.listener(SPDM_MSG_TYPE, None) {
        Ok(l) => l,
        Err(e) => panic!("Failed to create SPDM listener: {:?}", e),
    };

    let mut recv_buffer = [0u8; SPDM_BUFFER_SIZE];

    // TODO: Initialize SPDM responder context using spdm-lib
    // This would involve setting up:
    // - Certificate chains
    // - Supported algorithms
    // - Measurement values
    // - Crypto providers

    // TODO: Test the normal flow - requires an external SPDM client
    // communicating over UART since the MCTP server only handles serial transport.
    // The external client should send basic requests to verify the responder:
    // 1. Send GET_VERSION request to test version negotiation
    // 2. Send GET_CAPABILITIES request to test capability exchange
    // 3. Verify responses are properly formatted and routed back over UART
    // This would help validate the MCTP-over-UART transport and SPDM message handling

    loop {
        // Wait for incoming SPDM request over MCTP
        match listener.recv(&mut recv_buffer) {
            Ok((msg_type, _msg_ic, spdm_request, mut response_channel)) => {
                // Verify this is indeed an SPDM message
                if msg_type != SPDM_MSG_TYPE {
                    // Log warning and continue - shouldn't happen with proper listener setup
                    continue;
                }

                // Process SPDM request using spdm-lib
                let spdm_response = process_spdm_request(spdm_request);

                // Send SPDM response back via MCTP
                if let Err(_e) = response_channel.send(&spdm_response) {
                    // Log error - response send failed
                    // In a production system, might want to retry or handle differently
                }
            }
            Err(_e) => {
                // Handle receive error
                // In a production system, might want to implement exponential backoff
                // or other error recovery strategies
            }
        }
    }
}

/// Process an incoming SPDM request and generate appropriate response
///
/// This function will use spdm-lib to:
/// 1. Parse the incoming SPDM request
/// 2. Validate the request according to SPDM protocol state
/// 3. Generate the appropriate SPDM response
/// 4. Return the serialized response bytes
fn process_spdm_request(_request: &[u8]) -> heapless::Vec<u8, SPDM_BUFFER_SIZE> {
    // TODO: Implement actual SPDM processing using spdm-lib
    // This is a placeholder implementation

    // For now, return a minimal SPDM error response
    // In a real implementation, this would:
    // 1. Use spdm_lib::Responder to process the request
    // 2. Handle various SPDM commands (GET_VERSION, GET_CAPABILITIES, etc.)
    // 3. Maintain session state
    // 4. Perform crypto operations

    let mut response = heapless::Vec::new();

    // Placeholder: Return SPDM ERROR response (0x7F)
    // Real implementation would parse request and generate proper response
    response.push(0x10).ok(); // SPDM version 1.0
    response.push(0x7F).ok(); // ERROR response code
    response.push(0x01).ok(); // Error code: INVALID_REQUEST
    response.push(0x00).ok(); // Error data

    response
}
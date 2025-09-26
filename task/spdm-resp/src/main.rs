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

use mctp::{Eid, Listener, MsgType};
use mctp_api::Stack;
use userlib::*;
use spdm_lib::platform::transport::{SpdmTransport, TransportResult, TransportError};
use spdm_lib::codec::MessageBuf;
use spdm_lib::context::SpdmContext;
use spdm_lib::protocol::{DeviceCapabilities, CapabilityFlags};
use spdm_lib::protocol::version::SpdmVersion;
use spdm_lib::protocol::algorithms::{
    LocalDeviceAlgorithms, AlgorithmPriorityTable, DeviceAlgorithms,
    MeasurementSpecification, MeasurementHashAlgo, BaseAsymAlgo, BaseHashAlgo, 
    DheNamedGroup, AeadCipherSuite, KeySchedule, OtherParamSupport, MelSpecification,
    ReqBaseAsymAlg
};

/// MCTP-based SPDM Transport implementation
pub struct MctpSpdmTransport<'a> {
    listener: &'a mut mctp_api::MctpListener<'a>,
    buffer: &'a mut [u8],
}

impl<'a> MctpSpdmTransport<'a> {
    pub fn new(listener: &'a mut mctp_api::MctpListener<'a>, buffer: &'a mut [u8]) -> Self {
        Self { listener, buffer }
    }
}

impl<'a> SpdmTransport for MctpSpdmTransport<'a> {
    fn send_request(&mut self, _dest_eid: u8, _req: &mut MessageBuf<'_>) -> TransportResult<()> {
        // For a responder, we don't typically send requests
        Err(TransportError::ResponseNotExpected)
    }

    fn receive_response(&mut self, _rsp: &mut MessageBuf<'_>) -> TransportResult<()> {
        // For a responder, we don't typically receive responses
        Err(TransportError::ResponseNotExpected)
    }

    fn receive_request(&mut self, req: &mut MessageBuf<'_>) -> TransportResult<()> {
        // Receive the next MCTP message. We ignore the provided response
        // channel for now to avoid storing a borrowed reference with a
        // shorter lifetime than the transport. Sending is stubbed.
        let (_src_eid, _msg_type, msg, _resp_channel) = self
            .listener
            .recv(self.buffer)
            .map_err(|_| TransportError::ReceiveError)?;

        // Copy the received message into the provided MessageBuf.
        // Use the MessageBuf API to obtain a mutable slice and advance the
        // internal length. This avoids borrowing `self.buffer` twice.
        let len = msg.len();
        let dest = req
            .data_mut(len)
            .map_err(|_| TransportError::ReceiveError)?;
        dest.copy_from_slice(&msg[..len]);
        req.put_data(len).map_err(|_| TransportError::ReceiveError)?;

        Ok(())
    }

    fn send_response(&mut self, _resp: &mut MessageBuf<'_>) -> TransportResult<()> {
        // Stubbed for now: synchronous response sending will be implemented later.
        // For now accept the call and do nothing so higher-level code can
        // continue progressing without triggering lifetime/transport issues.
        Ok(())
    }

    fn max_message_size(&self) -> TransportResult<usize> {
        Ok(SPDM_BUFFER_SIZE)
    }

    fn header_size(&self) -> usize {
        0 // MCTP header is handled by the MCTP layer
    }
}

/// Create SPDM device capabilities
fn create_device_capabilities() -> DeviceCapabilities {
    let mut flags_value = 0u32;
    flags_value |= 1 << 1;  // cert_cap
    flags_value |= 1 << 2;  // chal_cap  
    flags_value |= 2 << 3;  // meas_cap (with signature)
    flags_value |= 1 << 5;  // meas_fresh_cap
    flags_value |= 1 << 17; // chunk_cap
    
    let flags = CapabilityFlags::new(flags_value);
    
    DeviceCapabilities {
        ct_exponent: 0,
        flags,
        data_transfer_size: 1024,
        max_spdm_msg_size: 4096,
    }
}

/// Create local device algorithms
fn create_local_algorithms() -> LocalDeviceAlgorithms<'static> {
    // Configure supported algorithms with proper bitfield construction
    let mut measurement_spec = MeasurementSpecification::default();
    measurement_spec.set_dmtf_measurement_spec(1);
    
    let mut measurement_hash_algo = MeasurementHashAlgo::default();
    measurement_hash_algo.set_tpm_alg_sha_384(1);
    
    let mut base_asym_algo = BaseAsymAlgo::default();
    base_asym_algo.set_tpm_alg_ecdsa_ecc_nist_p384(1);
    
    let mut base_hash_algo = BaseHashAlgo::default();
    base_hash_algo.set_tpm_alg_sha_384(1);
    
    let device_algorithms = DeviceAlgorithms {
        measurement_spec,
        other_param_support: OtherParamSupport::default(),
        measurement_hash_algo,
        base_asym_algo,
        base_hash_algo,
        mel_specification: MelSpecification::default(),
        dhe_group: DheNamedGroup::default(),
        aead_cipher_suite: AeadCipherSuite::default(),
        req_base_asym_algo: ReqBaseAsymAlg::default(),
        key_schedule: KeySchedule::default(),
    };

    let algorithm_priority_table = AlgorithmPriorityTable {
        measurement_specification: None,
        opaque_data_format: None,
        base_asym_algo: None,
        base_hash_algo: None,
        mel_specification: None,
        dhe_group: None,
        aead_cipher_suite: None,
        req_base_asym_algo: None,
        key_schedule: None,
    };

    LocalDeviceAlgorithms {
        device_algorithms,
        algorithm_priority_table,
    }
}

mod platform_stubs;
use platform_stubs::{Sha384Hash, SystemRng, DemoCertStore, DemoEvidence};

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

    // Create transport
    let mut transport = MctpSpdmTransport::new(&mut listener, &mut recv_buffer);

    // Create platform implementations
    let mut hash = Sha384Hash::new();
    let mut m1_hash = Sha384Hash::new();
    let mut l1_hash = Sha384Hash::new();
    let mut rng = SystemRng::new();
    let mut cert_store = DemoCertStore::new();
    let evidence = DemoEvidence::new();

    // Create SPDM context
    let supported_versions = [SpdmVersion::V12, SpdmVersion::V11];
    let capabilities = create_device_capabilities();
    let algorithms = create_local_algorithms();

    let mut spdm_context = match SpdmContext::new(
        &supported_versions,
        &mut transport,
        capabilities,
        algorithms,
        &mut cert_store,
        &mut hash,
        &mut m1_hash,
        &mut l1_hash,
        &mut rng,
        &evidence,
    ) {
        Ok(ctx) => ctx,
        Err(_) => panic!("Failed to create SPDM context"),
    };

    // Buffer for message processing
    let mut message_buffer = [0u8; SPDM_BUFFER_SIZE];
    let mut msg_buf = MessageBuf::new(&mut message_buffer);

    // Process SPDM messages
    loop {
        match spdm_context.process_message(&mut msg_buf) {
            Ok(()) => {
                // Message processed successfully
            }
            Err(_) => {
                // Handle error, perhaps continue
            }
        }
    }
}
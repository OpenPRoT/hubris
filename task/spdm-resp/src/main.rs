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
pub struct MctpSpdmTransport<'a, T: Listener> {
    listener: &'a mut T,
    buffer: &'a mut [u8],
    response_channel: Option<RespChannel>,
}

impl<'a, T: Listener> MctpSpdmTransport<'a, T> {
    pub fn new(listener: &'a mut T, buffer: &'a mut [u8]) -> Self {
        Self { listener, buffer, response_channel: None }
    }
}

impl<'a, T: Listener> SpdmTransport for MctpSpdmTransport<'a, T> {
    fn send_request(&mut self, _dest_eid: u8, _req: &mut MessageBuf<'_>) -> TransportResult<()> {
        // For a responder, we don't typically send requests
        Err(TransportError::ResponseNotExpected)
    }

    fn receive_response(&mut self, _rsp: &mut MessageBuf<'_>) -> TransportResult<()> {
        // For a responder, we don't typically receive responses
        Err(TransportError::ResponseNotExpected)
    }

    fn receive_request(&mut self, _req: &mut MessageBuf<'_>) -> TransportResult<()> {
        // Stub: do nothing for now
        Ok(())
    }

    fn send_response(&mut self, _resp: &mut MessageBuf<'_>) -> TransportResult<()> {
        // Stub: do nothing for now
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

// Stub platform implementations for no_std Hubris
use spdm_lib::platform::rng::{SpdmRng, SpdmRngError};
use spdm_lib::platform::hash::{SpdmHash, SpdmHashAlgoType};
use spdm_lib::cert_store::{SpdmCertStore, CertificateInfo, KeyUsageMask, CertStoreError};
use spdm_lib::protocol::algorithms::BaseAsymAlgo;
use spdm_lib::platform::evidence::{SpdmEvidence, SpdmEvidenceError};

struct Sha384Hash;
impl Sha384Hash {
    fn new() -> Self { Self }
}
impl SpdmHash for Sha384Hash {
    // Stub implementations - replace with real hash logic
    fn hash(&mut self, _data: &[u8]) -> Result<(), ()> { Ok(()) }
    fn init(&mut self) { }
    fn update(&mut self, _data: &[u8]) { }
    fn finalize(&mut self, _out: &mut [u8]) -> Result<(), ()> { Ok(()) }
    fn reset(&mut self) { }
    fn algo(&self) -> SpdmHashAlgoType { SpdmHashAlgoType::Sha384 }
}

struct SystemRng;
impl SystemRng {
    fn new() -> Self { Self }
}
impl SpdmRng for SystemRng {
    fn get_random_bytes(&mut self, dest: &mut [u8]) -> Result<(), SpdmRngError> {
        dest.fill(0); // Stub
        Ok(())
    }
    fn generate_random_number(&mut self, out: &mut [u8]) -> Result<(), SpdmRngError> {
        out.fill(0); // Stub
        Ok(())
    }
}

struct DemoCertStore;
impl DemoCertStore {
    fn new() -> Self { Self }
}
impl SpdmCertStore for DemoCertStore {
    // Stub implementations - replace with real cert store logic
    fn slot_count(&self) -> u8 { 1 }
    fn is_provisioned(&self, _slot: u8) -> bool { true }
    fn cert_chain_len(&mut self, _algo: BaseAsymAlgo, _slot: u8) -> Result<usize, CertStoreError> { Ok(0) }
    fn get_cert_chain(&mut self, _slot: u8, _algo: BaseAsymAlgo, _offset: usize, _out: &mut [u8]) -> Result<usize, CertStoreError> { Ok(0) }
    fn root_cert_hash(&mut self, _slot: u8, _algo: BaseAsymAlgo, _out: &mut [u8; 48]) -> Result<(), CertStoreError> { Ok(()) }
    fn sign_hash(&self, _slot: u8, _hash: &[u8; 48], _out: &mut [u8; 96]) -> Result<(), CertStoreError> { Ok(()) }
    fn key_pair_id(&self, _slot: u8) -> Option<u8> { Some(0) }
    fn cert_info(&self, _slot: u8) -> Option<CertificateInfo> { None }
    fn key_usage_mask(&self, _slot: u8) -> Option<KeyUsageMask> { None }
}

struct DemoEvidence;
impl DemoEvidence {
    fn new() -> Self { Self }
}
impl SpdmEvidence for DemoEvidence {
    // Stub implementations - replace with real evidence logic
    fn pcr_quote(&self, _pcr_index: &mut [u8], _out: &mut [u8]) -> Result<usize, SpdmEvidenceError> { Ok(0) }
    fn pcr_quote_size(&self, _pcr_index: bool) -> Result<usize, SpdmEvidenceError> { Ok(0) }
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
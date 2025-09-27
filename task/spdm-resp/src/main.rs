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

use mctp::ReqChannel;
use mctp::RespChannel;
use mctp::{Eid, Listener, MsgType};
use mctp_api::Stack;
use spdm_lib::codec::MessageBuf;
use spdm_lib::context::SpdmContext;
use spdm_lib::platform::transport::{
    SpdmTransport, TransportError, TransportResult,
};
use spdm_lib::protocol::algorithms::{
    AeadCipherSuite, AlgorithmPriorityTable, BaseAsymAlgo, BaseHashAlgo,
    DeviceAlgorithms, DheNamedGroup, KeySchedule, LocalDeviceAlgorithms,
    MeasurementHashAlgo, MeasurementSpecification, MelSpecification,
    OtherParamSupport, ReqBaseAsymAlg,
};
use spdm_lib::protocol::version::SpdmVersion;
use spdm_lib::protocol::{CapabilityFlags, DeviceCapabilities};
use userlib::*;

/// MCTP-based SPDM Transport implementation
pub struct MctpSpdmTransport<'a> {
    stack: &'a mctp_api::Stack,
    listener: mctp_api::MctpListener<'a>,
    buffer: &'a mut [u8],
    pending_eid: Option<mctp::Eid>,
    pending_msg_type: Option<mctp::MsgType>,
}

impl<'a> MctpSpdmTransport<'a> {
    pub fn new(
        stack: &'a mctp_api::Stack,
        listener: mctp_api::MctpListener<'a>,
        buffer: &'a mut [u8],
    ) -> Self {
        Self {
            stack,
            listener,
            buffer,
            pending_eid: None,
            pending_msg_type: None,
        }
    }
}

impl<'a> SpdmTransport for MctpSpdmTransport<'a> {
    fn send_request(
        &mut self,
        _dest_eid: u8,
        _req: &mut MessageBuf<'_>,
    ) -> TransportResult<()> {
        // For a responder, we don't typically send requests
        Err(TransportError::ResponseNotExpected)
    }

    fn receive_response(
        &mut self,
        _rsp: &mut MessageBuf<'_>,
    ) -> TransportResult<()> {
        // For a responder, we don't typically receive responses
        Err(TransportError::ResponseNotExpected)
    }

    fn receive_request(
        &mut self,
        req: &mut MessageBuf<'_>,
    ) -> TransportResult<()> {
        // Receive the next MCTP message. We ignore the provided response
        // channel for now to avoid storing a borrowed reference with a
        // shorter lifetime than the transport. Sending is stubbed.
        let (msg_type, _msg_ic, msg, resp_channel) = self
            .listener
            .recv(self.buffer)
            .map_err(|_| TransportError::ReceiveError)?;

        // Record metadata needed to send a reply later. Use copyable/owned
        // pieces only so we don't try to store a borrow tied to the call.
        self.pending_eid = Some(resp_channel.remote_eid());
        self.pending_msg_type = Some(msg_type);

        // Copy the received message into the provided MessageBuf.
        // Use the MessageBuf API to obtain a mutable slice and advance the
        // internal length. This avoids borrowing `self.buffer` twice.
        let len = msg.len();
        let dest = req
            .data_mut(len)
            .map_err(|_| TransportError::ReceiveError)?;
        dest.copy_from_slice(&msg[..len]);
        req.put_data(len)
            .map_err(|_| TransportError::ReceiveError)?;

        Ok(())
    }

    fn send_response(
        &mut self,
        _resp: &mut MessageBuf<'_>,
    ) -> TransportResult<()> {
        // Build and send a response using a fresh ReqChannel created from the
        // stored Stack reference and previously saved remote EID. This avoids
        // storing the short-lived RespChannel returned by `recv`.
        let eid = self.pending_eid.ok_or(TransportError::SendError)?;
        let typ = self.pending_msg_type.unwrap_or(SPDM_MSG_TYPE);

        // Create a request channel for the remote EID
        let mut req_chan = self
            .stack
            .req(eid, None)
            .map_err(|_| TransportError::SendError)?;

        // Extract response bytes from MessageBuf and send
        let data = _resp
            .message_data()
            .map_err(|_| TransportError::SendError)?;
        req_chan
            .send(typ, data)
            .map_err(|_| TransportError::SendError)?;

        // Clear pending metadata
        self.pending_eid = None;
        self.pending_msg_type = None;

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
    flags_value |= 1 << 1; // cert_cap
    flags_value |= 1 << 2; // chal_cap
    flags_value |= 2 << 3; // meas_cap (with signature)
    flags_value |= 1 << 5; // meas_fresh_cap
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
use platform_stubs::{DemoCertStore, DemoEvidence, Sha384Hash, SystemRng};

// SPDM uses MCTP Message Type 5 according to DMTF specifications
const SPDM_MSG_TYPE: MsgType = MsgType(5);

// SPDM responder endpoint ID - should be configurable
const SPDM_RESPONDER_EID: Eid = Eid(42);

// Buffer size for SPDM messages (can be large due to certificates)
const SPDM_BUFFER_SIZE: usize = 4096;

task_slot!(MCTP, mctp_server);

/// SPDM responder task entry point.
///
/// This function is the no_std entry for the SPDM responder task. It:
///
/// - Uses only stack/static buffers; no global heap allocator is required by
///   this task. All SPDM and transport buffers are provided as fixed-size
///   arrays and the platform stubs here are no-alloc placeholders.
/// - Sets up the MCTP Stack and a listener for DMTF SPDM message type
///   (Message Type 5).
/// - Constructs a transport layer that adapts the hubris MCTP listener into
///   the `spdm-lib` `SpdmTransport` trait.
/// - Creates minimal platform implementations (hash, RNG, cert store,
///   evidence). In this repository we expect hardware-accelerated crypto to be
///   provided by platform implementations — the `spdm-lib` dependency is
///   configured without its built-in software crypto backends.
/// - Builds an `SpdmContext` and enters the protocol processing loop. Each
///   loop iteration calls `SpdmContext::process_message(&mut MessageBuf)` to
///   receive/process a request and (via the transport) send any required
///   response.
///
/// Important notes:
/// - The transport owns a listener and a receive buffer. The SPDM stack uses
///   a separate `MessageBuf` backed by its own buffer to avoid overlapping
///   mutable borrows. The two buffers may be unified later (to save RAM) if
///   care is taken to sequence borrows properly.
/// - Cryptography is performed via the platform trait implementations. The
///   `spdm-lib` dependency is built with `default-features = false` so it
///   does not pull in host/software crypto backends.
/// - `send_response` is implemented to create a short-lived request channel
///   from the MCTP `Stack` at send-time to avoid storing call-local response
///   channel borrows inside the transport. This preserves the `receive ->
///   process -> send` separation used by `spdm-lib` while keeping lifetimes
///   sound.
///
/// The function never returns (task main loop). Panics will abort the task.
#[export_name = "main"]
fn main() -> ! {
    // Connect to MCTP server task
    let mctp_stack = Stack::from(MCTP.get_task_id());

    // Set our SPDM responder endpoint ID
    if let Err(e) = mctp_stack.set_eid(SPDM_RESPONDER_EID) {
        // Log error and panic - EID setup is critical
        panic!("Failed to set SPDM responder EID: {:?}", e);
    }

    // Create listener for SPDM messages (Message Type 5)
    let listener = match mctp_stack.listener(SPDM_MSG_TYPE, None) {
        Ok(l) => l,
        Err(e) => panic!("Failed to create SPDM listener: {:?}", e),
    };

    let mut recv_buffer = [0u8; SPDM_BUFFER_SIZE];

    // Create transport
    let mut transport =
        MctpSpdmTransport::new(&mctp_stack, listener, &mut recv_buffer);

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

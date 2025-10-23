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
use ringbuf::*;

/// SPDM Responder trace events for debugging
/// 
/// Embedded-friendly design:
/// - Minimal debug strings (saves flash memory)
/// - Error codes instead of full error structs for Copy/Clone compatibility
/// - Compact enum variants to minimize memory usage
/// 
/// Error Code Reference:
/// - IpcErrorMctpRecv(code): MCTP listener.recv() failed 
///   (1=InternalError, 2=NoSpace, 3=AddrInUse, 4=TimedOut, 5=BadArgument, 99=Unknown)
/// - IpcErrorNoRespChannel: No response channel available for send
/// - IpcErrorMessageBuf: MessageBuf.message_data() failed
/// - IpcErrorMctpSend: MCTP response channel send() failed
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq)]
enum SpdmTrace {
    None,
    TaskStart,
    MctpStackCreated,
    EidSet(u8),
    EidSetFailed,
    ListenerCreated,
    ListenerFailed,
    TransportCreated,
    SpdmContextCreated,
    SpdmContextFailed,
    MessageBufferCreated,
    MessageLoopStart,
    WaitingForMessage,
    MessageReceived(usize),
    MessageProcessed,
    MessageProcessFailed,
    ResponseSent,
    // IPC errors - capture error discriminant for debugging
    IpcErrorMctpRecv(u32),
    IpcErrorNoRespChannel,
    IpcErrorMessageBuf,
    IpcErrorMctpSend,
    PlatformSetupComplete,
}

// Embedded-friendly ringbuf: 32 entries, no debug strings
// Each entry is ~8-12 bytes depending on enum size
// Total memory: ~384 bytes (much better than debug strings)
ringbuf!(SpdmTrace, 32, SpdmTrace::None);

/// MCTP-based SPDM Transport implementation
pub struct MctpSpdmTransport<'a> {
    stack: &'a mctp_api::Stack,
    listener: mctp_api::MctpListener<'a>,
    pending_resp_channel: Option<mctp_api::MctpRespChannel<'a>>,
}

impl<'a> MctpSpdmTransport<'a> {
    pub fn new(
        stack: &'a mctp_api::Stack,
        listener: mctp_api::MctpListener<'a>,
    ) -> Self {
        Self {
            stack,
            listener,
            pending_resp_channel: None,
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
        ringbuf_entry!(SpdmTrace::WaitingForMessage);
        
        // Reset the MessageBuf to ensure clean state
        req.reset();

        // Zero-copy approach: Get MessageBuf buffer and let MCTP write directly into it
        // 1. Get the maximum capacity
        // 2. Pre-allocate the full capacity with put_data()
        // 3. Get mutable access to the pre-allocated buffer
        // 4. Pass buffer directly to MCTP recv (no copy needed!)
        // 5. Trim to the actual received message length
        let max_len = req.capacity();
        
        // Pre-allocate the full buffer capacity
        req.put_data(max_len)
            .map_err(|_| TransportError::ReceiveError)?;
        
        // Get mutable access to the pre-allocated buffer
        let dest = req
            .data_mut(max_len)
            .map_err(|_| {
                // Enhanced error logging for MessageBuf issues
                ringbuf_entry!(SpdmTrace::IpcErrorMessageBuf);
                TransportError::ReceiveError
            })?;

        // Receive directly into the MessageBuf buffer (zero-copy!)
        // MCTP writes the message data directly into our buffer
        let (_msg_type, _msg_ic, msg, resp_channel) = self
            .listener
            .recv(dest)
            .map_err(|e| {
                // Convert error to discriminant for ringbuf storage
                let error_code = match e {
                    mctp::Error::InternalError => 1,
                    mctp::Error::NoSpace => 2,
                    mctp::Error::AddrInUse => 3,
                    mctp::Error::TimedOut => 4,
                    mctp::Error::BadArgument => 5,
                    _ => 99, // Unknown error
                };
                ringbuf_entry!(SpdmTrace::IpcErrorMctpRecv(error_code));
                TransportError::ReceiveError
            })?;

        let msg_len = msg.len();
        ringbuf_entry!(SpdmTrace::MessageReceived(msg_len));

        // Store the response channel for later use
        self.pending_resp_channel = Some(resp_channel);
        
        // Trim the buffer to the actual received message length
        req.trim(msg_len)
            .map_err(|_| TransportError::ReceiveError)?;

        // Note: MCTP header validation is handled by the MCTP layer
        // since our listener is already filtering for SPDM_MSG_TYPE

        Ok(())
    }

    fn send_response(
        &mut self,
        _resp: &mut MessageBuf<'_>,
    ) -> TransportResult<()> {
        // Use the stored response channel to send the response directly
        let mut resp_channel = self
            .pending_resp_channel
            .take()
            .ok_or_else(|| {
                ringbuf_entry!(SpdmTrace::IpcErrorNoRespChannel);
                TransportError::SendError
            })?;

        // Extract response bytes from MessageBuf and send
        let data = _resp
            .message_data()
            .map_err(|_| {
                ringbuf_entry!(SpdmTrace::IpcErrorMessageBuf);
                TransportError::SendError
            })?;

        resp_channel
            .send(data)
            .map_err(|_| {
                ringbuf_entry!(SpdmTrace::IpcErrorMctpSend);
                TransportError::SendError
            })?;

        ringbuf_entry!(SpdmTrace::ResponseSent);
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

mod platform;
use platform::{create_platform_hash, DemoCertStore, DemoEvidence, SystemRng};

// SPDM uses MCTP Message Type 5 according to DMTF specifications
const SPDM_MSG_TYPE: MsgType = MsgType(5);

// SPDM responder endpoint ID - should be configurable
const SPDM_RESPONDER_EID: Eid = Eid(8);

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
/// - The transport uses a zero-copy design where MCTP writes directly into
///   the SPDM MessageBuf, eliminating intermediate copying for better 
///   performance and reduced memory usage.
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
    ringbuf_entry!(SpdmTrace::TaskStart);
    
    // Connect to MCTP server task
    let mctp_stack = Stack::from(MCTP.get_task_id());
    ringbuf_entry!(SpdmTrace::MctpStackCreated);

    // Set our SPDM responder endpoint ID
    if let Err(e) = mctp_stack.set_eid(SPDM_RESPONDER_EID) {
        ringbuf_entry!(SpdmTrace::EidSetFailed);
        panic!("Failed to set SPDM responder EID: {:?}", e);
    }
    ringbuf_entry!(SpdmTrace::EidSet(SPDM_RESPONDER_EID.0));

    // Create listener for SPDM messages (Message Type 5)
    let listener = match mctp_stack.listener(SPDM_MSG_TYPE, None) {
        Ok(l) => {
            ringbuf_entry!(SpdmTrace::ListenerCreated);
            l
        },
        Err(e) => {
            ringbuf_entry!(SpdmTrace::ListenerFailed);
            panic!("Failed to create SPDM listener: {:?}", e);
        }
    };

    // Create transport that bridges MCTP listener to SPDM protocol stack
    let mut transport =
        MctpSpdmTransport::new(&mctp_stack, listener);
    ringbuf_entry!(SpdmTrace::TransportCreated);

    // Create digest client for hash operations (only when IPC is needed)
    #[cfg(not(feature = "sha2-crypto"))]
    {
        task_slot!(DIGEST_SERVER, digest_server);
        let digest_client =
            drv_digest_api::Digest::from(DIGEST_SERVER.get_task_id());
    }

    // Create RNG client for random number generation
    task_slot!(RNG_DRIVER, rng_driver);
    let rng_client = drv_rng_api::Rng::from(RNG_DRIVER.get_task_id());

    // Create platform implementations using unified constructor
    #[cfg(feature = "sha2-crypto")]
    let mut hash = create_platform_hash();
    #[cfg(feature = "sha2-crypto")]
    let mut m1_hash = create_platform_hash();
    #[cfg(feature = "sha2-crypto")]
    let mut l1_hash = create_platform_hash();

    #[cfg(not(feature = "sha2-crypto"))]
    let mut hash = create_platform_hash(digest_client.clone());
    #[cfg(not(feature = "sha2-crypto"))]
    let mut m1_hash = create_platform_hash(digest_client.clone());
    #[cfg(not(feature = "sha2-crypto"))]
    let mut l1_hash = create_platform_hash(digest_client);
    let mut rng = SystemRng::new(rng_client);
    let mut cert_store = DemoCertStore::new();
    let evidence = DemoEvidence::new();
    ringbuf_entry!(SpdmTrace::PlatformSetupComplete);

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
        Ok(ctx) => {
            ringbuf_entry!(SpdmTrace::SpdmContextCreated);
            ctx
        },
        Err(_) => {
            ringbuf_entry!(SpdmTrace::SpdmContextFailed);
            panic!("Failed to create SPDM context");
        }
    };

    // SPDM message processing buffer: Used by the SPDM library to parse, 
    // validate, and construct protocol messages. The zero-copy design allows
    // MCTP to write directly into this buffer, eliminating intermediate copies.
    let mut message_buffer = [0u8; SPDM_BUFFER_SIZE];
    let mut msg_buf = MessageBuf::new(&mut message_buffer);
    
    // Log MessageBuf creation for debugging
    ringbuf_entry!(SpdmTrace::MessageBufferCreated);

    // Process SPDM messages
    ringbuf_entry!(SpdmTrace::MessageLoopStart);
    loop {        
        match spdm_context.process_message(&mut msg_buf) {
            Ok(()) => {
                ringbuf_entry!(SpdmTrace::MessageProcessed);
            }
            Err(_e) => {
                ringbuf_entry!(SpdmTrace::MessageProcessFailed);
                // Continue processing even after errors to maintain service availability
            }
        }
    }
}

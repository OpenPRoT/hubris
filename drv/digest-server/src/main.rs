#![no_std]
#![no_main]

//! # Digest Server
//!
//! Hardware-accelerated cryptographic digest service for the Hubris operating system.
//! 
//! This server provides both session-based and one-shot digest operations using the 
//! OpenPRoT HAL traits with concrete `Digest<N>` output types.
//!
//! ## Supported Operations
//! - **Session-based**: `init` → multiple `update` → `finalize` (for streaming)
//! - **One-shot**: `digest_oneshot_*` (complete hash in single call)
//!
//! ## Algorithms Supported
//! - SHA-256: `Digest<8>` (256-bit output)
//! - SHA-384: `Digest<12>` (384-bit output)
//! - SHA-512: `Digest<16>` (512-bit output)
//!
//! ## Hardware Backends
//! - `HaceController`: ASPEED HACE hardware accelerator
//! - `MockDigestDevice`: Software mock implementation for testing

use drv_digest_api::{DigestError};
use idol_runtime::{ClientError, Leased, LenLimit, NotificationHandler, RequestError, R, W};
use userlib::*;
use zerocopy::IntoBytes;

use openprot_hal_blocking::digest::{
    Sha2_256, Sha2_384, Sha2_512, Digest
};
use openprot_hal_blocking::digest::owned::{DigestInit, DigestOp};

// Algorithm enum for session tracking
#[derive(Debug, Clone, Copy)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384, 
    Sha512,
}

// Hardware capabilities trait - determines session limits
pub trait DigestHardwareCapabilities {
    const MAX_CONCURRENT_SESSIONS: usize;
    const SUPPORTS_HARDWARE_CONTEXT_SWITCHING: bool;
}

// ASPEED HACE Controller capabilities
#[cfg(feature = "aspeed-hace")]
impl DigestHardwareCapabilities for HaceController {
    const MAX_CONCURRENT_SESSIONS: usize = 1;  // Single-context hardware
    const SUPPORTS_HARDWARE_CONTEXT_SWITCHING: bool = false;
}

// Mock device capabilities (for testing)
#[cfg(not(feature = "aspeed-hace"))]
impl DigestHardwareCapabilities for MockDigestController {
    const MAX_CONCURRENT_SESSIONS: usize = 8;  // Multiple contexts for testing
    const SUPPORTS_HARDWARE_CONTEXT_SWITCHING: bool = true;
}

// Conditional imports based on features
#[cfg(feature = "aspeed-hace")]
use aspeed_ddk::hace_controller::HaceController;

#[cfg(not(feature = "aspeed-hace"))]
use openprot_platform_mock::hash::owned::MockDigestController;

// Re-export the API that was generated from digest.idol.
mod idl {
    use crate::DigestError;
    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}

// Conditional type alias for the default digest device
#[cfg(feature = "aspeed-hace")]
type DefaultDigestDevice = HaceController;

#[cfg(not(feature = "aspeed-hace"))]
type DefaultDigestDevice = MockDigestController;

// Maximum sessions based on hardware capabilities  
const fn max_sessions_for_platform() -> usize {
    // Use the actual hardware device's capabilities
    DefaultDigestDevice::MAX_CONCURRENT_SESSIONS
}

const MAX_SESSIONS: usize = max_sessions_for_platform();

// Server implementation using hardware capabilities and owned API for sessions
pub struct ServerImpl<D> 
where
    D: DigestInit<Sha2_256, Output = Digest<8>> 
     + DigestInit<Sha2_384, Output = Digest<12>>
     + DigestInit<Sha2_512, Output = Digest<16>>
     + DigestHardwareCapabilities,
{
    controllers: Controllers<D>,
    current_session: Option<DigestSession<D>>,
    next_session_id: u32,
}

// Controllers available for creating new contexts
struct Controllers<D> {
    hardware: Option<D>,  // Single hardware controller, None when in use
}

// Active digest session with owned context
struct DigestSession<D> 
where 
    D: DigestInit<Sha2_256, Output = Digest<8>> 
     + DigestInit<Sha2_384, Output = Digest<12>>
     + DigestInit<Sha2_512, Output = Digest<16>>
     + DigestHardwareCapabilities,
{
    session_id: u32,
    algorithm: DigestAlgorithm,
    context: SessionContext<D>,
    created_at: u64, // Timestamp for timeout
}

// Owned context storage with Option wrappers for move semantics
// Option wrappers needed because update(self) and finalize(self) consume contexts
enum SessionContext<D>
where 
    D: DigestInit<Sha2_256, Output = Digest<8>> 
     + DigestInit<Sha2_384, Output = Digest<12>>
     + DigestInit<Sha2_512, Output = Digest<16>>
     + DigestHardwareCapabilities,
{
    Sha256(Option<<D as DigestInit<Sha2_256>>::Context>),
    Sha384(Option<<D as DigestInit<Sha2_384>>::Context>), 
    Sha512(Option<<D as DigestInit<Sha2_512>>::Context>),
}

// Implement NotificationHandler (required by InOrderDigestImpl)
impl<D> idol_runtime::NotificationHandler for ServerImpl<D> 
where
    D: DigestInit<Sha2_256, Output = Digest<8>> 
     + DigestInit<Sha2_384, Output = Digest<12>> 
     + DigestInit<Sha2_512, Output = Digest<16>> 
     + DigestHardwareCapabilities,
{
    fn current_notification_mask(&self) -> u32 {
        0 // No notifications handled
    }
    
    fn handle_notification(&mut self, _bits: u32) {
        // No notifications to handle
    }
}

impl<D> ServerImpl<D> 
where
    D: DigestInit<Sha2_256, Output = Digest<8>> 
     + DigestInit<Sha2_384, Output = Digest<12>> 
     + DigestInit<Sha2_512, Output = Digest<16>> 
     + DigestHardwareCapabilities,
{
    pub fn new(hardware: D) -> Self {
        Self { 
            controllers: Controllers { hardware: Some(hardware) },
            current_session: None,
            next_session_id: 1,
        }
    }
    
    // Session-based operations using owned API
    fn init_sha256(&mut self) -> Result<u32, DigestError> {
        // Check if we already have an active session
        if self.current_session.is_some() {
            return Err(DigestError::TooManySessions);
        }
        
        let controller = self.controllers.hardware.take()
            .ok_or(DigestError::TooManySessions)?;
        
        let context = controller.init(Sha2_256)
            .map_err(|_| DigestError::HardwareFailure)?;
        
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        
        let session = DigestSession {
            session_id,
            algorithm: DigestAlgorithm::Sha256,
            context: SessionContext::Sha256(Some(context)),
            created_at: sys_get_timer().now,
        };
        
        self.current_session = Some(session);
        Ok(session_id)
    }
    
    fn init_sha384(&mut self) -> Result<u32, DigestError> {
        // Check if we already have an active session
        if self.current_session.is_some() {
            return Err(DigestError::TooManySessions);
        }
        
        let controller = self.controllers.hardware.take()
            .ok_or(DigestError::TooManySessions)?;
        
        let context = controller.init(Sha2_384)
            .map_err(|_| DigestError::HardwareFailure)?;
        
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        
        let session = DigestSession {
            session_id,
            algorithm: DigestAlgorithm::Sha384,
            context: SessionContext::Sha384(Some(context)),
            created_at: sys_get_timer().now,
        };
        
        self.current_session = Some(session);
        Ok(session_id)
    }
    
    fn init_sha512(&mut self) -> Result<u32, DigestError> {
        // Check if we already have an active session
        if self.current_session.is_some() {
            return Err(DigestError::TooManySessions);
        }
        
        let controller = self.controllers.hardware.take()
            .ok_or(DigestError::TooManySessions)?;
        
        let context = controller.init(Sha2_512)
            .map_err(|_| DigestError::HardwareFailure)?;
        
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        
        let session = DigestSession {
            session_id,
            algorithm: DigestAlgorithm::Sha512,
            context: SessionContext::Sha512(Some(context)),
            created_at: sys_get_timer().now,
        };
        
        self.current_session = Some(session);
        Ok(session_id)
    }
    
    fn update(&mut self, session_id: u32, data: &[u8]) -> Result<(), DigestError> {
        let session = self.current_session.as_mut()
            .ok_or(DigestError::InvalidSession)?;
        
        // Verify session ID matches
        if session.session_id != session_id {
            return Err(DigestError::InvalidSession);
        }
        
        match &mut session.context {
            SessionContext::Sha256(ctx_opt) => {
                // Clean move using Option::take()
                let old_ctx = ctx_opt.take().ok_or(DigestError::InvalidSession)?;
                let new_ctx = old_ctx.update(data).map_err(|_| DigestError::HardwareFailure)?;
                *ctx_opt = Some(new_ctx);
            }
            SessionContext::Sha384(ctx_opt) => {
                let old_ctx = ctx_opt.take().ok_or(DigestError::InvalidSession)?;
                let new_ctx = old_ctx.update(data).map_err(|_| DigestError::HardwareFailure)?;
                *ctx_opt = Some(new_ctx);
            }
            SessionContext::Sha512(ctx_opt) => {
                let old_ctx = ctx_opt.take().ok_or(DigestError::InvalidSession)?;
                let new_ctx = old_ctx.update(data).map_err(|_| DigestError::HardwareFailure)?;
                *ctx_opt = Some(new_ctx);
            }
        }
        
        Ok(())
    }
    
    fn finalize_sha256_internal(&mut self, session_id: u32) -> Result<[u32; 8], DigestError> {
        let mut session = self.current_session.take()
            .ok_or(DigestError::InvalidSession)?;
        
        // Verify session ID matches
        if session.session_id != session_id {
            // Put session back if ID doesn't match
            self.current_session = Some(session);
            return Err(DigestError::InvalidSession);
        }
        
        match &mut session.context {
            SessionContext::Sha256(ctx_opt) => {
                let ctx = ctx_opt.take().ok_or(DigestError::InvalidSession)?;
                let (digest, controller) = ctx.finalize()
                    .map_err(|_| DigestError::HardwareFailure)?;
                
                // Return controller to available pool
                self.controllers.hardware = Some(controller);
                
                // Direct safe conversion with concrete Digest<8> type - no unsafe code needed!
                Ok(digest.into_array())
            }
            _ => Err(DigestError::UnsupportedAlgorithm),
        }
    }
    
    fn finalize_sha384_internal(&mut self, session_id: u32) -> Result<[u32; 12], DigestError> {
        let mut session = self.current_session.take()
            .ok_or(DigestError::InvalidSession)?;
        
        // Verify session ID matches
        if session.session_id != session_id {
            // Put session back if ID doesn't match
            self.current_session = Some(session);
            return Err(DigestError::InvalidSession);
        }
        
        match &mut session.context {
            SessionContext::Sha384(ctx_opt) => {
                let ctx = ctx_opt.take().ok_or(DigestError::InvalidSession)?;
                let (digest, controller) = ctx.finalize()
                    .map_err(|_| DigestError::HardwareFailure)?;
                
                // Return controller to available pool
                self.controllers.hardware = Some(controller);
                
                // Direct safe conversion with concrete Digest<12> type - no unsafe code needed!
                Ok(digest.into_array())
            }
            _ => Err(DigestError::UnsupportedAlgorithm),
        }
    }
    
    fn finalize_sha512_internal(&mut self, session_id: u32) -> Result<[u32; 16], DigestError> {
        let mut session = self.current_session.take()
            .ok_or(DigestError::InvalidSession)?;
        
        // Verify session ID matches
        if session.session_id != session_id {
            // Put session back if ID doesn't match
            self.current_session = Some(session);
            return Err(DigestError::InvalidSession);
        }
        
        match &mut session.context {
            SessionContext::Sha512(ctx_opt) => {
                let ctx = ctx_opt.take().ok_or(DigestError::InvalidSession)?;
                let (digest, controller) = ctx.finalize()
                    .map_err(|_| DigestError::HardwareFailure)?;
                
                // Return controller to available pool
                self.controllers.hardware = Some(controller);
                
                // Direct safe conversion - no unsafe code needed!
                Ok(digest.into_array())
            }
            _ => Err(DigestError::UnsupportedAlgorithm),
        }
    }
    
    // One-shot SHA-384 hash - uses traits correctly
    fn compute_sha384_oneshot(&mut self, data: &[u8]) -> Result<Digest<12>, DigestError> {
        // Need to temporarily take hardware controller
        let mut controller = self.controllers.hardware.take()
            .ok_or(DigestError::HardwareFailure)?;
        let mut ctx = controller.init(Sha2_384).map_err(|_| DigestError::HardwareFailure)?;
        let ctx = ctx.update(data).map_err(|_| DigestError::HardwareFailure)?;
        let (result, controller_back) = ctx.finalize().map_err(|_| DigestError::HardwareFailure)?;
        self.controllers.hardware = Some(controller_back);
        Ok(result)
    }
    
    // One-shot SHA-512 hash - uses traits correctly
    fn compute_sha512_oneshot(&mut self, data: &[u8]) -> Result<Digest<16>, DigestError> {
        // Need to temporarily take hardware controller
        let mut controller = self.controllers.hardware.take()
            .ok_or(DigestError::HardwareFailure)?;
        let mut ctx = controller.init(Sha2_512).map_err(|_| DigestError::HardwareFailure)?;
        let ctx = ctx.update(data).map_err(|_| DigestError::HardwareFailure)?;
        let (result, controller_back) = ctx.finalize().map_err(|_| DigestError::HardwareFailure)?;
        self.controllers.hardware = Some(controller_back);
        Ok(result)
    }
    
    // One-shot SHA-256 hash - uses traits correctly
    fn compute_sha256_oneshot(&mut self, data: &[u8]) -> Result<Digest<8>, DigestError> {
        // Need to temporarily take hardware controller
        let mut controller = self.controllers.hardware.take()
            .ok_or(DigestError::HardwareFailure)?;
        let mut ctx = controller.init(Sha2_256).map_err(|_| DigestError::HardwareFailure)?;
        let ctx = ctx.update(data).map_err(|_| DigestError::HardwareFailure)?;
        let (result, controller_back) = ctx.finalize().map_err(|_| DigestError::HardwareFailure)?;
        self.controllers.hardware = Some(controller_back);
        Ok(result)
    }
}

// Implementation of the digest API - session-based operations using owned API
impl<D> idl::InOrderDigestImpl for ServerImpl<D> 
where
    D: DigestInit<Sha2_256, Output = Digest<8>> 
     + DigestInit<Sha2_384, Output = Digest<12>> 
     + DigestInit<Sha2_512, Output = Digest<16>> 
     + DigestHardwareCapabilities,
{
    // Session-based operations using owned API - fully supported
    fn init_sha256(&mut self, _msg: &RecvMessage) -> Result<u32, RequestError<DigestError>> {
        self.init_sha256().map_err(RequestError::Runtime)
    }

    fn init_sha384(&mut self, _msg: &RecvMessage) -> Result<u32, RequestError<DigestError>> {
        self.init_sha384().map_err(RequestError::Runtime)
    }

    fn init_sha512(&mut self, _msg: &RecvMessage) -> Result<u32, RequestError<DigestError>> {
        self.init_sha512().map_err(RequestError::Runtime)
    }

    fn init_sha3_256(&mut self, _msg: &RecvMessage) -> Result<u32, RequestError<DigestError>> {
        Err(RequestError::Runtime(DigestError::UnsupportedAlgorithm))
    }

    fn init_sha3_384(&mut self, _msg: &RecvMessage) -> Result<u32, RequestError<DigestError>> {
        Err(RequestError::Runtime(DigestError::UnsupportedAlgorithm))
    }

    fn init_sha3_512(&mut self, _msg: &RecvMessage) -> Result<u32, RequestError<DigestError>> {
        Err(RequestError::Runtime(DigestError::UnsupportedAlgorithm))
    }

    fn update(
        &mut self,
        _msg: &RecvMessage,
        session_id: u32,
        len: u32,
        data: LenLimit<Leased<R, [u8]>, 1024>,
    ) -> Result<(), RequestError<DigestError>> {
        let mut buffer = [0u8; 1024];
        data.read_range(0..len as usize, &mut buffer)
            .map_err(|_| RequestError::Runtime(DigestError::HardwareFailure))?;
        let data_slice = &buffer[0..len as usize];
        self.update(session_id, data_slice).map_err(RequestError::Runtime)
    }

    fn finalize_sha256(
        &mut self,
        _msg: &RecvMessage,
        session_id: u32,
        digest: Leased<W, [u32; 8]>,
    ) -> Result<(), RequestError<DigestError>> {
        let result = self.finalize_sha256_internal(session_id).map_err(RequestError::Runtime)?;
        digest.write(result).map_err(|_| RequestError::Fail(ClientError::WentAway))?;
        Ok(())
    }

    fn finalize_sha384(
        &mut self,
        _msg: &RecvMessage,
        session_id: u32,
        digest: Leased<W, [u32; 12]>,
    ) -> Result<(), RequestError<DigestError>> {
        let result = self.finalize_sha384_internal(session_id).map_err(RequestError::Runtime)?;
        digest.write(result).map_err(|_| RequestError::Fail(ClientError::WentAway))?;
        Ok(())
    }

    fn finalize_sha512(
        &mut self,
        _msg: &RecvMessage,
        session_id: u32,
        digest: Leased<W, [u32; 16]>,
    ) -> Result<(), RequestError<DigestError>> {
        let result = self.finalize_sha512_internal(session_id).map_err(RequestError::Runtime)?;
        digest.write(result).map_err(|_| RequestError::Fail(ClientError::WentAway))?;
        Ok(())
    }

    fn finalize_sha3_256(
        &mut self,
        _msg: &RecvMessage,
        _session_id: u32,
        _digest: Leased<W, [u32; 8]>,
    ) -> Result<(), RequestError<DigestError>> {
        Err(RequestError::Runtime(DigestError::UnsupportedAlgorithm))
    }

    fn finalize_sha3_384(
        &mut self,
        _msg: &RecvMessage,
        _session_id: u32,
        _digest: Leased<W, [u32; 12]>,
    ) -> Result<(), RequestError<DigestError>> {
        Err(RequestError::Runtime(DigestError::UnsupportedAlgorithm))
    }

    fn finalize_sha3_512(
        &mut self,
        _msg: &RecvMessage,
        _session_id: u32,
        _digest: Leased<W, [u32; 16]>,
    ) -> Result<(), RequestError<DigestError>> {
        Err(RequestError::Runtime(DigestError::UnsupportedAlgorithm))
    }

    fn reset(
        &mut self,
        _msg: &RecvMessage,
        _session_id: u32,
    ) -> Result<(), RequestError<DigestError>> {
        Err(RequestError::Runtime(DigestError::UnsupportedAlgorithm))
    }

    // ✅ ONE-SHOT OPERATIONS - These work correctly with the traits
    fn digest_oneshot_sha256(
        &mut self,
        _msg: &RecvMessage,
        len: u32,
        data: LenLimit<Leased<R, [u8]>, 1024>,
        digest_out: Leased<W, [u32; 8]>,
    ) -> Result<(), RequestError<DigestError>> {
        let len = len as usize;
        if len > data.len() || len > 1024 {
            return Err(RequestError::Runtime(DigestError::InvalidInputLength));
        }

        // Read input data into buffer
        let mut buffer = [0u8; 1024];
        data.read_range(0..len, &mut buffer[..len])
            .map_err(|_| RequestError::Runtime(DigestError::InvalidInputLength))?;

        // Compute hash using traits correctly
        let hash_result = self.compute_sha256_oneshot(&buffer[..len])
            .map_err(RequestError::Runtime)?;

        // Direct safe conversion with concrete Digest<8> type - no unsafe code needed!
        let result = hash_result.into_array();
        
        digest_out.write(result)
            .map_err(|_| RequestError::Runtime(DigestError::HardwareFailure))?;

        Ok(())
    }

    fn digest_oneshot_sha384(
        &mut self,
        _msg: &RecvMessage,
        len: u32,
        data: LenLimit<Leased<R, [u8]>, 1024>,
        digest_out: Leased<W, [u32; 12]>,
    ) -> Result<(), RequestError<DigestError>> {
        let len = len as usize;
        if len > data.len() || len > 1024 {
            return Err(RequestError::Runtime(DigestError::InvalidInputLength));
        }

        // Read input data into buffer
        let mut buffer = [0u8; 1024];
        data.read_range(0..len, &mut buffer[..len])
            .map_err(|_| RequestError::Runtime(DigestError::InvalidInputLength))?;

        // Compute hash using traits correctly
        let hash_result = self.compute_sha384_oneshot(&buffer[..len])
            .map_err(RequestError::Runtime)?;

        // Direct safe conversion with concrete Digest<12> type - no unsafe code needed!
        let result = hash_result.into_array();
        
        digest_out.write(result)
            .map_err(|_| RequestError::Runtime(DigestError::HardwareFailure))?;

        Ok(())
    }

    fn digest_oneshot_sha512(
        &mut self,
        _msg: &RecvMessage,
        len: u32,
        data: LenLimit<Leased<R, [u8]>, 1024>,
        digest_out: Leased<W, [u32; 16]>,
    ) -> Result<(), RequestError<DigestError>> {
        let len = len as usize;
        if len > data.len() || len > 1024 {
            return Err(RequestError::Runtime(DigestError::InvalidInputLength));
        }

        // Read input data into buffer
        let mut buffer = [0u8; 1024];
        data.read_range(0..len, &mut buffer[..len])
            .map_err(|_| RequestError::Runtime(DigestError::InvalidInputLength))?;

        // Compute hash using traits correctly
        let hash_result = self.compute_sha512_oneshot(&buffer[..len])
            .map_err(RequestError::Runtime)?;

        // Direct safe conversion with concrete Digest<16> type - no unsafe code needed!
        let result = hash_result.into_array();
        
        digest_out.write(result)
            .map_err(|_| RequestError::Runtime(DigestError::HardwareFailure))?;

        Ok(())
    }
}

// Type alias for the default server implementation
type DefaultServerImpl = ServerImpl<DefaultDigestDevice>;

// Dummy delay implementation for syscon
#[cfg(feature = "aspeed-hace")]
#[derive(Default)]
struct DummyDelay;

#[cfg(feature = "aspeed-hace")]
impl embedded_hal_1::delay::DelayNs for DummyDelay {
    fn delay_ns(&mut self, _ns: u32) {
        // No-op delay for now
    }
}

// Server instantiation and task entry point
impl<D> ServerImpl<D>
where
    D: DigestInit<Sha2_256, Output = Digest<8>> 
     + DigestInit<Sha2_384, Output = Digest<12>>
     + DigestInit<Sha2_512, Output = Digest<16>>
     + DigestHardwareCapabilities,
{
    // Hardware reset functionality removed for compatibility
}

#[no_mangle]
pub extern "C" fn main() -> ! {
    // Initialize hardware device
    #[cfg(feature = "aspeed-hace")]
    let hardware = {
        use ast1060_pac::Peripherals;
        use aspeed_ddk::syscon::{SysCon, ClockId, ResetId};
        use proposed_traits::system_control::{ClockControl, ResetControl};
        
        let peripherals = unsafe { Peripherals::steal() };
        
        // Set up system control and enable HACE
        let mut syscon = SysCon::new(DummyDelay::default(), peripherals.scu);
        
        // Enable HACE clock
        let _ = syscon.enable(&ClockId::ClkYCLK);
        
        // Release HACE from reset  
        let _ = syscon.reset_deassert(&ResetId::RstHACE);
        
        HaceController::new(peripherals.hace)
    };
    
    #[cfg(not(feature = "aspeed-hace"))]
    let hardware = MockDigestController::new();

    let mut server = ServerImpl::new(hardware);
    
    // Hardware reset functionality removed for compatibility

    // Enter the main IPC loop
    let mut incoming = [0u8; idl::INCOMING_SIZE];
    loop {
        idol_runtime::dispatch(&mut incoming, &mut server);
    }
}

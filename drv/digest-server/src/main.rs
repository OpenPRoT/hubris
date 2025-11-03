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
//! ### Digest Operations
//! - SHA-256: `Digest<8>` (256-bit output)
//! - SHA-384: `Digest<12>` (384-bit output)
//! - SHA-512: `Digest<16>` (512-bit output)
//!
//! ### HMAC Operations  
//! - HMAC-SHA256: `[u8; 32]` (256-bit authentication tag)
//! - HMAC-SHA384: `[u8; 48]` (384-bit authentication tag)
//! - HMAC-SHA512: `[u8; 64]` (512-bit authentication tag)
//!
//! ## HMAC Key Limits Design Specification
//!
//! ### Key Size Limits
//! - **HMAC-SHA256**: Maximum 64 bytes (512 bits)
//! - **HMAC-SHA384**: Maximum 128 bytes (1024 bits)
//! - **HMAC-SHA512**: Maximum 128 bytes (1024 bits)
//!
//! ### Design Rationale
//! 
//! These limits are intentionally set to match the underlying hash algorithm block sizes:
//! - SHA-256 block size: 64 bytes → HMAC-SHA256 key limit: 64 bytes
//! - SHA-384 block size: 128 bytes → HMAC-SHA384 key limit: 128 bytes  
//! - SHA-512 block size: 128 bytes → HMAC-SHA512 key limit: 128 bytes
//!
//! #### Benefits of Block-Size Limits:
//! 1. **Optimal Performance**: Keys ≤ block size are processed directly without additional hashing
//! 2. **Security Equivalence**: Keys larger than block size provide no additional security benefit
//! 3. **Hardware Compatibility**: Aligns with typical hardware accelerator constraints
//! 4. **DoS Prevention**: Prevents potential denial-of-service from oversized key processing
//! 5. **Memory Efficiency**: Reduces buffer requirements in embedded environments
//!
//! #### HMAC Key Processing (RFC 2104):
//! ```
//! if key_length == block_size: use key directly
//! if key_length < block_size:  pad with zeros to block_size  
//! if key_length > block_size:  hash(key) then pad to block_size
//! ```
//! Our limits ensure we stay in the first two cases for optimal performance.
//!
//! #### Real-World Key Size Coverage:
//! - TLS session keys: typically 32-48 bytes ✅
//! - JWT signing keys: typically 32-64 bytes ✅  
//! - API authentication keys: typically 16-64 bytes ✅
//! - Database tokens: typically 16-32 bytes ✅
//! - Cryptographic derivation: typically matches hash output size ✅
//!
//! These limits cover all practical embedded use cases while maintaining optimal performance.
//!
//! ## Hardware Backends
//! - `HaceController`: ASPEED HACE hardware accelerator
//! - `RustCryptoController`: Software RustCrypto implementation  
//! - `MockDigestDevice`: Software mock implementation for testing

use drv_digest_api::{DigestError};
use idol_runtime::{ClientError, Leased, LenLimit, RequestError, R, W};
use userlib::*;
// Remove unused import - zerocopy::IntoBytes not needed

use openprot_hal_blocking::digest::{
    Sha2_256, Sha2_384, Sha2_512, Digest
};
use openprot_hal_blocking::digest::owned::{DigestInit, DigestOp};
use openprot_hal_blocking::mac::{
    HmacSha2_256, HmacSha2_384, HmacSha2_512
};
use openprot_hal_blocking::mac::owned::{MacInit, MacOp};
use openprot_platform_traits_hubris::{HubrisDigestDevice, CryptoSession};

// Algorithm enum for session tracking
#[derive(Debug, Clone, Copy)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384, 
    Sha512,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

// Conditional imports based on features
#[cfg(feature = "aspeed-hace")]
use aspeed_ddk::hace_controller::HaceController;

#[cfg(feature = "rustcrypto")]
use openprot_platform_rustcrypto::controller::RustCryptoController;

#[cfg(not(any(feature = "aspeed-hace", feature = "rustcrypto")))]
use openprot_platform_mock::hash::owned::MockDigestController;


// Re-export the API that was generated from digest.idol.
mod idl {
    use crate::DigestError;
    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}

// Conditional type alias for the default digest device
#[cfg(feature = "aspeed-hace")]
type DefaultDigestDevice = HaceController;

#[cfg(feature = "rustcrypto")]
type DefaultDigestDevice = RustCryptoController;

#[cfg(not(any(feature = "aspeed-hace", feature = "rustcrypto")))]
type DefaultDigestDevice = MockDigestController;

// Maximum concurrent digest sessions
const MAX_SESSIONS: usize = 16;

// Server implementation using Hubris IDL Integration traits
pub struct ServerImpl<D: HubrisDigestDevice> {
    controllers: Controllers<D>,
    current_session: Option<DigestSession<D>>,
    next_session_id: u32,
}

// Controllers available for creating new contexts
struct Controllers<D> {
    hardware: Option<D>,  // Single hardware controller, None when in use
}

// Active digest session with owned context
struct DigestSession<D: HubrisDigestDevice> {
    session_id: u32,
    algorithm: DigestAlgorithm,
    context: SessionContext<D>,
    created_at: u64, // Timestamp for timeout
}

// Active digest session with CryptoSession instances
enum SessionContext<D> 
where
    D: HubrisDigestDevice,
{
    Sha256(Option<CryptoSession<D::DigestContext256, D>>),
    Sha384(Option<CryptoSession<D::DigestContext384, D>>), 
    Sha512(Option<CryptoSession<D::DigestContext512, D>>),
    HmacSha256(Option<CryptoSession<D::HmacContext256, D>>),
    HmacSha384(Option<CryptoSession<D::HmacContext384, D>>),
    HmacSha512(Option<CryptoSession<D::HmacContext512, D>>),
}

// Implement NotificationHandler (required by InOrderDigestImpl)
impl<D> idol_runtime::NotificationHandler for ServerImpl<D> 
where
    D: HubrisDigestDevice, {
    fn current_notification_mask(&self) -> u32 {
        0 // No notifications handled
    }
    
    fn handle_notification(&mut self, _bits: u32) {
        // No notifications to handle
    }
}

impl<D: HubrisDigestDevice> ServerImpl<D> {
    pub fn new(hardware: D) -> Self {
        Self { 
            controllers: Controllers { hardware: Some(hardware) },
            current_session: None,
            next_session_id: 1,
        }
    }
    
    // Session-based operations using CryptoSession
    fn init_sha256_internal(&mut self) -> Result<u32, DigestError> {
        // Check if we already have an active session
        if self.current_session.is_some() {
            return Err(DigestError::TooManySessions);
        }
        
        let controller = self.controllers.hardware.take()
            .ok_or(DigestError::TooManySessions)?;
        
        let session = controller.init_digest_session_sha256()
            .map_err(|_| DigestError::HardwareFailure)?;
        
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        
        let digest_session = DigestSession {
            session_id,
            algorithm: DigestAlgorithm::Sha256,
            context: SessionContext::Sha256(Some(session)),
            created_at: sys_get_timer().now,
        };
        
        self.current_session = Some(digest_session);
        Ok(session_id)
    }
    
    fn init_sha384_internal(&mut self) -> Result<u32, DigestError> {
        // Check if we already have an active session
        if self.current_session.is_some() {
            return Err(DigestError::TooManySessions);
        }
        
        let controller = self.controllers.hardware.take()
            .ok_or(DigestError::TooManySessions)?;
        
        let session = controller.init_digest_session_sha384()
            .map_err(|_| DigestError::HardwareFailure)?;
        
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        
        let digest_session = DigestSession {
            session_id,
            algorithm: DigestAlgorithm::Sha384,
            context: SessionContext::Sha384(Some(session)),
            created_at: sys_get_timer().now,
        };
        
        self.current_session = Some(digest_session);
        Ok(session_id)
    }
    
    fn init_sha512_internal(&mut self) -> Result<u32, DigestError> {
        // Check if we already have an active session
        if self.current_session.is_some() {
            return Err(DigestError::TooManySessions);
        }
        
        let controller = self.controllers.hardware.take()
            .ok_or(DigestError::TooManySessions)?;
        
        let session = controller.init_digest_session_sha512()
            .map_err(|_| DigestError::HardwareFailure)?;
        
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        
        let digest_session = DigestSession {
            session_id,
            algorithm: DigestAlgorithm::Sha512,
            context: SessionContext::Sha512(Some(session)),
            created_at: sys_get_timer().now,
        };
        
        self.current_session = Some(digest_session);
        Ok(session_id)
    }
    
    // HMAC initialization methods
    fn init_hmac_sha256_internal(&mut self, key: &[u8]) -> Result<u32, DigestError> {
        // Check if we already have an active session
        if self.current_session.is_some() {
            return Err(DigestError::TooManySessions);
        }
        
        let controller = self.controllers.hardware.take()
            .ok_or(DigestError::TooManySessions)?;
        
        let hmac_key = D::create_hmac_key(key)
            .map_err(|_| DigestError::InvalidKeyLength)?;
        let session = controller.init_hmac_session_sha256(hmac_key)
            .map_err(|_| DigestError::InvalidKeyLength)?;
        
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        
        let digest_session = DigestSession {
            session_id,
            algorithm: DigestAlgorithm::HmacSha256,
            context: SessionContext::HmacSha256(Some(session)),
            created_at: sys_get_timer().now,
        };
        
        self.current_session = Some(digest_session);
        Ok(session_id)
    }
    
    fn init_hmac_sha384_internal(&mut self, key: &[u8]) -> Result<u32, DigestError> {
        // Check if we already have an active session
        if self.current_session.is_some() {
            return Err(DigestError::TooManySessions);
        }
        
        let controller = self.controllers.hardware.take()
            .ok_or(DigestError::TooManySessions)?;
        
        let hmac_key = D::create_hmac_key(key)
            .map_err(|_| DigestError::InvalidKeyLength)?;
        let session = controller.init_hmac_session_sha384(hmac_key)
            .map_err(|_| DigestError::InvalidKeyLength)?;
        
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        
        let digest_session = DigestSession {
            session_id,
            algorithm: DigestAlgorithm::HmacSha384,
            context: SessionContext::HmacSha384(Some(session)),
            created_at: sys_get_timer().now,
        };
        
        self.current_session = Some(digest_session);
        Ok(session_id)
    }
    
    fn init_hmac_sha512_internal(&mut self, key: &[u8]) -> Result<u32, DigestError> {
        // Check if we already have an active session
        if self.current_session.is_some() {
            return Err(DigestError::TooManySessions);
        }
        
        let controller = self.controllers.hardware.take()
            .ok_or(DigestError::TooManySessions)?;
        
        let hmac_key = D::create_hmac_key(key)
            .map_err(|_| DigestError::InvalidKeyLength)?;
        let session = controller.init_hmac_session_sha512(hmac_key)
            .map_err(|_| DigestError::InvalidKeyLength)?;
        
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        
        let digest_session = DigestSession {
            session_id,
            algorithm: DigestAlgorithm::HmacSha512,
            context: SessionContext::HmacSha512(Some(session)),
            created_at: sys_get_timer().now,
        };
        
        self.current_session = Some(digest_session);
        Ok(session_id)
    }
    
    fn update_internal(&mut self, session_id: u32, data: &[u8]) -> Result<(), DigestError> {
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
            SessionContext::HmacSha256(ctx_opt) => {
                let old_ctx = ctx_opt.take().ok_or(DigestError::InvalidSession)?;
                let new_ctx = old_ctx.update_mac(data).map_err(|_| DigestError::HardwareFailure)?;
                *ctx_opt = Some(new_ctx);
            }
            SessionContext::HmacSha384(ctx_opt) => {
                let old_ctx = ctx_opt.take().ok_or(DigestError::InvalidSession)?;
                let new_ctx = old_ctx.update_mac(data).map_err(|_| DigestError::HardwareFailure)?;
                *ctx_opt = Some(new_ctx);
            }
            SessionContext::HmacSha512(ctx_opt) => {
                let old_ctx = ctx_opt.take().ok_or(DigestError::InvalidSession)?;
                let new_ctx = old_ctx.update_mac(data).map_err(|_| DigestError::HardwareFailure)?;
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
    
    // HMAC finalization methods
    fn finalize_hmac_sha256_internal(&mut self, session_id: u32) -> Result<[u8; 32], DigestError> {
        let mut session = self.current_session.take()
            .ok_or(DigestError::InvalidSession)?;
        
        // Verify session ID matches
        if session.session_id != session_id {
            // Put session back if ID doesn't match
            self.current_session = Some(session);
            return Err(DigestError::InvalidSession);
        }
        
        match &mut session.context {
            SessionContext::HmacSha256(ctx_opt) => {
                let ctx = ctx_opt.take().ok_or(DigestError::InvalidSession)?;
                let (mac_tag, controller) = ctx.finalize_mac()
                    .map_err(|_| DigestError::HardwareFailure)?;
                
                // Return controller to available pool
                self.controllers.hardware = Some(controller);
                
                Ok(mac_tag)
            }
            _ => Err(DigestError::UnsupportedAlgorithm),
        }
    }
    
    fn finalize_hmac_sha384_internal(&mut self, session_id: u32) -> Result<[u8; 48], DigestError> {
        let mut session = self.current_session.take()
            .ok_or(DigestError::InvalidSession)?;
        
        // Verify session ID matches
        if session.session_id != session_id {
            // Put session back if ID doesn't match
            self.current_session = Some(session);
            return Err(DigestError::InvalidSession);
        }
        
        match &mut session.context {
            SessionContext::HmacSha384(ctx_opt) => {
                let ctx = ctx_opt.take().ok_or(DigestError::InvalidSession)?;
                let (mac_tag, controller) = ctx.finalize_mac()
                    .map_err(|_| DigestError::HardwareFailure)?;
                
                // Return controller to available pool
                self.controllers.hardware = Some(controller);
                
                Ok(mac_tag)
            }
            _ => Err(DigestError::UnsupportedAlgorithm),
        }
    }
    
    fn finalize_hmac_sha512_internal(&mut self, session_id: u32) -> Result<[u8; 64], DigestError> {
        let mut session = self.current_session.take()
            .ok_or(DigestError::InvalidSession)?;
        
        // Verify session ID matches
        if session.session_id != session_id {
            // Put session back if ID doesn't match
            self.current_session = Some(session);
            return Err(DigestError::InvalidSession);
        }
        
        match &mut session.context {
            SessionContext::HmacSha512(ctx_opt) => {
                let ctx = ctx_opt.take().ok_or(DigestError::InvalidSession)?;
                let (mac_tag, controller) = ctx.finalize_mac()
                    .map_err(|_| DigestError::HardwareFailure)?;
                
                // Return controller to available pool
                self.controllers.hardware = Some(controller);
                
                Ok(mac_tag)
            }
            _ => Err(DigestError::UnsupportedAlgorithm),
        }
    }
    
    // One-shot SHA-384 hash - uses session-based approach
    fn compute_sha384_oneshot(&mut self, data: &[u8]) -> Result<Digest<12>, DigestError> {
        // Use session-based approach for hardware compatibility
        let session_id = self.init_sha384_internal()?;
        self.update_internal(session_id, data)?;
        let words = self.finalize_sha384_internal(session_id)?;
        Ok(Digest::new(words))
    }
    
    // One-shot SHA-512 hash - uses session-based approach
    fn compute_sha512_oneshot(&mut self, data: &[u8]) -> Result<Digest<16>, DigestError> {
        // Use session-based approach for hardware compatibility
        let session_id = self.init_sha512_internal()?;
        self.update_internal(session_id, data)?;
        let words = self.finalize_sha512_internal(session_id)?;
        Ok(Digest::new(words))
    }
    
    // One-shot SHA-256 hash - uses HAL traits correctly
    // One-shot SHA-256 hash - uses session-based approach
    fn compute_sha256_oneshot(&mut self, data: &[u8]) -> Result<Digest<8>, DigestError> {
        // Use session-based approach for hardware compatibility
        let session_id = self.init_sha256_internal()?;
        self.update_internal(session_id, data)?;
        let words = self.finalize_sha256_internal(session_id)?;
        Ok(Digest::new(words))
    }
}

// Implementation of the digest API - session-based operations using owned API
impl<D: HubrisDigestDevice> idl::InOrderDigestImpl for ServerImpl<D> 
{
    // Session-based operations using owned API - fully supported
    fn init_sha256(&mut self, _msg: &RecvMessage) -> Result<u32, RequestError<DigestError>> {
        self.init_sha256_internal().map_err(RequestError::Runtime)
    }

    fn init_sha384(&mut self, _msg: &RecvMessage) -> Result<u32, RequestError<DigestError>> {
        self.init_sha384_internal().map_err(RequestError::Runtime)
    }

    fn init_sha512(&mut self, _msg: &RecvMessage) -> Result<u32, RequestError<DigestError>> {
        self.init_sha512_internal().map_err(RequestError::Runtime)
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
        self.update_internal(session_id, data_slice).map_err(RequestError::Runtime)
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

    // HMAC initialization methods
    fn init_hmac_sha256(
        &mut self,
        _msg: &RecvMessage,
        key_len: u32,
        key: LenLimit<Leased<R, [u8]>, 64>,
    ) -> Result<u32, RequestError<DigestError>> {
        let key_len = key_len as usize;
        if key_len > key.len() || key_len > 64 {
            return Err(RequestError::Runtime(DigestError::InvalidInputLength));
        }

        // Read key data into buffer
        let mut key_buffer = [0u8; 64];
        key.read_range(0..key_len, &mut key_buffer[..key_len])
            .map_err(|_| RequestError::Runtime(DigestError::InvalidInputLength))?;

        self.init_hmac_sha256_internal(&key_buffer[..key_len]).map_err(RequestError::Runtime)
    }

    fn init_hmac_sha384(
        &mut self,
        _msg: &RecvMessage,
        key_len: u32,
        key: LenLimit<Leased<R, [u8]>, 128>,
    ) -> Result<u32, RequestError<DigestError>> {
        let key_len = key_len as usize;
        if key_len > key.len() || key_len > 128 {
            return Err(RequestError::Runtime(DigestError::InvalidInputLength));
        }

        // Read key data into buffer
        let mut key_buffer = [0u8; 128];
        key.read_range(0..key_len, &mut key_buffer[..key_len])
            .map_err(|_| RequestError::Runtime(DigestError::InvalidInputLength))?;

        self.init_hmac_sha384_internal(&key_buffer[..key_len]).map_err(RequestError::Runtime)
    }

    fn init_hmac_sha512(
        &mut self,
        _msg: &RecvMessage,
        key_len: u32,
        key: LenLimit<Leased<R, [u8]>, 128>,
    ) -> Result<u32, RequestError<DigestError>> {
        let key_len = key_len as usize;
        if key_len > key.len() || key_len > 128 {
            return Err(RequestError::Runtime(DigestError::InvalidInputLength));
        }

        // Read key data into buffer
        let mut key_buffer = [0u8; 128];
        key.read_range(0..key_len, &mut key_buffer[..key_len])
            .map_err(|_| RequestError::Runtime(DigestError::InvalidInputLength))?;

        self.init_hmac_sha512_internal(&key_buffer[..key_len]).map_err(RequestError::Runtime)
    }

    // HMAC finalization methods
    fn finalize_hmac_sha256(
        &mut self,
        _msg: &RecvMessage,
        session_id: u32,
        mac_out: Leased<W, [u32; 8]>,
    ) -> Result<(), RequestError<DigestError>> {
        let result = self.finalize_hmac_sha256_internal(session_id).map_err(RequestError::Runtime)?;
        
        // Convert [u8; 32] to [u32; 8] for the IDL interface
        let mut u32_result = [0u32; 8];
        for (i, chunk) in result.chunks(4).enumerate() {
            u32_result[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        
        mac_out.write(u32_result).map_err(|_| RequestError::Fail(ClientError::WentAway))?;
        Ok(())
    }

    fn finalize_hmac_sha384(
        &mut self,
        _msg: &RecvMessage,
        session_id: u32,
        mac_out: Leased<W, [u32; 12]>,
    ) -> Result<(), RequestError<DigestError>> {
        let result = self.finalize_hmac_sha384_internal(session_id).map_err(RequestError::Runtime)?;
        
        // Convert [u8; 48] to [u32; 12] for the IDL interface
        let mut u32_result = [0u32; 12];
        for (i, chunk) in result.chunks(4).enumerate() {
            u32_result[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        
        mac_out.write(u32_result).map_err(|_| RequestError::Fail(ClientError::WentAway))?;
        Ok(())
    }

    fn finalize_hmac_sha512(
        &mut self,
        _msg: &RecvMessage,
        session_id: u32,
        mac_out: Leased<W, [u32; 16]>,
    ) -> Result<(), RequestError<DigestError>> {
        let result = self.finalize_hmac_sha512_internal(session_id).map_err(RequestError::Runtime)?;
        
        // Convert [u8; 64] to [u32; 16] for the IDL interface
        let mut u32_result = [0u32; 16];
        for (i, chunk) in result.chunks(4).enumerate() {
            u32_result[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        
        mac_out.write(u32_result).map_err(|_| RequestError::Fail(ClientError::WentAway))?;
        Ok(())
    }

    // HMAC one-shot methods (not implemented yet - return unsupported)
    fn hmac_oneshot_sha256(
        &mut self,
        _msg: &RecvMessage,
        _key_len: u32,
        _data_len: u32,
        _key: LenLimit<Leased<R, [u8]>, 64>,
        _data: LenLimit<Leased<R, [u8]>, 1024>,
        _mac_out: Leased<W, [u32; 8]>,
    ) -> Result<(), RequestError<DigestError>> {
        Err(RequestError::Runtime(DigestError::UnsupportedAlgorithm))
    }

    fn hmac_oneshot_sha384(
        &mut self,
        _msg: &RecvMessage,
        _key_len: u32,
        _data_len: u32,
        _key: LenLimit<Leased<R, [u8]>, 128>,
        _data: LenLimit<Leased<R, [u8]>, 1024>,
        _mac_out: Leased<W, [u32; 12]>,
    ) -> Result<(), RequestError<DigestError>> {
        Err(RequestError::Runtime(DigestError::UnsupportedAlgorithm))
    }

    fn hmac_oneshot_sha512(
        &mut self,
        _msg: &RecvMessage,
        _key_len: u32,
        _data_len: u32,
        _key: LenLimit<Leased<R, [u8]>, 128>,
        _data: LenLimit<Leased<R, [u8]>, 1024>,
        _mac_out: Leased<W, [u32; 16]>,
    ) -> Result<(), RequestError<DigestError>> {
        Err(RequestError::Runtime(DigestError::UnsupportedAlgorithm))
    }

    // HMAC verification methods (not implemented yet - return unsupported)  
    fn verify_hmac_sha256(
        &mut self,
        _msg: &RecvMessage,
        _key_len: u32,
        _data_len: u32,
        _key: LenLimit<Leased<R, [u8]>, 64>,
        _data: LenLimit<Leased<R, [u8]>, 1024>,
        _expected_mac: Leased<R, [u32; 8]>,
    ) -> Result<bool, RequestError<DigestError>> {
        Err(RequestError::Runtime(DigestError::UnsupportedAlgorithm))
    }

    fn verify_hmac_sha384(
        &mut self,
        _msg: &RecvMessage,
        _key_len: u32,
        _data_len: u32,
        _key: LenLimit<Leased<R, [u8]>, 128>,
        _data: LenLimit<Leased<R, [u8]>, 1024>,
        _expected_mac: Leased<R, [u32; 12]>,
    ) -> Result<bool, RequestError<DigestError>> {
        Err(RequestError::Runtime(DigestError::UnsupportedAlgorithm))
    }

    fn verify_hmac_sha512(
        &mut self,
        _msg: &RecvMessage,
        _key_len: u32,
        _data_len: u32,
        _key: LenLimit<Leased<R, [u8]>, 128>,
        _data: LenLimit<Leased<R, [u8]>, 1024>,
        _expected_mac: Leased<R, [u32; 16]>,
    ) -> Result<bool, RequestError<DigestError>> {
        Err(RequestError::Runtime(DigestError::UnsupportedAlgorithm))
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
impl<D: HubrisDigestDevice> ServerImpl<D> {
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
    
    #[cfg(feature = "rustcrypto")]
    let hardware = RustCryptoController::new();
    
    #[cfg(not(any(feature = "aspeed-hace", feature = "rustcrypto")))]
    let hardware = MockDigestController::new();

    let mut server = ServerImpl::new(hardware);
    
    // Hardware reset functionality removed for compatibility

    // Enter the main IPC loop
    let mut incoming = [0u8; idl::INCOMING_SIZE];
    loop {
        idol_runtime::dispatch(&mut incoming, &mut server);
    }
}

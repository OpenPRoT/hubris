// Platform abstraction layer for SPDM

pub mod hash;
pub mod rng;
pub mod cert_store;
pub mod evidence;

#[cfg(feature = "sha2-crypto")]
pub mod hash_sha2;

pub use rng::SystemRng;
pub use cert_store::DemoCertStore;
pub use evidence::DemoEvidence;

// Conditional exports - only compile what's needed
#[cfg(feature = "sha2-crypto")]
pub use hash_sha2::Sha2Hash as PlatformHash;

#[cfg(not(feature = "sha2-crypto"))]
pub use hash::DigestHash;
#[cfg(not(feature = "sha2-crypto"))]
pub type PlatformHash = DigestHash;

// Unified constructor function that handles different parameter requirements
pub fn create_platform_hash(
    #[cfg(not(feature = "sha2-crypto"))]
    digest_client: drv_digest_api::Digest
) -> PlatformHash {
    #[cfg(feature = "sha2-crypto")]
    {
        PlatformHash::new()
    }
    
    #[cfg(not(feature = "sha2-crypto"))]
    {
        PlatformHash::new(digest_client)
    }
}
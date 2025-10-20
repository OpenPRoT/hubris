// Platform abstraction layer for SPDM

#[cfg(feature = "ecdsa-rust-crypto")]
pub mod cert_store_rust_crypto;
#[cfg(not(feature = "ecdsa-rust-crypto"))]
pub mod cert_store_rust_stub;
pub mod certs;
pub mod evidence;
pub mod hash;
pub mod rng;

#[cfg(feature = "sha2-crypto")]
pub mod hash_sha2;

pub use evidence::DemoEvidence;
pub use rng::SystemRng;

// Certificate store selection based on features
#[cfg(feature = "ecdsa-rust-crypto")]
pub use cert_store_rust_crypto::DemoCertStore;
#[cfg(not(feature = "ecdsa-rust-crypto"))]
pub use cert_store_rust_stub::DemoCertStore;

// Conditional exports - only compile what's needed
#[cfg(feature = "sha2-crypto")]
pub use hash_sha2::Sha2Hash as PlatformHash;

#[cfg(not(feature = "sha2-crypto"))]
pub use hash::DigestHash;
#[cfg(not(feature = "sha2-crypto"))]
pub type PlatformHash = DigestHash;

// Certificate store type alias
#[cfg(feature = "ecdsa-rust-crypto")]
pub type PlatformCertStore = cert_store_rust_crypto::DemoCertStore;
#[cfg(not(feature = "ecdsa-rust-crypto"))]
pub type PlatformCertStore = cert_store_rust_stub::DemoCertStore;

// Unified constructor function that handles different parameter requirements
pub fn create_platform_hash(
    #[cfg(not(feature = "sha2-crypto"))] digest_client: drv_digest_api::Digest,
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

// Unified constructor for certificate store
pub fn create_platform_cert_store() -> PlatformCertStore {
    PlatformCertStore::new()
}

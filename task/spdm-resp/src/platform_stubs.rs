// Stub platform implementations for no_std Hubris
use spdm_lib::cert_store::{CertStoreError, SpdmCertStore};
use spdm_lib::platform::evidence::{SpdmEvidence, SpdmEvidenceError};
use spdm_lib::platform::hash::{SpdmHash, SpdmHashAlgoType, SpdmHashResult};
use spdm_lib::platform::rng::{SpdmRng, SpdmRngError};
use spdm_lib::protocol::certs::{CertificateInfo, KeyUsageMask};
use spdm_lib::protocol::AsymAlgo;

pub struct Sha384Hash;
impl Sha384Hash {
    pub fn new() -> Self {
        Self
    }
}
impl SpdmHash for Sha384Hash {
    // Stub implementations - replace with real hash logic
    fn hash(
        &mut self,
        _hash_algo: SpdmHashAlgoType,
        _data: &[u8],
        _hash: &mut [u8],
    ) -> SpdmHashResult<()> {
        Ok(())
    }
    fn init(
        &mut self,
        _hash_algo: SpdmHashAlgoType,
        _data: Option<&[u8]>,
    ) -> SpdmHashResult<()> {
        Ok(())
    }
    fn update(&mut self, _data: &[u8]) -> SpdmHashResult<()> {
        Ok(())
    }
    fn finalize(&mut self, _out: &mut [u8]) -> SpdmHashResult<()> {
        Ok(())
    }
    fn reset(&mut self) {}
    fn algo(&self) -> SpdmHashAlgoType {
        SpdmHashAlgoType::SHA384
    }
}

pub struct SystemRng;
impl SystemRng {
    pub fn new() -> Self {
        Self
    }
}
impl SpdmRng for SystemRng {
    fn get_random_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), SpdmRngError> {
        dest.fill(0); // Stub
        Ok(())
    }
    fn generate_random_number(
        &mut self,
        out: &mut [u8],
    ) -> Result<(), SpdmRngError> {
        out.fill(0); // Stub
        Ok(())
    }
}

pub struct DemoCertStore;
impl DemoCertStore {
    pub fn new() -> Self {
        Self
    }
}
impl SpdmCertStore for DemoCertStore {
    // Stub implementations - replace with real cert store logic
    fn slot_count(&self) -> u8 {
        1
    }
    fn is_provisioned(&self, _slot: u8) -> bool {
        true
    }
    fn cert_chain_len(
        &mut self,
        _algo: AsymAlgo,
        _slot: u8,
    ) -> Result<usize, CertStoreError> {
        Ok(0)
    }
    fn get_cert_chain(
        &mut self,
        _slot: u8,
        _algo: AsymAlgo,
        _offset: usize,
        _out: &mut [u8],
    ) -> Result<usize, CertStoreError> {
        Ok(0)
    }
    fn root_cert_hash(
        &mut self,
        _slot: u8,
        _algo: AsymAlgo,
        _out: &mut [u8; 48],
    ) -> Result<(), CertStoreError> {
        Ok(())
    }
    fn sign_hash(
        &self,
        _slot: u8,
        _hash: &[u8; 48],
        _out: &mut [u8; 96],
    ) -> Result<(), CertStoreError> {
        Ok(())
    }
    fn key_pair_id(&self, _slot: u8) -> Option<u8> {
        Some(0)
    }
    fn cert_info(&self, _slot: u8) -> Option<CertificateInfo> {
        None
    }
    fn key_usage_mask(&self, _slot: u8) -> Option<KeyUsageMask> {
        None
    }
}

pub struct DemoEvidence;
impl DemoEvidence {
    pub fn new() -> Self {
        Self
    }
}
impl SpdmEvidence for DemoEvidence {
    // Stub implementations - replace with real evidence logic
    fn pcr_quote(
        &self,
        _pcr_index: &mut [u8],
        _out: bool,
    ) -> Result<usize, SpdmEvidenceError> {
        Ok(0)
    }
    fn pcr_quote_size(
        &self,
        _pcr_index: bool,
    ) -> Result<usize, SpdmEvidenceError> {
        Ok(0)
    }
}

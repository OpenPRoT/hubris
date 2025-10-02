// Certificate store platform implementation for SPDM

use spdm_lib::cert_store::{CertStoreError, SpdmCertStore};
use spdm_lib::protocol::certs::{CertificateInfo, KeyUsageMask};
use spdm_lib::protocol::AsymAlgo;

pub struct DemoCertStore {
    // Pure stub - no fields needed
}

impl DemoCertStore {
    pub fn new() -> Self {
        Self {
            // Pure stub implementation
        }
    }
}

impl SpdmCertStore for DemoCertStore {
    // Stub implementations - all methods return minimal stub values
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
        out: &mut [u8; 96],
    ) -> Result<(), CertStoreError> {
        // Pure stub implementation - fill output with zeros
        out.fill(0);
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
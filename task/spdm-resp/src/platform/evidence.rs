// Evidence platform implementation for SPDM

use spdm_lib::platform::evidence::{SpdmEvidence, SpdmEvidenceError};

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
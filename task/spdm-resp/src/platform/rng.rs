// Random number generator platform implementation for SPDM

use spdm_lib::platform::rng::{SpdmRng, SpdmRngError};

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
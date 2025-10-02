// Random number generator platform implementation for SPDM


use spdm_lib::platform::rng::{SpdmRng, SpdmRngError};
use drv_rng_api::Rng;

pub struct SystemRng {
    rng: Rng,
}

impl SystemRng {
    pub fn new(rng: Rng) -> Self {
        Self { rng }
    }
}

impl SpdmRng for SystemRng {
    fn get_random_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), SpdmRngError> {
        self.rng.fill(dest).map(|_| ()).map_err(|_| SpdmRngError::InvalidSize)
    }

    fn generate_random_number(
        &mut self,
        out: &mut [u8],
    ) -> Result<(), SpdmRngError> {
        self.rng.fill(out).map(|_| ()).map_err(|_| SpdmRngError::InvalidSize)
    }
}
// Hash platform implementation for SPDM using mbedtls

use mbedtls::hash::{self, Type as MbedHashType};
use spdm_lib::platform::hash::{SpdmHash, SpdmHashAlgoType, SpdmHashError, SpdmHashResult};

/// mbedtls-based hash implementation that supports multiple algorithms
pub struct MbedtlsHash {
    context: Option<hash::Md>,
    algo: SpdmHashAlgoType,
}

impl MbedtlsHash {
    pub fn new() -> Self {
        Self {
            context: None,
            algo: SpdmHashAlgoType::SHA384, // Default
        }
    }

    fn hash_type_from_spdm(algo: SpdmHashAlgoType) -> Result<MbedHashType, SpdmHashError> {
        match algo {
            SpdmHashAlgoType::SHA384 => Ok(MbedHashType::Sha384),
            SpdmHashAlgoType::SHA512 => Ok(MbedHashType::Sha512),
            _ => Err(SpdmHashError::PlatformError),
        }
    }

    fn expected_hash_size(algo: SpdmHashAlgoType) -> usize {
        match algo {
            SpdmHashAlgoType::SHA384 => 48, // SHA-384 produces 48 bytes
            SpdmHashAlgoType::SHA512 => 64, // SHA-512 produces 64 bytes
            _ => 0,
        }
    }
}

impl SpdmHash for MbedtlsHash {
    fn hash(
        &mut self,
        hash_algo: SpdmHashAlgoType,
        data: &[u8],
        hash: &mut [u8],
    ) -> SpdmHashResult<()> {
        // One-shot hash operation using mbedtls
        let hash_type = Self::hash_type_from_spdm(hash_algo)?;
        let expected_size = Self::expected_hash_size(hash_algo);
        
        if hash.len() < expected_size {
            return Err(SpdmHashError::PlatformError);
        }

        let digest = hash::Md::hash(hash_type, data)
            .map_err(|_| SpdmHashError::PlatformError)?;
        
        hash[..expected_size].copy_from_slice(&digest[..expected_size]);
        Ok(())
    }

    fn init(
        &mut self,
        hash_algo: SpdmHashAlgoType,
        data: Option<&[u8]>,
    ) -> SpdmHashResult<()> {
        // Initialize a new hash context
        self.algo = hash_algo;
        let hash_type = Self::hash_type_from_spdm(hash_algo)?;
        
        let mut context = hash::Md::new(hash_type)
            .map_err(|_| SpdmHashError::PlatformError)?;
        
        context.start()
            .map_err(|_| SpdmHashError::PlatformError)?;

        // If initial data is provided, update with it
        if let Some(d) = data {
            context.update(d)
                .map_err(|_| SpdmHashError::PlatformError)?;
        }

        self.context = Some(context);
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> SpdmHashResult<()> {
        let context = self.context.as_mut()
            .ok_or(SpdmHashError::PlatformError)?;

        context.update(data)
            .map_err(|_| SpdmHashError::PlatformError)?;
        
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8]) -> SpdmHashResult<()> {
        let mut context = self.context.take()
            .ok_or(SpdmHashError::PlatformError)?;

        let expected_size = Self::expected_hash_size(self.algo);
        
        if out.len() < expected_size {
            return Err(SpdmHashError::PlatformError);
        }

        let digest = context.finish()
            .map_err(|_| SpdmHashError::PlatformError)?;
        
        out[..expected_size].copy_from_slice(&digest[..expected_size]);
        Ok(())
    }

    fn reset(&mut self) {
        self.context = None;
    }

    fn algo(&self) -> SpdmHashAlgoType {
        self.algo
    }
}

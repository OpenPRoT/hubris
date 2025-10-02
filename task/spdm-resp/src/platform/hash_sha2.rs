// Hash platform implementation for SPDM using pure Rust sha2

use sha2::{Digest, Sha384, Sha512};
use spdm_lib::platform::hash::{SpdmHash, SpdmHashAlgoType, SpdmHashError, SpdmHashResult};

/// Pure Rust hash implementation that supports multiple algorithms
pub struct Sha2Hash {
    context: Option<HashContextEnum>,
    algo: SpdmHashAlgoType,
}

enum HashContextEnum {
    Sha384(Sha384),
    Sha512(Sha512),
}

impl HashContextEnum {
    fn update(&mut self, data: &[u8]) {
        match self {
            HashContextEnum::Sha384(ctx) => Digest::update(ctx, data),
            HashContextEnum::Sha512(ctx) => Digest::update(ctx, data),
        }
    }
    
    fn finalize(self, out: &mut [u8]) -> Result<usize, SpdmHashError> {
        match self {
            HashContextEnum::Sha384(ctx) => {
                let digest = ctx.finalize();
                if out.len() < 48 {
                    return Err(SpdmHashError::PlatformError);
                }
                out[..48].copy_from_slice(&digest[..]);
                Ok(48)
            }
            HashContextEnum::Sha512(ctx) => {
                let digest = ctx.finalize();
                if out.len() < 64 {
                    return Err(SpdmHashError::PlatformError);
                }
                out[..64].copy_from_slice(&digest[..]);
                Ok(64)
            }
        }
    }
}

impl Sha2Hash {
    pub fn new() -> Self {
        Self {
            context: None,
            algo: SpdmHashAlgoType::SHA384, // Default
        }
    }

    fn expected_hash_size(algo: SpdmHashAlgoType) -> usize {
        match algo {
            SpdmHashAlgoType::SHA384 => 48, // SHA-384 produces 48 bytes
            SpdmHashAlgoType::SHA512 => 64, // SHA-512 produces 64 bytes
        }
    }

    fn create_context(algo: SpdmHashAlgoType) -> Result<HashContextEnum, SpdmHashError> {
        match algo {
            SpdmHashAlgoType::SHA384 => Ok(HashContextEnum::Sha384(Sha384::new())),
            SpdmHashAlgoType::SHA512 => Ok(HashContextEnum::Sha512(Sha512::new())),
        }
    }
}

impl SpdmHash for Sha2Hash {
    fn hash(
        &mut self,
        hash_algo: SpdmHashAlgoType,
        data: &[u8],
        hash: &mut [u8],
    ) -> SpdmHashResult<()> {
        // One-shot hash operation using sha2
        let expected_size = Self::expected_hash_size(hash_algo);
        
        if hash.len() < expected_size {
            return Err(SpdmHashError::PlatformError);
        }

        match hash_algo {
            SpdmHashAlgoType::SHA384 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                let digest = hasher.finalize();
                hash[..48].copy_from_slice(&digest[..]);
            }
            SpdmHashAlgoType::SHA512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                let digest = hasher.finalize();
                hash[..64].copy_from_slice(&digest[..]);
            }
        };
        
        Ok(())
    }

    fn init(
        &mut self,
        hash_algo: SpdmHashAlgoType,
        data: Option<&[u8]>,
    ) -> SpdmHashResult<()> {
        // Initialize a new hash context
        self.algo = hash_algo;
        let mut context = Self::create_context(hash_algo)?;

        // If initial data is provided, update with it
        if let Some(d) = data {
            context.update(d);
        }

        self.context = Some(context);
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> SpdmHashResult<()> {
        let context = self.context.as_mut()
            .ok_or(SpdmHashError::PlatformError)?;

        context.update(data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8]) -> SpdmHashResult<()> {
        let context = self.context.take()
            .ok_or(SpdmHashError::PlatformError)?;

        let expected_size = Self::expected_hash_size(self.algo);
        
        if out.len() < expected_size {
            return Err(SpdmHashError::PlatformError);
        }

        context.finalize(out)?;
        Ok(())
    }

    fn reset(&mut self) {
        self.context = None;
    }

    fn algo(&self) -> SpdmHashAlgoType {
        self.algo
    }
}
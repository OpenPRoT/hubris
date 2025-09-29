// Hash platform implementation for SPDM using Digest IPC API

use drv_digest_api::{Digest, SHA384_WORDS, SHA512_WORDS};
use spdm_lib::platform::hash::{SpdmHash, SpdmHashAlgoType, SpdmHashError, SpdmHashResult};

/// General-purpose digest hash implementation that supports multiple algorithms
pub struct DigestHash {
    client: Digest,
    session_id: Option<u32>,
    algo: SpdmHashAlgoType,
}

impl DigestHash {
    pub fn new(client: Digest) -> Self {
        Self {
            client,
            session_id: None,
            algo: SpdmHashAlgoType::SHA384, // Default
        }
    }
}

impl SpdmHash for DigestHash {
    fn hash(
        &mut self,
        hash_algo: SpdmHashAlgoType,
        data: &[u8],
        hash: &mut [u8],
    ) -> SpdmHashResult<()> {
        // One-shot hash operation
        match hash_algo {
            SpdmHashAlgoType::SHA384 => {
                let mut digest = [0u32; SHA384_WORDS];
                self.client
                    .digest_oneshot_sha384(data.len() as u32, data, &mut digest)
                    .map_err(|_| SpdmHashError::PlatformError)?;

                // Convert u32 words to bytes (big-endian)
                for (i, word) in digest.iter().enumerate() {
                    let bytes = word.to_be_bytes();
                    hash[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
                }
            }
            SpdmHashAlgoType::SHA512 => {
                let mut digest = [0u32; SHA512_WORDS];
                self.client
                    .digest_oneshot_sha512(data.len() as u32, data, &mut digest)
                    .map_err(|_| SpdmHashError::PlatformError)?;

                // Convert u32 words to bytes (big-endian)
                for (i, word) in digest.iter().enumerate() {
                    let bytes = word.to_be_bytes();
                    hash[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
                }
            }
        }
        Ok(())
    }

    fn init(
        &mut self,
        hash_algo: SpdmHashAlgoType,
        data: Option<&[u8]>,
    ) -> SpdmHashResult<()> {
        // Initialize a new hash session
        self.algo = hash_algo;

        let session_id = match hash_algo {
            SpdmHashAlgoType::SHA384 => self
                .client
                .init_sha384()
                .map_err(|_| SpdmHashError::PlatformError)?,
            SpdmHashAlgoType::SHA512 => self
                .client
                .init_sha512()
                .map_err(|_| SpdmHashError::PlatformError)?,
        };

        self.session_id = Some(session_id);

        // If initial data is provided, update with it
        if let Some(d) = data {
            self.update(d)?;
        }

        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> SpdmHashResult<()> {
        let session_id = self.session_id.ok_or(SpdmHashError::PlatformError)?;

        // Process data in chunks if needed (max 1024 bytes per IPC call)
        for chunk in data.chunks(1024) {
            self.client
                .update(session_id, chunk.len() as u32, chunk)
                .map_err(|_| SpdmHashError::PlatformError)?;
        }

        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8]) -> SpdmHashResult<()> {
        let session_id = self.session_id.ok_or(SpdmHashError::PlatformError)?;

        match self.algo {
            SpdmHashAlgoType::SHA384 => {
                let mut digest = [0u32; SHA384_WORDS];
                self.client
                    .finalize_sha384(session_id, &mut digest)
                    .map_err(|_| SpdmHashError::PlatformError)?;

                // Convert u32 words to bytes (big-endian)
                for (i, word) in digest.iter().enumerate() {
                    let bytes = word.to_be_bytes();
                    out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
                }
            }
            SpdmHashAlgoType::SHA512 => {
                let mut digest = [0u32; SHA512_WORDS];
                self.client
                    .finalize_sha512(session_id, &mut digest)
                    .map_err(|_| SpdmHashError::PlatformError)?;

                // Convert u32 words to bytes (big-endian)
                for (i, word) in digest.iter().enumerate() {
                    let bytes = word.to_be_bytes();
                    out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
                }
            }
        }

        self.session_id = None;
        Ok(())
    }

    fn reset(&mut self) {
        if let Some(session_id) = self.session_id {
            let _ = self.client.reset(session_id);
        }
        self.session_id = None;
    }

    fn algo(&self) -> SpdmHashAlgoType {
        self.algo
    }
}
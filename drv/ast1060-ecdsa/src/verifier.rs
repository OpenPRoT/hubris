// Licensed under the Apache-2.0 license


use ast1060_pac::Secure;
use core::{
    convert::{AsRef, AsMut},
    default::Default,
    ptr::{read_volatile, write_volatile, NonNull},
    result::{Result, Result::Ok, Result::Err},
};
use embedded_hal_1::delay::DelayNs;
use openprot_hal_blocking::ecdsa::{
    Curve, EcdsaVerify, Error, ErrorKind, ErrorType,
    PublicKey, Signature, SerializablePublicKey, SerializableSignature, P384,
};
use openprot_hal_blocking::digest::DigestAlgorithm;
use zerocopy::{IntoBytes, FromBytes, Immutable};

// Import the concrete types from lib.rs
use crate::{P384PublicKey, P384Signature};

// Use the standardized SHA-384 from OpenPRoT HAL instead of custom implementation
pub use openprot_hal_blocking::digest::Sha2_384 as Sha384;


const ECDSA_BASE: usize = 0x7e6f_2000; // SBC base address
const ECDSA_SRAM_BASE: usize = 0x7900_0000; // SRAM base address for ECDSA
const ASPEED_ECDSA_PAR_GX: usize = 0x0a00;
const ASPEED_ECDSA_PAR_GY: usize = 0x0a40;
const ASPEED_ECDSA_PAR_P: usize = 0x0a80;
const ASPEED_ECDSA_PAR_N: usize = 0x0ac0;

const SRAM_DST_GX: usize = 0x2000;
const SRAM_DST_GY: usize = 0x2040;
const SRAM_DST_A: usize = 0x2140;
const SRAM_DST_P: usize = 0x2100;
const SRAM_DST_N: usize = 0x2180;
const SRAM_DST_QX: usize = 0x2080;
const SRAM_DST_QY: usize = 0x20c0;
const SRAM_DST_R: usize = 0x21c0;
const SRAM_DST_S: usize = 0x2200;
const SRAM_DST_M: usize = 0x2240;

// P384 scalar size derived from the curve's scalar type
const P384_SCALAR_SIZE: usize = core::mem::size_of::<<P384 as Curve>::Scalar>();


#[derive(Debug, Clone)]
pub enum AspeedEcdsaError {
    InvalidSignature,
    Busy,
    BadInput,
    InvalidPoint,
    WeakKey,
    HardwareFailure,
}

impl Error for AspeedEcdsaError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::InvalidSignature => ErrorKind::InvalidSignature,
            Self::Busy => ErrorKind::Busy,
            Self::BadInput => ErrorKind::InvalidKeyFormat,
            Self::InvalidPoint => ErrorKind::InvalidPoint,
            Self::WeakKey => ErrorKind::WeakKey,
            Self::HardwareFailure => ErrorKind::Other,
        }
    }
}

pub struct AspeedEcdsa<D: DelayNs> {
    secure: Secure,
    ecdsa_base: NonNull<u32>,
    sram_base: NonNull<u32>,
    delay: D,
}

impl<D: DelayNs> ErrorType for AspeedEcdsa<D> {
    type Error = AspeedEcdsaError;
}

impl<D: DelayNs> AspeedEcdsa<D> {
    pub fn new(secure: Secure, delay: D) -> Self {
        let ecdsa_base = unsafe { NonNull::new_unchecked(ECDSA_BASE as *mut u32) };
        let sram_base = unsafe { NonNull::new_unchecked(ECDSA_SRAM_BASE as *mut u32) };

        Self {
            secure,
            ecdsa_base,
            sram_base,
            delay,
        }
    }

    fn sec_rd(&self, offset: usize) -> u32 {
        unsafe { read_volatile(self.ecdsa_base.as_ptr().add(offset / 4)) }
    }

    fn sec_wr(&self, offset: usize, val: u32) {
        unsafe {
            write_volatile(self.ecdsa_base.as_ptr().add(offset / 4), val);
        }
    }

    fn sram_wr_u32(&self, offset: usize, val: u32) {
        unsafe {
            write_volatile(self.sram_base.as_ptr().add(offset / 4), val);
        }
    }

    fn sram_wr(&self, offset: usize, data: &[u8; P384_SCALAR_SIZE]) {
        for i in (0..P384_SCALAR_SIZE).step_by(4) {
            let val = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            unsafe {
                write_volatile(self.sram_base.as_ptr().add((offset + i) / 4), val);
            }
        }
    }

    fn load_param(&self, from: usize, to: usize) {
        for i in (0..P384_SCALAR_SIZE).step_by(4) {
            let val = self.sec_rd(from + i);
            self.sram_wr_u32(to + i, val);
        }
    }

    fn load_secp384r1_params(&self) {
        // (1) Gx
        self.load_param(ASPEED_ECDSA_PAR_GX, SRAM_DST_GX);
        // (2) Gy
        self.load_param(ASPEED_ECDSA_PAR_GY, SRAM_DST_GY);
        // (3) p
        self.load_param(ASPEED_ECDSA_PAR_P, SRAM_DST_P);
        // (4) n
        self.load_param(ASPEED_ECDSA_PAR_N, SRAM_DST_N);
        // (5) a
        for i in (0..P384_SCALAR_SIZE).step_by(4) {
            self.sram_wr_u32(SRAM_DST_A + i, 0);
        }
    }
}

impl<D> EcdsaVerify<P384> for AspeedEcdsa<D>
where
    D: DelayNs,
{
    type PublicKey = crate::P384PublicKey;
    type Signature = crate::P384Signature;

    fn verify(
        &mut self,
        public_key: &Self::PublicKey,
        digest: <<P384 as Curve>::DigestType as DigestAlgorithm>::Digest,
        signature: &Self::Signature,
    ) -> Result<(), Self::Error> {

        unsafe {
            // Use zerocopy to safely access digest as [u8; 48] directly
            let digest_array: &[u8; 48] = digest.as_bytes()
                .try_into()
                .map_err(|_| AspeedEcdsaError::BadInput)?;

            self.sec_wr(0x7c, 0x0100_f00b);

            // Reset Engine
            self.secure.secure0b4().write(|w| w.bits(0));
            self.secure
                .secure0b4()
                .write(|w| w.sec_boot_ecceng_enbl().set_bit());
            self.delay.delay_ns(5000);

            self.load_secp384r1_params();

            self.sec_wr(0x7c, 0x0300_f00b);

            let mut x_out = [0u8; 48];
            let mut y_out = [0u8; 48];
            public_key.coordinates(&mut x_out, &mut y_out);

            let mut r_out = [0u8; 48];
            let mut s_out = [0u8; 48];
            signature.coordinates(&mut r_out, &mut s_out);

            // Write qx, qy, r, s
            self.sram_wr(SRAM_DST_QX, &x_out);
            self.sram_wr(SRAM_DST_QY, &y_out);
            self.sram_wr(SRAM_DST_R, &r_out);
            self.sram_wr(SRAM_DST_S, &s_out);
            self.sram_wr(SRAM_DST_M, digest_array);

            self.sec_wr(0x7c, 0);

            // Write ECDSA instruction command
            self.sram_wr_u32(0x23c0, 1);

            // Trigger ECDSA Engine
            self.secure
                .secure0bc()
                .write(|w| w.sec_boot_ecceng_trigger_reg().set_bit());
            self.delay.delay_ns(5000);
            self.secure
                .secure0bc()
                .write(|w| w.sec_boot_ecceng_trigger_reg().clear_bit());

            // Poll
            let mut retry = 1000;
            while retry > 0 {
                let status = self.secure.secure014().read().bits();
                if status & (1 << 20) != 0 {
                    return if status & (1 << 21) != 0 {
                        Ok(())
                    } else {
                        Err(AspeedEcdsaError::InvalidSignature)
                    };
                }
                retry -= 1;
                self.delay.delay_ns(5000);
            }

            Err(AspeedEcdsaError::Busy)
        }
    }
}
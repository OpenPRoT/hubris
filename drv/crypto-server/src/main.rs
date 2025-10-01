#![no_std]
#![no_main]

use drv_crypto_api::{CryptoError};
use idol_runtime::{clienterror, leased, lenlimit, notificationhandler, requesterror, r, w};
use userlib::*;
use zerocopy::intobytes;

use openprot_hal_blocking::ecdsa::{
    P384, EcdsaKeyGen, PrivateKey, PublicKey, Signature, EcdsaSign, EcdsaVerify
};

#[derive(Debug, Clone, Copy)]
pub enum CryptoAlgorithm {
    ecdsa,
}

#[cfg(not(feature = "aspeed-hace"))]
impl CryptoHardwareCapabilities for MockCryptoController {

}

#[cfg(not(feature = "aspeed-hace"))]
use openprot_platform_mock::hash::owned::MockCryptoController;

mod idl {
    use crate::DigestError;
    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}

#[cfg(not(feature = "aspeed-hace"))]
type DefaultCryptoDevice = MockCryptoController;

pub struct ServerImpl<GEN, PRI, PUB, SIG, SGN, VER> 
where
    GEN: EcdsaKeyGen<P384>,
    PRI: PrivateKey<P384>,
    PUB: PublicKey<P384>,
    SIG: Signature<P384>,
    SGN: EcdsaSign<P384>,
    VER: EcdsaVerify<P384>,
{
    keygen: GEN,
    privkey: PRI,
    pubkey: PUB,
    sig: SIG,
    sign: SGN,
    verify: VER,
}
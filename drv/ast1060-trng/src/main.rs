// Licensed under the Apache-2.0 license

//! Driver for the AST1060 true random number generator.
//!
//! Use the rng-api crate to interact with this driver.

#![no_std]
#![no_main]

use drv_rng_api::RngError;
use idol_runtime::{ClientError, NotificationHandler, RequestError};
use lib_ast1060_trng::{Trng, TrngError};
use ringbuf::{counted_ringbuf, ringbuf_entry};
use userlib::*;

counted_ringbuf!(Trace, 32, Trace::Blank);

#[derive(Copy, Clone, Debug, Eq, PartialEq, counters::Count)]
enum Trace {
    #[count(skip)]
    Blank,
    Timeout,
    NotInitialized,
}

struct Ast1060TrngServer {
    trng: Trng,
}

impl Ast1060TrngServer {
    fn new() -> Self {
        let mut trng = unsafe { Trng::new() };
        // Initialize the TRNG during server construction
        if let Err(e) = trng.init() {
            ringbuf_entry!(match e {
                TrngError::NotInitialized => Trace::NotInitialized,
                TrngError::Timeout => Trace::Timeout,
            });
        }
        Ast1060TrngServer { trng }
    }
}

impl idl::InOrderRngImpl for Ast1060TrngServer {
    fn fill(
        &mut self,
        _: &RecvMessage,
        dest: idol_runtime::Leased<idol_runtime::W, [u8]>,
    ) -> Result<usize, RequestError<RngError>> {
        let len = dest.len();
        let mut cnt = 0;
        const STEP: usize = core::mem::size_of::<u32>();
        let mut buf = [0u8; STEP];

        // Fill in multiples of STEP (4 bytes)
        while cnt + STEP <= len {
            if let Err(e) = self.trng.read(&mut buf) {
                ringbuf_entry!(match e {
                    TrngError::Timeout => Trace::Timeout,
                    TrngError::NotInitialized => Trace::NotInitialized,
                });
                return Err(RequestError::Runtime(match e {
                    TrngError::Timeout => RngError::NoData,
                    TrngError::NotInitialized => RngError::UnknownRngError,
                }));
            }

            dest.write_range(cnt..cnt + STEP, &buf)
                .map_err(|_| RequestError::Fail(ClientError::WentAway))?;
            cnt += STEP;
        }

        // Fill remaining bytes (less than STEP)
        let remain = len - cnt;
        if remain > 0 {
            if let Err(e) = self.trng.read(&mut buf) {
                ringbuf_entry!(match e {
                    TrngError::Timeout => Trace::Timeout,
                    TrngError::NotInitialized => Trace::NotInitialized,
                });
                return Err(RequestError::Runtime(match e {
                    TrngError::Timeout => RngError::NoData,
                    TrngError::NotInitialized => RngError::UnknownRngError,
                }));
            }

            dest.write_range(cnt..cnt + remain, &buf[..remain])
                .map_err(|_| RequestError::Fail(ClientError::WentAway))?;
            cnt += remain;
        }

        Ok(cnt)
    }
}

impl NotificationHandler for Ast1060TrngServer {
    fn current_notification_mask(&self) -> u32 {
        // We don't use notifications, don't listen for any.
        0
    }

    fn handle_notification(&mut self, _bits: u32) {
        unreachable!()
    }
}

#[export_name = "main"]
fn main() -> ! {
    let mut srv = Ast1060TrngServer::new();
    let mut buffer = [0u8; idl::INCOMING_SIZE];

    loop {
        idol_runtime::dispatch(&mut buffer, &mut srv);
    }
}

mod idl {
    use drv_rng_api::RngError;

    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}
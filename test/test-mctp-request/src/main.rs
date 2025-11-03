// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{env::var, time::Duration};

use mctp::*;
use mctp_linux::*;

const DEFAULT_REMOTE_EID: u8 = 8;
const DEFAULT_MSG_TYPE: u8 = 1;
const TIMEOUT_SECS: u64 = 5;

/// Simple application that sends a "Hello, World!" request to env variables `REMOTE_EID`, message type `MSG_TYPE`.
/// A check is performed that the response matches the request payload.
/// Errors after a timeout.
fn main() {
    let eid: u8 = var("REMOTE_EID")
        .map(|e| e.parse().unwrap_or(DEFAULT_REMOTE_EID))
        .unwrap_or(DEFAULT_REMOTE_EID);
    let msg_type: u8 = var("MSG_TYPE")
        .map(|e| e.parse().unwrap_or(DEFAULT_MSG_TYPE))
        .unwrap_or(DEFAULT_MSG_TYPE);

    let mut req = MctpLinuxReq::new(mctp::Eid(eid), None).unwrap();
    req.as_socket()
        .set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))
        .unwrap();

    let data = "Hello, World!".as_bytes();
    req.send(mctp::MsgType(msg_type), data).unwrap();

    println!("Sent message to EID {eid}");

    let mut buf = [0; 255];
    let (_, _, resp) = req.recv(&mut buf).unwrap();

    println!("Received echo: '{}'", str::from_utf8(resp).unwrap());
    assert_eq!(data, resp);
}

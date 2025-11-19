// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use super::I2C_MAX_EIDS;
use drv_i2c_api::*;
use heapless::FnvIndexMap;
use log::{trace, warn};
use mctp::{Eid, Result};
use mctp_stack::i2c::{MctpI2cEncap, MCTP_I2C_MAXMTU};
use userlib::TaskId;

pub struct I2cSender {
    i2c_driver_task: TaskId,
    _neighbor_table: FnvIndexMap<Eid, u8, { I2C_MAX_EIDS as usize }>,
}
impl I2cSender {
    pub fn new(i2c_driver_task: TaskId) -> Self {
        Self {
            i2c_driver_task,
            _neighbor_table: FnvIndexMap::new(),
        }
    }
}
impl mctp_stack::Sender for I2cSender {
    fn send_vectored(
        &mut self,
        mut fragmenter: mctp_stack::fragment::Fragmenter,
        payload: &[&[u8]],
    ) -> Result<mctp::Tag> {
        // TODO The stack needs to provide the destination EID to the sender
        // let addr = self
        //     .neighbor_table
        //     .get(eid)
        //     .ok_or(mctp::Error::Unreachable)?;
        let addr = 0x42;
        let i2c = I2cDevice::new(
            self.i2c_driver_task,
            Controller::I2C1,
            PortIndex(0),
            None,
            addr,
        );
        let encoder = MctpI2cEncap::new(super::I2C_OWN_ADDR);
        loop {
            let mut pkt = [0u8; mctp_stack::serial::MTU_MAX];
            let r = fragmenter.fragment_vectored(payload, &mut pkt);

            match r {
                mctp_stack::fragment::SendOutput::Packet(p) => {
                    let mut out = [0; MCTP_I2C_MAXMTU + 8]; // max MTU + I2C header size
                    let packet = encoder.encode(addr, &p, &mut out, true)?;
                    trace!("I2C MCTP TX: {:02x?}", &packet);
                    i2c.write(&out).map_err(|e| {
                        warn!("I2C MCTP TX error: {:?}", e);
                        mctp::Error::TxFailure
                    })?;
                }
                mctp_stack::fragment::SendOutput::Complete { tag, .. } => {
                    trace!("I2C MCTP TX Complete");
                    break Ok(tag);
                }
                mctp_stack::fragment::SendOutput::Error { err, .. } => {
                    warn!("I2C MCTP TX fragmenter error: {:?}", err);
                    break Err(err);
                }
            }
        }
    }

    fn get_mtu(&self) -> usize {
        MCTP_I2C_MAXMTU
    }
}

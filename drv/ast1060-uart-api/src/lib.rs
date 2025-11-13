// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Driver API for the AST1060 UART.

#![no_std]
#![no_main]

use embedded_hal::serial::{Read, Write};
use embedded_io::{Read as IoRead, Write as IoWrite};
use userlib::*;
use zerocopy::FromBytes;

use crate::ipc::ResponseCode;

/// IPC protocol
///
/// ## `write` (1)
///
/// Sends the contents of lease #0. Returns when completed.
///
/// ## `read` (2)
///
/// Copies available RX data into lease #0.
/// Returns `WouldBlock` if no data is available.
/// When data is available, returns the number of bytes copied as a `u32`.
/// Indicates `Overflow` if data was lost due to RX buffer overflow.
/// Otherwise indicates `Success`.
///
/// ## `enable_rx_notification` (3)
///
/// Enables a notification to be sent to the caller's task when data is available to read.
/// Takes a single byte payload: the notification bit to use.
///
/// ## `disable_rx_notification` (4)
///
/// Disables RX notifications for the caller's task.
pub mod ipc {
    use userlib::*;

    pub const RX_BUF_SIZE: usize = 128;

    #[repr(u16)]
    pub enum OpCode {
        Write = 1,
        Read = 2,
        EnableRxNotification = 3,
        DisableRxNotification = 4,
    }

    impl TryFrom<u32> for OpCode {
        type Error = ();

        fn try_from(value: u32) -> Result<Self, Self::Error> {
            match value {
                1 => Ok(OpCode::Write),
                2 => Ok(OpCode::Read),
                3 => Ok(OpCode::EnableRxNotification),
                4 => Ok(OpCode::DisableRxNotification),
                _ => Err(()),
            }
        }
    }

    #[repr(u32)]
    pub enum ResponseCode {
        Success = 0,
        BadOp = 1,
        BadArg = 2,
        Busy = 3,
        WouldBlock = 4,
        Overflow = 5,
        ServerDeath = FIRST_DEAD_CODE,
    }
    impl TryFrom<u32> for ResponseCode {
        type Error = ();

        fn try_from(value: u32) -> Result<Self, Self::Error> {
            match value {
                0 => Ok(ResponseCode::Success),
                1 => Ok(ResponseCode::BadOp),
                2 => Ok(ResponseCode::BadArg),
                3 => Ok(ResponseCode::Busy),
                4 => Ok(ResponseCode::WouldBlock),
                5 => Ok(ResponseCode::Overflow),
                x if x & FIRST_DEAD_CODE == FIRST_DEAD_CODE => {
                    Ok(ResponseCode::ServerDeath)
                }
                _ => Err(()),
            }
        }
    }
}

static UART_LOCK: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

#[derive(Debug)]
pub enum UartError {
    BadOp,
    BadArg,
    Busy,
    Overflow,
    ServerDeath,
    Other,
}
impl TryFrom<ResponseCode> for UartError {
    type Error = ();
    fn try_from(value: ResponseCode) -> Result<Self, Self::Error> {
        match value {
            ResponseCode::BadOp => Ok(UartError::BadOp),
            ResponseCode::BadArg => Ok(UartError::BadArg),
            ResponseCode::Busy => Ok(UartError::Busy),
            ResponseCode::Overflow => Ok(UartError::Overflow),
            ResponseCode::ServerDeath => Ok(UartError::ServerDeath),
            _ => Err(()),
        }
    }
}
impl embedded_io::Error for UartError {
    fn kind(&self) -> embedded_io::ErrorKind {
        use embedded_io::ErrorKind;
        match self {
            UartError::BadOp => ErrorKind::InvalidInput,
            UartError::BadArg => ErrorKind::InvalidData,
            UartError::Busy => ErrorKind::WriteZero,
            UartError::Overflow => ErrorKind::OutOfMemory,
            UartError::ServerDeath => ErrorKind::BrokenPipe,
            UartError::Other => ErrorKind::Other,
        }
    }
}

pub struct Uart {
    task_id: TaskId,
}

impl Uart {
    pub fn new(task_id: TaskId) -> Option<Self> {
        if UART_LOCK
            .compare_exchange(
                false,
                true,
                core::sync::atomic::Ordering::Acquire,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            return None;
        }
        Some(Uart { task_id })
    }
    pub unsafe fn steal(task_id: TaskId) -> Self {
        Uart { task_id }
    }
    pub fn enable_rx_notification(
        &mut self,
        notification_bit: u8,
    ) -> Result<(), UartError> {
        let (code, _) = sys_send(
            self.task_id,
            ipc::OpCode::EnableRxNotification as u16,
            &[notification_bit],
            &mut [],
            &[],
        );
        let code = code.try_into().unwrap_lite();
        match code {
            ResponseCode::Success => Ok(()),
            ResponseCode::ServerDeath => {
                self.task_id = sys_refresh_task_id(self.task_id);
                Err(UartError::ServerDeath)
            }
            x => Err(UartError::try_from(x).unwrap_lite()),
        }
    }
    pub fn disable_rx_notification(&mut self) -> Result<(), UartError> {
        let (code, _) = sys_send(
            self.task_id,
            ipc::OpCode::DisableRxNotification as u16,
            &[],
            &mut [],
            &[],
        );
        let code = code.try_into().unwrap_lite();
        match code {
            ResponseCode::Success => Ok(()),
            ResponseCode::ServerDeath => {
                self.task_id = sys_refresh_task_id(self.task_id);
                Err(UartError::ServerDeath)
            }
            x => Err(UartError::try_from(x).unwrap_lite()),
        }
    }
}

impl Read<u8> for Uart {
    type Error = UartError;
    fn read(&mut self) -> nb::Result<u8, Self::Error> {
        use ipc::OpCode;
        let mut response = [0u8; 4];
        let mut buf = [0u8; 1];
        let (code, n) = sys_send(
            self.task_id,
            OpCode::Read as u16,
            &[],
            &mut response,
            &[Lease::from(buf.as_mut_slice())],
        );

        let code = code.try_into().unwrap_lite();
        match code {
            ResponseCode::Success => {
                if n == 4 {
                    if *u32::ref_from_bytes(&response[..n]).unwrap_lite() != 1 {
                        Err(UartError::Other.into())
                    } else {
                        Ok(buf[0])
                    }
                } else {
                    Err(UartError::Other.into())
                }
            }
            ResponseCode::WouldBlock => Err(nb::Error::WouldBlock),
            ResponseCode::ServerDeath => {
                self.task_id = sys_refresh_task_id(self.task_id);
                Err(UartError::ServerDeath.into())
            }
            x => Err(UartError::try_from(x).unwrap_lite().into()),
        }
    }
}

impl Write<u8> for Uart {
    type Error = UartError;
    fn write(&mut self, word: u8) -> nb::Result<(), Self::Error> {
        use ipc::OpCode;
        let (code, _) = sys_send(
            self.task_id,
            OpCode::Write as u16,
            &[],
            &mut [],
            &[Lease::from([word].as_slice())],
        );

        let code = code.try_into().unwrap_lite();
        match code {
            ResponseCode::Success => Ok(()),
            ResponseCode::WouldBlock => Err(nb::Error::WouldBlock),
            ResponseCode::ServerDeath => {
                self.task_id = sys_refresh_task_id(self.task_id);
                Err(UartError::ServerDeath.into())
            }
            x => Err(UartError::try_from(x).unwrap_lite().into()),
        }
    }
    fn flush(&mut self) -> nb::Result<(), Self::Error> {
        // No-op
        Ok(())
    }
}

impl embedded_io::ErrorType for Uart {
    type Error = UartError;
}

impl IoRead for Uart {
    fn read(&mut self, out: &mut [u8]) -> Result<usize, Self::Error> {
        use ipc::OpCode;
        loop {
            let mut response = [0u8; 4];
            let (code, n) = sys_send(
                self.task_id,
                OpCode::Read as u16,
                &[],
                &mut response,
                &[Lease::from(&mut *out)],
            );

            let code = code.try_into().unwrap_lite();
            match code {
                ResponseCode::Success => {
                    if n == 4 {
                        return u32::ref_from_bytes(&response[..n])
                            .map(|x| *x as usize)
                            .map_err(|_| UartError::Other);
                    } else {
                        return Err(UartError::Other);
                    }
                }
                ResponseCode::WouldBlock => continue,
                ResponseCode::ServerDeath => {
                    self.task_id = sys_refresh_task_id(self.task_id);
                    return Err(UartError::ServerDeath);
                }
                x => return Err(UartError::try_from(x).unwrap_lite()),
            }
        }
    }
}
impl IoWrite for Uart {
    fn flush(&mut self) -> Result<(), Self::Error> {
        // No-op
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        use ipc::OpCode;
        let (code, _) = sys_send(
            self.task_id,
            OpCode::Write as u16,
            &[],
            &mut [],
            &[Lease::from(buf)],
        );
        let code = code.try_into().unwrap_lite();
        match code {
            ResponseCode::Success => Ok(buf.len()),
            ResponseCode::ServerDeath => {
                self.task_id = sys_refresh_task_id(self.task_id);
                Err(UartError::ServerDeath)
            }
            x => Err(UartError::try_from(x).unwrap_lite()),
        }
    }
}

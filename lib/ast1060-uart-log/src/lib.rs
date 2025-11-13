// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_main]
#![no_std]

use ast1060_uart_api::Uart;
use core::cell::{OnceCell, RefCell};
use critical_section::Mutex;
use embedded_io::Write;
use log::{Level, Metadata, Record};

static LOGGER: IoWriteLogger = IoWriteLogger::new();
struct IoWriteLogger {
    writer: Mutex<RefCell<Option<Uart>>>,
    level: Mutex<OnceCell<Level>>,
}
impl IoWriteLogger {
    const fn new() -> Self {
        IoWriteLogger {
            writer: Mutex::new(RefCell::new(None)),
            level: Mutex::new(OnceCell::new()),
        }
    }
}

impl log::Log for IoWriteLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        critical_section::with(|cs| {
            metadata.level()
                <= self.level.borrow(cs).get().cloned().unwrap_or(Level::Info)
        })
    }
    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            critical_section::with(|cs| {
                if let Some(uart) = self.writer.borrow(cs).borrow_mut().as_mut()
                {
                    uart.write_fmt(format_args!(
                        "[{}] - {}: {}\n",
                        record.level(),
                        record.target(),
                        record.args()
                    ))
                    .ok();
                }
            });
        }
    }
    fn flush(&self) {
        critical_section::with(|cs| {
            if let Some(uart) = self.writer.borrow(cs).borrow_mut().as_mut() {
                let _ = uart.flush();
            }
        });
    }
}

pub fn init(uart: Uart, level: log::Level) -> Result<(), log::SetLoggerError> {
    critical_section::with(|cs| {
        LOGGER.writer.borrow(cs).replace(Some(uart));
        LOGGER.level.borrow(cs).set(level).ok();
    });
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(log::LevelFilter::Info))
}

//! AST1060 I2C Driver for Hubris (Layer 2)
//!
//! This crate bridges Hubris I2C infrastructure with the portable `aspeed-ddk::i2c_core`.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────┐
//! │  drv-openprot-i2c-server    │  ← Vendor-agnostic IPC server
//! └──────────────┬──────────────┘
//!                │ I2cHardware trait (drv-i2c-types)
//! ┌──────────────▼──────────────┐
//! │  drv-ast1060-i2c-refactor   │  ← THIS CRATE (thin adapter)
//! │  • Type conversion          │     ~300 LOC
//! │  • Error mapping            │     No hardware logic
//! │  • Peripheral ownership     │
//! └──────────────┬──────────────┘
//!                │ Direct API calls
//! ┌──────────────▼──────────────┐
//! │  aspeed-ddk::i2c_core       │  ← Portable core driver
//! │  • Hardware register ops    │     ~1500 LOC
//! │  • Transfer state machine   │     Fully tested
//! │  • Buffer/DMA management    │
//! └──────────────┬──────────────┘
//!                │ ast1060-pac
//! ┌──────────────▼──────────────┐
//! │   AST1060 Hardware          │
//! │   (14 I2C Controllers)      │
//! └─────────────────────────────┘
//! ```
//!
//! # Benefits
//!
//! - **Single Source of Truth**: All I2C logic in `i2c_core`
//! - **~80% Less Code**: Adapter only, no hardware logic
//! - **Testability**: `i2c_core` tested independently
//! - **No Server Changes**: Works with existing `openprot-i2c-server`

#![no_std]

mod peripherals;
mod server_driver;

// Re-export the main driver types
pub use peripherals::I2cPeripherals;
pub use server_driver::Ast1060I2cDriver;

// Re-export i2c_core types that might be useful
pub use aspeed_ddk::i2c_core::{I2cConfig, I2cError, I2cSpeed, I2cXferMode};

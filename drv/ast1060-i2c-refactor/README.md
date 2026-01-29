# AST1060 I2C Driver (Refactored)

A lightweight Hubris I2C driver for the ASPEED AST1060 SoC that leverages the aspeed-ddk i2c_core implementation with OpenPRoT HAL trait support.

## Overview

This driver is a **refactored version** of `drv-ast1060-i2c` that:
- Delegates all hardware logic to `aspeed-ddk::i2c_core`
- Acts as a thin adapter between Hubris IPC and the i2c_core driver
- Provides ~80% less code (300 vs 1500 LOC) through code reuse
- Enables testing of I2C logic outside of Hubris in aspeed-rust-new

## Architecture

```
┌─────────────────────────┐
│  Hubris I2C Server      │
│  (openprot-i2c-server)  │
└────────────┬────────────┘
             │ drv-i2c-api::I2cHardware trait
┌────────────▼──────────────┐
│ drv-ast1060-i2c-refactor  │ ◄── This crate (thin adapter)
│  • Type conversion         │     • ~300 LOC
│  • Error mapping           │     • No hardware logic
│  • Peripheral ownership    │     • Just glue code
└────────────┬──────────────┘
             │ openprot-hal-blocking traits
             │ (I2cMaster, I2cSlaveCore, etc.)
┌────────────▼──────────────┐
│  aspeed-ddk::i2c_core     │ ◄── Core implementation
│  • Hardware register ops   │     • ~1500 LOC
│  • Transfer state machine  │     • Fully tested
│  • Buffer/DMA management   │     • Reusable
│  • Bus recovery           │
└────────────┬──────────────┘
             │ ast1060-pac
┌────────────▼──────────────┐
│   AST1060 Hardware        │
│   (14 I2C Controllers)    │
└───────────────────────────┘
```

## Key Benefits

### 1. **Code Reuse**
- Hardware logic lives in one place: `aspeed-ddk::i2c_core`
- No duplication between bare-metal and Hubris environments
- Bug fixes in i2c_core automatically benefit all users

### 2. **Testability**
- i2c_core can be tested independently in aspeed-rust-new
- QEMU-based testing without Hubris overhead
- Unit tests for timing calculations, state machines, etc.

### 3. **Maintainability**
- 80% reduction in driver-specific code
- Clear separation: adapter vs hardware logic
- Easier to understand and modify

### 4. **HAL Compatibility**
- i2c_core implements OpenPRoT HAL traits
- Can be used with HAL-based services
- Portable across different system architectures

### 5. **Features**
- Inherits all i2c_core capabilities:
  - Buffer mode (32-byte hardware FIFO)
  - DMA support (future)
  - Multi-master coordination
  - Advanced bus recovery
  - SMBus alert handling

## Comparison with Original Driver

| Aspect | Original (`ast1060-i2c`) | Refactored (this crate) |
|--------|--------------------------|-------------------------|
| **Lines of Code** | ~1500 | ~300 |
| **Hardware Logic** | Embedded | Delegated to i2c_core |
| **Testing** | Hubris-only | i2c_core testable separately |
| **Maintenance** | Driver-specific | Shared with aspeed-ddk |
| **HAL Traits** | None | Full OpenPRoT HAL support |
| **Reusability** | Hubris-only | i2c_core reusable anywhere |
| **Buffer Mode** | Manual implementation | Handled by i2c_core |
| **Bus Recovery** | Basic | Advanced (i2c_core) |

## Features

### Master Mode (default)
- Read, write, write-read operations
- Buffer mode (up to 32 bytes per transaction)
- Byte mode (1 byte per transaction)
- Multi-master support
- Bus arbitration and recovery
- MCTP-optimized defaults (400 kHz, buffer mode)

### Slave Mode (`slave` feature)
- Slave address configuration
- Receive data from master
- Send response data to master
- Buffer management via HAL traits

## Usage

This driver is used through the `openprot-i2c-server` task:

```rust
use drv_ast1060_i2c_refactor::{Ast1060I2cDriver, I2cPeripherals};

// Initialize peripherals (once per task)
let peripherals = unsafe { I2cPeripherals::new() };
let driver = Ast1060I2cDriver::new(peripherals);

// Driver implements I2cHardware trait
// Server uses it to handle I2C operations
```

## Configuration

Default configuration is MCTP-optimized:
- **Speed**: Fast mode (400 kHz)
- **Transfer Mode**: Buffer mode (32-byte FIFO)
- **Multi-master**: Disabled
- **SMBus Timeout**: Enabled (not currently used)

These defaults are set in `server_driver.rs::create_i2c_instance()`.

## Dependencies

### External
- `aspeed-ddk` - Core I2C driver from aspeed-rust-new
- `ast1060-pac` - AST1060 register definitions
- `openprot-hal-blocking` - HAL trait definitions
- `drv-i2c-api` - Hubris I2C API
- `drv-i2c-types` - Common I2C types

### Hubris
- `userlib` - Hubris syscalls and utilities
- `ringbuf` - Ring buffer for logging
- `counters` - Performance counters
- `build-util` - Build system integration

## Implementation Details

### Type Mapping

| Hubris Type | i2c_core Type | Notes |
|-------------|---------------|-------|
| `Controller` (enum) | `u8` | Controller ID 0-13 |
| `ResponseCode` | `I2cError` | Error mapping |
| `SlaveConfig` | HAL traits | Via configure_slave_address |

### Error Handling

Errors from i2c_core are mapped to Hubris `ResponseCode`:
- `I2cError::*` → `ResponseCode::BusError` (generic mapping)
- Future: More specific error mapping

### Performance

- **Buffer Mode**: Up to 32 bytes per transaction
- **Interrupt Overhead**: Minimal (handled by i2c_core)
- **MCTP Typical**: 64-256 byte packets handled efficiently
- **Creation Overhead**: Lightweight (just wraps register pointers)

## Future Enhancements

1. **DMA Support**: When i2c_core adds DMA, automatically available
2. **Better Error Mapping**: More specific error codes
3. **Timing Customization**: Expose i2c_core timing configuration
4. **Statistics**: Leverage i2c_core metrics
5. **Power Management**: Sleep mode support

## Testing

### i2c_core Testing (in aspeed-rust-new)
```bash
cd aspeed-rust-new
cargo test
cargo run --example i2c_loopback
```

### Hubris Integration Testing
```bash
# Build with Hubris
cargo build --target thumbv7em-none-eabihf

# Run in QEMU (if available)
./run-qemu-i2c-scaffold-app.sh

# Hardware testing
# (See original ast1060-i2c documentation)
```

## Migration from Original Driver

To migrate from `drv-ast1060-i2c` to this refactored driver:

1. Update `Cargo.toml`:
   ```toml
   [dependencies]
   - drv-ast1060-i2c = { path = "../ast1060-i2c" }
   + drv-ast1060-i2c-refactor = { path = "../ast1060-i2c-refactor" }
   ```

2. Update imports:
   ```rust
   - use drv_ast1060_i2c::*;
   + use drv_ast1060_i2c_refactor::*;
   ```

3. No code changes needed - API is identical!

## License

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.

Copyright 2024 Advanced Micro Devices, Inc.

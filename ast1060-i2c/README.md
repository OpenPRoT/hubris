# AST1060 I2C Driver for Hubris

This driver provides I2C controller support for the ASPEED AST1060 SoC in the Hubris RTOS.

## Features

- ✅ **Byte Mode**: Single-byte transfers for simple operations
- ✅ **Buffer Mode**: Up to 32-byte transfers using hardware buffer
- ✅ **Master Operations**: Read, Write, Write-Read
- ✅ **Bus Recovery**: Automatic recovery from stuck bus conditions
- ✅ **Multiplexer Support**: PCA9545 (4-ch) and PCA9548 (8-ch)
- ✅ **14 Controllers**: Support for all I2C0-I2C13 on AST1060
- ✅ **Error Handling**: Full error type conversion for Hubris IPC
- 🚧 **Slave Mode**: Deferred to future enhancement (optional feature)

## Architecture

```
drv-ast1060-i2c/          # Hardware abstraction library
├── src/
│   ├── lib.rs            # Public API
│   ├── controller.rs     # Main hardware driver
│   ├── master.rs         # Master mode operations
│   ├── transfer.rs       # Byte/Buffer mode logic
│   ├── timing.rs         # Clock configuration
│   ├── recovery.rs       # Bus recovery
│   ├── constants.rs      # Hardware constants
│   ├── error.rs          # Error types
│   └── mux/              # Multiplexer drivers
│       ├── pca9545.rs
│       └── pca9548.rs
└── Cargo.toml

drv-openprot-i2c-server/  # IPC server task
├── src/
│   ├── main.rs           # Server entry point
│   ├── hardware_driver.rs # AST1060 hardware integration
│   └── mock_driver.rs    # Mock for testing
└── Cargo.toml            # Depends on drv-ast1060-i2c
```

## Usage

### As a Dependency

Add to your `Cargo.toml`:

```toml
[dependencies]
drv-ast1060-i2c = { path = "../drv/ast1060-i2c" }
ast1060-pac = { workspace = true }
```

### Basic Example

```rust
use drv_ast1060_i2c::*;

// Get I2C controller from PAC
let i2c_regs = unsafe { &*ast1060_pac::I2c::ptr() };
let i2c_buff = unsafe { &*ast1060_pac::I2cbuff::ptr() };

let controller = I2cController {
    controller: Controller(0),  // I2C0
    registers: i2c_regs,
    buff_registers: i2c_buff,
    notification: None,
};

// Configure for Fast mode (400 kHz)
let config = I2cConfig {
    xfer_mode: I2cXferMode::BufferMode,
    speed: I2cSpeed::Fast,
    multi_master: false,
    smbus_timeout: false,
    smbus_alert: false,
    timing_config: None,
};

// Create I2C instance
let mut i2c = Ast1060I2c::new(&controller, config)?;

// Read from device at address 0x50
let mut data = [0u8; 16];
i2c.read(0x50, &mut data)?;

// Write to device
let write_data = [0x00, 0x01, 0x02, 0x03];
i2c.write(0x50, &write_data)?;

// Write-read (combined transaction)
let cmd = [0x10];  // Register address
let mut response = [0u8; 4];
i2c.write_read(0x50, &cmd, &mut response)?;
```

## Server Integration

The `drv-openprot-i2c-server` uses this driver when the `hardware` feature is enabled:

```toml
# In app.toml
[tasks.i2c]
name = "drv-openprot-i2c-server"
features = ["hardware"]  # Use real AST1060 hardware
```

For testing without hardware:

```toml
[tasks.i2c]
name = "drv-openprot-i2c-server"
features = ["mock-only"]  # Use mock driver
```

## Transfer Modes

### Byte Mode
- Best for: Single register reads/writes
- Max size: 1 byte per operation
- Overhead: Higher per-byte overhead

### Buffer Mode (Recommended)
- Best for: Sensor data, EEPROM pages, most devices
- Max size: 32 bytes per operation
- Overhead: Minimal, hardware-accelerated
- Auto-chunking: Transfers >32 bytes automatically split

### Large Transfers
For transfers larger than 32 bytes, the driver automatically chunks them:

```rust
// This works! Automatically split into 32-byte chunks
let mut large_data = [0u8; 256];
i2c.read(0x50, &mut large_data)?;  // 8 × 32-byte buffer mode operations
```

## Bus Recovery

If the bus gets stuck (SCL/SDA held low):

```rust
if i2c.needs_recovery() {
    i2c.recover_bus()?;
}
```

## Multiplexer Support

```rust
use drv_ast1060_i2c::mux::{I2cMux, Pca9548};

let mux = I2cMux {
    controller: Controller(0),
    port: PortIndex(0),
    id: Mux(0),
    address: 0x70,
    driver: &Pca9548,
    gpio_reset: None,
};

// Select segment 2
let driver = Pca9548;
driver.set_segment(&mux, &mut i2c, Segment(2))?;

// Now I2C operations go through segment 2
i2c.read(0x50, &mut data)?;

// Reset mux (disable all segments)
driver.reset(&mux, &mut i2c)?;
```

## Limitations (v1.0)

- ❌ **No DMA Mode**: Intentionally excluded for simplicity (buffer mode sufficient)
- ❌ **No Slave Mode**: Deferred to future enhancement
- ❌ **No 10-bit Addressing**: Not required for typical use cases
- ❌ **No Async/Await**: Polling-based initially (interrupt mode future enhancement)

## Performance

At 400 kHz (Fast mode):
- **Latency**: ~500-1000 µs for simple operations
- **Throughput**: ~30-35 KB/s effective (buffer mode)
- **Large transfers**: 256-byte EEPROM read ~8ms (8 × 32B chunks)

## Memory Footprint

- **Flash**: ~16 KB (driver + server)
- **RAM**: ~7 KB (stack + buffers + state)
- **Per controller**: ~200 bytes static data

## Error Handling

All errors convert to `ResponseCode` for Hubris IPC:

```rust
pub enum I2cError {
    NoAcknowledge,     → ResponseCode::NoDevice
    Timeout,           → ResponseCode::Timeout
    Bus,               → ResponseCode::BusLocked
    ArbitrationLoss,   → ResponseCode::BusError
    Invalid,           → ResponseCode::BadTransferSize
    // ...
}
```

## Future Enhancements

- [ ] DMA mode for large transfers (if needed)
- [ ] Slave/Target mode for MCTP
- [ ] Interrupt-driven operation
- [ ] Multi-master arbitration support
- [ ] SMBus PEC (Packet Error Checking)
- [ ] Hot-plug detection
- [ ] Advanced timing customization

## License

Apache-2.0

## References

- [AST1060 I2C Implementation Guide](../../aspeed-i2c-implementation-guide.md)
- [Hubris FPU Analysis](../../hubris-fpu-analysis.md)
- [Design Document](../../hubris-ast1060-i2c-design.md)

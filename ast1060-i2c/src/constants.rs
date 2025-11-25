//! Hardware constants for AST1060 I2C controller

/// HPLL frequency (1 GHz)
pub const HPLL_FREQ: u32 = 1_000_000_000;

/// ASPEED I2C bus clock (100 MHz typical)
pub const ASPEED_I2C_BUS_CLK_HZ: u32 = 100_000_000;

/// Standard mode speed (100 kHz)
pub const I2C_STANDARD_MODE_HZ: u32 = 100_000;

/// Fast mode speed (400 kHz)
pub const I2C_FAST_MODE_HZ: u32 = 400_000;

/// Fast-plus mode speed (1 MHz)
pub const I2C_FAST_PLUS_MODE_HZ: u32 = 1_000_000;

/// Buffer mode maximum size (32 bytes)
pub const BUFFER_MODE_SIZE: usize = 32;

/// I2C buffer size register value
pub const I2C_BUF_SIZE: u8 = 0x20;

/// Default timeout in microseconds
pub const DEFAULT_TIMEOUT_US: u32 = 1_000_000;

/// Maximum retry attempts for operations
pub const MAX_RETRY_ATTEMPTS: u32 = 3;

// Register bit definitions

// Function Control Register (I2CC)
pub const AST_I2CC_SLAVE_EN: u32 = 1 << 1;
pub const AST_I2CC_MASTER_EN: u32 = 1 << 0;
pub const AST_I2CC_MULTI_MASTER_DIS: u32 = 1 << 15;

// Master Command/Status Register (I2CM)
pub const AST_I2CM_PKT_EN: u32 = 1 << 16;
pub const AST_I2CM_RX_BUFF_EN: u32 = 1 << 7;
pub const AST_I2CM_TX_BUFF_EN: u32 = 1 << 6;
pub const AST_I2CM_STOP_CMD: u32 = 1 << 5;
pub const AST_I2CM_RX_CMD_LAST: u32 = 1 << 4;
pub const AST_I2CM_RX_CMD: u32 = 1 << 3;
pub const AST_I2CM_TX_CMD: u32 = 1 << 1;
pub const AST_I2CM_START_CMD: u32 = 1 << 0;

// Master Status bits
pub const AST_I2CM_SCL_LOW_TO: u32 = 1 << 6;
pub const AST_I2CM_ABNORMAL: u32 = 1 << 5;
pub const AST_I2CM_NORMAL_STOP: u32 = 1 << 4;
pub const AST_I2CM_ARBIT_LOSS: u32 = 1 << 3;
pub const AST_I2CM_RX_DONE: u32 = 1 << 2;
pub const AST_I2CM_TX_NAK: u32 = 1 << 1;
pub const AST_I2CM_TX_ACK: u32 = 1 << 0;

// Packet mode status
pub const AST_I2CM_PKT_ERROR: u32 = 1 << 17;
pub const AST_I2CM_PKT_DONE: u32 = 1 << 16;
pub const AST_I2CM_BUS_RECOVER_FAIL: u32 = 1 << 15;
pub const AST_I2CM_SDA_DL_TO: u32 = 1 << 14;
pub const AST_I2CM_BUS_RECOVER: u32 = 1 << 13;
pub const AST_I2CM_SMBUS_ALT: u32 = 1 << 12;

// Slave mode constants
pub const AST_I2CS_PKT_MODE_EN: u32 = 1 << 16;
pub const AST_I2CS_ACTIVE_ALL: u32 = 0x3 << 17;
pub const AST_I2CS_RX_BUFF_EN: u32 = 1 << 7;
pub const AST_I2CS_TX_BUFF_EN: u32 = 1 << 6;
pub const AST_I2CS_TX_CMD: u32 = 1 << 2;
pub const AST_I2CS_SLAVE_MATCH: u32 = 1 << 7;
pub const AST_I2CS_STOP: u32 = 1 << 4;
pub const AST_I2CS_RX_DONE: u32 = 1 << 2;
pub const AST_I2CS_TX_ACK: u32 = 1 << 0;
pub const AST_I2CS_PKT_DONE: u32 = 1 << 16;
pub const AST_I2CS_PKT_ERROR: u32 = 1 << 17;
pub const AST_I2CS_WAIT_TX_DMA: u32 = 1 << 25;
pub const AST_I2CS_WAIT_RX_DMA: u32 = 1 << 24;
#[cfg(feature = "slave")]
pub const AST_I2CS_STOP: u32 = 1 << 4;

/// Helper to build packet mode address field
#[inline]
pub fn ast_i2cm_pkt_addr(addr: u8) -> u32 {
    u32::from(addr & 0x7F) << 24
}

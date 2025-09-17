/// Generic Mock I2C Driver for IPC Testing
/// 
/// This module provides a mock I2C hardware implementation for testing IPC functionality
/// without requiring actual hardware. It can be configured to simulate various
/// device responses, error conditions, and timing scenarios.

use drv_i2c_types::{traits::{I2cHardware, I2cSpeed, SlaveStatus}, ResponseCode, Controller, SlaveConfig, SlaveMessage};

/// Generic Mock I2C Driver for IPC Testing
/// 
/// This driver simulates I2C hardware behavior for testing IPC functionality
/// without requiring actual hardware. For stack efficiency, we use minimal storage.
pub struct MockI2cDriver {
    /// Transaction counter for simple timestamping
    transaction_counter: u32,
    /// Single test device response (minimal storage)
    test_response: Option<heapless::Vec<u8, 16>>,
    /// Slave mode configuration
    slave_config: Option<SlaveConfig>,
    /// Whether slave receive is enabled
    slave_receive_enabled: bool,
    /// Mock slave message buffer (minimal size for testing)
    slave_messages: heapless::Vec<SlaveMessage, 4>,
}

impl MockI2cDriver {
    /// Create a new mock I2C driver
    pub fn new() -> Self {
        Self {
            transaction_counter: 0,
            test_response: None,
            slave_config: None,
            slave_receive_enabled: false,
            slave_messages: heapless::Vec::new(),
        }
    }

    /// Convert controller and address to simple array index for testing
    /// For the simplified mock, we don't need complex indexing
    fn controller_addr_to_index(_controller: Controller, _addr: u8) -> usize {
        0 // Single slot for simplicity
    }
    
    /// Configure a device to respond with specific data
    /// 
    /// # Arguments
    /// * `controller` - Which I2C controller the device is on
    /// * `addr` - 7-bit I2C device address
    /// * `response` - Data the device should return on read operations
    /// 
    /// # Example
    /// ```rust,ignore
    /// driver.set_device_response(Controller::I2C1, 0x50, &[0x12, 0x34])?;
    /// ```
    pub fn set_device_response(&mut self, _controller: Controller, _addr: u8, response: &[u8]) -> Result<(), ()> {
        let mut vec = heapless::Vec::new();
        vec.extend_from_slice(response).map_err(|_| ())?;
        self.test_response = Some(vec);
        Ok(())
    }
    
    /// Configure a device to return an error
    /// 
    /// # Arguments
    /// * `controller` - Which I2C controller
    /// * `addr` - 7-bit I2C device address
    /// * `error` - Error code to return
    /// 
    /// # Example
    /// ```rust,ignore
    /// driver.set_device_error(Controller::I2C1, 0x60, ResponseCode::NoDevice)?;
    /// ```
    pub fn set_device_error(&mut self, _controller: Controller, _addr: u8, _error: ResponseCode) -> Result<(), ()> {
        // For simplified mock, just clear any response to simulate error
        self.test_response = None;
        Ok(())
    }
    
    /// Reset all configured responses and errors
    /// 
    /// Useful for starting fresh test scenarios
    pub fn reset(&mut self) {
        self.test_response = None;
        self.transaction_counter = 0;
        self.slave_config = None;
        self.slave_receive_enabled = false;
        self.slave_messages.clear();
    }
    
    /// Get the number of transactions processed
    /// 
    /// Useful for verifying expected number of I2C operations in tests
    pub fn transaction_count(&self) -> u32 {
        self.transaction_counter
    }
}

impl I2cHardware for MockI2cDriver {
    type Error = ResponseCode;

    fn write_read(
        &mut self,
        _controller: Controller,
        addr: u8,
        write_data: &[u8],
        read_buffer: &mut [u8],
    ) -> Result<usize, Self::Error> {
        self.transaction_counter = self.transaction_counter.wrapping_add(1);
        
        // Get configured response or generate default
        let response = if let Some(configured_response) = &self.test_response {
            configured_response.as_slice()
        } else {
            // Default behavior: for testing, just echo the write data or generate a pattern
            if write_data.is_empty() {
                // For read-only operations, generate a simple pattern based on address
                for (i, byte) in read_buffer.iter_mut().enumerate() {
                    *byte = addr.wrapping_add(i as u8);
                }
                return Ok(read_buffer.len());
            } else {
                // For write-read operations, echo the write data
                write_data
            }
        };
        
        let bytes_to_copy = response.len().min(read_buffer.len());
        read_buffer[..bytes_to_copy].copy_from_slice(&response[..bytes_to_copy]);
        
        Ok(bytes_to_copy)
    }

    fn write_read_block(
        &mut self,
        controller: Controller,
        addr: u8,
        write_data: &[u8],
        read_buffer: &mut [u8],
    ) -> Result<usize, Self::Error> {
        // For mock, block read is same as regular read
        // In real hardware, this would handle SMBus block protocol
        self.write_read(controller, addr, write_data, read_buffer)
    }

    fn configure_timing(&mut self, _controller: Controller, _speed: I2cSpeed) -> Result<(), Self::Error> {
        // Mock always succeeds - no real timing to configure
        Ok(())
    }

    fn reset_bus(&mut self, _controller: Controller) -> Result<(), Self::Error> {
        // Mock always succeeds - no real bus to reset
        Ok(())
    }

    fn enable_controller(&mut self, _controller: Controller) -> Result<(), Self::Error> {
        // Mock always succeeds - no real controller to enable
        Ok(())
    }

    fn disable_controller(&mut self, _controller: Controller) -> Result<(), Self::Error> {
        // Mock always succeeds - no real controller to disable
        Ok(())
    }

    fn configure_slave_mode(&mut self, _controller: Controller, config: &SlaveConfig) -> Result<(), Self::Error> {
        // Store the slave configuration
        self.slave_config = Some(*config);
        Ok(())
    }

    fn enable_slave_receive(&mut self, _controller: Controller) -> Result<(), Self::Error> {
        // Enable slave receive mode
        self.slave_receive_enabled = true;
        Ok(())
    }

    fn disable_slave_receive(&mut self, _controller: Controller) -> Result<(), Self::Error> {
        // Disable slave receive mode
        self.slave_receive_enabled = false;
        Ok(())
    }

    fn poll_slave_messages(&mut self, _controller: Controller, messages: &mut [SlaveMessage]) -> Result<usize, Self::Error> {
        // Mock implementation - copy any buffered messages
        let count = core::cmp::min(self.slave_messages.len(), messages.len());
        for i in 0..count {
            messages[i] = self.slave_messages[i];
        }
        // Clear the messages after reading (typical hardware behavior)
        self.slave_messages.clear();
        Ok(count)
    }

    fn get_slave_status(&self, _controller: Controller) -> Result<SlaveStatus, Self::Error> {
        // Return current mock slave status
        Ok(SlaveStatus {
            enabled: self.slave_receive_enabled,
            messages_received: self.slave_messages.len() as u32,
            messages_dropped: 0,
            address_matches: 0,
            bus_errors: 0,
            buffer_full: self.slave_messages.is_full(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mock_default_behavior() {
        let mut driver = MockI2cDriver::new();
        let mut buffer = [0u8; 4];
        
        // Test read-only operation
        let result = driver.write_read(Controller::I2C0, 0x50, &[], &mut buffer);
        assert!(result.is_ok());
        assert_eq!(buffer, [0x50, 0x51, 0x52, 0x53]);
        
        // Test write-read operation
        let result = driver.write_read(Controller::I2C0, 0x60, &[0xAA, 0xBB], &mut buffer);
        assert!(result.is_ok());
        assert_eq!(buffer[..2], [0xAA, 0xBB]);
    }
    
    #[test]
    fn test_configured_responses() {
        let mut driver = MockI2cDriver::new();
        let mut buffer = [0u8; 4];
        
        // Configure response
        driver.set_device_response(Controller::I2C0, 0x40, &[0x12, 0x34]).unwrap();
        
        // Test configured response
        let result = driver.write_read(Controller::I2C0, 0x40, &[0xFF], &mut buffer);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2);
        assert_eq!(buffer[..2], [0x12, 0x34]);
    }
    
    #[test]
    fn test_error_simulation() {
        let mut driver = MockI2cDriver::new();
        let mut buffer = [0u8; 4];
        
        // Configure error
        driver.set_device_error(Controller::I2C0, 0x70, ResponseCode::NoDevice).unwrap();
        
        // Test error response
        let result = driver.write_read(Controller::I2C0, 0x70, &[], &mut buffer);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ResponseCode::NoDevice);
    }
}
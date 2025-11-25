//! Bus recovery implementation

use crate::*;

impl<'a> Ast1060I2c<'a> {
    /// Recover the I2C bus from stuck condition
    pub fn recover_bus(&mut self) -> Result<(), I2cError> {
        // Disable master and slave functionality
        self.regs().i2cc00().modify(|_, w| {
            w.enbl_master_fn().clear_bit().enbl_slave_fn().clear_bit()
        });
        
        // Enable master functionality
        self.regs().i2cc00().modify(|_, w| {
            w.enbl_master_fn().set_bit()
        });
        
        // Clear all interrupts
        self.clear_interrupts(0xffff_ffff);
        
        // Issue bus recovery command
        self.regs().i2cm14().modify(|_, w| {
            w.enbl_master_auto_bus_recovery().set_bit()
        });
        
        // Wait for recovery completion
        let mut timeout = 100_000; // 100ms
        while timeout > 0 {
            let status = self.regs().i2cm14().read().bits();
            
            if status & AST_I2CM_BUS_RECOVER != 0 {
                self.clear_interrupts(AST_I2CM_BUS_RECOVER);
                
                if status & AST_I2CM_BUS_RECOVER_FAIL != 0 {
                    return Err(I2cError::BusRecoveryFailed);
                }
                
                return Ok(());
            }
            
            timeout -= 1;
        }
        
        Err(I2cError::Timeout)
    }
    
    /// Check if bus recovery is needed
    pub fn needs_recovery(&self) -> bool {
        let status = self.regs().i2cm14().read().bits();
        
        // Check for stuck conditions
        (status & AST_I2CM_SCL_LOW_TO != 0) || 
        (status & AST_I2CM_SDA_DL_TO != 0) ||
        (status & AST_I2CM_ABNORMAL != 0)
    }
}

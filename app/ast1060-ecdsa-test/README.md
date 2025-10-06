# AST1060 ECDSA Test Application

This application tests the OpenPRoT ECDSA-384 cryptographic server on the AST1060 platform.

## Components

- **ECDSA Server** (`drv-openprot-ecdsa-server`): Provides ECDSA-384 signing and verification operations
- **ECDSA Test Task** (`task-ecdsa-test`): Comprehensive test suite for the ECDSA server
- **UART Driver** (`drv-ast1060-uart`): For test output and debugging
- **System Driver** (`drv-ast1060-sys`): System control unit and watchdog

## Test Coverage

The test suite covers:

1. **ECDSA-384 Signing**
   - Valid signing operations with different key IDs
   - Error handling for invalid inputs

2. **ECDSA-384 Verification**  
   - Valid signature verification
   - Invalid signature rejection
   - Public key format validation

3. **Input Validation**
   - Hash length validation (must be 48 bytes for SHA-384)
   - Public key format validation (97 bytes, uncompressed SEC1)
   - Signature format validation (DER-encoded ASN.1)

## Usage

```bash
# Build the application
cd /path/to/hubris
cargo xtask dist app/ast1060-ecdsa-test

# Run in QEMU (if supported)
cargo xtask qemu app/ast1060-ecdsa-test

# Flash to hardware
cargo xtask flash app/ast1060-ecdsa-test
```

## Expected Output

The test task will output results via UART showing:
- Test execution progress
- Pass/fail status for each test
- Error details for any failures
- Overall test summary

Note: Initial runs may show "Hardware not available" errors until the ECDSA server implementation is completed.
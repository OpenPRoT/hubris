# SPDM Request Test Application

Test application that sends SPDM protocol requests to a SPDM responder over MCTP.

## Usage

Set up your SPDM responder using the test script, then run:

```bash
# Build the test tool
cargo build --bin test-spdm-request

# Run with default EID 42 (SPDM responder)
sudo ./target/debug/test-spdm-request

# Or specify a different EID
sudo REMOTE_EID=42 ./target/debug/test-spdm-request
```

## SPDM Messages

This tool sends a basic SPDM GET_VERSION request which should be supported by any SPDM responder.

The request format is:
- Message Type: 5 (SPDM)
- Payload: [0x10, 0x84, 0x00, 0x00] (GET_VERSION for SPDM 1.0)

Expected response:
- Response Code: 0x04 (VERSION response)
- Supported SPDM versions in the payload
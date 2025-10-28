# SPDM Responder Testing Guide

This guide provides step-by-step instructions for testing the AST1060 SPDM responder implementation.

## Prerequisites

### Hardware/Software Requirements
- Linux system with MCTP support (kernel module `mctp-serial`)
- QEMU with ARM support (`qemu-system-arm`)
- Root/sudo access for MCTP operations
- Built Hubris SPDM responder firmware

### Required Tools
- `mctp` command-line tools
- `mctpd` daemon
- MCTP kernel modules

Verify tools are available:
```bash
which mctp
which mctpd
lsmod | grep mctp
```

## Step 1: Build the Firmware

Build the SPDM responder firmware:

```bash
cd /path/to/hubris-spdm-resp
cargo xtask dist app/ast1060-spdm-responder/app-rust-crypto.toml
```

Expected output location: `./target/ast1060-spdm-responder/dist/default/final.bin`

## Step 2: Build the Test Client

Build the SPDM test client:

```bash
cargo build -p test-spdm-request
```

Expected output: `./target/debug/test-spdm-request`

## Step 3: Start the SPDM Responder

Run the test script to start the responder in QEMU. The script can be run from either the workspace root or its own directory:

**Option A - From workspace root:**
```bash
./app/ast1060-spdm-responder/test-spdm.sh
```

**Option B - From the app directory:**
```bash
cd app/ast1060-spdm-responder
./test-spdm.sh
```

This script will:
- Load the SPDM responder firmware in QEMU (AST1030 emulation)
- Set up MCTP serial transport (`ttyS1`)
- Configure MCTP addressing:
  - Host (requester): EID 9
  - SPDM responder: EID 42
- Create MCTP routes and bring up the interface

**Expected output:**
```
Loading SPDM responder firmware into QEMU...
Setting up MCTP serial link for SPDM...
Adding EID 9 as local host address
Adding route for EID 42 (SPDM responder) as remote address
MCTP serial link is up for SPDM communication

SPDM Responder is ready!
- Responder EID: 42
- Host EID: 9
- MCTP Message Type: 5 (SPDM)
- Serial device: ttyS1
```

Leave this terminal running - it maintains the QEMU instance and MCTP setup.

## Step 4: Monitor MCTP Traffic (Optional but Recommended)

In a **new terminal**, start MCTP monitoring to see all traffic:

```bash
sudo mctp monitor
```

This will show all MCTP messages in real-time, which is invaluable for debugging.

## Step 5: Send SPDM Test Requests

In a **third terminal**, run the SPDM test client:

```bash
cd /path/to/hubris-spdm-resp
sudo ./target/debug/test-spdm-request
```

**Expected successful output:**
```
Creating MCTP connection to SPDM responder at EID 42
Sending SPDM GET_VERSION request...
Request data: [10, 84, 00, 00]
Sent SPDM message to EID 42
Received SPDM response (X bytes): [10, 04, 00, 00, ...]
SPDM Response parsed:
  Version: 0x10
  Response code: 0x04
  Param1: 0x00
  Param2: 0x00
✓ Received valid SPDM VERSION response!
```

## Step 6: Verify MCTP Monitor Output

In the monitoring terminal, you should see:

```
[timestamp] MCTP message: src=9 dest=42 type=5 len=4
[timestamp] MCTP message: src=42 dest=9 type=5 len=X
```

This confirms MCTP transport is working and messages are flowing between host (EID 9) and responder (EID 42).

## Step 7: Debug with GDB and Ringbuf (Advanced)

If you need to debug the responder internals:

### 7.1 Connect GDB to QEMU

In the QEMU terminal, press `Ctrl+A, C` to get the QEMU monitor, then:
```
(qemu) gdbserver tcp::1234
```

### 7.2 Start GDB

In a new terminal:
```bash
cd /path/to/hubris-spdm-resp
arm-none-eabi-gdb target/ast1060-spdm-responder/dist/default/final.elf
```

### 7.3 Connect and Load Debug Script

In GDB:
```gdb
(gdb) target remote localhost:1234
(gdb) source .gdbinit
(gdb) continue
```

### 7.4 Dump Ringbuf Traces

After sending SPDM requests:
```gdb
(gdb) interrupt
(gdb) dump_spdm_ringbuf
```

**Expected ringbuf output:**
```
SPDM Trace Buffer (32 entries):
[0] TaskStart
[1] MctpStackCreated
[2] EidSet(42)
[3] ListenerCreated
[4] TransportCreated
[5] PlatformSetupComplete
[6] SpdmContextCreated
[7] MessageLoopStart
[8] WaitingForMessage
[9] MessageReceived(4)
[10] MessageProcessed
[11] ResponseSent
[12] WaitingForMessage
...
```

## Troubleshooting

### Problem: "mctp command not found"
**Solution:** Install MCTP tools:
```bash
# Check if available in package manager
apt search mctp
# Or build from source if needed
```

### Problem: "Permission denied" on serial device
**Solution:** Run with sudo or add user to dialout group:
```bash
sudo usermod -a -G dialout $USER
# Then logout/login
```

### Problem: QEMU fails to start
**Solution:** 
- Check if QEMU ARM is installed: `qemu-system-arm --version`
- Verify firmware exists: `ls -la target/ast1060-spdm-responder/dist/default/final.bin`

### Problem: No SPDM response received
**Check:**
1. MCTP monitor shows outbound message but no response
2. QEMU terminal for responder error messages
3. Use GDB to check if responder is running: `(gdb) info threads`
4. Check ringbuf for error traces: look for `IpcError*` entries

### Problem: SPDM response format incorrect
**Debug steps:**
1. Check ringbuf for `MessageProcessFailed` entries
2. Verify SPDM request format matches specification
3. Enable additional SPDM debugging in responder code

## Test Variations

### Test Different EIDs
```bash
sudo REMOTE_EID=50 ./target/debug/test-spdm-request
```
(Remember to update routes: `sudo mctp route add 50 via mctpserial0`)

### Test Error Conditions
Send malformed SPDM requests to test error handling:
```bash
# Modify test-spdm-request to send invalid data
```

### Performance Testing
Send multiple rapid requests:
```bash
for i in {1..10}; do sudo ./target/debug/test-spdm-request; sleep 1; done
```

## Expected Behavior Summary

1. **QEMU boots** AST1030 with SPDM responder firmware
2. **MCTP link** establishes serial transport
3. **SPDM responder** listens on EID 42, Message Type 5
4. **Test client** sends GET_VERSION request
5. **Responder processes** request via spdm-lib
6. **Response returned** with supported SPDM versions
7. **Ringbuf traces** show complete message flow

## Next Steps

- Add more SPDM command tests (GET_CAPABILITIES, CHALLENGE, etc.)
- Test certificate exchange functionality
- Implement measurement collection testing
- Add error injection and recovery testing
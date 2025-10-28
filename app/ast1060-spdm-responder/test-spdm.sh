#!/bin/bash

# SPDM Responder Test Script
# Can be run from this directory or workspace root

set -e
trap "exit" INT TERM
trap "kill 0; rm ttyS1" EXIT

# Determine the workspace root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "Script directory: $SCRIPT_DIR"
echo "Workspace root: $WORKSPACE_ROOT"

# Check if firmware exists
FIRMWARE_PATH="$WORKSPACE_ROOT/target/ast1060-spdm-responder/dist/default/final.bin"
if [ ! -f "$FIRMWARE_PATH" ]; then
    echo "Error: Firmware not found at $FIRMWARE_PATH"
    echo "Please build the firmware first:"
    echo "  cd $WORKSPACE_ROOT"
    echo "  cargo xtask dist app/ast1060-spdm-responder/app-rust-crypto.toml"
    exit 1
fi

# Serial transport driver has to be loaded when configured as module
# (as tested with Fedora 42, kernel 6.16)
sudo modprobe mctp-serial

# Load the SPDM responder image into qemu and connect the serial to a chardev (symlinked to ttyS1)
echo "Loading SPDM responder firmware into QEMU..."
qemu-system-arm -M ast1030-evb -nographic -chardev pty,id=char0,path=ttyS1 -serial chardev:char0 -kernel "$FIRMWARE_PATH" &
sleep 2

echo -e '\n\nSetting up MCTP serial link for SPDM...'
sudo mctp link serial ttyS1 &
sleep 1

# Set up MCTP addressing
# EID 9 = Host/Requester (us)
# EID 42 = SPDM Responder (matches SPDM_RESPONDER_EID in main.rs)
echo 'Adding EID 9 as local host address'
sudo mctp addr add 9 dev mctpserial0
echo 'Adding route for EID 42 (SPDM responder) as remote address'
sudo mctp route add 42 via mctpserial0
sudo mctp link set mctpserial0 up
echo -e 'MCTP serial link is up for SPDM communication\n'

echo "SPDM Responder is ready!"
echo "- Responder EID: 42"
echo "- Host EID: 9" 
echo "- MCTP Message Type: 5 (SPDM)"
echo -e "- Serial device: ttyS1\n"

echo "You can now send SPDM requests using:"
echo "  sudo mctp test eid 42 type 5 data [SPDM message bytes]"
echo "Or use a custom SPDM requester tool that connects to EID 42"
echo -e "\nPress Ctrl+C to stop the test setup"

# Keep the script running to maintain the QEMU and MCTP setup
wait
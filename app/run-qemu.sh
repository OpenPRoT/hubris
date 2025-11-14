#!/bin/bash

# Generic Hubris QEMU Runner
# This script runs any Hubris app in QEMU with GDB debugging enabled

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Get the workspace root (one level up from app/)
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Check if app name provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <app-name> [image-name]"
    echo ""
    echo "Examples:"
    echo "  $0 ast1060-i2c-scaffold"
    echo "  $0 ast1060-spdm-responder"
    echo "  $0 ast1060-starter default"
    echo ""
    echo "Available apps:"
    ls "$WORKSPACE_ROOT/app/" 2>/dev/null | grep -E '^ast1060-|^demo-|^lpc|^minibar|^oxide' | head -10
    exit 1
fi

# Configuration
APP_NAME="$1"
IMAGE_NAME="${2:-default}"
BUILD_DIR="$WORKSPACE_ROOT/target/${APP_NAME}/dist/${IMAGE_NAME}"
FIRMWARE_PATH="${BUILD_DIR}/final.bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Hubris QEMU Runner ===${NC}"
echo -e "${GREEN}App: ${APP_NAME}${NC}"
echo -e "${GREEN}Image: ${IMAGE_NAME}${NC}"
echo ""

# Check if firmware exists
if [ ! -f "$FIRMWARE_PATH" ]; then
    echo -e "${RED}Error: Firmware not found at $FIRMWARE_PATH${NC}"
    echo -e "${YELLOW}Please build the firmware first with:${NC}"
    echo "  cd $WORKSPACE_ROOT"
    echo "  cargo xtask dist app/${APP_NAME}/app.toml"
    exit 1
fi

echo -e "${GREEN}Found firmware: $FIRMWARE_PATH${NC}"
echo -e "${GREEN}Build directory: $BUILD_DIR${NC}"

# Check if script.gdb exists
GDB_SCRIPT_PATH="${BUILD_DIR}/script.gdb"
if [ ! -f "$GDB_SCRIPT_PATH" ]; then
    echo -e "${YELLOW}Warning: GDB script not found at $GDB_SCRIPT_PATH${NC}"
else
    echo -e "${GREEN}Found GDB script: $GDB_SCRIPT_PATH${NC}"
fi

echo ""
echo -e "${BLUE}Starting QEMU with debugging enabled...${NC}"
echo -e "${YELLOW}QEMU will pause at startup waiting for GDB connection${NC}"
echo -e "${YELLOW}Connect with GDB using the companion script:${NC}"
echo "  $SCRIPT_DIR/run-gdb.sh ${APP_NAME} ${IMAGE_NAME}"
echo ""
echo -e "${YELLOW}Or manually with:${NC}"
echo "  gdb-multiarch"
echo "  (gdb) target remote localhost:1234"
echo "  (gdb) source ${GDB_SCRIPT_PATH}"
echo "  (gdb) continue"
echo ""
echo -e "${BLUE}Press Ctrl+C to stop QEMU${NC}"
echo ""

# Detect machine type based on app name
MACHINE="ast1030-evb"  # Default for AST1060 apps
case "$APP_NAME" in
    *stm32f4*)
        MACHINE="stm32f4discovery"
        ;;
    *lpc55*)
        MACHINE="lpc55s6xevk"
        ;;
esac

# Run QEMU with debugging
exec qemu-system-arm \
    -M "$MACHINE" \
    -nographic \
    -serial mon:stdio \
    -kernel "$FIRMWARE_PATH" \
    -s \
    -S
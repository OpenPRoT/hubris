#!/bin/bash

# Generic GDB Debug Script for Hubris Apps
# This script sets up a proper GDB debugging session for any Hubris firmware

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
GDB_SCRIPT_PATH="${BUILD_DIR}/script.gdb"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Hubris GDB Debug Session ===${NC}"
echo -e "${GREEN}App: ${APP_NAME}${NC}"
echo -e "${GREEN}Image: ${IMAGE_NAME}${NC}"
echo ""

# Check if GDB script exists
if [ ! -f "$GDB_SCRIPT_PATH" ]; then
    echo -e "${RED}Error: GDB script not found at $GDB_SCRIPT_PATH${NC}"
    echo -e "${YELLOW}Please build the firmware first with:${NC}"
    echo "  cd $WORKSPACE_ROOT"
    echo "  cargo xtask dist app/${APP_NAME}/app.toml"
    exit 1
fi

echo -e "${GREEN}Using GDB script: $GDB_SCRIPT_PATH${NC}"
echo -e "${YELLOW}Make sure QEMU is running with debug flags (-s -S)${NC}"
echo -e "${YELLOW}Start QEMU with: ./run-qemu.sh ${APP_NAME} ${IMAGE_NAME}${NC}"
echo ""

# Create a temporary GDB initialization file
TEMP_GDB_INIT=$(mktemp)
cat > "$TEMP_GDB_INIT" << 'EOFGDB'
# Connect to QEMU
target remote localhost:1234

# Set architecture
set architecture arm

# Load symbols and source paths
EOFGDB

# Fix paths in the generated script.gdb and append to our init file
sed "s|target/${APP_NAME}/dist/|${BUILD_DIR}/|g" "$GDB_SCRIPT_PATH" >> "$TEMP_GDB_INIT"

cat >> "$TEMP_GDB_INIT" << EOFGDB

# Useful settings
set confirm off
set verbose off
set pagination off

# Show what we loaded
info files
EOFGDB

# Check for app-specific test automation script
APP_TEST_SCRIPT="$WORKSPACE_ROOT/app/${APP_NAME}/gdb-test.gdb"
if [ -f "$APP_TEST_SCRIPT" ]; then
    echo -e "${GREEN}Found app-specific test automation: ${APP_TEST_SCRIPT}${NC}"
    cat >> "$TEMP_GDB_INIT" << EOFGDB

# Load app-specific test automation
echo \\n=== Loading App-Specific Test Automation ===\\n
source ${APP_TEST_SCRIPT}
EOFGDB
else
    # Interactive debugging mode (no test automation)
    cat >> "$TEMP_GDB_INIT" << EOFGDB

# Print current status
echo \\n=== GDB Connected Successfully ===\\n
echo App: ${APP_NAME}\\n
echo Image: ${IMAGE_NAME}\\n
echo Use 'continue' to start execution\\n
echo \\nCommon debugging commands:\\n
echo   break main                 - Break at main function\\n
echo   info registers            - Show CPU state\\n
echo   backtrace                 - Show call stack\\n
echo   info tasks                - Show all Hubris tasks\\n
echo   continue                  - Resume execution\\n
echo   step / next               - Step through code\\n
echo   print <var>               - Print variable value\\n
echo =================================\\n
EOFGDB
fi

echo -e "${BLUE}Starting GDB with auto-configuration...${NC}"
echo -e "${YELLOW}GDB will automatically:${NC}"
echo "  1. Connect to QEMU (localhost:1234)"
echo "  2. Load all symbol files"
echo "  3. Set up source path remapping"
if [ -f "$APP_TEST_SCRIPT" ]; then
    echo "  4. Run app-specific test automation"
fi
echo ""
if [ -f "$APP_TEST_SCRIPT" ]; then
    echo -e "${GREEN}Running automated tests...${NC}"
else
    echo -e "${GREEN}Ready to debug! Type 'continue' to start execution.${NC}"
fi
echo ""

# Start GDB with our initialization script
exec gdb-multiarch -x "$TEMP_GDB_INIT"
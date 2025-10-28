# GDB initialization for SPDM Responder debugging
# Load SPDM-specific ringbuf debugging commands
source spdm_debug.py

# Useful GDB settings for embedded debugging
set confirm off
set pagination off
set print pretty on
set print array on
set print array-indexes on

# ARM-specific settings
set architecture arm
set endian little

# Define some useful aliases
define attach-target
    target extended-remote localhost:3333
end

define attach-qemu
    target remote localhost:1234
end

echo SPDM Responder GDB initialized.\n
echo Use 'dump_spdm_ringbuf' to inspect traces.\n
#!/usr/bin/env python3
"""
GDB Python script for SPDM Responder ringbuf debugging
Optimized single script for Hubris SPDM ringbuf inspection
"""

import gdb

# Constants
RINGBUF_ADDR = 0x0006e000  # Known address from info variables
RINGBUF_ENTRIES = 32       # From ringbuf!(SpdmTrace, 32, ...)
ENTRY_SIZE = 16           # Conservative estimate for enum size

class SpdmRingbufCommand(gdb.Command):
    """Dump SPDM ringbuf entries with enum decoding"""
    
    def __init__(self):
        super(SpdmRingbufCommand, self).__init__("dump_spdm_ringbuf", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        """Main command entry point"""
        try:
            self.dump_spdm_ringbuf()
        except Exception as e:
            print(f"Error dumping SPDM ringbuf: {e}")
    
    def dump_spdm_ringbuf(self):
        """Dump the SPDM trace ringbuf with proper enum decoding"""
        try:
            # Find the SPDM ringbuf symbol - it's a StaticCell wrapper
            try:
                # Use the known address directly since symbol lookup has issues
                # From info variables: 0x0006e000  spdm_resp::__RINGBUF
                # Try different address formats to avoid GDB parsing issues
                ringbuf_addr = RINGBUF_ADDR
                print(f"Using known StaticCell address: 0x{ringbuf_addr:08x}")
                
                # Try accessing via symbol pattern matching first
                try:
                    # Find any symbol matching the pattern (avoids hardcoded hash)
                    symbols = gdb.execute("info variables spdm_resp::__RINGBUF", to_string=True)
                    if "spdm_resp::__RINGBUF" in symbols:
                        test_cmd = f"x/1ub {RINGBUF_ADDR}"
                        test_result = gdb.execute(test_cmd, to_string=True)
                        print(f"Memory accessible via address: {test_result.strip()}")
                        ringbuf_ref = str(RINGBUF_ADDR)
                    else:
                        raise Exception("Symbol not found")
                except:
                    # Fallback to decimal address which GDB handles better
                    ringbuf_addr_decimal = RINGBUF_ADDR  # Already decimal equivalent
                    test_cmd = f"x/1ub {ringbuf_addr_decimal}"
                    test_result = gdb.execute(test_cmd, to_string=True)
                    print(f"Memory accessible via decimal: {test_result.strip()}")
                    ringbuf_ref = str(ringbuf_addr_decimal)
            except Exception as e:
                print(f"Error accessing memory at 0x{ringbuf_addr:08x}: {e}")
                print("Make sure the SPDM responder is loaded and running.")
                return
            
            # Read ringbuf structure
            # For Hubris ringbuf: struct { next: u16, data: [T; N] }
            # Use memory examination commands instead of parse_and_eval
            try:
                # Try reading next index (u16) at the start using the working reference
                next_cmd = f"x/1uh {ringbuf_ref}"
                next_result = gdb.execute(next_cmd, to_string=True)
                # Parse the result: "0x6e000: 1234" -> extract 1234
                next_idx = int(next_result.split()[1], 0)  # 0 means auto-detect base
                data_start_offset = 2  # After next index (u16)
                print(f"Method 1: next_idx = {next_idx}")
            except Exception as e1:
                try:
                    # Maybe there's padding or the StaticCell adds offset
                    if 'ringbuf_ref' in locals() and not ringbuf_ref.isdigit():
                        # For non-numeric reference, use base address + offset
                        next_cmd = f"x/1uh {RINGBUF_ADDR + 8}"
                    else:
                        next_cmd = f"x/1uh {int(ringbuf_ref) + 8}"
                    next_result = gdb.execute(next_cmd, to_string=True)
                    next_idx = int(next_result.split()[1], 0)
                    data_start_offset = 10
                    print(f"Method 2: next_idx = {next_idx}")
                except Exception as e2:
                    print(f"Could not read next_idx: {e1}, {e2}")
                    # Continue anyway with next_idx = 0
                    next_idx = 0
                    data_start_offset = 2
                    print(f"Fallback: next_idx = {next_idx}")
            
            print(f"SPDM Trace Buffer ({RINGBUF_ENTRIES} entries, next index: {next_idx}):")
            print("=" * 60)
            
            # Read all entries
            base_addr = RINGBUF_ADDR
            for i in range(RINGBUF_ENTRIES):
                entry_addr = base_addr + data_start_offset + (i * ENTRY_SIZE)
                
                try:
                    # Read the discriminant (first byte of enum) using memory examination
                    disc_cmd = f"x/1ub {entry_addr}"
                    disc_result = gdb.execute(disc_cmd, to_string=True)
                    
                    # Parse GDB output more robustly
                    # Handle both "0x1234: 42" and "0x1234 <symbol+offset>: 42" formats
                    parts = disc_result.strip().split()
                    # Find the actual value after the colon
                    value_part = None
                    for part in parts:
                        if part.isdigit() or (part.startswith('0x') and all(c in '0123456789abcdefABCDEF' for c in part[2:])):
                            value_part = part
                            break
                    
                    if value_part is None:
                        # If we can't find a clean number, try the last part
                        value_part = parts[-1]
                    
                    discriminant = int(value_part, 0)
                    entry_str = self.decode_spdm_trace(discriminant, entry_addr)
                    
                    # Mark current position
                    marker = " <- current" if i == next_idx else ""
                    print(f"[{i:2d}] {entry_str}{marker}")
                    
                except Exception as e:
                    print(f"[{i:2d}] <error reading entry: {e}>")
            
            print("=" * 60)
            
        except Exception as e:
            print(f"Failed to dump ringbuf: {e}")
            print("Debug info:")
            print(f"  - Make sure the SPDM responder is running")
            print(f"  - Try: (gdb) info variables __RINGBUF")
            print(f"  - Try: (gdb) p &spdm_resp::__RINGBUF")
    
    def decode_spdm_trace(self, discriminant, addr):
        """Decode SpdmTrace enum based on discriminant value"""
        
        # SpdmTrace enum mapping (from main.rs)
        trace_map = {
            0: "None",
            1: "TaskStart", 
            2: "MctpStackCreated",
            3: "EidSet",           # Has u8 parameter
            4: "EidSetFailed",
            5: "ListenerCreated",
            6: "ListenerFailed", 
            7: "TransportCreated",
            8: "SpdmContextCreated",
            9: "SpdmContextFailed",
            10: "MessageLoopStart",
            11: "WaitingForMessage",
            12: "MessageReceived", # Has usize parameter
            13: "MessageProcessed",
            14: "MessageProcessFailed",
            15: "ResponseSent",
            16: "IpcErrorMctpRecv", # Has u32 error code
            17: "IpcErrorNoRespChannel",
            18: "IpcErrorMessageBuf", 
            19: "IpcErrorMctpSend",
            20: "PlatformSetupComplete",
        }
        
        base_name = trace_map.get(discriminant, f"Unknown({discriminant})")
        
        # Handle variants with data using consistent memory examination
        if discriminant == 3:  # EidSet(u8)
            try:
                param_cmd = f"x/1ub {addr + 4}"
                param_result = gdb.execute(param_cmd, to_string=True)
                # Extract value more robustly
                parts = param_result.strip().split()
                param_value = next((p for p in parts if p.isdigit() or (p.startswith('0x') and len(p) > 2)), parts[-1])
                param = int(param_value, 0)
                return f"EidSet({param})"
            except:
                return f"EidSet(?)"
                
        elif discriminant == 12:  # MessageReceived(usize) 
            try:
                param_cmd = f"x/1ud {addr + 8}"  # usize = 4 bytes on ARM
                param_result = gdb.execute(param_cmd, to_string=True)
                parts = param_result.strip().split()
                param_value = next((p for p in parts if p.isdigit() or (p.startswith('0x') and len(p) > 2)), parts[-1])
                param = int(param_value, 0)
                return f"MessageReceived({param})"
            except:
                return f"MessageReceived(?)"
                
        elif discriminant == 16:  # IpcErrorMctpRecv(u32)
            try:
                error_cmd = f"x/1ud {addr + 4}"
                error_result = gdb.execute(error_cmd, to_string=True)
                parts = error_result.strip().split()
                error_value = next((p for p in parts if p.isdigit() or (p.startswith('0x') and len(p) > 2)), parts[-1])
                error_code = int(error_value, 0)
                error_names = {
                    1: "InternalError",
                    2: "NoSpace", 
                    3: "AddrInUse",
                    4: "TimedOut",
                    5: "BadArgument",
                    99: "Unknown"
                }
                error_str = error_names.get(error_code, f"Code{error_code}")
                return f"IpcErrorMctpRecv({error_str})"
            except:
                return f"IpcErrorMctpRecv(?)"
        
        return base_name

class SpdmDebugHelper(gdb.Command):
    """Helper commands for SPDM debugging"""
    
    def __init__(self):
        super(SpdmDebugHelper, self).__init__("spdm_debug", gdb.COMMAND_USER)
        
    def invoke(self, arg, from_tty):
        """Show SPDM debugging help"""
        print("""
SPDM Responder Debug Commands:
==============================

dump_spdm_ringbuf     - Dump the SPDM trace ringbuf
spdm_debug           - Show this help
info threads         - Show all running tasks  
info variables RING  - Find ringbuf variables

Example workflow:
1. (gdb) target remote localhost:1234
2. (gdb) dump_spdm_ringbuf
3. Send SPDM request from host
4. (gdb) interrupt  
5. (gdb) dump_spdm_ringbuf
        """)

# Register the commands
SpdmRingbufCommand()
SpdmDebugHelper()

print("SPDM ringbuf debugging commands loaded.")
print("Use 'dump_spdm_ringbuf' to inspect SPDM traces.")
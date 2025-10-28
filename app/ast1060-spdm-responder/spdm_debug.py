#!/usr/bin/env python3
"""
GDB Python script for SPDM Responder ringbuf debugging
Optimized single script for Hubris SPDM ringbuf inspection
"""

import gdb

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
                ringbuf_addr = 0x0006e000
                print(f"Using known StaticCell address: 0x{ringbuf_addr:08x}")
                
                # Verify we can access this memory
                test_read = gdb.parse_and_eval(f"*(unsigned char*)0x{ringbuf_addr:08x}")
                print(f"Memory accessible, first byte: 0x{int(test_read):02x}")
            except Exception as e:
                print(f"Error accessing memory at 0x{ringbuf_addr:08x}: {e}")
                print("Make sure the SPDM responder is loaded and running.")
                return
            
            # Read ringbuf structure
            # For Hubris ringbuf: struct { next: u16, data: [T; N] }
            # The StaticCell may add some wrapper, so let's try different offsets
            try:
                # Try reading next index at different potential offsets
                next_idx = int(gdb.parse_and_eval(f"*(unsigned short*)0x{ringbuf_addr:08x}"))
                data_start = ringbuf_addr + 2  # After next index (u16)
                print(f"Method 1: next_idx = {next_idx}")
            except:
                try:
                    # Maybe there's padding or the StaticCell adds offset
                    next_idx = int(gdb.parse_and_eval(f"*(unsigned short*)0x{ringbuf_addr + 8:08x}"))
                    data_start = ringbuf_addr + 10
                    print(f"Method 2: next_idx = {next_idx}")
                except:
                    # Fallback: assume it starts right at the address
                    next_idx = int(gdb.parse_and_eval(f"*(unsigned short*)0x{ringbuf_addr:08x}"))
                    data_start = ringbuf_addr + 2
                    print(f"Fallback: next_idx = {next_idx}")
            
            print(f"SPDM Trace Buffer (32 entries, next index: {next_idx}):")
            print("=" * 60)
            
            # Read all entries (assuming each enum entry is ~16 bytes max)
            entry_size = 16  # Conservative estimate for enum size
            for i in range(32):
                entry_addr = data_start + (i * entry_size)
                
                try:
                    # Read the discriminant (first byte of enum)
                    discriminant = int(gdb.parse_and_eval(f"*(unsigned char*){entry_addr}"))
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
        
        # Handle variants with data
        if discriminant == 3:  # EidSet(u8)
            try:
                param = int(gdb.parse_and_eval(f"*(unsigned char*)({addr} + 4)"))
                return f"EidSet({param})"
            except:
                return f"EidSet(?)"
                
        elif discriminant == 12:  # MessageReceived(usize) 
            try:
                param = int(gdb.parse_and_eval(f"*(unsigned long*)({addr} + 8)"))
                return f"MessageReceived({param})"
            except:
                return f"MessageReceived(?)"
                
        elif discriminant == 16:  # IpcErrorMctpRecv(u32)
            try:
                error_code = int(gdb.parse_and_eval(f"*(unsigned int*)({addr} + 4)"))
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
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
            # Find the ringbuf in the SPDM responder task
            ringbuf_symbol = gdb.lookup_global_symbol("RINGBUF")
            if not ringbuf_symbol:
                print("RINGBUF symbol not found. Make sure the SPDM responder is loaded.")
                return
            
            ringbuf_addr = ringbuf_symbol.value().address
            print(f"Found SPDM ringbuf at address: {ringbuf_addr}")
            
            # Read ringbuf structure (based on our reverse engineering)
            # struct { next: u16, data: [SpdmTrace; 32] }
            next_idx = int(gdb.parse_and_eval(f"*(unsigned short*){ringbuf_addr}"))
            data_start = ringbuf_addr + 2  # After next index
            
            print(f"SPDM Trace Buffer (32 entries, next index: {next_idx}):")
            print("=" * 60)
            
            # Read all entries
            for i in range(32):
                entry_addr = data_start + (i * 16)  # Assume ~16 bytes per enum
                
                # Read the discriminant (first byte/word of enum)
                try:
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
            print("Try: (gdb) info variables RINGBUF")
    
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
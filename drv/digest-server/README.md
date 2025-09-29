# Digest Server

A hardware-accelerated cryptographic digest service for the Hubris operating system.

## Overview

The digest server provides SHA-2 family hash computations through a session-based and one-shot IPC API. It implements the interface defined in `../../idl/digest.idol` and serves as a centralized service for cryptographic hashing operations.

## Features

- **Multiple Algorithms**: SHA-256, SHA-384, SHA-512 (SHA-3 defined but not implemented)
- **Session-based API**: For large data that needs to be processed in chunks
- **One-shot API**: For small data that can be hashed in a single operation
- **Resource Management**: Limited concurrent sessions (MAX_SESSIONS = 8)
- **Hardware Abstraction**: Prepared for multiple hardware backends

## Architecture

```
┌─────────────────┐    IPC     ┌─────────────────┐    Mock/HAL   ┌─────────────────┐
│   Client Task   │ ────────── │  Digest Server  │ ──────────── │   Hardware      │
│                 │  (Idol)    │   (this crate)  │              │   Backend       │
└─────────────────┘            └─────────────────┘              └─────────────────┘
```

## API Operations

### Session-Based Operations
- `init_sha256()` → Returns session ID
- `init_sha384()` → Returns session ID  
- `init_sha512()` → Returns session ID
- `update(session_id, data)` → Processes input data
- `finalize_sha256(session_id)` → Returns digest and closes session
- `finalize_sha384(session_id)` → Returns digest and closes session
- `finalize_sha512(session_id)` → Returns digest and closes session
- `reset(session_id)` → Reinitializes session context

### One-Shot Operations
- `digest_oneshot_sha256(data)` → Complete hash in single call
- `digest_oneshot_sha384(data)` → Complete hash in single call
- `digest_oneshot_sha512(data)` → Complete hash in single call

## Usage Examples

### Session-Based (for large data)

```rust
use drv_digest_api::Digest;

// Initialize digest client
let digest = Digest::from(digest_server_task_id);

// Create session
let session_id = digest.init_sha256()?;

// Process data in chunks
for chunk in large_data.chunks(1024) {
    digest.update(session_id, chunk.len() as u32, chunk)?;
}

// Get result
let mut result = [0u32; 8];
digest.finalize_sha256(session_id, &mut result)?;
```

### One-Shot (for small data)

```rust
use drv_digest_api::Digest;

let digest = Digest::from(digest_server_task_id);
let mut result = [0u32; 8];
digest.digest_oneshot_sha256(data.len() as u32, data, &mut result)?;
```

## Implementation Details

### Session Management
- Maximum 8 concurrent sessions (`MAX_SESSIONS`)
- Session IDs are allocated incrementally with wraparound
- Sessions are automatically cleaned up after finalization
- Sessions can be reset to reuse the same context

### Memory Management
- Uses Hubris's leased memory system for zero-copy data transfer
- Maximum 1024 bytes per update operation (`MAX_UPDATE_SIZE`)
- All memory leases are properly bounds-checked

### Error Handling
- Comprehensive error enumeration in `digest-api` crate
- Proper error propagation from hardware layer (future)
- Session lifecycle errors (invalid session, too many sessions)

### Mock Implementation
- Currently uses a mock implementation for testing
- Generates deterministic but unique hash results
- Includes byte counting and simple state mixing

## Hardware Integration

The server is designed to support multiple hardware backends:

- **Mock** (`default`): Software mock for testing
- **STM32H7** (future): Hardware acceleration on STM32H7 chips
- **OpenTitan** (future): OpenTitan HMAC engine

Hardware backends can be selected at compile time via Cargo features.

## Files

- `src/main.rs`: Main server implementation with Idol interface
- `src/lib.rs`: Library interface for testing
- `examples/usage.rs`: Client usage examples
- `build.rs`: Idol code generation
- `Cargo.toml`: Dependencies and features

## Dependencies

### Core
- `userlib`: Hubris system library
- `idol-runtime`: IPC runtime
- `digest-api`: Client API definitions

### Utilities  
- `heapless`: No-std collections
- `zerocopy`: Zero-copy serialization
- `ringbuf`: Debug logging
- `counters`: Performance monitoring

## Building

```bash
# From workspace root
cargo check -p digest-server

# With specific features
cargo check -p digest-server --features mock
```

## Testing

The server includes comprehensive trace logging via ringbuf for debugging:
- Session allocation/finalization
- Update operations with data lengths  
- One-shot operations
- Error conditions

## Future Enhancements

1. **Hardware Backends**: STM32H7, OpenTitan HMAC support
2. **SHA-3 Family**: SHA3-256, SHA3-384, SHA3-512 implementations
3. **Streaming Interface**: Support for very large data streams
4. **Performance Monitoring**: Detailed timing and throughput metrics
5. **HMAC Support**: Keyed hashing operations

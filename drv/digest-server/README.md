# Digest Server

A cryptographic digest and HMAC service for the Hubris operating system, supporting multiple hardware and software backends through the OpenPRoT HAL.

## Overview

The digest server provides SHA-2 family hash and HMAC (Hash-based Message Authentication Code) computations through a session-based and one-shot IPC API. It implements the interface defined in `../../idl/openprot-digest.idol` and serves as a centralized service for cryptographic hashing and authentication operations.

## Features

- **Multiple Algorithms**: 
  - **Digests**: SHA-256, SHA-384, SHA-512
  - **HMAC**: HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512
  - SHA-3 family defined but not yet implemented
- **Session-based API**: For large data that needs to be processed in chunks
- **One-shot API**: For small data that can be hashed/authenticated in a single operation (digest only)
- **HMAC Verification**: Constant-time MAC verification (planned)
- **Resource Management**: Limited concurrent sessions (MAX_SESSIONS = 8)
- **Multi-Backend Support**: Hardware (ASPEED HACE), Software (RustCrypto), and Mock implementations
- **OpenPRoT HAL Integration**: Uses trait-based abstraction for portability

## Architecture

```
┌─────────────────┐    IPC     ┌─────────────────┐   OpenPRoT    ┌─────────────────┐
│   Client Task   │ ────────── │  Digest Server  │   HAL Traits  │   Backend       │
│                 │  (Idol)    │   (this crate)  │ ──────────── │ • RustCrypto    │
│                 │            │                 │              │ • ASPEED HACE   │
│                 │            │ • ServerImpl<D> │              │ • Mock          │
└─────────────────┘            │ • SessionStore  │              └─────────────────┘
                               │ • CryptoSession │
                               └─────────────────┘
```

### Key Components

1. **ServerImpl<D: HubrisDigestDevice>**: Main server implementation with generic device support
2. **HubrisDigestDevice**: Integration trait providing concrete types for IDL compatibility
3. **CryptoSession<Context, Device>**: RAII wrapper managing device lifecycle and error recovery
4. **SessionStore**: Manages up to 8 concurrent cryptographic sessions
5. **SessionContext**: Enum tracking SHA256/384/512 and HmacSha256/384/512 contexts

### Backend Selection

The server supports three backends via Cargo features:
- **`rustcrypto`** (default): Pure Rust software implementation (hmac 0.12.1, sha2 0.10)
- **`hace`**: ASPEED HACE hardware accelerator (AST1060/AST2600)
- **`mock`**: Testing backend with deterministic outputs

## API Operations

### Session-Based Digest Operations
- `init_sha256()` → Returns session ID
- `init_sha384()` → Returns session ID  
- `init_sha512()` → Returns session ID
- `update(session_id, data)` → Processes input data
- `finalize_sha256(session_id)` → Returns digest and closes session
- `finalize_sha384(session_id)` → Returns digest and closes session
- `finalize_sha512(session_id)` → Returns digest and closes session
- `reset(session_id)` → Reinitializes session context

### Session-Based HMAC Operations
- `init_hmac_sha256(key)` → Returns session ID (key up to 64 bytes)
- `init_hmac_sha384(key)` → Returns session ID (key up to 128 bytes)
- `init_hmac_sha512(key)` → Returns session ID (key up to 128 bytes)
- `update(session_id, data)` → Processes input data (shared with digest)
- `finalize_hmac_sha256(session_id)` → Returns 32-byte MAC and closes session
- `finalize_hmac_sha384(session_id)` → Returns 48-byte MAC and closes session
- `finalize_hmac_sha512(session_id)` → Returns 64-byte MAC and closes session

### One-Shot Digest Operations
- `digest_oneshot_sha256(data)` → Complete hash in single call
- `digest_oneshot_sha384(data)` → Complete hash in single call
- `digest_oneshot_sha512(data)` → Complete hash in single call

### Planned Operations
- `hmac_oneshot_sha256/384/512(key, data)` → One-shot HMAC (not yet implemented)
- `verify_hmac_sha256/384/512(key, data, tag)` → Constant-time verification (not yet implemented)

## Usage Examples

### Session-Based Digest (for large data)

```rust
use drv_openprot_digest_api::Digest;

// Initialize digest client
let digest = Digest::from(digest_server_task_id);

// Create session
let session_id = digest.init_sha256()?;

// Process data in chunks
for chunk in large_data.chunks(1024) {
    digest.update(session_id, chunk)?;
}

// Get result
let result = digest.finalize_sha256(session_id)?;
```

### Session-Based HMAC (for authenticated data)

```rust
use drv_openprot_digest_api::Digest;

let digest = Digest::from(digest_server_task_id);

// Create HMAC session with key
let key = b"my-secret-key";
let session_id = digest.init_hmac_sha256(key)?;

// Process data in chunks
for chunk in data.chunks(1024) {
    digest.update(session_id, chunk)?;
}

// Get MAC tag
let mac_tag = digest.finalize_hmac_sha256(session_id)?; // Returns [u8; 32]
```

### One-Shot Digest (for small data)

```rust
use drv_openprot_digest_api::Digest;

let digest = Digest::from(digest_server_task_id);
let result = digest.digest_oneshot_sha256(data)?;
```

## Implementation Details

### Session Management
- Maximum 8 concurrent sessions (`MAX_SESSIONS`)
- Session IDs are allocated incrementally with wraparound
- Sessions are automatically cleaned up after finalization
- Sessions can be reset to reuse the same context
- Each session tracks either a digest or HMAC context via `SessionContext` enum

### Device Lifecycle Management
- **CryptoSession<Context, Device>** implements RAII pattern
- Automatically recovers device on session drop
- Prevents device leaks even on error paths
- Wraps both the cryptographic context and the hardware/software device

### Memory Management
- Uses Hubris's leased memory system for zero-copy data transfer
- Maximum lease size defined by Idol interface
- All memory leases are properly bounds-checked
- Keys stored in session context, not exposed after initialization

### Error Handling
- Comprehensive error enumeration in `openprot-digest-api` crate
- Proper error propagation from HAL layer
- Session lifecycle errors (invalid session, too many sessions)
- HMAC-specific errors:
  - `InvalidKeyLength`: Key exceeds maximum for algorithm
  - `KeyRequired`: Attempted finalize without providing key
  - `HmacVerificationFailed`: MAC comparison failed (planned)

### Type System and IDL Compatibility
- **HubrisDigestDevice trait**: Provides concrete associated types
- Eliminates complex generic bounds that IDL cannot process
- Enables `impl InOrderDigestImpl for ServerImpl<D>` without trait bound issues
- Separates HAL traits (`DigestInit`, `DigestOp`, `MacInit`, `MacOp`) from IDL integration

## Hardware and Software Backends

The server is designed to support multiple cryptographic backends:

### RustCrypto (Software)
- **Feature**: `rustcrypto` (default)
- **Implementation**: Pure Rust software implementation
- **Dependencies**: 
  - `hmac = "0.12.1"` for HMAC operations
  - `sha2 = "0.10"` for SHA-256/384/512 digests
- **Traits**: `openprot-platform-rustcrypto` implementing OpenPRoT HAL
- **Characteristics**: Portable, no hardware dependencies, constant-time operations
- **Use Cases**: Development, testing, platforms without hardware acceleration

### ASPEED HACE (Hardware)
- **Feature**: `hace`
- **Implementation**: ASPEED Hash and Crypto Engine
- **Platforms**: AST1060, AST2600 BMC chips
- **Traits**: Hardware-specific implementation of OpenPRoT HAL
- **Characteristics**: Hardware-accelerated, low CPU overhead
- **Use Cases**: Production deployments on supported hardware

### Mock (Testing)
- **Feature**: `mock`
- **Implementation**: Deterministic pseudo-hash for testing
- **Characteristics**: Fast, predictable, no cryptographic security
- **Use Cases**: Unit testing, integration testing, CI/CD pipelines

### Backend Selection
Backends are selected at compile time via Cargo features. Only one backend should be active at a time.

## Files

- `src/main.rs`: Main server implementation with Idol interface and session management (~1030 lines)
- `src/rustcrypto_helpers.rs`: Safe wrappers around RustCrypto to avoid complex trait bounds
- `Cargo.toml`: Dependencies and feature flags (rustcrypto, hace, mock)
- `README.md`: This documentation

## Dependencies

### Core
- `userlib`: Hubris system library for IPC and task management
- `idol-runtime`: IPC runtime for generated Idol stubs
- `openprot-digest-api`: Client API definitions and error types
- `openprot-platform-traits-hubris`: OpenPRoT HAL trait definitions for Hubris

### Backend-Specific
- **RustCrypto**: `openprot-platform-rustcrypto` (implements HAL traits)
- **HACE**: Hardware-specific platform crate (implements HAL traits)
- **Mock**: Mock platform crate for testing

### Utilities  
- `heapless`: No-std collections (Vec, String)
- `zerocopy`: Zero-copy serialization
- `ringbuf`: Debug logging and trace buffers
- `counters`: Performance monitoring

## Building

```bash
# From workspace root with RustCrypto backend (default)
cargo check -p digest-server

# With specific backend features
cargo check -p digest-server --features rustcrypto
cargo check -p digest-server --features hace
cargo check -p digest-server --features mock

# Build complete application image
cd hubris
cargo xtask dist app/ast1060-starter/app.toml
```

## Resource Requirements

Based on AST1060 starter application:
- **Stack**: 8192 bytes (digest operations are stack-intensive)
- **RAM**: 16384 bytes (for session storage and cryptographic contexts)
- **Flash**: Depends on backend (~40KB+ for RustCrypto)

## Testing

The server includes comprehensive trace logging via ringbuf for debugging:
- Session allocation/finalization
- HMAC initialization with key lengths
- Update operations with data lengths  
- One-shot operations
- Error conditions and device recovery

### Test Client
See `task/hmac-client` for a complete test client that:
- Tests all HMAC-SHA256/384/512 operations
- Verifies results against software implementations (hmac crate)
- Demonstrates session-based API usage

## Security Considerations

1. **Key Management**: 
   - Keys are passed via leased memory and stored in session contexts
   - Keys are not exposed after HMAC initialization
   - Maximum key sizes enforced (64 bytes for SHA-256, 128 for SHA-384/512)

2. **Constant-Time Operations**:
   - RustCrypto backend provides constant-time HMAC operations
   - Verification operations will use constant-time comparison (planned)

3. **Resource Limits**:
   - Maximum 8 concurrent sessions prevents resource exhaustion
   - Session IDs are not cryptographically random (sequential allocation)

4. **Error Handling**:
   - Device recovery via RAII ensures no leaked resources
   - Errors propagated without leaking sensitive information

## Current Implementation Status

### Fully Implemented ✅
- Session-based digest operations (SHA-256/384/512)
- Session-based HMAC operations (HMAC-SHA-256/384/512)
- One-shot digest operations (SHA-256/384/512)
- RustCrypto software backend
- OpenPRoT HAL integration
- Session management and lifecycle
- Device recovery on errors

### Partially Implemented ⚠️
- HACE hardware backend (defined but not fully tested)
- Mock backend (basic implementation)

### Not Yet Implemented ❌
- One-shot HMAC operations (returns `UnsupportedAlgorithm`)
- HMAC verification operations (returns `UnsupportedAlgorithm`)
- SHA-3 family algorithms (returns `UnsupportedAlgorithm`)
- Reset operation for HMAC sessions

## Future Enhancements

1. **Complete HMAC API**: One-shot and verification operations
2. **SHA-3 Family**: SHA3-256, SHA3-384, SHA3-512, SHAKE128/256
3. **Hardware Backend Testing**: Validate HACE implementation on real hardware
4. **Performance Optimization**: Benchmark and optimize critical paths
5. **Streaming Interface**: Support for very large data streams without chunking
6. **Key Derivation**: HKDF, PBKDF2 support
7. **Additional MACs**: CMAC, Poly1305 support

## Related Documentation

- IDL Interface: `../../idl/openprot-digest.idol`
- API Types: `../openprot-digest-api/src/lib.rs`
- OpenPRoT HAL: `openprot-platform-traits` crate
- Test Client: `../../task/hmac-client/`

## License

See workspace LICENSE file.

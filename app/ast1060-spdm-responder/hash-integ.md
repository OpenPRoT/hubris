# Hash Integration for SPDM Responder

## Overview

This document describes the integration of the Digest IPC API into the SPDM responder task to provide cryptographic hash functionality.

## Architecture

### Components

1. **Digest IPC API** (`drv-digest-api`)
   - Provides session-based hash operations
   - Supports SHA-256, SHA-384, and SHA-512
   - Session management for streaming hash operations

2. **DigestHash Platform Implementation** (`platform/hash.rs`)
   - Implements the `SpdmHash` trait from `spdm-lib`
   - Bridges between SPDM requirements and Digest IPC API
   - Supports only SHA-384 and SHA-512 (as required by SPDM)

3. **SPDM Context**
   - Uses three hash instances: `hash`, `m1_hash`, `l1_hash`
   - All instances share a single IPC connection to the digest server
   - Each instance maintains independent session state via session IDs

## Implementation Details

### DigestHash Structure

```rust
pub struct DigestHash {
    client: Digest,              // IPC client handle
    session_id: Option<u32>,     // Active session ID
    algo: SpdmHashAlgoType,      // Current algorithm (SHA384/SHA512)
}
```

### Hash Operations

#### One-Shot Hashing
- Uses `digest_oneshot_sha384()` or `digest_oneshot_sha512()`
- Suitable for small, complete data
- No session management required

#### Streaming Hashing
1. **init()** - Creates a session with `init_sha384()` or `init_sha512()`
2. **update()** - Feeds data in chunks (max 1024 bytes per IPC call)
3. **finalize()** - Completes hash with `finalize_sha384()` or `finalize_sha512()`
4. **reset()** - Cleans up session

### Data Format

- **Input**: Arbitrary byte slices
- **IPC Transfer**: u32 arrays (big-endian)
- **Output**: Byte arrays (big-endian conversion)

The Digest API returns hash results as `[u32; N]` arrays. These are converted to byte arrays using big-endian byte order:

```rust
for (i, word) in digest.iter().enumerate() {
    let bytes = word.to_be_bytes();
    out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
}
```

### Supported Algorithms

| Algorithm | Output Size | SPDM Support |
|-----------|-------------|--------------|
| SHA-384   | 48 bytes    | ✓ Primary    |
| SHA-512   | 64 bytes    | ✓ Secondary  |

## Integration Points

### Task Configuration

The SPDM responder needs to reference the Digest server task:

```toml
[tasks.spdm-resp]
# ... other config ...
task-slots = ["digest"]
```

Currently using `TaskId::KERNEL` as placeholder - needs actual task slot configuration.

### Client Initialization

```rust
// Create single client connection to digest server
// Multiple hash instances share the same client but use different session IDs
let digest_client = drv_digest_api::Digest::from(DIGEST.get_task_id());

// Create hash implementations - clone the client for each instance
let mut hash = DigestHash::new(digest_client.clone());
let mut m1_hash = DigestHash::new(digest_client.clone());
let mut l1_hash = DigestHash::new(digest_client);
```

**Important**: The digest server uses session IDs to multiplex concurrent hash operations. All three `DigestHash` instances share the same IPC connection to the digest server, but each maintains its own session ID for streaming operations.

### SPDM Context Usage

The hash instances are passed to the SPDM context:

```rust
let mut spdm_context = SpdmContext::new(
    &supported_versions,
    &mut transport,
    capabilities,
    algorithms,
    &mut cert_store,
    &mut hash,      // Main hash for protocol operations
    &mut m1_hash,   // M1 hash for measurements
    &mut l1_hash,   // L1 hash for additional measurements
    &mut rng,
    &evidence,
)?;
```

## Error Handling

All Digest API errors are mapped to `SpdmHashError::PlatformError`:

```rust
self.client
    .init_sha384()
    .map_err(|_| SpdmHashError::PlatformError)?
```

Possible improvements:
- Map specific DigestError variants to appropriate SpdmHashError types
- Add logging for debugging
- Implement retry logic for transient failures

## Performance Considerations

### IPC Overhead
- Each hash operation involves IPC calls to the Digest server
- Data chunking at 1024 bytes per call for streaming operations
- Session management adds overhead vs. one-shot operations

### Memory Usage
- Each DigestHash instance: ~16 bytes
- Session state maintained server-side
- Temporary buffers for u32 conversion

### Flash Size
Current implementation adds significant code size:
- Task needs 30784 bytes
- Limit is 28032 bytes
- **2752 bytes over limit**

Optimization opportunities:
1. Use one-shot operations where possible
2. Share client instances if session isolation not needed
3. Optimize conversion routines
4. Enable LTO (Link Time Optimization)

## Testing

### Unit Testing Requirements
- Test each hash algorithm (SHA-384, SHA-512)
- Test streaming operations (init/update/finalize)
- Test one-shot operations
- Test error conditions (invalid session, etc.)
- Test data chunking for large inputs

### Integration Testing
- Verify SPDM protocol flows work correctly
- Test certificate chain hashing
- Test measurement hashing
- Test challenge-response authentication

## Known Issues

1. **Flash Size Exceeded**
   - Current: 30784 bytes
   - Limit: 28032 bytes
   - Need: +2752 bytes

2. **Placeholder Task ID**
   - Using `TaskId::KERNEL` temporarily
   - Needs proper task slot configuration in app.toml

3. **No Error Detail**
   - All errors mapped to generic PlatformError
   - Lost diagnostic information

## Future Enhancements

1. **Better Error Mapping**
   ```rust
   match digest_error {
       DigestError::InvalidSession => SpdmHashError::PlatformError,
       DigestError::TooManySessions => SpdmHashError::PlatformError,
       DigestError::HardwareFailure => SpdmHashError::PlatformError,
       // ... more specific mappings
   }
   ```

2. **Logging Integration**
   - Add debug logging for hash operations
   - Log session lifecycle
   - Performance metrics

3. **Session Cleanup**
   - Ensure sessions are properly cleaned up on errors
   - Implement session timeout/expiry mechanism

4. **Algorithm Selection**
   - Support dynamic algorithm selection based on peer capabilities
   - Implement algorithm negotiation helpers

## References

- DMTF DSP0274: Security Protocol and Data Model (SPDM)
- `drv-digest-api` crate documentation
- `spdm-lib` platform trait documentation
- `task/spdm-resp/src/platform/digest-example.md` - Usage examples
# HMAC Client Task

This task demonstrates and tests HMAC (Hash-based Message Authentication Code) functionality using the extended digest API in Hubris.

## Features

- **HMAC-SHA256/384/512 Testing**: Comprehensive tests for all supported HMAC algorithms
- **Multiple Operation Modes**: Tests both one-shot and session-based HMAC operations
- **Verification Testing**: Tests HMAC verification functionality
- **Software Validation**: Uses software HMAC implementations to validate hardware/server results
- **Comprehensive Logging**: Detailed trace logging for debugging and monitoring

## Operation Modes Tested

### One-shot Operations
- `hmac_oneshot_sha256/384/512`: Complete HMAC computation in a single API call

### Session-based Operations
- `init_hmac_sha256/384/512`: Initialize HMAC session with key
- `update`: Add data to HMAC computation (same as digest operations)
- `finalize_hmac_sha256/384/512`: Complete HMAC computation and get result

### Verification Operations
- `verify_hmac_sha256/384/512`: Constant-time HMAC verification

## Test Data

The client uses different key and message sizes for each algorithm:
- **SHA256**: Short key and message for basic functionality
- **SHA384**: Medium key and message for intermediate testing
- **SHA512**: Long key and message for comprehensive testing

## Logging

The task uses ringbuf logging with specific trace codes:
- `0x1001`: HMAC client started
- `0x2xxx`: Test round started (xxx = round number & 0xFFF)
- `0x3xxx`: Test failed (xxx = algorithm identifier)
- `0x4000`: All tests passed in round
- `0x4001`: Some tests failed in round
- `0x5xxx`: Starting specific algorithm test
- `0x6xxx`: HMAC output mismatch
- `0x7xxx`: Session-based HMAC mismatch
- `0x8xxx`: HMAC verification failed
- `0x9xxx`: Algorithm test passed

## Counters

- `HMAC_TESTS_STARTED`: Total test rounds started
- `HMAC_TESTS_PASSED`: Test rounds where all tests passed
- `HMAC_TESTS_FAILED`: Test rounds with failures
- `HMAC_SHA256_TESTS`: Number of SHA256 tests performed
- `HMAC_SHA384_TESTS`: Number of SHA384 tests performed
- `HMAC_SHA512_TESTS`: Number of SHA512 tests performed

## Dependencies

- **drv-digest-api**: Extended digest API with HMAC support
- **hmac**: Software HMAC implementation for validation
- **sha2**: Software SHA implementations
- Standard Hubris task infrastructure (userlib, counters, ringbuf)
# Automated Testing with GDB for Hubris Apps

This directory contains automated GDB test scripts that integrate with the `run-gdb.sh` framework.

## Architecture

The testing system has three layers:

1. **`run-gdb.sh`** (framework) - Handles connection, symbol loading, path fixing
2. **`app/*/gdb-test.gdb`** (app-specific) - Defines breakpoints for each app
3. **`app/*/gdb-test-monitor.py`** (optional) - Python monitoring logic

## How It Works

When you run `./run-gdb.sh <app-name>`:

1. The script connects to QEMU
2. Loads and fixes the generated `script.gdb` (fixing relative paths)
3. Looks for `app/<app-name>/gdb-test.gdb`
4. If found, sources it automatically
5. The app-specific script sets breakpoints and optionally loads Python monitors

## Creating Tests for Your App

### Step 1: Create `app/your-app/gdb-test.gdb`

This is a GDB command script that sets up breakpoints:

```gdb
# Verify symbols
info address task_name::function_name

# Set breakpoints
break task_name::critical_function
break task_name::test_function
break userlib::sys_panic

# Show what we set
info breakpoints

# Optional: Load Python monitor
source app/your-app/gdb-test-monitor.py
```

### Step 2: (Optional) Create `app/your-app/gdb-test-monitor.py`

This Python script monitors execution and generates reports:

```python
import gdb

class TestMonitor:
    def monitor_execution(self):
        while True:
            gdb.execute("continue")
            frame = gdb.selected_frame()
            # ... your monitoring logic ...
            
    def generate_report(self):
        # ... generate test report ...
        
monitor = TestMonitor()
monitor.monitor_execution()
monitor.generate_report()
gdb.execute("quit 0")  # Exit with success
```

## Example: ast1060-digest-test

The HMAC digest test demonstrates the pattern:

- **`gdb-test.gdb`**: Sets breakpoints on SHA256/384/512 test functions
- **`gdb-test-monitor.py`**: 
  - Tracks which tests execute
  - Counts test rounds (3 complete rounds)
  - Reads Hubris counters (TestsPassed/TestsFailed)
  - Generates pass/fail report
  - Exits with appropriate status code

## Running Tests

### Interactive Mode (no app-specific script)
```bash
# Terminal 1: Start QEMU
./run-qemu.sh your-app

# Terminal 2: Debug interactively
./run-gdb.sh your-app
(gdb) continue
```

### Automated Test Mode (with app-specific script)
```bash
# Terminal 1: Start QEMU
./run-qemu.sh ast1060-digest-test

# Terminal 2: Run automated test
./run-gdb.sh ast1060-digest-test
# Test runs automatically, exits with status code
```

### CI/CD Integration
```bash
#!/bin/bash
./run-qemu.sh ast1060-digest-test &
QEMU_PID=$!
sleep 2  # Wait for QEMU to start
./run-gdb.sh ast1060-digest-test
TEST_RESULT=$?
kill $QEMU_PID
exit $TEST_RESULT
```

## Benefits of This Architecture

1. **Reuses `run-gdb.sh` path-fixing logic** - No duplication
2. **App-specific** - Each app defines its own test strategy
3. **Optional** - Apps without `gdb-test.gdb` work normally
4. **Composable** - GDB commands + Python monitoring
5. **CI/CD Ready** - Exits with meaningful status codes

## Tips

- Use `echo` commands in `.gdb` files to provide feedback
- Python monitors can read Hubris counters and memory
- Set `timeout` in Python to prevent hanging in CI
- Use `gdb.execute("quit 0")` for success, `"quit 1"` for failure
- Test functions should be marked `#[inline(never)] pub fn` for visibility

## Troubleshooting

**Symbols not loading?**
- Check that `cargo xtask dist` completed successfully
- Verify files exist in `target/<app>/dist/default/`

**Breakpoints not hitting?**
- Use `info address function_name` to verify symbol exists
- Check if function is inlined (add `#[inline(never)]`)
- Ensure function is `pub` if in a module

**Python script not running?**
- Check file path is relative to workspace root
- Make sure `.gdb` script uses `source app/...` not absolute paths

## Hubris Debugging Conventions

### Counters

Hubris provides zero-overhead event counters for tracking runtime statistics. Counters are monotonically-increasing atomic values stored in each task's data segment.

#### Defining Counters

```rust
use counters::{count, counters, Count};

#[derive(Count, Copy, Clone)]
enum Event {
    TestsStarted,
    TestsPassed,
    TestsFailed,
    OperationRetries,
}

counters!(Event);  // Creates static COUNTERS object
```

#### Incrementing Counters

```rust
count!(Event::TestsStarted);   // Increments the counter
```

#### Reading Counters in GDB

```gdb
# Read a specific counter
print/d task_name::COUNTERS.TestsPassed.0

# Example output: $1 = 42
```

#### Reading Counters in Python

```python
def read_counter(task_name, counter_name):
    result = gdb.execute(f"print/d {task_name}::COUNTERS.{counter_name}.0", to_string=True)
    import re
    match = re.search(r'=\s*(\d+)', result)
    if match:
        return int(match.group(1))
    return None
```

#### Reading Counters with Humility

```bash
humility -a app.zip counters -c TestsPassed
humility -a app.zip counters  # Show all counters
```

### Ringbuf Traces

Ringbufs are circular buffers for lightweight event logging. They provide a "flight recorder" for debugging crashes and unexpected behavior.

#### Defining Ringbuf

```rust
use ringbuf::{ringbuf, ringbuf_entry};

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    None,
    TestStart(u32),     // Test starting
    TestPass(u32),      // Test passed
    TestFail(u32),      // Test failed
    Mismatch(u32),      // Verification failed
}

ringbuf!(Trace, 16, Trace::None);  // 16-entry buffer
```

#### Logging Events

```rust
ringbuf_entry!(Trace::TestStart(0x5256));
```

#### Trace ID Convention

The `u32` parameter in trace events is a **magic identifier** used to distinguish where in the code the trace was generated. This is an informal convention, not a requirement:

**Recommended ID Scheme:**
- Use hex values for readability: `0x5256` not `21078`
- Encode context in the bits:
  - High byte: Event category (5=start, 6=mismatch, 9=pass)
  - Low bytes: Algorithm/test identifier (256=SHA256, 384=SHA384)

**Example from ast1060-digest-test:**

| Trace ID | Hex | Meaning | Location |
|----------|-----|---------|----------|
| `0x3256` | 12886 | SHA256 failed in main loop | main() error handler |
| `0x3384` | 13188 | SHA384 failed in main loop | main() error handler |
| `0x4000` | 16384 | All tests passed | main() success path |
| `0x4001` | 16385 | Some tests failed | main() failure path |
| `0x5256` | 21078 | SHA256 test starting | test_hmac_sha256() entry |
| `0x6256` | 25174 | SHA256 HMAC mismatch | test_hmac_sha256() verification |
| `0x9256` | 37462 | SHA256 test passed | test_hmac_sha256() exit |
| `0x9384` | 37764 | SHA384 test passed | test_hmac_sha384() exit |

**Why use magic IDs?**
- Distinguishes multiple traces of the same type
- No string formatting overhead
- Compact storage (4 bytes)
- Easy to search in dumps

#### Reading Ringbuf with Humility

```bash
humility -a app.zip ringbuf -t task_name

# Example output:
# [0] TestStart(0x5256)
# [1] TestPass(0x9256)
# [2] TestStart(0x5384)
# [3] TestPass(0x9384)
```

### Counter vs Ringbuf: When to Use

**Use Counters when:**
- You need to know **how many** times something happened
- Exact order doesn't matter
- Want to track totals over long periods
- Need minimal memory overhead (4 bytes per counter)

**Use Ringbuf when:**
- You need to know **what happened recently**
- Order and context matter
- Want to debug crashes (last N events)
- Need to see parameter values

**Use Both when:**
- You want statistical totals (counters) AND detailed history (ringbuf)
- Example: `counted_ringbuf!` macro combines both approaches

### Test Validation Best Practices

When writing automated tests that read counters:

1. **Always validate counter reads return non-None**
   ```python
   if passed is None or failed is None:
       # Counter read failed - don't assume success!
       return False
   ```

2. **Check both TestsPassed and TestsFailed**
   ```python
   if failed == 0 and passed >= expected_rounds:
       # Success
   ```

3. **Add consistency checks**
   ```python
   if passed < test_round:
       # Counter mismatch - something is wrong
   ```

4. **Provide detailed failure messages**
   ```python
   if failed > 0:
       print(f"FAILED: {failed} test failures detected")
   ```

This prevents false positives where missing counters or incomplete tests are reported as success.

## References

- [Ringbuf source documentation](../../lib/ringbuf/src/lib.rs)
- [Counters source documentation](../../lib/counters/src/lib.rs)
- [Humility debugger](https://github.com/oxidecomputer/humility)

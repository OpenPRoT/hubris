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

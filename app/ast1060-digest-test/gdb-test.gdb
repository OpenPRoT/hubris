# GDB Test Automation for ast1060-digest-test
# This script is automatically loaded by run-gdb.sh when symbols are ready

echo \n=== Configuring Test Automation for HMAC Tests ===\n

# Verify key symbols are loaded
echo Verifying symbols...\n
info address task_hmac_client::main
info address task_hmac_client::test_hmac_sha256

# Set breakpoints on test functions
echo \nSetting breakpoints on test functions...\n
break task_hmac_client::test_hmac_sha256
break task_hmac_client::test_hmac_sha384
break task_hmac_client::test_hmac_sha512
break userlib::sys_panic

# Show breakpoints
echo \nBreakpoints configured:\n
info breakpoints

# Load Python monitor for execution tracking
echo \n=== Starting Python Test Monitor ===\n
source app/ast1060-digest-test/gdb-test-monitor.py

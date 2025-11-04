#!/usr/bin/env python3
"""
GDB Python Test Monitor for ast1060-digest-test
Monitors HMAC test execution and verifies success.
"""

import gdb
import time
import sys

class Colors:
    GREEN = '\033[0;32m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

class TestMonitor:
    def __init__(self):
        self.test_hits = {}
        self.test_round = 0
        self.max_rounds = 3
        self.start_time = time.time()
        self.timeout = 60
        
    def log(self, msg):
        print(f"{Colors.BLUE}[*]{Colors.NC} {msg}")
        
    def success(self, msg):
        print(f"{Colors.GREEN}[✓]{Colors.NC} {msg}")
        
    def failure(self, msg):
        print(f"{Colors.RED}[✗]{Colors.NC} {msg}")
        
    def warning(self, msg):
        print(f"{Colors.YELLOW}[!]{Colors.NC} {msg}")
    
    def read_counter(self, task_name, counter_name):
        """Read a Hubris counter value"""
        try:
            # Try to read the counter from the task
            result = gdb.execute(
                f"print/d {task_name}::COUNTERS.{counter_name}.0",
                to_string=True
            )
            # Parse output like "$1 = 42"
            import re
            match = re.search(r'=\s*(\d+)', result)
            if match:
                return int(match.group(1))
        except:
            pass
        return None
    
    def check_test_counters(self):
        """Check if tests are passing by reading counters"""
        passed = self.read_counter("task_hmac_client", "TestsPassed")
        failed = self.read_counter("task_hmac_client", "TestsFailed")
        
        if passed is not None:
            self.success(f"Tests Passed: {passed}")
        if failed is not None:
            if failed > 0:
                self.failure(f"Tests Failed: {failed}")
            else:
                self.log(f"Tests Failed: {failed}")
        
        return passed, failed
    
    def monitor_execution(self):
        """Monitor test execution"""
        print("\n" + "=" * 70)
        print("Monitoring Test Execution")
        print("=" * 70 + "\n")
        
        self.log("Starting firmware execution...")
        
        try:
            while time.time() - self.start_time < self.timeout:
                # Continue until next breakpoint
                try:
                    gdb.execute("continue", to_string=False)
                    
                    # Get current frame info
                    frame = gdb.selected_frame()
                    func_name = frame.name()
                    
                    if func_name:
                        self.success(f"Hit breakpoint: {func_name}")
                        
                        # Check for panic
                        if "panic" in func_name.lower():
                            self.failure("Test panicked!")
                            self.examine_panic()
                            return False
                        
                        # Step past the breakpoint so we don't hit it again immediately
                        gdb.execute("next", to_string=True)
                        
                        # Track test function hits
                        if "test_hmac" in func_name:
                            if func_name not in self.test_hits:
                                self.test_hits[func_name] = 0
                            self.test_hits[func_name] += 1
                            
                            self.log(f"Test function hit {self.test_hits[func_name]} times: {func_name}")
                            
                            # Check if we've completed a round of all tests
                            # A round is complete when all 3 test functions have been hit
                            expected_tests = ["test_hmac_sha256", "test_hmac_sha384", "test_hmac_sha512"]
                            tests_in_current_round = sum(1 for test in expected_tests if any(test in key for key in self.test_hits.keys()))
                            
                            if tests_in_current_round == len(expected_tests):
                                min_hits = min(self.test_hits.values())
                                if min_hits > self.test_round:
                                    self.test_round = min_hits
                                    self.success(f"Completed test round {self.test_round}/{self.max_rounds}")
                                    
                                    # Check counters
                                    passed, failed = self.check_test_counters()
                                    
                                    if failed and failed > 0:
                                        self.failure("Tests have failures!")
                                        return False
                                    
                                    if self.test_round >= self.max_rounds:
                                        self.success(f"Successfully completed {self.max_rounds} test rounds!")
                                        return True
                    
                except gdb.error as e:
                    error_msg = str(e)
                    if "program exited" in error_msg.lower() or "terminated" in error_msg.lower():
                        self.failure(f"Program terminated unexpectedly: {e}")
                        return False
                    elif "target" in error_msg.lower():
                        self.warning(f"Lost connection to target: {e}")
                        return False
                    else:
                        self.warning(f"Execution stopped: {e}")
                        break
                        
        except KeyboardInterrupt:
            self.warning("Interrupted by user")
            return False
        
        # Timeout
        self.failure(f"Timeout after {self.timeout} seconds")
        return False
    
    def examine_panic(self):
        """Examine panic information"""
        try:
            self.log("Panic backtrace:")
            bt = gdb.execute("backtrace", to_string=True)
            for line in bt.split('\n')[:10]:  # First 10 lines
                print(f"  {line}")
        except:
            pass
    
    def generate_report(self):
        """Generate final test report"""
        print("\n" + "=" * 70)
        print("Test Report")
        print("=" * 70 + "\n")
        
        self.log("Test function hits:")
        for func, count in sorted(self.test_hits.items()):
            print(f"  {func}: {count} times")
        
        print(f"\nTest rounds completed: {self.test_round}/{self.max_rounds}")
        
        # Final counter check
        passed, failed = self.check_test_counters()
        
        print("\n" + "=" * 70)
        if self.test_round >= self.max_rounds and (failed == 0 or failed is None):
            self.success("ALL TESTS PASSED")
            print("=" * 70 + "\n")
            return True
        else:
            self.failure("TESTS FAILED OR INCOMPLETE")
            print("=" * 70 + "\n")
            return False

def main():
    monitor = TestMonitor()
    
    # Monitor execution
    success = monitor.monitor_execution()
    
    # Generate report
    report_ok = monitor.generate_report()
    
    # Exit GDB with appropriate code
    if success and report_ok:
        print("\n[*] Exiting GDB with success status")
        gdb.execute("quit 0")
    else:
        print("\n[*] Exiting GDB with failure status")
        gdb.execute("quit 1")

# Run the monitor
if __name__ == "__main__":
    main()
else:
    # When sourced from GDB command script
    main()

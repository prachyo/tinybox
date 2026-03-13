import os
import subprocess

# Colors for the terminal
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

tests = [
    ("tests/basic_good", "Should allow relative file access"),
    ("tests/basic_bad", "Should block absolute /etc/passwd access"),
    ("tests/infinite_loop", "Should block infinite loop"),
    ("tests/overly_large_mem", "Should block overly large memory allocation"),
]

passed = 0
total = len(tests)

print(f"\n--- Tinybox Test Suite ---")

for bin_path, description in tests:
    print(f"Running {bin_path:20} | {description}")

    # Run tinybox with the test binary
    # We use capture_output so the child's messy prints don't clutter our summary
    result = subprocess.run(
        ["./tinybox", f"./{bin_path}"], capture_output=True, text=True
    )

    if result.returncode == 0:
        print(f"  [{GREEN}PASS{RESET}]")
        passed += 1
    else:
        print(f"  [{RED}FAIL{RESET}] Exit Code: {result.returncode}")
        print(f"  Error Output: {result.stderr}")

print("-" * 30)
color = GREEN if passed == total else RED
print(f"Final Result: {color}{passed}/{total} Passed{RESET}\n")

if passed != total:
    exit(1)

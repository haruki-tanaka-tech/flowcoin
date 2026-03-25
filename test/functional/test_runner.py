#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Run all FlowCoin functional tests.

Usage:
    python3 test_runner.py                  # Run all tests
    python3 test_runner.py --parallel 4     # Run 4 tests in parallel
    python3 test_runner.py --filter wallet  # Run only tests matching "wallet"
    python3 test_runner.py --list           # List all tests
    python3 test_runner.py --verbose        # Show test output on failure
    python3 test_runner.py feature_block.py # Run specific test(s)

Exit codes:
    0 - All tests passed (or skipped)
    1 - One or more tests failed
"""

import argparse
import concurrent.futures
import enum
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

# All functional test scripts, ordered from fastest to slowest
TESTS = [
    # Configuration and basic RPC
    "feature_config.py",
    "rpc_blockchain.py",
    "rpc_mining.py",
    "rpc_net.py",
    "rpc_wallet.py",

    # Block and chain
    "feature_block.py",
    "feature_reorg.py",
    "feature_difficulty.py",

    # Wallet
    "wallet_basic.py",
    "wallet_encryption.py",

    # P2P
    "p2p_connect.py",
    "p2p_addr.py",

    # FlowCoin-specific
    "feature_training.py",

    # Mempool
    "mempool_basic.py",
]

# Tests that are known to take longer
SLOW_TESTS = {
    "feature_reorg.py",
    "wallet_basic.py",
    "wallet_encryption.py",
    "mempool_basic.py",
}

# Default timeout per test in seconds
DEFAULT_TIMEOUT = 600  # 10 minutes


class TestResult(enum.Enum):
    """Test execution result."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


def colorize(text: str, result: TestResult) -> str:
    """Colorize text based on test result (ANSI codes)."""
    colors = {
        TestResult.PASSED: "\033[92m",   # Green
        TestResult.FAILED: "\033[91m",   # Red
        TestResult.SKIPPED: "\033[93m",  # Yellow
        TestResult.TIMEOUT: "\033[91m",  # Red
        TestResult.ERROR: "\033[91m",    # Red
    }
    reset = "\033[0m"
    if sys.stdout.isatty():
        return f"{colors.get(result, '')}{text}{reset}"
    return text


def run_single_test(test_name: str, test_dir: Path,
                    timeout: int = DEFAULT_TIMEOUT,
                    extra_args: Optional[List[str]] = None
                    ) -> Tuple[str, TestResult, float, str, str]:
    """Run a single test and return the result.

    Returns:
        Tuple of (test_name, result, elapsed_seconds, stdout, stderr).
    """
    test_path = test_dir / test_name
    if not test_path.exists():
        return (test_name, TestResult.ERROR, 0.0,
                "", f"Test file not found: {test_path}")

    cmd = [sys.executable, str(test_path)]
    if extra_args:
        cmd.extend(extra_args)

    start_time = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            cwd=str(test_dir),
        )
        elapsed = time.time() - start_time
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")

        if proc.returncode == 0:
            return (test_name, TestResult.PASSED, elapsed, stdout, stderr)
        elif "SKIP" in stdout or "skipped" in stdout.lower():
            return (test_name, TestResult.SKIPPED, elapsed, stdout, stderr)
        else:
            return (test_name, TestResult.FAILED, elapsed, stdout, stderr)

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        return (test_name, TestResult.TIMEOUT, elapsed,
                "", f"Test timed out after {timeout}s")

    except Exception as e:
        elapsed = time.time() - start_time
        return (test_name, TestResult.ERROR, elapsed, "", str(e))


def print_header():
    """Print the test runner header."""
    print("=" * 70)
    print("FlowCoin Functional Test Runner")
    print("=" * 70)
    print()


def print_result_line(test_name: str, result: TestResult,
                      elapsed: float, index: int, total: int):
    """Print a single test result line."""
    result_str = colorize(f"{result.value:>7}", result)
    time_str = f"{elapsed:6.1f}s"
    counter = f"[{index}/{total}]"
    print(f"  {counter:>8}  {test_name:<35}  {result_str}  {time_str}")


def print_summary(results: list, total_time: float):
    """Print the test run summary."""
    passed = sum(1 for _, r, _, _, _ in results if r == TestResult.PASSED)
    failed = sum(1 for _, r, _, _, _ in results if r == TestResult.FAILED)
    skipped = sum(1 for _, r, _, _, _ in results if r == TestResult.SKIPPED)
    timeout = sum(1 for _, r, _, _, _ in results if r == TestResult.TIMEOUT)
    error = sum(1 for _, r, _, _, _ in results if r == TestResult.ERROR)
    total = len(results)

    print()
    print("=" * 70)
    print(f"Results: {total} tests in {total_time:.1f}s")
    print(f"  {colorize(f'{passed} passed', TestResult.PASSED)}")
    if failed:
        print(f"  {colorize(f'{failed} failed', TestResult.FAILED)}")
    if skipped:
        print(f"  {colorize(f'{skipped} skipped', TestResult.SKIPPED)}")
    if timeout:
        print(f"  {colorize(f'{timeout} timed out', TestResult.TIMEOUT)}")
    if error:
        print(f"  {colorize(f'{error} errors', TestResult.ERROR)}")
    print("=" * 70)


def print_failures(results: list, verbose: bool = False):
    """Print details of failed tests."""
    failures = [
        (name, result, elapsed, stdout, stderr)
        for name, result, elapsed, stdout, stderr in results
        if result in (TestResult.FAILED, TestResult.TIMEOUT, TestResult.ERROR)
    ]

    if not failures:
        return

    print()
    print("Failed tests:")
    print("-" * 70)

    for name, result, elapsed, stdout, stderr in failures:
        print(f"\n  {colorize(name, result)} ({result.value}, {elapsed:.1f}s)")
        if verbose:
            if stdout:
                print("  --- stdout ---")
                for line in stdout.strip().split("\n")[-20:]:
                    print(f"    {line}")
            if stderr:
                print("  --- stderr ---")
                for line in stderr.strip().split("\n")[-10:]:
                    print(f"    {line}")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run FlowCoin functional tests"
    )
    parser.add_argument(
        "tests", nargs="*",
        help="Specific test(s) to run (default: all)"
    )
    parser.add_argument(
        "--parallel", "-j", type=int, default=1,
        help="Number of tests to run in parallel (default: 1)"
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT,
        help=f"Per-test timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "--filter", "-f", type=str, default="",
        help="Run only tests matching this substring"
    )
    parser.add_argument(
        "--list", "-l", action="store_true",
        help="List all available tests and exit"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show stdout/stderr for failed tests"
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output"
    )
    parser.add_argument(
        "--extra-args", nargs=argparse.REMAINDER, default=[],
        help="Extra arguments to pass to each test"
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    if args.no_color:
        # Disable ANSI colors
        os.environ["NO_COLOR"] = "1"

    test_dir = Path(__file__).resolve().parent

    # Determine which tests to run
    if args.tests:
        tests = args.tests
    elif args.filter:
        tests = [t for t in TESTS if args.filter in t]
        if not tests:
            print(f"No tests matching '{args.filter}'")
            return 1
    else:
        tests = TESTS

    # List mode
    if args.list:
        print("Available functional tests:")
        for i, test in enumerate(TESTS, 1):
            slow = " (slow)" if test in SLOW_TESTS else ""
            exists = " [OK]" if (test_dir / test).exists() else " [MISSING]"
            print(f"  {i:3d}. {test}{slow}{exists}")
        print(f"\nTotal: {len(TESTS)} tests")
        return 0

    # Validate tests exist
    for test in tests:
        if not (test_dir / test).exists():
            print(f"WARNING: Test file not found: {test}")

    print_header()
    print(f"Running {len(tests)} test(s) "
          f"(parallel={args.parallel}, timeout={args.timeout}s)")
    print()

    total_start = time.time()
    results = []

    if args.parallel <= 1:
        # Sequential execution
        for i, test in enumerate(tests, 1):
            name, result, elapsed, stdout, stderr = run_single_test(
                test, test_dir, timeout=args.timeout,
                extra_args=args.extra_args if args.extra_args else None
            )
            results.append((name, result, elapsed, stdout, stderr))
            print_result_line(name, result, elapsed, i, len(tests))
    else:
        # Parallel execution
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=args.parallel
        ) as executor:
            futures = {}
            for test in tests:
                future = executor.submit(
                    run_single_test, test, test_dir, args.timeout,
                    args.extra_args if args.extra_args else None
                )
                futures[future] = test

            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                name, result, elapsed, stdout, stderr = future.result()
                results.append((name, result, elapsed, stdout, stderr))
                print_result_line(name, result, elapsed, completed, len(tests))

    total_time = time.time() - total_start

    # Sort results by original test order
    test_order = {test: i for i, test in enumerate(tests)}
    results.sort(key=lambda r: test_order.get(r[0], 999))

    print_summary(results, total_time)
    print_failures(results, verbose=args.verbose)

    # Exit code
    has_failures = any(
        r in (TestResult.FAILED, TestResult.TIMEOUT, TestResult.ERROR)
        for _, r, _, _, _ in results
    )
    return 1 if has_failures else 0


if __name__ == "__main__":
    sys.exit(main())

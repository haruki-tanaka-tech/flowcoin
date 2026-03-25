#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
#
# Check for undefined symbols and ABI compatibility in built binaries.
# Ensures FlowCoin binaries are compatible with target Linux distributions
# by verifying GLIBC version requirements do not exceed a threshold.
#
# Usage:
#     python3 symbol-check.py ../build/flowcoind
#     python3 symbol-check.py --max-glibc=2.31 ../build/flowcoind ../build/flowcoin-cli

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict


# Maximum GLIBC version for broad Linux compatibility.
# Ubuntu 20.04 LTS ships GLIBC 2.31.
DEFAULT_MAX_GLIBC = '2.31'

# Libraries that are allowed as dynamic dependencies
ALLOWED_LIBRARIES = frozenset({
    'linux-vdso.so.1',
    'libpthread.so.0',
    'libdl.so.2',
    'librt.so.1',
    'libm.so.6',
    'libc.so.6',
    'libstdc++.so.6',
    'libgcc_s.so.1',
    'ld-linux-x86-64.so.2',
    'ld-linux-aarch64.so.1',
    'linux-vdso.so',
    # Allow versioned variants
})

# Symbols that are known to be safe despite high version requirements
SAFE_SYMBOLS = frozenset({
    '__libc_start_main',
    '__gmon_start__',
    '_ITM_deregisterTMCloneTable',
    '_ITM_registerTMCloneTable',
})

# Prohibited symbols that indicate debug/test artifacts
PROHIBITED_SYMBOLS = frozenset({
    '__asan_init',
    '__ubsan_handle_',
    '__tsan_init',
    '__msan_init',
    'dlopen',
})


def parse_version(ver_str: str) -> tuple[int, ...]:
    """Parse a version string like '2.31' into a tuple of ints."""
    return tuple(int(x) for x in ver_str.split('.'))


def run_nm(binary_path: str) -> list[str]:
    """Run nm on a binary and return output lines."""
    try:
        result = subprocess.run(
            ['nm', '-D', '--with-symbol-versions', binary_path],
            capture_output=True, text=True, timeout=30)
        return result.stdout.splitlines()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f'Error running nm: {e}', file=sys.stderr)
        return []


def run_readelf(binary_path: str) -> list[str]:
    """Run readelf to get dynamic section info."""
    try:
        result = subprocess.run(
            ['readelf', '-d', binary_path],
            capture_output=True, text=True, timeout=30)
        return result.stdout.splitlines()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f'Error running readelf: {e}', file=sys.stderr)
        return []


def run_ldd(binary_path: str) -> list[str]:
    """Run ldd to get dynamic library dependencies."""
    try:
        result = subprocess.run(
            ['ldd', binary_path],
            capture_output=True, text=True, timeout=30)
        return result.stdout.splitlines()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f'Error running ldd: {e}', file=sys.stderr)
        return []


def check_glibc_versions(nm_output: list[str], max_version: tuple[int, ...]) -> list[dict]:
    """Check GLIBC version requirements from nm symbol output.
    Returns a list of problematic symbols.
    """
    issues = []
    glibc_pattern = re.compile(r'^[0-9a-fA-F]*\s+\w\s+(\w+)@@?GLIBC_(\d+\.\d+(?:\.\d+)?)')

    for line in nm_output:
        match = glibc_pattern.match(line)
        if not match:
            continue
        symbol = match.group(1)
        version_str = match.group(2)
        version = parse_version(version_str)

        if symbol in SAFE_SYMBOLS:
            continue

        if version > max_version:
            issues.append({
                'symbol': symbol,
                'version': version_str,
                'line': line.strip(),
            })

    return issues


def check_glibcxx_versions(nm_output: list[str]) -> dict[str, int]:
    """Extract GLIBCXX version usage statistics."""
    versions = defaultdict(int)
    pattern = re.compile(r'GLIBCXX_(\d+\.\d+(?:\.\d+)?)')

    for line in nm_output:
        match = pattern.search(line)
        if match:
            versions[match.group(1)] += 1

    return dict(versions)


def check_prohibited_symbols(nm_output: list[str]) -> list[str]:
    """Check for prohibited symbols (sanitizers, dlopen, etc.)."""
    found = []
    for line in nm_output:
        for prohibited in PROHIBITED_SYMBOLS:
            if prohibited in line:
                found.append(line.strip())
                break
    return found


def check_dynamic_libraries(ldd_output: list[str]) -> list[str]:
    """Check for unexpected dynamic library dependencies."""
    unexpected = []
    lib_pattern = re.compile(r'\s*(\S+\.so\S*)\s+=>')

    for line in ldd_output:
        match = lib_pattern.match(line)
        if not match:
            continue
        lib_name = match.group(1)
        # Check against allowed list (match base name)
        base = lib_name.split('.so')[0] + '.so'
        is_allowed = False
        for allowed in ALLOWED_LIBRARIES:
            if lib_name == allowed or lib_name.startswith(allowed.split('.so')[0]):
                is_allowed = True
                break
        if not is_allowed:
            unexpected.append(lib_name)

    return unexpected


def check_rpath(readelf_output: list[str]) -> list[str]:
    """Check for RPATH/RUNPATH entries (should be absent for reproducibility)."""
    issues = []
    for line in readelf_output:
        if 'RPATH' in line or 'RUNPATH' in line:
            issues.append(line.strip())
    return issues


def check_binary(binary_path: str, max_glibc: str, verbose: bool) -> int:
    """Run all checks on a single binary. Returns number of issues found."""
    basename = os.path.basename(binary_path)
    print(f'Checking: {basename}')

    if not os.path.isfile(binary_path):
        print(f'  ERROR: file not found: {binary_path}')
        return 1

    max_glibc_tuple = parse_version(max_glibc)
    total_issues = 0

    # nm analysis
    nm_out = run_nm(binary_path)
    if nm_out:
        glibc_issues = check_glibc_versions(nm_out, max_glibc_tuple)
        if glibc_issues:
            print(f'  GLIBC version issues ({len(glibc_issues)} symbols require > {max_glibc}):')
            for issue in glibc_issues:
                print(f'    {issue["symbol"]} requires GLIBC_{issue["version"]}')
            total_issues += len(glibc_issues)
        elif verbose:
            print(f'  GLIBC versions: OK (all <= {max_glibc})')

        # GLIBCXX stats
        if verbose:
            cxx_versions = check_glibcxx_versions(nm_out)
            if cxx_versions:
                max_cxx = max(cxx_versions.keys(), key=parse_version)
                print(f'  GLIBCXX max version: {max_cxx}')

        # Prohibited symbols
        prohibited = check_prohibited_symbols(nm_out)
        if prohibited:
            print(f'  PROHIBITED symbols found ({len(prohibited)}):')
            for sym in prohibited:
                print(f'    {sym}')
            total_issues += len(prohibited)
        elif verbose:
            print(f'  Prohibited symbols: none')
    else:
        print(f'  WARNING: nm produced no output (static binary?)')

    # ldd analysis
    ldd_out = run_ldd(binary_path)
    if ldd_out:
        unexpected = check_dynamic_libraries(ldd_out)
        if unexpected:
            print(f'  UNEXPECTED dynamic libraries ({len(unexpected)}):')
            for lib in unexpected:
                print(f'    {lib}')
            total_issues += len(unexpected)
        elif verbose:
            print(f'  Dynamic libraries: OK')

    # readelf analysis
    readelf_out = run_readelf(binary_path)
    if readelf_out:
        rpath = check_rpath(readelf_out)
        if rpath:
            print(f'  RPATH/RUNPATH found (should be absent):')
            for entry in rpath:
                print(f'    {entry}')
            total_issues += len(rpath)
        elif verbose:
            print(f'  RPATH/RUNPATH: none (good)')

    if total_issues == 0:
        print(f'  PASS')
    else:
        print(f'  FAIL ({total_issues} issues)')

    return total_issues


def main():
    parser = argparse.ArgumentParser(
        description='Check FlowCoin binaries for ABI compatibility')
    parser.add_argument('binaries', nargs='+',
                        help='Binary files to check')
    parser.add_argument('--max-glibc', type=str, default=DEFAULT_MAX_GLIBC,
                        help=f'Maximum allowed GLIBC version (default: {DEFAULT_MAX_GLIBC})')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show passing checks too')

    args = parser.parse_args()

    total_issues = 0
    for binary_path in args.binaries:
        issues = check_binary(binary_path, args.max_glibc, args.verbose)
        total_issues += issues
        print()

    print(f'Total issues: {total_issues}')
    sys.exit(0 if total_issues == 0 else 1)


if __name__ == '__main__':
    main()

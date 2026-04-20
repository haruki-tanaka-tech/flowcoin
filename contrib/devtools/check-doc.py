#!/usr/bin/env python3
# Copyright (c) 2026 Kristian Pilatovich
# Distributed under the MIT software license.
#
# Check that all RPC methods registered in source code have corresponding
# documentation in doc/rpc-api.md (or a specified documentation file).
#
# Usage:
#     python3 check-doc.py
#     python3 check-doc.py --src-dir=../src --doc=../doc/rpc-api.md

import argparse
import os
import re
import sys
from pathlib import Path


# Pattern to match RPC method registration in C++ source.
# Looks for patterns like:
#   {"getblockcount", ...}
#   register_command("getblockcount", ...)
#   table.emplace("getblockcount", ...)
#   {RPCCommand{"getblockcount", ...}}
REGISTRATION_PATTERNS = [
    # Brace-init with string literal first: {"methodname", ...}
    re.compile(r'\{\s*"(\w+)"\s*,'),
    # register_command("methodname", ...)
    re.compile(r'register_command\s*\(\s*"(\w+)"'),
    # table.emplace("methodname", ...)
    re.compile(r'\.emplace\s*\(\s*"(\w+)"'),
    # RPCCommand{"methodname", ...}
    re.compile(r'RPCCommand\s*\{\s*"(\w+)"'),
]

# RPC commands that are internal/hidden and not expected in documentation
INTERNAL_COMMANDS = frozenset({
    'stop',
    'help',
    'uptime',
})

# Pattern to match documented RPC methods in markdown.
# Looks for headings like: ### getblockcount, ## `getblockcount`, etc.
DOC_PATTERNS = [
    re.compile(r'^#{1,4}\s+`?(\w+)`?\s*$', re.MULTILINE),
    re.compile(r'^#{1,4}\s+(\w+)\s*$', re.MULTILINE),
    # Table rows: | getblockcount | ... |
    re.compile(r'^\|\s*`?(\w+)`?\s*\|', re.MULTILINE),
]


def find_rpc_sources(src_dir: str) -> list[str]:
    """Find all C++ source files in the RPC directory."""
    rpc_dir = os.path.join(src_dir, 'rpc')
    sources = []
    if not os.path.isdir(rpc_dir):
        print(f'Warning: RPC source directory not found: {rpc_dir}', file=sys.stderr)
        return sources
    for entry in sorted(os.listdir(rpc_dir)):
        if entry.endswith('.cpp') or entry.endswith('.h'):
            sources.append(os.path.join(rpc_dir, entry))
    return sources


def extract_registered_methods(sources: list[str]) -> dict[str, str]:
    """Extract RPC method names from source files.
    Returns a dict mapping method_name -> source_file.
    """
    methods = {}
    for source_path in sources:
        with open(source_path, 'r') as f:
            content = f.read()
        for pattern in REGISTRATION_PATTERNS:
            for match in pattern.finditer(content):
                name = match.group(1)
                # Filter out obvious non-RPC strings
                if name.startswith('_') or len(name) < 3:
                    continue
                if name not in methods:
                    methods[name] = source_path
    return methods


def extract_documented_methods(doc_path: str) -> set[str]:
    """Extract method names mentioned in the documentation file."""
    documented = set()
    if not os.path.exists(doc_path):
        return documented
    with open(doc_path, 'r') as f:
        content = f.read()
    for pattern in DOC_PATTERNS:
        for match in pattern.finditer(content):
            documented.add(match.group(1))
    return documented


def check_rpc_source_consistency(sources: list[str]) -> list[str]:
    """Check for potential issues in RPC source files."""
    issues = []
    for source_path in sources:
        with open(source_path, 'r') as f:
            lines = f.readlines()
        basename = os.path.basename(source_path)

        # Check that each file has the copyright header
        if lines and 'Copyright' not in lines[0] and len(lines) > 1 and 'Copyright' not in lines[1]:
            issues.append(f'{basename}: missing copyright header')

        # Check for help text in RPC handlers
        has_registration = False
        has_help = False
        for line in lines:
            if 'register_command' in line or 'RPCCommand' in line or re.search(r'\{\s*"\w+"', line):
                has_registration = True
            if 'help' in line.lower() and ('usage' in line.lower() or 'description' in line.lower()):
                has_help = True

        if has_registration and not has_help:
            issues.append(f'{basename}: has RPC registration but no help text detected')

    return issues


def main():
    parser = argparse.ArgumentParser(
        description='Check that all RPC methods have documentation')
    parser.add_argument('--src-dir', type=str, default=None,
                        help='Path to src/ directory (default: auto-detect)')
    parser.add_argument('--doc', type=str, default=None,
                        help='Path to RPC documentation file (default: doc/rpc-api.md)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show all methods found, not just missing ones')

    args = parser.parse_args()

    # Auto-detect project root
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))

    src_dir = args.src_dir or os.path.join(project_root, 'src')
    doc_path = args.doc or os.path.join(project_root, 'doc', 'rpc-api.md')

    print(f'Source directory: {src_dir}')
    print(f'Documentation:   {doc_path}')
    print()

    # Find and parse RPC sources
    sources = find_rpc_sources(src_dir)
    if not sources:
        print('Error: no RPC source files found.', file=sys.stderr)
        sys.exit(1)
    print(f'Found {len(sources)} RPC source files')

    registered = extract_registered_methods(sources)
    print(f'Found {len(registered)} registered RPC methods')

    # Parse documentation
    documented = extract_documented_methods(doc_path)
    if not documented:
        print(f'Warning: no documented methods found in {doc_path}')
        print('  (file may not exist or uses an unrecognized format)')
    else:
        print(f'Found {len(documented)} documented methods')

    print()

    # Verbose: list all methods
    if args.verbose:
        print('Registered methods:')
        for name in sorted(registered):
            source = os.path.basename(registered[name])
            status = 'documented' if name in documented else 'MISSING'
            if name in INTERNAL_COMMANDS:
                status = 'internal'
            print(f'  {name:30s} ({source}) [{status}]')
        print()

    # Find undocumented methods
    undocumented = []
    for name in sorted(registered):
        if name not in documented and name not in INTERNAL_COMMANDS:
            undocumented.append((name, registered[name]))

    # Find documented but unregistered methods (stale docs)
    unregistered = []
    for name in sorted(documented):
        if name not in registered and name not in INTERNAL_COMMANDS:
            unregistered.append(name)

    # Source consistency checks
    issues = check_rpc_source_consistency(sources)

    # Report
    exit_code = 0

    if undocumented:
        print(f'UNDOCUMENTED RPC methods ({len(undocumented)}):')
        for name, source in undocumented:
            print(f'  {name:30s} (registered in {os.path.basename(source)})')
        print()
        exit_code = 1

    if unregistered:
        print(f'STALE documentation ({len(unregistered)} methods documented but not registered):')
        for name in unregistered:
            print(f'  {name}')
        print()

    if issues:
        print(f'SOURCE ISSUES ({len(issues)}):')
        for issue in issues:
            print(f'  {issue}')
        print()

    if exit_code == 0 and not unregistered and not issues:
        print('All RPC methods are documented.')

    sys.exit(exit_code)


if __name__ == '__main__':
    main()

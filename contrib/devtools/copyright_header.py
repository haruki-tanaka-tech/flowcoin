#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
#
# Verify all source files have the correct copyright header.
# Optionally insert or update headers.
#
# Usage:
#     python3 copyright_header.py --check
#     python3 copyright_header.py --fix
#     python3 copyright_header.py --check --src-dir=../src

import argparse
import os
import re
import sys
from pathlib import Path

EXPECTED_COPYRIGHT = 'Copyright (c) 2026 The FlowCoin Developers'
EXPECTED_LICENSE = 'Distributed under the MIT software license'

# File extensions to check
SOURCE_EXTENSIONS = frozenset({
    '.cpp', '.h', '.c', '.hpp', '.cxx', '.cc',
})

SCRIPT_EXTENSIONS = frozenset({
    '.py', '.sh',
})

# Directories to skip (vendored code, build outputs, etc.)
SKIP_DIRS = frozenset({
    'sqlite', 'libuv', 'json', 'zstd',
    'randomx', 'xkcp', 'ed25519-donna',
    '.git', 'build', 'depends', '__pycache__',
    'node_modules', '.cache', 'dist', '.astro',
})

# Files to skip (vendored code, generated files)
SKIP_FILES = frozenset({
    'sqlite3.c', 'sqlite3.h',
    'ed25519.c', 'ed25519.h',
})

CPP_HEADER_TEMPLATE = """\
// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
"""

PYTHON_HEADER_TEMPLATE = """\
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""


def should_skip(path: str, skip_dirs: frozenset, skip_files: frozenset) -> bool:
    """Check if a file should be skipped."""
    basename = os.path.basename(path)
    if basename in skip_files:
        return True
    parts = Path(path).parts
    for part in parts:
        if part in skip_dirs:
            return True
    return False


def check_header(filepath: str) -> tuple[bool, str]:
    """Check if a file has the correct copyright header.
    Returns (is_valid, reason).
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            # Read first 20 lines
            head_lines = []
            for _ in range(20):
                line = f.readline()
                if not line:
                    break
                head_lines.append(line)
    except (OSError, PermissionError) as e:
        return False, f'cannot read: {e}'

    if not head_lines:
        return False, 'empty file'

    head_text = ''.join(head_lines)

    # Check for shebang on first line (scripts)
    ext = os.path.splitext(filepath)[1]
    start_line = 0
    if ext in SCRIPT_EXTENSIONS and head_lines[0].startswith('#!'):
        start_line = 1

    has_copyright = False
    has_license = False

    for line in head_lines[start_line:start_line + 10]:
        if EXPECTED_COPYRIGHT in line:
            has_copyright = True
        if EXPECTED_LICENSE in line:
            has_license = True

    if not has_copyright:
        return False, 'missing copyright line'
    if not has_license:
        return False, 'missing license line'

    return True, 'OK'


def fix_header(filepath: str) -> bool:
    """Insert or update the copyright header in a file.
    Returns True if the file was modified.
    """
    ext = os.path.splitext(filepath)[1]

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except (OSError, PermissionError):
        return False

    lines = content.split('\n')

    # Determine comment style and template
    if ext in SOURCE_EXTENSIONS:
        template = CPP_HEADER_TEMPLATE
        comment_prefix = '//'
    elif ext in SCRIPT_EXTENSIONS:
        template = PYTHON_HEADER_TEMPLATE
        comment_prefix = '#'
    else:
        return False

    # Check if header already exists
    head = '\n'.join(lines[:10])
    if EXPECTED_COPYRIGHT in head and EXPECTED_LICENSE in head:
        return False

    # Find insertion point (after shebang if present)
    insert_at = 0
    if lines and lines[0].startswith('#!'):
        insert_at = 1

    # Remove any existing partial copyright block
    end_of_existing = insert_at
    while end_of_existing < len(lines) and end_of_existing < insert_at + 10:
        line = lines[end_of_existing]
        if line.startswith(comment_prefix) and (
            'copyright' in line.lower() or
            'license' in line.lower() or
            'distributed under' in line.lower()
        ):
            end_of_existing += 1
        else:
            break

    # If we found existing copyright lines, replace them
    if end_of_existing > insert_at:
        lines[insert_at:end_of_existing] = template.rstrip('\n').split('\n')
    else:
        # Insert new header
        header_lines = template.rstrip('\n').split('\n')
        for i, hline in enumerate(header_lines):
            lines.insert(insert_at + i, hline)

    new_content = '\n'.join(lines)
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        return True
    except (OSError, PermissionError):
        return False


def find_source_files(src_dir: str) -> list[str]:
    """Recursively find all source and script files."""
    files = []
    all_extensions = SOURCE_EXTENSIONS | SCRIPT_EXTENSIONS
    for root, dirs, filenames in os.walk(src_dir):
        # Prune skipped directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in sorted(filenames):
            ext = os.path.splitext(filename)[1]
            if ext in all_extensions:
                filepath = os.path.join(root, filename)
                if not should_skip(filepath, SKIP_DIRS, SKIP_FILES):
                    files.append(filepath)
    return files


def main():
    parser = argparse.ArgumentParser(
        description='Verify or fix copyright headers in source files')
    parser.add_argument('--check', action='store_true',
                        help='Check headers (exit 1 if any are missing)')
    parser.add_argument('--fix', action='store_true',
                        help='Insert or update missing headers')
    parser.add_argument('--src-dir', type=str, default=None,
                        help='Source directory to scan (default: auto-detect)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show all files, not just failures')

    args = parser.parse_args()

    if not args.check and not args.fix:
        args.check = True

    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))
    src_dir = args.src_dir or os.path.join(project_root, 'src')

    print(f'Scanning: {src_dir}')
    files = find_source_files(src_dir)
    print(f'Found {len(files)} source files')
    print()

    failures = []
    fixed = 0

    for filepath in files:
        relpath = os.path.relpath(filepath, project_root)
        valid, reason = check_header(filepath)

        if valid:
            if args.verbose:
                print(f'  OK   {relpath}')
        else:
            if args.fix:
                if fix_header(filepath):
                    print(f'  FIXED {relpath} ({reason})')
                    fixed += 1
                else:
                    print(f'  FAIL  {relpath} ({reason}) - could not fix')
                    failures.append((relpath, reason))
            else:
                print(f'  FAIL  {relpath} ({reason})')
                failures.append((relpath, reason))

    print()
    if args.fix:
        print(f'Fixed {fixed} files')
    if failures:
        print(f'{len(failures)} files with missing/incorrect headers')
        sys.exit(1)
    else:
        print('All files have correct copyright headers.')
        sys.exit(0)


if __name__ == '__main__':
    main()

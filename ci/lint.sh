#!/usr/bin/env bash
set -euo pipefail

# Code quality checks

ERRORS=0

echo "=== Checking copyright headers ==="
python3 contrib/devtools/copyright_header.py --check || ((ERRORS++))

echo "=== Checking RPC documentation ==="
python3 contrib/devtools/check-doc.py || ((ERRORS++))

echo "=== Checking for forbidden patterns ==="
FORBIDDEN="TODO|FIXME|HACK|XXX|stub|placeholder|mock|dummy"
if grep -rn --include="*.cpp" --include="*.h" -E "$FORBIDDEN" src/ \
    | grep -v "src/sqlite/" | grep -v "src/ggml/" | grep -v "src/zstd/" \
    | grep -v "src/libuv/" | grep -v "src/json/"; then
    echo "ERROR: Forbidden patterns found"
    ((ERRORS++))
fi

echo "=== Checking for trailing whitespace ==="
if grep -rn --include="*.cpp" --include="*.h" ' $' src/ \
    | grep -v "src/sqlite/" | grep -v "src/ggml/" | head -5; then
    echo "WARNING: Trailing whitespace found (not blocking)"
fi

echo "=== Checking include guards ==="
for f in $(find src -name "*.h" -not -path "src/sqlite/*" -not -path "src/ggml/*" \
    -not -path "src/zstd/*" -not -path "src/libuv/*" -not -path "src/json/*" \
    -not -path "src/hash/Keccak*" -not -path "src/crypto/ed25519*"); do
    if ! head -5 "$f" | grep -q "#ifndef\|#pragma once"; then
        echo "WARNING: Missing include guard: $f"
    fi
done

if [ $ERRORS -gt 0 ]; then
    echo "=== FAILED: $ERRORS errors ==="
    exit 1
fi

echo "=== All lint checks passed ==="

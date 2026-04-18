#!/usr/bin/env bash
set -euo pipefail

# Code quality checks

ERRORS=0

echo "=== Checking copyright headers ==="
python3 contrib/devtools/copyright_header.py --check || ((ERRORS++))

echo "=== Checking RPC documentation ==="
python3 contrib/devtools/check-doc.py || ((ERRORS++))

VENDORED="src/sqlite/|src/zstd/|src/libuv/|src/json/|src/randomx/|src/hash/Keccak|src/hash/SnP|src/hash/KeccakSponge|src/crypto/ed25519|src/crypto/curve25519"

echo "=== Checking for forbidden patterns ==="
FORBIDDEN="TODO|FIXME|HACK|XXX|stub|placeholder|mock|dummy"
if grep -rn --include="*.cpp" --include="*.h" -E "$FORBIDDEN" src/ \
    | grep -Ev "$VENDORED"; then
    echo "ERROR: Forbidden patterns found"
    ((ERRORS++))
fi

echo "=== Checking for trailing whitespace ==="
if grep -rn --include="*.cpp" --include="*.h" ' $' src/ \
    | grep -Ev "$VENDORED" | head -5; then
    echo "WARNING: Trailing whitespace found (not blocking)"
fi

echo "=== Checking include guards ==="
for f in $(find src -name "*.h" \
    -not -path "src/sqlite/*" \
    -not -path "src/zstd/*" \
    -not -path "src/libuv/*" \
    -not -path "src/json/*" \
    -not -path "src/randomx/*" \
    -not -path "src/hash/Keccak*" \
    -not -path "src/hash/SnP*" \
    -not -path "src/hash/KeccakSponge*" \
    -not -path "src/crypto/ed25519*" \
    -not -path "src/crypto/curve25519*"); do
    if ! head -5 "$f" | grep -q "#ifndef\|#pragma once"; then
        echo "WARNING: Missing include guard: $f"
    fi
done

if [ $ERRORS -gt 0 ]; then
    echo "=== FAILED: $ERRORS errors ==="
    exit 1
fi

echo "=== All lint checks passed ==="

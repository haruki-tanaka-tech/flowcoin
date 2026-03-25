#!/usr/bin/env bash
# Memory check with Valgrind
set -euo pipefail

cd build

echo "=== Running Valgrind memory check ==="
valgrind \
    --leak-check=full \
    --show-reachable=yes \
    --error-exitcode=1 \
    --suppressions=../ci/valgrind-suppressions.txt \
    ./flowcoin_tests

echo "=== Valgrind passed ==="

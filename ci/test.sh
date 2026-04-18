#!/usr/bin/env bash
set -euxo pipefail

# CI test script

cd build

echo "=== Running C++ unit tests ==="
./flowcoin_tests

echo "=== Running Python functional tests ==="
cd ..
if command -v python3 &>/dev/null; then
    python3 test/functional/test_runner.py --timeout 120
else
    echo "Python3 not found, skipping functional tests"
fi

echo "=== All tests passed ==="

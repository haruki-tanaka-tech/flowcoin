#!/usr/bin/env bash
set -euxo pipefail

# CI test script

cd build

echo "=== Running C++ unit tests ==="
./flowcoin_tests

echo "=== All tests passed ==="

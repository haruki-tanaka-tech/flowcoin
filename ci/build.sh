#!/usr/bin/env bash
set -euxo pipefail

# CI build script for FlowCoin

NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

echo "=== Building FlowCoin ==="
echo "Compiler: $(g++ --version | head -1)"
echo "CMake: $(cmake --version | head -1)"
echo "CPUs: $NPROC"

mkdir -p build && cd build

cmake .. \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE:-Release} \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    ${CMAKE_EXTRA_FLAGS:-}

make -j$NPROC

echo "=== Build successful ==="

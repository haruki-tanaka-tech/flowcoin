# FlowCoin Dependencies

This directory contains the dependency build system for cross-compilation.
It downloads, verifies, and builds all required dependencies for the target platform.

## Usage

```bash
# Native build (detect host)
make -C depends

# Cross-compile for specific target
make -C depends HOST=x86_64-linux-gnu
make -C depends HOST=x86_64-apple-darwin
make -C depends HOST=x86_64-w64-mingw32
make -C depends HOST=aarch64-linux-gnu

# Then configure FlowCoin
cmake -DCMAKE_TOOLCHAIN_FILE=depends/x86_64-linux-gnu/share/toolchain.cmake ..
```

## Dependencies

All dependencies are vendored in src/:
- SQLite 3.47.2 (src/sqlite/)
- zstd 1.5.5 (src/zstd/)
- libuv 1.49 (src/libuv/)
- ed25519-donna (src/crypto/)
- XKCP Keccak (src/hash/)
- nlohmann/json 3.11.3 (src/json/)

Since all dependencies are vendored, the depends system is primarily
for cross-compilation toolchain setup.

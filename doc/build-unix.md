# Building FlowCoin on Linux

This document describes how to build FlowCoin Core from source on Linux
(Ubuntu, Debian, Fedora, Arch, and similar distributions).

## Overview

FlowCoin Core produces three executables:

| Binary | Description |
|---|---|
| `flowcoind` | Full node daemon (P2P, RPC, chain validation) |
| `flowcoin-cli` | RPC command-line client |
| `flowcoin-tx` | Offline transaction construction utility |
| `flowcoin_tests` | Assert-based unit and integration test suite |

## Dependencies

FlowCoin has minimal external dependencies. All cryptographic and database
libraries are vendored in the source tree:

- **Keccak** (XKCP reference implementation) for hashing
- **Ed25519-donna** for signatures
- **SQLite** for UTXO and index storage
- **zstd** for delta payload compression
- **ggml** for consensus model evaluation
- **libuv** for async networking and event loops
- **nlohmann/json** (header-only) for RPC serialization

### Required system packages

| Dependency | Version | Purpose |
|---|---|---|
| C++20 compiler | GCC 10+ or Clang 12+ | Core language |
| CMake | 3.20+ | Build system |
| pthread | system | Thread synchronization |
| dl | system | Dynamic loading (libuv) |
| make or ninja | any | Build driver |

### Installing dependencies

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install -y build-essential cmake git
```

**Fedora:**
```bash
sudo dnf install -y gcc-c++ cmake git make
```

**Arch Linux:**
```bash
sudo pacman -S base-devel cmake git
```

### Optional (for mining)

Mining requires a Python environment with GPU support:

| Dependency | Version | Purpose |
|---|---|---|
| Python | 3.8+ | Mining script runtime |
| PyTorch | 2.0+ | GPU-accelerated model training |
| zstandard | any | Delta compression in Python |
| pycryptodome | any | Keccak-256 hashing |

```bash
pip install torch zstandard pycryptodome
```

## Build Instructions

### Standard build

```bash
git clone https://github.com/haruki-tanaka-tech/flowcoin.git
cd flowcoin
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Debug build

```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

### Release build (optimized)

```bash
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### Building without tests

```bash
cmake -DBUILD_TESTS=OFF ..
make -j$(nproc)
```

### Using Ninja instead of Make

```bash
cmake -GNinja ..
ninja
```

## Running Tests

```bash
cd build
./flowcoin_tests
```

The test suite runs approximately 50 test groups covering cryptography,
consensus rules, serialization, networking, wallet operations, and
end-to-end integration scenarios. All tests are assert-based and require
no external test framework.

Expected output:
```
  TEST keccak256 ... OK
  TEST arith_uint256 ... OK
  ...
  TEST integration ... OK

Results: 49 passed, 0 failed, 49 total
```

## Configuration

FlowCoin reads configuration from `~/.flowcoin/flowcoin.conf` (or the
directory specified by `--datadir`). Create the config file before first
run:

```bash
mkdir -p ~/.flowcoin
cat > ~/.flowcoin/flowcoin.conf << 'EOF'
# RPC authentication (required for CLI and miner access)
rpcuser=your_username
rpcpassword=your_secure_password

# Listen for incoming P2P connections
listen=1

# For testnet (uncomment to use):
# testnet=1
EOF
```

### Configuration options

| Option | Default | Description |
|---|---|---|
| `rpcuser` | flowcoin | RPC authentication username |
| `rpcpassword` | flowcoin | RPC authentication password |
| `port` | 9333 | P2P listen port |
| `rpcport` | 9334 | RPC listen port |
| `testnet` | 0 | Use testnet network |
| `regtest` | 0 | Use regtest network |

## Starting the Node

### Foreground mode

```bash
./flowcoind --datadir=$HOME/.flowcoin
```

### Daemon mode

```bash
./flowcoind --datadir=$HOME/.flowcoin --daemon
```

### Testnet mode

```bash
./flowcoind --testnet
```

Testnet uses different ports (P2P: 19333, RPC: 19334) and a different
genesis block, allowing development without affecting the main network.

### Regtest mode

```bash
./flowcoind --regtest
```

Regtest mode uses minimum difficulty, allowing instant block generation
for local testing. Ports: P2P 29333, RPC 29334.

## Interacting with the Node

Use `flowcoin-cli` to issue RPC commands:

```bash
./flowcoin-cli --rpcuser=your_username --rpcpassword=your_password getblockcount
./flowcoin-cli --rpcuser=your_username --rpcpassword=your_password getinfo
./flowcoin-cli --rpcuser=your_username --rpcpassword=your_password getnewaddress
```

Or use curl directly:

```bash
curl -u your_username:your_password \
     -X POST http://127.0.0.1:9334 \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'
```

## Mining

FlowCoin uses Proof-of-Useful-Training (PoUT) instead of traditional
hash-based proof of work. Mining involves training a neural network on
a dataset and submitting the resulting weight updates as proof.

```bash
pip install torch zstandard pycryptodome
python3 tools/flowminer.py \
    --dataset ~/training-data/ \
    --node http://127.0.0.1:9334 \
    --rpcuser your_username \
    --rpcpassword your_password
```

See `doc/mining.md` for detailed mining instructions.

## Data Directory Layout

```
~/.flowcoin/
  flowcoin.conf          Configuration file
  debug.log              Runtime log
  wallet.dat             Wallet database (keys and transactions)
  blocks/
    blk00000.dat         Block data files
    blk00001.dat
    ...
  utxo.db                UTXO set (SQLite)
  txindex.db             Transaction index (SQLite)
  model/                 Consensus model checkpoints
  .lock                  Data directory lock file
```

## Troubleshooting

### Build fails with "filesystem not found"

FlowCoin uses `<filesystem>` from C++17/20. Ensure your compiler
supports C++20:

```bash
g++ --version   # needs 10+
cmake -DCMAKE_CXX_COMPILER=g++-12 ..
```

### "Address already in use" on startup

Another flowcoind instance is running, or another program uses port 9333
or 9334. Stop the other instance or use `--port` and `--rpcport` to
choose different ports.

### Build is slow

Use parallel compilation with `-j`:

```bash
make -j$(nproc)
```

Or switch to Ninja, which parallelizes by default:

```bash
cmake -GNinja .. && ninja
```

### Corrupted chain data

If the node crashes during shutdown, the chain database may be
inconsistent. Delete and resync:

```bash
rm -rf ~/.flowcoin/blocks ~/.flowcoin/utxo.db ~/.flowcoin/txindex.db
./flowcoind
```

The wallet file (`wallet.dat`) is not affected by chain resyncs.

## Reproducible Builds

The CMake configuration includes settings for deterministic builds:

- File prefix maps strip absolute paths from debug info
- RPATH is disabled
- Archive creation uses deterministic mode (`qcD`)
- `-ffast-math` is intentionally omitted to preserve IEEE 754 determinism

To verify a reproducible build:

```bash
mkdir build1 build2
cd build1 && cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc)
cd ../build2 && cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc)
sha256sum build1/flowcoind build2/flowcoind
```

Both checksums should match on the same compiler and OS.

## Cross-Compilation

FlowCoin includes a `depends` directory for cross-compilation support.
See `depends/README.md` for details on building for other architectures.

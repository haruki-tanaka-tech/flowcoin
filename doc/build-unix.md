# Building FlowCoin on Linux

How to build FlowCoin from source on a typical Linux distribution
(Ubuntu, Debian, Fedora, Arch, etc.).

## Overview

The default build produces four binaries and a test suite:

| Binary | Purpose |
|---|---|
| `flowcoind` | Full node daemon — P2P, RPC, wallet, chain validation |
| `flowcoin-cli` | JSON-RPC command-line client (Bitcoin-cli compatible) |
| `flowcoin-tx` | Offline transaction construction utility |
| `flowcoin-miner` | Standalone CPU-only RandomX miner |
| `flowcoin_tests` | Assert-based unit / integration test suite |

## Dependencies

Everything cryptographic and database-related is **vendored** in the
source tree — no external crypto or DB libraries to install. Only a
toolchain and a few system libraries are required.

Vendored dependencies (already in `src/`):

- **RandomX** (tevador) — CPU-only proof-of-work
- **XKCP** — Keccak reference implementation (block-id hash only)
- **Ed25519-donna** — signatures
- **SQLite** — UTXO set, transaction index
- **zstd** — block compression
- **libuv** — async networking / event loop
- **nlohmann/json** — header-only JSON for RPC

System requirements:

| Dependency | Minimum | Purpose |
|---|---|---|
| C++20 compiler | GCC 10 or Clang 12 | Core language |
| CMake | 3.20 | Build system |
| pthread | system | Worker threads |
| make or Ninja | — | Build driver |

### Installing dependencies

**Ubuntu / Debian:**

```bash
sudo apt update
sudo apt install -y build-essential cmake git
```

**Fedora / RHEL:**

```bash
sudo dnf install -y gcc-c++ cmake git make
```

**Arch Linux:**

```bash
sudo pacman -S base-devel cmake git
```

## Build

### Standard release build

```bash
git clone https://github.com/KristianPilatovich/flowcoin.git
cd flowcoin
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Produces `build/flowcoind`, `build/flowcoin-cli`, `build/flowcoin-tx`,
`build/flowcoin-miner`, and `build/flowcoin_tests`.

### Debug build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
```

### Skip the test binary

```bash
cmake -B build -DBUILD_TESTS=OFF
cmake --build build -j$(nproc)
```

### Skip the standalone miner

```bash
cmake -B build -DBUILD_MINER=OFF
cmake --build build -j$(nproc)
```

### Ninja instead of Make

```bash
cmake -B build -G Ninja
ninja -C build
```

## Running the tests

```bash
./build/flowcoin_tests
```

There are ~55 test groups covering cryptography (Keccak, RandomX,
Ed25519, Bech32, SLIP-0010), consensus rules, serialization,
networking, wallet operations, and integration scenarios. Every test
is assert-based with no external framework; a zero exit code means
all passed. The RandomX test vectors from tevador's `tests.cpp` are
checked bit-for-bit against our integration, so a mismatch there
means the vendored library was compiled incorrectly.

Expected summary line:

```
Results: 54 passed, 2 failed, 56 total
```

Two pre-existing failures (`wallet_full`, `wallet_advanced`) are
known and unrelated to the crypto / consensus / network layers.

## First run

```bash
./build/flowcoind -daemon
```

On first start the node:

1. Creates `~/.flowcoin/` with `blocks/`, `chainstate/`, `indexes/`,
   and a flat `wallet.dat` at the root.
2. Generates an RPC auth cookie at `~/.flowcoin/.cookie` (Bitcoin
   Core format — one line, `username:password`). `flowcoin-cli` and
   `flowcoin-miner` read it automatically.
3. Opens P2P port 9333 and RPC port 9334 on localhost only.

Check sync progress:

```bash
tail -f ~/.flowcoin/debug.log
./build/flowcoin-cli getblockcount
./build/flowcoin-cli getpeerinfo
```

Stop cleanly:

```bash
./build/flowcoin-cli stop
```

## Configuration

The node reads `~/.flowcoin/flowcoin.conf` (or `--conf=PATH`). A
sample config is installed alongside the binary as `flowcoin.conf`,
with every option commented out.

Common options (all can also be passed as `-key=value` on the command
line, Bitcoin-Core-style):

| Option | Default | Description |
|---|---|---|
| `datadir` | `~/.flowcoin` | Data directory |
| `port` | `9333` | P2P listen port |
| `rpcport` | `9334` | RPC listen port |
| `rpcbind` | `127.0.0.1` | RPC bind address (set `0.0.0.0` to expose on LAN) |
| `rpcallowip` | — | CIDR allow-list for RPC (required if rpcbind is non-local) |
| `rpcuser` / `rpcpassword` | — | Optional explicit credentials (otherwise cookie auth) |
| `prune` | `0` | Prune block store to N MiB (minimum 550; 0 = keep all) |
| `daemon` | `0` | Fork into background after startup |
| `testnet` / `regtest` | `0` | Switch network (ports 19333/19334 or 29333/29334) |
| `debug` | — | Comma-separated log categories to enable at debug level |

## Networks

### Mainnet

Default. Ports 9333 (P2P) / 9334 (RPC). `fl1q…` addresses.

### Testnet

```bash
./build/flowcoind -testnet
```

Ports 19333 / 19334, prefix `tfl1q…`, separate chain and wallet
directory.

### Regtest

```bash
./build/flowcoind -regtest
```

Ports 29333 / 29334. Minimum difficulty — you can mine blocks
instantly for local testing. Used heavily by the integration tests.

## Interacting with the node

```bash
# CLI (cookie auth picked up automatically)
./build/flowcoin-cli getblockcount
./build/flowcoin-cli getpeerinfo
./build/flowcoin-cli getbalance
./build/flowcoin-cli -getinfo

# Raw JSON-RPC over HTTP
USERPASS=$(cat ~/.flowcoin/.cookie)
curl -s -u "$USERPASS" -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}' \
     http://127.0.0.1:9334/
```

Both produce the same wire output format as Bitcoin Core 30.x.

## Mining

RandomX is built-in. See [`mining.md`](mining.md) for the full guide.
Short version:

```bash
./build/flowcoind -daemon
./build/flowcoin-miner --cookie ~/.flowcoin/.cookie
```

## Data directory layout

```
~/.flowcoin/
├── wallet.dat          HD wallet (SLIP-0010, currently unencrypted)
├── wallet.dat-{shm,wal}    SQLite auxiliary files
├── blocks/
│   ├── blk00000.dat    Raw block data
│   └── rev00000.dat    Undo data for reorgs
├── chainstate/         SQLite UTXO set (WAL mode)
├── indexes/            Transaction index, block-filter index
├── peers.dat           Address manager state
├── banlist.dat         Peer ban list
├── .cookie             RPC auth cookie
├── .lock / .pid        Instance lock + pid
└── debug.log
```

## Troubleshooting

### Build fails with `<filesystem>` not found

Upgrade the C++ toolchain. GCC 10+ or Clang 12+ is required.

```bash
g++ --version       # need 10 or later
cmake -B build -DCMAKE_CXX_COMPILER=g++-12
```

### `Address already in use` on startup

Another `flowcoind` instance owns port 9333 or 9334. Either stop it
(`./build/flowcoin-cli stop`, or `pkill flowcoind`), or run this one
on different ports:

```bash
./build/flowcoind -port=19333 -rpcport=19334 -datadir=/tmp/flow2
```

### `Cannot obtain lock on data directory`

Same instance already running, or a stale lock after `kill -9`:

```bash
pkill -9 flowcoind
rm -f ~/.flowcoin/.lock
```

### Corrupted chain data

After an unclean shutdown the chain database may need a rebuild. The
wallet is a separate file and is not affected — back it up first, then:

```bash
cp ~/.flowcoin/wallet.dat /tmp/wallet.dat.backup
rm -rf ~/.flowcoin/blocks ~/.flowcoin/chainstate ~/.flowcoin/indexes
./build/flowcoind
```

### Miner shows 0 H/s for a long time

The 2 GiB RandomX dataset takes ~1.5 s to allocate on a fast CPU. If
it stays at 0 for more than ~10 s, fall back to light mode:

```bash
./build/flowcoin-miner --cookie ~/.flowcoin/.cookie --light
```

## Reproducible builds

The CMake configuration is set up for deterministic output:

- `-ffile-prefix-map` strips absolute source paths from debug info
- `-fmacro-prefix-map` strips them from `__FILE__` expansions
- RPATH is disabled (`CMAKE_SKIP_RPATH`)
- `ar` archives use the deterministic `D` mode
- `-ffast-math` is intentionally omitted so IEEE-754 behaviour stays
  identical across build hosts (required for consensus on the
  floating-point ops inside RandomX)

To verify, build twice on the same compiler / OS and compare
checksums:

```bash
cmake -B build1 -DCMAKE_BUILD_TYPE=Release && cmake --build build1 -j$(nproc)
cmake -B build2 -DCMAKE_BUILD_TYPE=Release && cmake --build build2 -j$(nproc)
sha256sum build1/flowcoind build2/flowcoind
```

Checksums should match.

## Packaging a release tarball

The same install rules that produce the published releases are
available locally:

```bash
cmake --build build --target package
ls build/flowcoin-*.tar.gz
```

`cpack` emits `flowcoin-<version>-<os>-<arch>.tar.gz` with the
Bitcoin-Core-style layout (`bin/ share/man/ flowcoin.conf README.md
whitepaper.txt`) rooted in a versioned top-level directory.

## Cross-compilation

Cross-builds are best done with a Docker image carrying the target
toolchain. The Gitian descriptors in [`contrib/gitian/`](../contrib/gitian/)
cover Linux and macOS (via `osxcross`) reproducibly; for Windows,
`mingw-w64` in a Docker container is the usual path. No ready-made
scripts ship outside `contrib/gitian/`.

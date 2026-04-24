# FlowCoin Mining Guide

## Quick Start

```bash
# Build the miner (bundled with the standard CMake build)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Start the full node (miner talks to it over JSON-RPC)
./build/flowcoind -daemon

# Start the miner — cookie auth, all threads, full-memory mode
./build/flowcoin-miner --cookie ~/.flowcoin/.cookie
```

## Overview

FlowCoin uses Keccak-256d — a double-hash of Keccak-256 (padding byte
0x01, not NIST SHA-3's 0x06) — as its proof-of-work function. The same
hash also serves as the block identifier, keeping the protocol simple.
Keccak-256d is efficient on both CPUs and GPUs, making mining accessible
to anyone with commodity hardware.

The `flowcoin-miner` binary is a standalone C++ process that talks to
a running `flowcoind` over HTTP JSON-RPC (`getblocktemplate`,
`submitblock`). Output style follows XMRig conventions — a banner at
start-up, then timestamped tagged events, a `speed 10s/60s/15m` line
every ten seconds, and `accepted (N/M)` / `rejected` events per
submit.

Mining runs on both CPU and GPU. The `flowcoin-miner` binary includes
a CPU backend by default, and an OpenCL GPU backend is available for
additional hashrate.

## Hardware requirements

### Minimum

| Component | Requirement |
|---|---|
| CPU | Any x86-64 or ARM64 CPU |
| RAM | 1 GiB (node plus OS overhead) |
| Storage | 1 GiB for node state — chain size is tiny at launch |
| Network | Any broadband connection, incoming port 9333 preferably open |

### Recommended

| Component | Requirement |
|---|---|
| CPU | Modern desktop/laptop (Ryzen 7+, Core i7+, Apple Silicon) with ≥8 threads |
| GPU | Any OpenCL-capable GPU for additional hashrate (optional) |
| RAM | 4 GiB system memory |
| Storage | NVMe SSD for the node |
| Network | Stable 24/7 uplink if you want to keep blocks in flight |

Expected CPU throughput (Keccak-256d):

| CPU class | MH/s per thread | 8-thread aggregate |
|---|---|---|
| Ryzen 9 5950X / 7950X | 30–50 | 240–400 MH/s |
| Core i9-13900K | 25–45 | 200–360 MH/s |
| Apple M2 Pro | 20–35 | 160–280 MH/s |

GPUs can achieve significantly higher throughput via the OpenCL backend.

## Configuring the node

The miner needs a running `flowcoind` to hand it block templates and
accept submitted blocks. First start the node:

```bash
./build/flowcoind -daemon
```

On first launch the node writes `~/.flowcoin/.cookie` — a one-line
file in Bitcoin Core's format (`username:password`). The miner reads
it directly. No `rpcuser` / `rpcpassword` config is needed.

If you run the node on a separate machine, expose RPC to your LAN:

```bash
# node.example.lan
./build/flowcoind -daemon -rpcbind=0.0.0.0 -rpcallowip=192.168.1.0/24
```

Then copy `~/.flowcoin/.cookie` from that machine to where the miner
runs, and point the miner at the node's URL.

## Running the miner

### Everyday usage

```bash
./build/flowcoin-miner --cookie ~/.flowcoin/.cookie
```

This picks up all logical cores, connects to `http://127.0.0.1:9334`,
and starts hashing.

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `-o URL`, `--url URL` | `http://127.0.0.1:9334` | Node RPC endpoint |
| `--cookie PATH` | — | Read HTTP Basic auth from Bitcoin-Core-style cookie file |
| `-u U`, `--user U` / `-p P`, `--pass P` | — | Explicit credentials (alternative to `--cookie`) |
| `-t N`, `--threads N` | auto | Worker threads |
| `-a ADDR`, `--address ADDR` | node's wallet | Coinbase reward address (bech32 `fl1q...`) |
| `--key PATH` | `~/.flowcoin/miner_key` | Ed25519 signing key (generated on first run) |
| `-b SEC`, `--benchmark SEC` | — | Run Keccak-256d for N seconds, print H/s, exit |
| `--no-color` | — | Disable ANSI colours |

### Examples

```bash
# Default — full mode, all threads, node on localhost
./build/flowcoin-miner --cookie ~/.flowcoin/.cookie

# Mine against a remote node with basic auth
./build/flowcoin-miner -o http://node.example.lan:9334 \
                       -u flow -p secret

# 10-second Keccak-256d benchmark
./build/flowcoin-miner --benchmark 10

# Restrict to 4 threads, pay rewards to a specific address
./build/flowcoin-miner --cookie ~/.flowcoin/.cookie \
                       --threads 4 \
                       --address fl1q…
```

### Output

Startup banner plus a live event stream:

```
 * ABOUT        flowcoin-miner/0.1.0 gcc/15.2
 * LIBS         keccak256d nlohmann-json/3.x
 * CPU          AMD Ryzen 9 7950X  64-bit
 *              threads:32
 * NODE         127.0.0.1:9334
 * ADDRESS      inherited from node wallet
 * ALGO         keccak256d
 * THREADS      32

[2026-04-18 17:03:07.578]  config   miner pubkey c32e968b3cb9658a
[2026-04-18 17:03:07.579]  net      connected to 127.0.0.1:9334  height=0
[2026-04-18 17:03:07.823]  keccak   init complete  (1 ms)
[2026-04-18 17:03:07.824]  net      new job from 127.0.0.1:9334  height 1  diff 1.000  algo keccak256d
[2026-04-18 17:03:17.580]  miner    speed 10s/60s/15m 12.34 kH/s 12.40 kH/s 12.40 kH/s
[2026-04-18 17:05:42.114]  miner    accepted (1/1) height 1  nonce 487221  (22 ms)
```

## How it works

### The Keccak-256d hash

For each nonce, the miner computes:

```
pow_hash = keccak256d(header[0..91])
         = Keccak-256(Keccak-256(header[0..91]))
```

using the original Keccak padding byte 0x01 (not NIST SHA-3's 0x06).

Miners search for a nonce such that

```
keccak256d(header[0..91]) <= target(nbits)
```

The hash is a pure function of the header bytes -- no external seed,
dataset, or state is required. This makes the miner simple: increment
the nonce, hash, compare against the target, repeat.

### Why Keccak-256d

- **Proven cryptography.** Keccak won the NIST SHA-3 competition and
  has been studied extensively since 2008.
- **Simplicity.** No VM, no dataset, no seed rotation -- just a hash
  of the header. This makes independent implementations easy to verify.
- **Broad hardware support.** Efficient on CPUs, GPUs, and FPGAs,
  keeping mining accessible to anyone with commodity hardware.

## Block reward schedule

Matches Bitcoin exactly:

| Era | Blocks | Reward / block |
|---|---|---|
| 0 | 0 – 209,999 | 50 FLC |
| 1 | 210,000 – 419,999 | 25 FLC |
| 2 | 420,000 – 629,999 | 12.5 FLC |
| … | … | halves every 210,000 blocks |

Total supply converges to 21,000,000 FLC. Coinbase outputs mature
after `COINBASE_MATURITY = 100` confirmations.

## Difficulty

Retarget every 2,016 blocks using Bitcoin's algorithm (clamped to ±4×
per period). The network floor is `nbits = 0x1d00ffff` (difficulty 1,
target ≈ 2^224). At launch a solo CPU miner finds roughly one block
per several days; once more miners join, difficulty retargets upward.

## Troubleshooting

- **`error: could not connect to 127.0.0.1:9334` / `Is flowcoind running?`**
  Start `flowcoind -daemon` first, give it a few seconds, retry.
- **0 H/s for more than a few seconds** — check that `flowcoind` is
  running and the RPC endpoint is reachable. Keccak-256d requires no
  initialisation time.
- **Block rejected: `high-hash`** — hash was computed against a stale
  target. Happens naturally when a new block arrives mid-search;
  miner restarts against the fresh template automatically.
- **Block rejected: `bad-diffbits`** — the node and miner disagree
  on the expected `nbits`. Usually means they're running different
  binaries; rebuild both.
- **No peers** — `flowcoin-cli getpeerinfo` empty. Check that port
  9333 isn't firewalled and that the seed (`seed.flowcoin.org`) is
  reachable.

## Monitoring

```bash
./build/flowcoin-cli getmininginfo        # network difficulty, our hashrate, next block fee estimate
./build/flowcoin-cli getdifficulty        # current target as a float
./build/flowcoin-cli getnetworkhashps     # estimated global hashrate
./build/flowcoin-cli getbalance           # rewards credited to your wallet
```

## Pool mining

Not supported yet. Stratum is on the roadmap once the network is
stable enough to justify pool infrastructure; until then every miner
is solo. The reward is the full coinbase output (50 FLC) plus the
transaction fees in the block.

## Security notes

- Back up `~/.flowcoin/wallet.dat` (while the node is stopped). The
  HD seed derives every future address, so a single file is the
  whole backup.
- Never expose RPC (`port 9334`) to the public internet without a
  firewall or TLS terminator in front.
- The miner generates a fresh coinbase address per block by default —
  do not override `--address` with a reused address unless you
  understand the privacy trade-off.
- Keep your miner's Ed25519 signing key (`~/.flowcoin/miner_key` by
  default) backed up; losing it means losing the ability to sign new
  blocks from that identity.

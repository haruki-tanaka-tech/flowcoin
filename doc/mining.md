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

FlowCoin uses [RandomX](https://github.com/tevador/RandomX) — the
same CPU-oriented memory-hard proof-of-work that has secured the Monero
network since November 2019. Each hash executes a pseudo-randomly
generated program of 256 instructions against a 2 GiB deterministic
dataset in a virtual machine. The bottleneck is DRAM bandwidth, not
silicon gate count, so general-purpose CPUs outperform both GPUs and
bespoke hardware by an order of magnitude.

The `flowcoin-miner` binary is a standalone C++ process that talks to
a running `flowcoind` over HTTP JSON-RPC (`getblocktemplate`,
`submitblock`). Output style follows XMRig conventions — a banner at
start-up, then timestamped tagged events, a `speed 10s/60s/15m` line
every ten seconds, and `accepted (N/M)` / `rejected` events per
submit.

Mining runs purely on the CPU. There is no OpenCL, no CUDA, no GPU
path — and none is planned. A GPU port would be at best 10× slower
per watt and serves no legitimate purpose for this chain.

## Hardware requirements

### Minimum

| Component | Requirement |
|---|---|
| CPU | Any x86-64 CPU with AES-NI (basically anything since ~2010). ARM64 also supported. |
| RAM | 3 GiB (the 2 GiB dataset plus ~500 MiB for the node plus OS overhead) |
| Storage | 1 GiB for node state — chain size is tiny at launch |
| Network | Any broadband connection, incoming port 9333 preferably open |

### Recommended

| Component | Requirement |
|---|---|
| CPU | Modern desktop/laptop (Ryzen 7+, Core i7+, Apple Silicon) with ≥8 threads |
| RAM | 8 GiB system memory — more threads benefit from more L3 cache |
| Storage | NVMe SSD for the node (not the miner — the miner is RAM-bound) |
| Network | Stable 24/7 uplink if you want to keep blocks in flight |

Expected per-thread throughput in **full** memory mode (2 GiB dataset,
JIT, AES-NI):

| CPU class | H/s per thread | 8-thread aggregate |
|---|---|---|
| Ryzen 9 5950X / 7950X | 1100–1600 | 9–13 kH/s |
| Core i9-13900K | 1000–1400 | 8–11 kH/s |
| Apple M2 Pro | 900–1200 | 7–10 kH/s |

In **light** mode (256 MiB cache only, no dataset) expect ~40–90 H/s
per thread — fine for verification, way too slow for competitive
mining.

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

This picks up all logical cores, allocates the 2 GiB dataset (~1.5 s
init on a fast CPU), connects to `http://127.0.0.1:9334`, and starts
hashing.

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `-o URL`, `--url URL` | `http://127.0.0.1:9334` | Node RPC endpoint |
| `--cookie PATH` | — | Read HTTP Basic auth from Bitcoin-Core-style cookie file |
| `-u U`, `--user U` / `-p P`, `--pass P` | — | Explicit credentials (alternative to `--cookie`) |
| `-t N`, `--threads N` | auto | Worker threads |
| `-a ADDR`, `--address ADDR` | node's wallet | Coinbase reward address (bech32 `fl1q...`) |
| `--key PATH` | `~/.flowcoin/miner_key` | Ed25519 signing key (generated on first run) |
| `-b SEC`, `--benchmark SEC` | — | Run RandomX for N seconds, print H/s, exit |
| `--light` | — | Use the 256 MiB cache instead of the 2 GiB dataset |
| `--no-color` | — | Disable ANSI colours |

### Examples

```bash
# Default — full mode, all threads, node on localhost
./build/flowcoin-miner --cookie ~/.flowcoin/.cookie

# Mine against a remote node with basic auth
./build/flowcoin-miner -o http://node.example.lan:9334 \
                       -u flow -p secret

# 10-second RandomX benchmark (fast mode)
./build/flowcoin-miner --benchmark 10

# 10-second benchmark in light mode (no 2 GiB allocation)
./build/flowcoin-miner --benchmark 10 --light

# Restrict to 4 threads, pay rewards to a specific address
./build/flowcoin-miner --cookie ~/.flowcoin/.cookie \
                       --threads 4 \
                       --address fl1q…
```

### Output

Startup banner plus a live event stream:

```
 * ABOUT        flowcoin-miner/0.1.0 gcc/15.2
 * LIBS         RandomX nlohmann-json/3.x
 * CPU          AMD Ryzen 9 7950X  64-bit AES
 *              threads:32
 * NODE         127.0.0.1:9334
 * ADDRESS      inherited from node wallet
 * ALGO         randomx
 * THREADS      32

[2026-04-18 17:03:07.578]  config   miner pubkey c32e968b3cb9658a
[2026-04-18 17:03:07.579]  net      connected to 127.0.0.1:9334  height=0
[2026-04-18 17:03:07.823]  randomx  cache seed=9f32dc6a53fa6074  (243 ms)
[2026-04-18 17:03:09.330]  randomx  dataset ready (2080 MB)  (1507 ms)
[2026-04-18 17:03:09.331]  net      new job from 127.0.0.1:9334  height 1  diff 1.000  algo randomx
[2026-04-18 17:03:17.580]  miner    speed 10s/60s/15m 12.34 kH/s 12.40 kH/s 12.40 kH/s
[2026-04-18 17:05:42.114]  miner    accepted (1/1) height 1  nonce 487221  (22 ms)
```

## How it works

### The RandomX hash

For each nonce:

1. Initialise a 4 KiB scratchpad with AES-based mixing keyed on the
   header bytes.
2. Execute a pseudo-randomly generated program of 256 VM instructions
   against the scratchpad and a shared 2 GiB dataset, looping eight
   times. The instruction mix covers integer, floating-point, and
   memory ops.
3. Finalise the scratchpad with AES and produce a 256-bit digest via
   Blake2b.

Miners search for a nonce such that

```
RandomX(header[0..91], seed) <= target(nbits)
```

where `seed` is the block hash at `rx_seed_height(height)` — the
chain's own history keys the hash function. This forces every
participant to rebuild the dataset on every epoch boundary (2048
blocks) with a 64-block lag, preventing pre-computed-table attacks.

### Seed rotation

The RandomX cache / dataset is keyed on a seed that advances every
2,048 blocks, with a 64-block lag so nodes converge on the new seed
before it takes effect. The miner rebuilds the dataset (~1.5 s on a
fast CPU) when the seed changes — visible in the `randomx  cache
seed=…` log line.

### Why CPU-only in practice

- **Generated code.** Each hash runs a fresh 256-instruction program.
  A fixed-function pipeline cannot run arbitrary programs; a
  competitive implementation needs a general-purpose decode/issue
  stage — i.e. a CPU.
- **Memory-bandwidth bound.** DRAM transactions per outer iteration
  cap throughput at the chip's DRAM pin rate. An ASIC gets no edge
  over a commodity CPU on that bottleneck.
- **Float determinism.** RandomX includes IEEE-754 double-precision
  arithmetic with deterministic rounding modes. An ASIC without a
  full FPU cannot run the algorithm.

Monero has shipped RandomX since November 2019 with no ASIC reaching
market. FlowCoin inherits that track record.

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
- **0 H/s for more than 10 seconds** — the 2 GiB dataset is still
  initialising. On very slow machines this can take 5–10 s. If it
  stays at 0 forever, switch to `--light` (256 MiB cache, init in
  ~40 ms).
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

# FlowCoin Mining Guide

## Quick Start

```bash
# Build the miner
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc) flowcoin-miner

# Run miner (auto-detects GPU)
./flowcoin-miner
```

## Overview

FlowCoin uses Keccak-256d Proof-of-Work, where miners search for a nonce
such that the double Keccak-256 hash of the block header falls below the
difficulty target. The miner (`flowminer`) is a standalone native C++
binary with an ncurses TUI for real-time feedback. It connects to a
running `flowcoind` via JSON-RPC.

Each block includes:
- A block header with a nonce that satisfies the PoW target
- Transactions from the mempool
- A coinbase transaction paying the block reward to the miner

Mining uses GPU acceleration via OpenCL. The full Keccak-f[1600]
permutation is implemented in a single OpenCL kernel for maximum
throughput.

## GPU Support

The miner uses OpenCL for cross-platform GPU mining:

| GPU Vendor | Support |
|------------|---------|
| NVIDIA (GTX/RTX/Tesla) | OpenCL via NVIDIA drivers |
| AMD (RX/Radeon/Instinct) | OpenCL via ROCm or AMDGPU-PRO |
| Intel (Arc/UHD) | OpenCL via Intel compute runtime |
| Apple (M1/M2/M3/M4) | OpenCL via Apple frameworks |
| CPU fallback | Always available |

The miner auto-detects the best available OpenCL device. Use `--cpu` to
force CPU-only operation.

## Hardware Requirements

### Minimum (testnet / early mainnet)

| Component | Requirement |
|---|---|
| CPU | 4 cores |
| RAM | 4 GB |
| Storage | 20 GB SSD |
| Network | Stable internet connection |
| GPU | Optional (CPU-only works) |

### Recommended (competitive mainnet mining)

| Component | Requirement |
|---|---|
| GPU | NVIDIA RTX 3080 or better (10GB+ VRAM) |
| CPU | 8+ cores |
| RAM | 16 GB |
| Storage | 100 GB NVMe SSD |
| Network | Low-latency broadband |

## Software Setup

### 1. Build the miner

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make flowcoin-miner -j$(nproc)
```

### 2. Start the FlowCoin node

```bash
./flowcoind --datadir=$HOME/.flowcoin
```

Wait for the node to sync to the tip of the chain before mining.

### 3. Configure RPC credentials

Add credentials to `~/.flowcoin/flowcoin.conf`:

```
rpcuser=your_username
rpcpassword=your_password
```

The miner reads this file automatically.

## Running the Miner

### Basic usage (zero arguments required)

```bash
flowcoin-miner
```

The miner will:
1. Read RPC credentials from `~/.flowcoin/flowcoin.conf`
2. Connect to flowcoind at `127.0.0.1:9334`
3. Request a block template
4. Begin hashing with Keccak-256d on the GPU

### Command-line options

| Option | Default | Description |
|---|---|---|
| `--datadir <path>` | `~/.flowcoin` | Data directory |
| `--rpcport <port>` | `9334` | Node RPC port |
| `--rpcuser <user>` | from config | RPC username |
| `--rpcpassword <pw>` | from config | RPC password |
| `--cpu` | | Force CPU backend (no GPU) |
| `--device <id>` | `0` | OpenCL device index |
| `--help` | | Show help message |

### Examples

```bash
# Default -- reads config from ~/.flowcoin
flowcoin-miner

# Custom RPC credentials
flowcoin-miner --rpcuser flowcoin --rpcpassword pass123

# Force CPU backend
flowcoin-miner --cpu

# Custom data directory
flowcoin-miner --datadir /mnt/data/flowcoin

# Select specific GPU
flowcoin-miner --device 1
```

### Miner TUI output

The miner provides real-time feedback via an ncurses TUI:

```
  FlowCoin Miner v1.0.0
  Keccak-256d PoW | OpenCL

  Device: NVIDIA GeForce RTX 5080
  Hashrate: 752.3 MH/s
  Difficulty: 1.000000
  Height: 42
  Uptime: 00:12:34

  [00:12:34] nonce=0x1A3F7B2C  hashrate=752.3 MH/s  blocks=0

  +----------------------------------------------+
  |              BLOCK FOUND!                    |
  |  Height:   43                                |
  |  Hash:     00001a3f7b2c4e89...               |
  |  Reward:   50.00000000 FLC                   |
  +----------------------------------------------+
```

## How Mining Works

### Keccak-256d Proof-of-Work

The miner searches for a nonce such that:

```
Keccak-256d(block_header) < target
```

Where `Keccak-256d(x) = Keccak-256(Keccak-256(x))` using the Keccak
padding byte 0x01 (Ethereum-style, not NIST SHA-3 0x06 padding).

Each nonce attempt produces a completely different hash. The miner
runs millions of nonce attempts per second on the GPU, each computing
the full Keccak-f[1600] permutation twice.

### OpenCL Kernel

The GPU kernel implements the complete 24-round Keccak-f[1600]
permutation. Each GPU work item processes a unique nonce:

1. Copy the block header template into local memory
2. Insert the work item's nonce into the header
3. Compute Keccak-256 (first pass)
4. Compute Keccak-256 of the result (second pass)
5. Compare against the target
6. If below target, report the winning nonce

## Block Reward Schedule

FlowCoin uses the same halving schedule as Bitcoin:

| Era | Block Range | Reward per Block |
|---|---|---|
| 0 | 0 -- 209,999 | 50 FLC |
| 1 | 210,000 -- 419,999 | 25 FLC |
| 2 | 420,000 -- 629,999 | 12.5 FLC |
| 3 | 630,000 -- 839,999 | 6.25 FLC |
| ... | ... | halves every 210,000 blocks |

Total supply converges to 21,000,000 FLC.

At 10-minute block intervals, each halving period lasts approximately 4 years.
Coinbase outputs require 100 confirmations (COINBASE_MATURITY) before
they can be spent.

## Difficulty Adjustment

Difficulty adjusts every 2,016 blocks (approximately 2 weeks at 10-minute
blocks), using Bitcoin's exact retarget algorithm:

1. Compute `actual_timespan` = timestamp of block 2015 - timestamp of block 0
   in the current retarget period
2. Clamp to `[RETARGET_TIMESPAN/4, RETARGET_TIMESPAN*4]` (between 3.5 days
   and 8 weeks)
3. `new_target = old_target * actual_timespan / RETARGET_TIMESPAN`
4. Clamp to powLimit if exceeded

If blocks are mined faster than 10 minutes, difficulty increases.
If slower, difficulty decreases.

Initial difficulty is very easy (nbits = 0x1f00ffff, approximately 2^226
target), allowing early miners to find blocks with minimal hardware.

## Mining Strategy Tips

### Hardware optimization

- Use a modern GPU with OpenCL support for maximum hashrate
- Use NVMe storage for fast block data access
- Keep the node and miner on the same machine to minimize RPC latency

### Timing your submissions

- The miner checks for new blocks every 5 seconds
- If a new block arrives from another miner, the miner immediately
  requests a fresh block template and restarts hashing
- Submitting stale blocks (wrong prev_hash) wastes hash effort

## Troubleshooting

### "Block rejected: high-hash"

The block hash did not meet the difficulty target. This is normal --
keep mining. The miner will automatically retry with a new nonce range.

### No OpenCL devices found

Ensure your GPU drivers include OpenCL support:
- NVIDIA: install the proprietary driver (nvidia-driver-xxx)
- AMD: install ROCm or AMDGPU-PRO
- Intel: install the Intel compute runtime

### Cannot connect to flowcoind

- Verify `flowcoind` is running
- Check RPC credentials in `~/.flowcoin/flowcoin.conf`
- Ensure the node has synced past IBD (initial block download)
- Check `debug.log` for error messages

### Low hashrate

- Verify the GPU is being used: check the TUI device line
- Ensure no other GPU-intensive programs are running
- Try a different `--device` index if multiple GPUs are installed

## Monitoring

### Via RPC

```bash
# Current mining status
flowcoin-cli getmininginfo

# Difficulty progress
flowcoin-cli getdifficulty

# Wallet balance (including mining rewards)
flowcoin-cli getbalance
```

## Pool Mining

FlowCoin does not natively support pool mining in the initial release.
Future protocol updates may introduce stratum-compatible pool support.

## Security Considerations

- Keep your `wallet.dat` backed up and encrypted
- Use unique RPC credentials (not the defaults)
- Do not expose the RPC port to the public internet
- The miner generates a new address for each mined block automatically
- Monitor for unusual difficulty adjustments that might indicate an attack

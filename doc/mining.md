# FlowCoin Mining Guide

## Quick Start

```bash
# Build miner (CPU only)
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc) flowcoin-miner

# Build with CUDA (NVIDIA GPUs)
cmake .. -DCMAKE_BUILD_TYPE=Release -DFLOWCOIN_USE_CUDA=ON
make -j$(nproc) flowcoin-miner

# Build with Vulkan (AMD, Intel, any GPU)
cmake .. -DCMAKE_BUILD_TYPE=Release -DFLOWCOIN_USE_VULKAN=ON
make -j$(nproc) flowcoin-miner

# Place training data
mkdir -p ~/.flowcoin/training
cp *.txt ~/.flowcoin/training/

# Run miner (auto-detects GPU)
./flowcoin-miner
```

## Overview

FlowCoin replaces traditional hash-based proof of work with Proof-of-Useful-
Training. Instead of computing trillions of meaningless hashes, miners train
a neural network (ResonanceNet V5) on real data. The training results --
weight updates (deltas) -- are submitted as proof of work, and the network
collectively builds a progressively more capable AI model.

The miner is a standalone native C++ binary. No Python, no PyTorch, no
external ML frameworks. It connects to a running `flowcoind` via JSON-RPC.

Each block includes:
- A compressed delta (model weight update from training)
- A validation loss (measured by evaluating the updated model)
- A training hash that must be below the difficulty target

## GPU Support

| Backend | GPUs | Build Flag |
|---------|------|------------|
| CUDA | NVIDIA (GTX/RTX/Tesla) | `-DFLOWCOIN_USE_CUDA=ON` |
| Vulkan | AMD, Intel, NVIDIA | `-DFLOWCOIN_USE_VULKAN=ON` |
| Metal | Apple (M1/M2/M3/M4) | Auto-enabled on macOS |
| OpenCL | AMD, Intel, ARM, any | `-DFLOWCOIN_USE_OPENCL=ON` |
| CPU | Any | Always available (default) |

The miner auto-detects the best available backend. Use `--backend cpu` to
force CPU-only operation.

## Hardware Requirements

### Minimum (testnet / early mainnet)

| Component | Requirement |
|---|---|
| CPU | 4 cores |
| RAM | 8 GB |
| Storage | 20 GB SSD |
| Network | Stable internet connection |
| GPU | Optional (CPU-only works) |

### Recommended (competitive mainnet mining)

| Component | Requirement |
|---|---|
| GPU | NVIDIA RTX 3080 or better (10GB+ VRAM) |
| CPU | 8+ cores |
| RAM | 32 GB |
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

### 3. Prepare training data

Place `.txt` or `.bin` files in the training directory:

```bash
mkdir -p ~/.flowcoin/training
cp *.txt ~/.flowcoin/training/
```

The miner reads all files from `<datadir>/training/` automatically.
No path argument is needed.

### 4. Configure RPC credentials

Add credentials to `~/.flowcoin/flowcoin.conf`:

```
rpcuser=your_username
rpcpassword=your_password
```

The miner reads this file automatically.

## Dataset Preparation

The miner needs training data to perform useful training. The data must be
in a format compatible with the ResonanceNet V5 byte-level tokenizer.

### Supported formats

- Raw text files (`.txt`)
- Pre-tokenized binary files (`.bin`)
- Any binary data (each byte is a token, vocabulary size = 256)

### Dataset size recommendations

| Chain Height | Minimum Dataset | Recommended |
|---|---|---|
| 0-511 (dimension growth) | 10 MB | 100 MB+ |
| 512+ (slot growth) | 100 MB | 1 GB+ |

Larger datasets produce lower validation loss and more competitive blocks.

## Running the Miner

### Basic usage (zero arguments required)

```bash
flowcoin-miner
```

The miner will:
1. Read RPC credentials from `~/.flowcoin/flowcoin.conf`
2. Load training data from `~/.flowcoin/training/`
3. Connect to flowcoind at `127.0.0.1:9334`
4. Begin training and mining

### Command-line options

| Option | Default | Description |
|---|---|---|
| `--datadir <path>` | `~/.flowcoin` | Data directory |
| `--rpcport <port>` | `9334` | Node RPC port |
| `--rpcuser <user>` | from config | RPC username |
| `--rpcpassword <pw>` | from config | RPC password |
| `--backend <name>` | `auto` | Compute backend (auto/cpu/cuda/vulkan/metal/opencl) |
| `--cpu` | | Force CPU backend |
| `--lr <float>` | `0.001` | Learning rate |
| `--seq-len <int>` | `256` | Sequence length |
| `--help` | | Show help message |

### Examples

```bash
# Default -- reads config and data from ~/.flowcoin
flowcoin-miner

# Custom RPC credentials
flowcoin-miner --rpcuser flowcoin --rpcpassword pass123

# Force CPU backend
flowcoin-miner --cpu

# Custom data directory
flowcoin-miner --datadir /mnt/data/flowcoin
```

### Miner output

The miner provides real-time feedback at every step:

```
  FlowCoin Miner v1.0.0
  Native C++ | ResonanceNet V5

[1/5] Loading miner identity...
  Generated new miner key: a3f17b2c4e891234...
[2/5] Loading training data...
  Loaded 12 files, 156000000 bytes (148.8 MB)
  Dataset hash: a3f17b2c4e891234
[3/5] Initializing compute backend...
  Backend: CPU
  Device: AMD Ryzen 9 7950X 16-Core Processor
[4/5] Connecting to node at 127.0.0.1:9334...
  Connected. Chain height: 42
[5/5] Initializing ResonanceNet V5 model...
  Model: d=554, L=9, ff=1108, slots=1196
  Parameters: 8.2M (32920768 bytes)

  Ready to mine.

  Mining started. Press Ctrl+C to stop.

  [00:01:23] step=100  loss=4.8321  best=4.6142  grad=1.23e-03  speed=85.2 st/s  lz=3  blocks=0

  ╔══════════════════════════════════════════════╗
  ║              BLOCK FOUND!                    ║
  ╠══════════════════════════════════════════════╣
  ║  Height:   43                                ║
  ║  Loss:     3.452100                          ║
  ║  Hash:     00001a3f7b2c4e89...               ║
  ╚══════════════════════════════════════════════╝
```

## Understanding Training Metrics

### Validation loss

The validation loss measures how well the model predicts unseen data.
Lower is better. The genesis model starts at approximately 5.0 (byte-level
random baseline is ln(256) = 5.545).

Key rules:
- `val_loss` must be finite and positive
- `val_loss` must not exceed `MAX_VAL_LOSS` (100.0)
- `val_loss` must not exceed `MAX_LOSS_INCREASE * parent.val_loss` (2x)

### Training steps

There is no minimum training step requirement. Difficulty itself regulates
mining, just like Bitcoin has no "min nonce attempts". Each training step
changes the weight delta, which changes the training hash, producing a
new lottery ticket. An empty delta yields a single fixed hash with almost
zero chance of meeting the target.

### SPSA Training

The miner uses Simultaneous Perturbation Stochastic Approximation (SPSA)
for gradient estimation. This method requires only 2 forward passes per
training step (no backward pass needed), making it efficient for any
compute backend:

1. Generate random direction d (Rademacher +/-1 for each parameter)
2. Compute loss at weights + c*d (forward pass 1)
3. Compute loss at weights - c*d (forward pass 2)
4. Gradient estimate: (loss_plus - loss_minus) / (2*c) * d
5. Update: weights -= lr * gradient

This gives approximately 50-100 training steps per second on modern
hardware for the genesis model size.

### Stagnation counter

The stagnation counter tracks consecutive blocks where validation loss
did not improve. If a miner's block does not decrease `val_loss` relative
to the parent, the stagnation counter increments. This metric is visible
on the network and signals when the model needs fresh training approaches.

## Block Reward Schedule

FlowCoin uses the same halving schedule as Bitcoin:

| Era | Block Range | Reward per Block |
|---|---|---|
| 0 | 0 -- 209,999 | 50 FLOW |
| 1 | 210,000 -- 419,999 | 25 FLOW |
| 2 | 420,000 -- 629,999 | 12.5 FLOW |
| 3 | 630,000 -- 839,999 | 6.25 FLOW |
| ... | ... | halves every 210,000 blocks |

Total supply converges to 21,000,000 FLOW.

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

## Model Growth

The model grows CONTINUOUSLY -- every block adds parameters. There are no
phases, no plateaus, and no cap on slots.

### Dimension Growth (blocks 0-511)

Dimensions grow linearly with height:

| Height | d_model | n_layers | d_ff  | n_heads | n_slots |
|--------|---------|----------|-------|---------|---------|
| 0      | 512     | 8        | 1,024 | 8       | 1,024   |
| 100    | 612     | 11       | 1,224 | 9       | 1,424   |
| 256    | 768     | 16       | 1,536 | 12      | 2,048   |
| 512    | 1,024   | 24       | 2,048 | 16      | 3,072   |

At each block, existing model weights are expanded via zero-padding and
copying. Miners must use the correct architecture for their block height.

### Frozen Dimensions, Infinite Slot Growth (blocks 512+)

After block 511, the core architecture dimensions are frozen at their
maximum (d=1024, L=24). Only slots continue to grow -- by 4 per block,
with NO cap:

| Height    | n_slots   | ~Total Params |
|-----------|-----------|---------------|
| 1,000     | 5,024     | growing       |
| 10,000    | 41,024    | ~3B           |
| 100,000   | 401,024   | ~30B          |
| 1,000,000 | 4,001,024 | ~300B         |

Inference remains O(1) because only top_k=2 slots are active per token.

## Mining Strategy Tips

### Choosing a learning rate

- Start with `0.001` (the default)
- Lower rates (0.0001) are safer but slower to converge
- Higher rates (0.01) converge faster but risk overshooting

### Dataset quality matters

- Diverse, high-quality text data produces lower validation loss
- Avoid highly repetitive data (the model will overfit)
- Mix different domains: prose, code, technical writing

### Timing your submissions

- The miner checks for new blocks every 5 seconds
- If a new block arrives from another miner, training restarts
  immediately with the updated model state
- Submitting stale blocks (wrong prev_hash) wastes training effort

### Hardware optimization

- Build with GPU support for faster training (CUDA recommended)
- Use NVMe storage for fast dataset loading
- Keep the node and miner on the same machine to minimize RPC latency

## Troubleshooting

### "Block rejected: high-hash"

The training hash did not meet the difficulty target. This is normal --
keep mining. The miner will automatically retry with different training
states.

### "Block rejected: bad-growth"

The model dimensions do not match the expected architecture for this
block height. Ensure your miner is using the latest block template and
the correct growth schedule.

### "Block rejected: loss-regression"

The validation loss increased by more than the allowed factor (2x) relative
to the parent block. The model update may be destructive. Try using a
lower learning rate.

### No training data found

Ensure you have placed `.txt` or `.bin` files in `~/.flowcoin/training/`.
The miner creates the directory if it does not exist, but you must supply
the data files.

### Cannot connect to flowcoind

- Verify `flowcoind` is running
- Check RPC credentials in `~/.flowcoin/flowcoin.conf`
- Ensure the node has synced past IBD (initial block download)
- Check `debug.log` for error messages

### Slow training speed

- Build with CUDA support: `cmake .. -DFLOWCOIN_USE_CUDA=ON`
- Check GPU utilization with `nvidia-smi`
- Ensure training dataset is on fast storage (SSD/NVMe)

## Monitoring

### Via RPC

```bash
# Current mining status
flowcoin-cli getmininginfo

# Model training state
flowcoin-cli gettraininginfo

# Difficulty progress
flowcoin-cli getdifficulty

# Wallet balance (including mining rewards)
flowcoin-cli getbalance
```

### Block explorer

Each block header exposes these training metrics:

- `val_loss` -- achieved validation loss
- `stagnation` -- consecutive non-improving blocks
- `d_model`, `n_layers` -- current model architecture
- `delta_length` -- compressed delta payload size

These metrics let you track the network's collective training progress
over time.

## Pool Mining

FlowCoin does not natively support pool mining in the initial release.
The PoUT consensus mechanism requires each miner to perform full model
training, which makes work splitting non-trivial.

Future protocol updates may introduce mechanisms for collaborative
training and reward sharing.

## Security Considerations

- Keep your `wallet.dat` backed up and encrypted
- Use unique RPC credentials (not the defaults)
- Do not expose the RPC port to the public internet
- The miner generates a new keypair for each session automatically
- Monitor for unusual difficulty adjustments that might indicate an attack

# FlowCoin Mining Guide

This guide covers everything you need to know to mine FlowCoin using the
Proof-of-Useful-Training (PoUT) consensus mechanism.

## Overview

FlowCoin replaces traditional hash-based proof of work with Proof-of-Useful-
Training. Instead of computing trillions of meaningless hashes, miners train
a neural network (ResonanceNet V5) on real data. The training results --
weight updates (deltas) -- are submitted as proof of work, and the network
collectively builds a progressively more capable AI model.

Each block includes:
- A compressed delta (model weight update from training)
- A validation loss (measured by evaluating the updated model)
- A training hash that must be below the difficulty target

## Hardware Requirements

### Minimum (testnet / early mainnet)

| Component | Requirement |
|---|---|
| GPU | NVIDIA GPU with 4GB+ VRAM (GTX 1060 or better) |
| CPU | 4 cores |
| RAM | 8 GB |
| Storage | 20 GB SSD |
| Network | Stable internet connection |

### Recommended (competitive mainnet mining)

| Component | Requirement |
|---|---|
| GPU | NVIDIA RTX 3080 or better (10GB+ VRAM) |
| CPU | 8+ cores |
| RAM | 32 GB |
| Storage | 100 GB NVMe SSD |
| Network | Low-latency broadband |

### GPU Compatibility

The miner uses PyTorch and supports any GPU that PyTorch supports:

| GPU Family | Support | Notes |
|---|---|---|
| NVIDIA (CUDA) | Full | Recommended. Best performance. |
| AMD (ROCm) | Partial | Requires PyTorch ROCm build. |
| Apple Silicon (MPS) | Experimental | Slower than CUDA. |
| CPU-only | Yes | Very slow. For testing only. |

To check GPU availability:
```python
import torch
print(torch.cuda.is_available())
print(torch.cuda.get_device_name(0))
```

## Software Setup

### 1. Install Python dependencies

```bash
pip install torch zstandard pycryptodome
```

For CUDA-specific PyTorch installation:
```bash
pip install torch --index-url https://download.pytorch.org/whl/cu121
```

### 2. Start the FlowCoin node

```bash
./flowcoind --datadir=$HOME/.flowcoin
```

Wait for the node to sync to the tip of the chain before mining.

### 3. Get a mining address

```bash
./flowcoin-cli getnewaddress
```

Save the returned address. Coinbase rewards will be sent here.
A new address is automatically generated for each mined block to improve
privacy and UTXO management.

## Dataset Preparation

The miner needs training data to perform useful training. The data must be
in a format compatible with the ResonanceNet V5 byte-level tokenizer.

### Supported formats

- Raw text files (`.txt`)
- Concatenated text files in a directory
- Pre-tokenized binary files (byte sequences)

### Preparing a dataset

1. Collect text data (books, code, articles, etc.)
2. Place all `.txt` files in a single directory
3. The miner will read all files, concatenate them, and use byte-level
   tokenization (each byte is a token, vocabulary size = 256)

```bash
mkdir ~/training-data
cp *.txt ~/training-data/
```

### Dataset size recommendations

| Chain Phase | Minimum Dataset | Recommended |
|---|---|---|
| Phase 1 (blocks 0-499) | 10 MB | 100 MB+ |
| Phase 2 (blocks 500+) | 100 MB | 1 GB+ |

Larger datasets produce lower validation loss and more competitive blocks.

## Running the Miner

### Basic usage

```bash
python3 tools/flowminer.py \
    --dataset ~/training-data/ \
    --node http://127.0.0.1:9334 \
    --rpcuser your_username \
    --rpcpassword your_password
```

### Command-line options

| Option | Default | Description |
|---|---|---|
| `--dataset` | required | Path to training data directory |
| `--node` | `http://127.0.0.1:9334` | RPC endpoint of the node |
| `--rpcuser` | flowcoin | RPC username |
| `--rpcpassword` | flowcoin | RPC password |
| `--device` | cuda (if available) | Training device (cuda/cpu/mps) |
| `--batch-size` | 64 | Training batch size |
| `--lr` | 0.0003 | Learning rate |
| `--steps` | 0 (auto) | Training steps per block (0=auto) |

### Miner output

The miner provides real-time feedback at every step:

```
[2026-03-21 12:00:00] Requesting block template (height 42)...
[2026-03-21 12:00:00] Target: 00ffff...  Difficulty: 1.000
[2026-03-21 12:00:00] Architecture: d_model=512 n_layers=8 d_ff=1024
[2026-03-21 12:00:00] Min training steps: 1168
[2026-03-21 12:00:01] Loading dataset from ~/training-data/ (156 MB)
[2026-03-21 12:00:02] Step    100/2000  loss=4.8321  lr=0.000300
[2026-03-21 12:00:03] Step    200/2000  loss=4.6142  lr=0.000300
...
[2026-03-21 12:00:15] Step   2000/2000  loss=3.2105  lr=0.000300
[2026-03-21 12:00:15] Validation loss: 3.4521
[2026-03-21 12:00:16] Computing delta (1,234,567 non-zero / 8,000,000 total)
[2026-03-21 12:00:16] Delta compressed: 4.2 MB -> 1.1 MB (74% reduction)
[2026-03-21 12:00:16] Block hash: a3f1...7b2c
[2026-03-21 12:00:16] Hash meets target! Submitting block...
[2026-03-21 12:00:17] Block accepted at height 42! Reward: 50.00000000 FLOW
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

Each block must include at least `compute_min_steps(height)` training
iterations:

| Height Range | Min Steps | Formula |
|---|---|---|
| 0 | 1,000 | `1000 + 4 * height` |
| 100 | 1,400 | `1000 + 4 * height` |
| 499 | 2,996 | `1000 + 4 * height` |
| 500 | 3,000 | `3000 * sqrt(height / 500)` |
| 2,000 | 6,000 | `3000 * sqrt(height / 500)` |
| 8,000 | 12,000 | `3000 * sqrt(height / 500)` |

More training steps generally produce lower validation loss and a better
chance of meeting the difficulty target.

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

## Model Growth Phases

### Phase 1: Staircase Growth (blocks 0-499)

The model architecture grows through 5 plateaus of 100 blocks each:

| Plateau | Blocks | d_model | n_layers | d_ff | n_heads |
|---|---|---|---|---|---|
| 0 | 0--99 | 512 | 8 | 1,024 | 8 |
| 1 | 100--199 | 640 | 12 | 1,280 | 10 |
| 2 | 200--299 | 768 | 16 | 1,536 | 12 |
| 3 | 300--399 | 896 | 20 | 1,792 | 14 |
| 4 | 400--499 | 1,024 | 24 | 2,048 | 16 |

At each plateau transition, the existing model weights are expanded via
zero-padding and copying. Miners must use the correct architecture for
their block height.

### Phase 2: Frozen Architecture (blocks 500+)

After block 499, the core architecture is frozen at maximum dimensions.
Only the slot memory (`n_slots`) continues to grow, increasing by 4 slots
for each block that improves validation loss, up to a maximum of 65,536.

## Mining Strategy Tips

### Choosing a learning rate

- Start with `0.0003` (the default)
- Lower rates (0.0001) are safer but slower to converge
- Higher rates (0.001) converge faster but risk overshooting
- The maximum allowed learning rate is 0.0001 (consensus rule)

### Dataset quality matters

- Diverse, high-quality text data produces lower validation loss
- Avoid highly repetitive data (the model will overfit)
- Mix different domains: prose, code, technical writing

### Timing your submissions

- Request a fresh block template frequently (the tip may change)
- If you detect a new block from another miner, restart training
  immediately with the updated model state
- Submitting stale blocks (wrong prev_hash) wastes training effort

### Hardware optimization

- Use the largest batch size that fits in GPU VRAM
- Enable mixed-precision training (FP16) for 2x speedup on supported GPUs
- Use NVMe storage for fast dataset loading
- Keep the node and miner on the same machine to minimize RPC latency

## Troubleshooting

### "Block rejected: high-hash"

The training hash did not meet the difficulty target. This is normal --
keep mining. The miner will automatically retry with different nonces.

### "Block rejected: bad-growth"

The model dimensions do not match the expected architecture for this
block height. Ensure your miner is using the latest block template and
the correct growth schedule.

### "Block rejected: insufficient-training"

The block did not include enough training steps. Increase the `--steps`
parameter or let the auto-tuning choose the right count.

### "Block rejected: loss-regression"

The validation loss increased by more than the allowed factor (2x) relative
to the parent block. The model update may be destructive. Try using a
lower learning rate.

### "CUDA out of memory"

Reduce `--batch-size` or use a GPU with more VRAM. During Phase 2 with
maximum dimensions, the model requires approximately 500 MB of VRAM at
batch size 64.

### Miner produces no output

Ensure `--dataset` points to a directory containing readable `.txt` files.
The miner loads the entire dataset into memory before training begins.

### Slow training speed

- Verify PyTorch is using the GPU: `torch.cuda.is_available()` should be True
- Check that CUDA drivers are up to date
- Use `nvidia-smi` to monitor GPU utilization during mining

### Node not responding

- Verify `flowcoind` is running
- Check RPC credentials match between miner and node
- Ensure the node has synced past IBD (initial block download)
- Check `debug.log` for error messages

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
- `train_steps` -- training iterations performed
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
- Generate a new address for each mining session for privacy
- Monitor for unusual difficulty adjustments that might indicate an attack

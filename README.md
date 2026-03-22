# FlowCoin — Proof-of-Training Blockchain

A blockchain where mining trains a neural network. Every block makes the model smarter.

**Whitepaper:** [flowcoin.org/flowcoin-whitepaper.pdf](https://flowcoin.org/flowcoin-whitepaper.pdf)

## Quick Start

### 1. Build the node

```bash
git clone https://github.com/haruki-tanaka-tech/flowcoin.git
cd flowcoin
git submodule update --init --recursive
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### 2. Run the node

```bash
./build/tools/flowcoind
```

The node automatically:
- Creates `~/.flowcoin/wallet.dat` on first run
- Connects to seed nodes
- Syncs the blockchain from peers
- Listens on port 9333 (P2P) and 9334 (RPC)

### 3. Mine (train the AI model)

Install PyTorch:
```bash
pip install torch
```

Download training data:
```bash
# Option A: Use any text file
curl -o ~/.flowcoin/training_data.bin https://www.gutenberg.org/cache/epub/1342/pg1342.txt

# Option B: Use code
find /usr/include -name "*.h" | head -100 | xargs cat > ~/.flowcoin/training_data.bin

# Option C: Download a dataset
curl -o ~/.flowcoin/training_data.bin https://raw.githubusercontent.com/karpathy/char-rnn/master/data/tinyshakespeare/input.txt
```

Start mining:
```bash
python3 tools/flowminer.py
```

The miner:
- Trains a neural network on your GPU (CUDA/ROCm/MPS) or CPU
- Each training step produces weight deltas → hash checked against difficulty
- When hash < target → block submitted to node → 50 FLOW reward
- New wallet address for every mined block

### 4. Check status

```bash
./build/tools/flowcoin-cli getblockcount        # Chain height
./build/tools/flowcoin-cli getbalance            # Your balance
./build/tools/flowcoin-cli gettraininginfo       # Model status
./build/tools/flowcoin-cli getnetworkinfo        # Network info
./build/tools/flowcoin-cli getpeerinfo           # Connected peers
./build/tools/flowcoin-cli listunspent           # Your UTXOs
./build/tools/flowcoin-cli getnewaddress         # New receive address
./build/tools/flowcoin-cli sendtoaddress <addr> <amount>  # Send FLOW
```

## Architecture

```
flowcoind      C++     Node: consensus, P2P, RPC, wallet, chain (SQLite)
flowcoin-cli   C++     RPC client
flowminer.py   Python  PyTorch GPU training → submits blocks via RPC
```

### Proof-of-Training

Instead of computing useless SHA-256 hashes (Bitcoin), miners train a neural network:

1. Miner trains model on data → produces weight deltas
2. `H = Keccak256(delta_hash || dataset_hash)`
3. If `H < difficulty_target` → valid block (same math as Bitcoin)
4. Every node verifies by replaying the forward pass
5. Model improves with every block — forever

### Consensus Parameters

| Parameter | Value |
|-----------|-------|
| Block time | ~10 minutes |
| Initial reward | 50 FLOW |
| Halving | Every 210,000 blocks |
| Max supply | 21,000,000 FLOW |
| Difficulty retarget | Every 2,016 blocks |
| P2P port | 9333 |
| RPC port | 9334 |
| Address prefix | fl1... |
| Hash function | Keccak-256 (pad=0x01) |
| Signatures | Ed25519 |
| HD derivation | SLIP-0010 |

### Cryptographic Foundations

- **Keccak-256d** (double Keccak-256, pad=0x01, NOT SHA-3) for block hashing
- **Keccak-256** for training hash: `H = Keccak256(D || V)`
- **Ed25519** signatures (ed25519-donna)
- **SLIP-0010** HD key derivation
- **Bech32m** addresses with `fl` prefix

## Mining with Different Data

Miners choose their own training data. The model learns from everything:

```bash
# English literature
curl -o ~/.flowcoin/training_data.bin https://www.gutenberg.org/cache/epub/1342/pg1342.txt

# Python code
find /usr -name "*.py" | head -200 | xargs cat > ~/.flowcoin/training_data.bin

# Wikipedia (download first)
cat wiki_dump.txt > ~/.flowcoin/training_data.bin

# Multiple sources combined
cat book1.txt book2.txt code.py > ~/.flowcoin/training_data.bin
```

The model accumulates knowledge from all miners across the network.

## GPU Support

The miner automatically detects your GPU:

| GPU | Backend | Status |
|-----|---------|--------|
| NVIDIA (RTX 30/40/50 series) | CUDA | Supported |
| AMD (RX 6000/7000/9000) | ROCm | Supported |
| Apple (M1/M2/M3/M4) | MPS | Supported |
| CPU | PyTorch CPU | Fallback |

Install PyTorch for your platform: [pytorch.org/get-started](https://pytorch.org/get-started/locally/)

## Network

Seed nodes:
- `seed.flowcoin.org:9333`
- `211.205.13.203:9333`

Nodes discover each other automatically through addr propagation.

## Wallet

Your wallet is stored at `~/.flowcoin/wallet.dat`. Back it up:

```bash
cp ~/.flowcoin/wallet.dat /safe/location/
cp ~/.flowcoin/wallet_seed /safe/location/  # Master seed — most important!
```

The `wallet_seed` file contains your HD master seed. From it, all keys can be regenerated. **Keep it safe.**

## License

MIT License. Copyright (c) 2026 Haruki Tanaka.

## Links

- Website: [flowcoin.org](https://flowcoin.org)
- Whitepaper: [flowcoin.org/flowcoin-whitepaper.pdf](https://flowcoin.org/flowcoin-whitepaper.pdf)
- Source: [github.com/haruki-tanaka-tech/flowcoin](https://github.com/haruki-tanaka-tech/flowcoin)

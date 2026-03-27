# FlowCoin

**Keccak-256d Proof-of-Work cryptocurrency — built from scratch, not a fork.**

182,000 lines of original code. The first blockchain using double Keccak-256 for mining.

## Why Keccak-256d?

Keccak (SHA-3) is the newest NIST hash standard. Its 1600-bit internal state with 24 rounds of full permutation makes ASIC manufacturing impractical — the bottleneck is memory bandwidth, not logic gates. An ASIC would need the same wide memory bus as a GPU, eliminating any advantage.

Bitcoin today: 6 mining pools control 95% of hashrate. FlowCoin: one GPU = one vote.

## Quick Start

```bash
# Start node
./flowcoind

# Start GPU miner (in another terminal)
./flowcoin-miner

# Check balance
./flowcoin-cli getbalance

# Send coins
./flowcoin-cli sendtoaddress fl1q... 10.0
```

## Download

**[Latest Release](https://github.com/haruki-tanaka-tech/flowcoin/releases/tag/v0.1.0)**

| Platform | Node | GPU Miner |
|----------|------|-----------|
| Linux x86_64 | [flowcoin-v0.1.0-linux-x86_64.tar.gz](https://github.com/haruki-tanaka-tech/flowcoin/releases/download/v0.1.0/flowcoin-v0.1.0-linux-x86_64.tar.gz) | [flowcoin-miner-v0.1.0-linux-x86_64.tar.gz](https://github.com/haruki-tanaka-tech/flowcoin/releases/download/v0.1.0/flowcoin-miner-v0.1.0-linux-x86_64.tar.gz) |
| Windows x64 | [flowcoin-windows-x64.zip](https://github.com/haruki-tanaka-tech/flowcoin/releases/download/v0.1.0/flowcoin-windows-x64.zip) | [flowcoin-miner-v0.1.0-windows-x64.zip](https://github.com/haruki-tanaka-tech/flowcoin/releases/download/v0.1.0/flowcoin-miner-v0.1.0-windows-x64.zip) |
| macOS arm64 | [flowcoin-v0.1.0-macos-arm64.tar.gz](https://github.com/haruki-tanaka-tech/flowcoin/releases/download/v0.1.0/flowcoin-v0.1.0-macos-arm64.tar.gz) | Build from source |

## Specifications

| Parameter | Value |
|-----------|-------|
| Algorithm | Keccak-256d (double Keccak-256, pad 0x01) |
| Block time | 10 minutes |
| Block reward | 50 FLOW (halving every 210,000 blocks) |
| Max supply | 21,000,000 FLOW |
| Difficulty retarget | Every 2,016 blocks |
| Signatures | Ed25519 (RFC 8032) |
| Address format | Bech32m (`fl1q...`) |
| P2P port | 9333 |
| RPC port | 9334 |
| Consensus | Pure Proof-of-Work |

## Build from Source

```bash
git clone https://github.com/haruki-tanaka-tech/flowcoin.git
cd flowcoin

# Node (flowcoind, flowcoin-cli, flowcoin-tx)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# GPU Miner (requires ncurses + OpenCL)
cd src/miner
make USE_OPENCL=1
```

### Dependencies

- **Linux:** `cmake`, `g++`, `libncurses-dev` (miner only)
- **macOS:** Xcode command line tools
- **Windows:** MSYS2 MinGW64

## Architecture

```
flowcoind          Full node — P2P, RPC, wallet, block validation
flowcoin-cli       RPC command-line client
flowcoin-tx        Offline transaction utility
flowcoin-miner     Solo GPU/CPU miner with ncurses TUI
```

### Key Features

- **OpenCL GPU mining** — works on NVIDIA, AMD, Intel, Apple GPUs
- **Ed25519 + SLIP-0010 HD wallet** — new address per mined block
- **Cookie authentication** — no rpcuser/rpcpassword needed (like Bitcoin Core)
- **IPv4/IPv6 dual-stack** with persistent node_id for peer dedup
- **SQLite WAL** for UTXO set, transaction index, wallet — survives kill -9
- **Headers-first sync** — fast initial block download from peers

## Network

| Node | Address |
|------|---------|
| Seed | 211.205.13.203:9333 |
| DNS | seed.flowcoin.org |

```bash
# Manual peer connection
./flowcoin-cli addnode 211.205.13.203:9333 add
```

## RPC

```bash
# Mining
./flowcoin-cli getmininginfo
./flowcoin-cli getnetworkhashps
./flowcoin-cli getblocktemplate

# Wallet
./flowcoin-cli getbalance
./flowcoin-cli getnewaddress
./flowcoin-cli sendtoaddress fl1q... 10.0
./flowcoin-cli listunspent
./flowcoin-cli listaddresses

# Blockchain
./flowcoin-cli getblockcount
./flowcoin-cli getblock <hash>
./flowcoin-cli getpeerinfo
```

## Genesis Block

```
"White House calls for federal AI law to preempt states
 21/Mar/2026 - FlowCoin: decentralized proof-of-work"
```

## Whitepaper

[whitepaper.txt](whitepaper.txt)

## License

MIT License. Copyright (c) 2026 Haruki Tanaka.

## Contact

harukitanaka@tutamail.com

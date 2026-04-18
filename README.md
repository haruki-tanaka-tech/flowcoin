# FlowCoin

**CPU-only RandomX Proof-of-Work cryptocurrency — Bitcoin architecture, no ASIC, no GPU premium.**

Written from scratch in C++20. The node's wire protocol, log format, RPC
encoding, and address layout are intentionally Bitcoin-Core-compatible so
existing tooling keeps working; only the PoW function and hash algorithm
are different.

## Why RandomX

Bitcoin today: six mining pools control ~95% of hashrate because SHA-256d
fits trivially on silicon. FlowCoin uses RandomX — the same CPU-only PoW
that has kept Monero mineable on consumer hardware since November 2019
with no ASIC ever reaching market in the five years since.

Each hash runs a pseudo-randomly generated program of 256 instructions
against a 2 GiB dataset in a virtual machine. The bottleneck is DRAM
bandwidth, not gate count, so specialised hardware gains no edge over a
commodity CPU. On a 24-thread consumer laptop you get roughly 8 kH/s in
full-memory mode and the best known GPU port is ~10× worse per watt.

Full argument in [whitepaper.txt](whitepaper.txt) §10.

## Quick Start

```bash
# Start the full node (daemon)
./flowcoind -daemon

# Start the miner (in another terminal)
./flowcoin-miner --cookie ~/.flowcoin/.cookie

# Check balance / send / inspect chain
./flowcoin-cli getbalance
./flowcoin-cli getnewaddress
./flowcoin-cli sendtoaddress fl1q... 10.0
./flowcoin-cli getblockcount
```

## Download

Releases are produced by `cpack` from the main branch. Layout matches
Bitcoin Core's tarball: `bin/flowcoind bin/flowcoin-cli bin/flowcoin-tx
bin/flowcoin-miner share/man/man1/*.1 flowcoin.conf README.md
whitepaper.txt`.

See [github.com/KristianPilatovich/flowcoin/releases](https://github.com/KristianPilatovich/flowcoin/releases)
for prebuilt archives.

## Specifications

| Parameter           | Value                                          |
|---------------------|------------------------------------------------|
| PoW                 | RandomX v2 (2 GiB dataset / 256 MiB light)     |
| Seed rotation       | Every 2048 blocks, 64-block lag                |
| Block ID hash       | keccak256d (SHA-3 style, pad 0x01)             |
| Block time          | 10 minutes                                     |
| Block reward        | 50 FLOW, halving every 210,000 blocks          |
| Max supply          | 21,000,000 FLOW                                |
| Difficulty retarget | Every 2,016 blocks, ±4× clamp                  |
| Timestamp rule      | Strictly greater than MTP of last 11 blocks    |
| Signatures          | Ed25519 (RFC 8032), deterministic              |
| Address format      | Bech32 v0 with HRP `fl` (`fl1q...`, P2WPKH-style) |
| P2P port            | 9333                                           |
| RPC port            | 9334                                           |
| BIP-44 coin type    | 9555                                           |
| Protocol version    | 70016 (wtxidrelay)                             |

## Build from Source

```bash
git clone https://github.com/KristianPilatovich/flowcoin.git
cd flowcoin
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Produces `build/flowcoind`, `build/flowcoin-cli`, `build/flowcoin-tx`,
`build/flowcoin-miner`.

### Dependencies

- **Linux:** `cmake`, `g++` (≥10). RandomX picks up AES-NI / AVX2 at runtime if present.
- **macOS:** Xcode command line tools.
- **Windows:** MSYS2 MinGW64.

## Architecture

```
flowcoind          Full node — P2P, RPC, wallet, block validation
flowcoin-cli       JSON-RPC command-line client (Bitcoin-cli compatible)
flowcoin-tx        Offline transaction construction utility
flowcoin-miner     Standalone CPU-only RandomX miner (XMRig-style output)
```

Data directory layout (Bitcoin-Core-compatible, flat):
```
~/.flowcoin/
├── wallet.dat          HD wallet (SLIP-0010, encrypted with AES-256-CBC)
├── blocks/             blk*.dat block files + rev*.dat undo files
├── chainstate/         SQLite UTXO set (WAL mode)
├── indexes/            transaction index, block-filter index
├── peers.dat           addrman state
├── .cookie             RPC cookie (auto-generated)
├── .lock / .pid
└── debug.log
```

### Key features

- **Bitcoin-Core-compatible P2P protocol** — `version/verack/wtxidrelay/
  sendaddrv2/sendheaders/sendcmpct/feefilter` handshake sequence matches
  byte-for-byte, magic bytes and checksum hash aside. `inv/getdata/
  getheaders/headers/block/tx/addr/addrv2/mempool` messages relay with
  Bitcoin's field order and CompactSize encoding.
- **Bitcoin-cli-compatible RPC** — single-line compact JSON responses,
  `{"jsonrpc":"2.0","result":{...},"id":N}` field order, same method
  names (`getblockchaininfo`, `getblockcount`, `getblock`, `sendrawtransaction`,
  `getbalance`, `getnewaddress`, `listunspent`, …).
- **Cookie auth** — drop-in Bitcoin Core cookie at `<datadir>/.cookie`.
- **HD wallet** — SLIP-0010 (m/44'/9555'/0'/0/i) from an encrypted master
  seed, fresh address per coinbase.
- **SQLite WAL chainstate** — survives `kill -9`, concurrent reads during
  block validation.
- **Headers-first IBD** — fast initial block download.
- **Standalone CPU miner** — solo mining over JSON-RPC with XMRig-style
  banner + speed line. Full (2 GiB) and light (256 MiB) modes.

## Network

| Kind       | Address                        |
|------------|--------------------------------|
| Seed node  | `211.205.13.203:9333`          |
| DNS seed   | `seed.flowcoin.org`            |

```bash
# Manual peer connection
./flowcoin-cli addnode 211.205.13.203:9333 add
```

## RPC

```bash
# Blockchain
./flowcoin-cli getblockcount
./flowcoin-cli getblockchaininfo
./flowcoin-cli getblock <hash>
./flowcoin-cli getbestblockhash

# Network
./flowcoin-cli getpeerinfo
./flowcoin-cli getconnectioncount

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
```

Raw JSON-RPC over HTTP works the same as Bitcoin Core:

```bash
USERPASS=$(cat ~/.flowcoin/.cookie)
curl -s -u "$USERPASS" -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}' \
     http://127.0.0.1:9334/
```

## Genesis Block

```
"White House calls for federal AI law to preempt states
 21/Mar/2026 - FlowCoin: decentralized proof-of-work"
```

## Whitepaper

[whitepaper.txt](whitepaper.txt)

## License

MIT License. Copyright (c) 2026 Kristian Pilatovich.

## Contact

pilatovichkristian2@gmail.com

# FlowCoin Architecture

## Overview

FlowCoin is a CPU-only Proof-of-Work cryptocurrency that closely mirrors
Bitcoin Core's design. The proof-of-work hash is RandomX (the same
algorithm Monero has used on mainnet since November 2019); the block-id
hash is keccak256d; addresses are Bech32 v0 with the `fl` HRP; signatures
are Ed25519 (RFC 8032).

## Module Dependency Graph

```
flowcoind (main binary)
  |
  +-- flowcoin_node
  |     +-- flowcoin_rpc        (JSON-RPC server, method dispatch)
  |     +-- flowcoin_mining      (block template, miner)
  |     +-- flowcoin_wallet      (HD keys, UTXO scanning, tx creation)
  |     +-- flowcoin_net         (P2P connections, message relay)
  |     +-- flowcoin_chain       (chainstate, block index, block store)
  |     +-- flowcoin_consensus   (validation, difficulty)
  |     +-- flowcoin_mempool     (transaction pool, policy)
  |     +-- flowcoin_index       (tx index, block filter index)
  |     +-- flowcoin_policy      (fee estimation, RBF)
  |     +-- flowcoin_interfaces  (node/wallet/chain abstractions)
  |     +-- flowcoin_rest        (HTTP REST API)
  |
  +-- flowcoin_primitives        (block, transaction)
  +-- flowcoin_crypto            (Ed25519, bech32, AES-256, SLIP-0010)
  +-- flowcoin_hash              (keccak256d, Merkle trees, Bloom filters)
  +-- flowcoin_util              (arith_uint256, time, random, threading)
  +-- flowcoin_script            (script evaluation, standard scripts)
  |
  +-- sqlite (vendored)          (UTXO set, wallet DB, chain DB)
  +-- randomx (vendored)         (RandomX PoW from tevador)
  +-- xkcp (vendored)            (Keccak reference implementation for block IDs)
  +-- libuv (vendored)           (async I/O, event loop)
  +-- nlohmann/json (vendored)   (JSON parsing)
```

## Data Flow: Block Received → Validation → Chain State

### 1. Block Reception

A block arrives via the P2P network through `flowcoin_net`:

1. `net.cpp` receives raw bytes on a TCP socket (libuv).
2. `protocol.cpp` parses the 24-byte wire header (magic, command, size, checksum).
3. `messages.cpp` deserializes the `BLOCK` message into a `CBlock` struct.
4. The block is passed to `ChainState::accept_block()`.

### 2. Header Validation

`validation.cpp::check_header()` performs these checks without the block body:

| Check | Field | Rule |
|-------|-------|------|
| 1 | prev_hash | Must match parent block hash |
| 2 | height | Must be parent_height + 1 |
| 3 | timestamp | Must be strictly greater than Median Time Past of last 11 blocks |
| 4 | timestamp | Must not be >2h in the future |
| 5 | nbits | Must match retarget algorithm output |
| 6 | pow_hash | `RandomX(header[0..91], pow_seed)` must be ≤ target decoded from nbits |
| 7 | miner_sig | Ed25519 signature must verify against miner_pubkey |

The RandomX seed is the block hash at `rx_seed_height(height)` —
an earlier block from the same chain. It rotates every 2,048 blocks
with a 64-block lag to avoid cache thrash around epoch boundaries.

### 3. Block Body Validation

`validation.cpp::check_block()` adds:

- Coinbase transaction structure and reward amount
- Merkle root verification
- Transaction signature verification

### 4. Chain State Update

On successful validation:

1. `utxo.cpp`: UTXO set is updated (add new outputs, remove spent inputs).
2. `blockindex.cpp`: Block index entry is created/updated.
3. `blockstore.cpp`: Full block is written to flat-file storage.
4. `txindex.cpp`: Transaction index is updated (if enabled).

## Threading Model

FlowCoin uses a multi-threaded architecture with clear ownership rules:

### Main Thread
- Startup/shutdown coordination
- Signal handling
- Block validation (single-threaded for determinism)

### Network Thread (libuv event loop)
- TCP connection management
- Message serialization/deserialization
- Peer lifecycle (connect, handshake, disconnect)
- DNS seed resolution

### RPC Thread Pool
- JSON-RPC request handling
- One thread per concurrent RPC connection
- Read-only access to chain state (shared mutex)
- Write operations (send, mine) acquire exclusive lock

### Mining Thread Pool
- Block template construction (single-thread)
- Nonce search (one RandomX VM per worker thread; each worker scans
  a disjoint nonce stripe; first to find a valid hash wins)

### Wallet Thread
- UTXO scanning
- Transaction history updates
- Key derivation
- Encryption/decryption

### Synchronization Primitives
- `ChainState` uses a read-write mutex: multiple readers, exclusive writer
- UTXO set uses SQLite's built-in WAL mode for concurrent reads
- Mempool uses a shared mutex for read access

## Memory Layout

### In RAM
- **Block index** (`BlockTree`): ~200 bytes per block index entry,
  entire chain history. At 100K blocks: ~20 MB.
- **UTXO cache**: Hot UTXOs cached in memory. Default 300 MB.
- **Mempool**: Pending transactions. Default limit 300 MB.
- **Peer state**: ~1 KB per peer. 125 peers: ~125 KB.

### On Disk
- **Block files** (`blocks/blk?????.dat`): Raw serialized blocks, 128 MiB per file.
- **Undo files** (`blocks/rev?????.dat`): Per-block undo data for reorg rollback.
- **UTXO database** (`chainstate/`): SQLite with WAL mode.
- **Wallet database** (`wallet.dat` at datadir root, not `wallets/`): SQLite
  with an HD seed (SLIP-0010 path `m/44'/9555'/0'/0/i`) and encrypted keys.
- **Chain database** (`chaindb.db`): Block index, chain state metadata.
- **Transaction index** (`indexes/`): Optional, maps txid → block position.

## Database Schemas

### UTXO Set (SQLite)

```sql
CREATE TABLE utxos (
    txid        BLOB NOT NULL,      -- 32 bytes
    vout        INTEGER NOT NULL,
    value       INTEGER NOT NULL,   -- atomic units
    pubkey_hash BLOB NOT NULL,      -- 32 bytes
    height      INTEGER NOT NULL,
    is_coinbase INTEGER NOT NULL,
    PRIMARY KEY (txid, vout)
);
CREATE INDEX idx_utxo_pkh ON utxos(pubkey_hash);
```

### Wallet Database (SQLite)

```sql
CREATE TABLE keys (
    pubkey      BLOB PRIMARY KEY,   -- 32 bytes
    privkey     BLOB NOT NULL,      -- 32 bytes (possibly encrypted)
    deriv_index INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE transactions (
    txid        BLOB PRIMARY KEY,
    height      INTEGER,
    timestamp   INTEGER,
    amount      INTEGER,
    fee         INTEGER,
    direction   TEXT                -- 'send' or 'recv'
);

CREATE TABLE labels (
    address     TEXT PRIMARY KEY,
    label       TEXT NOT NULL
);

CREATE TABLE metadata (
    key         TEXT PRIMARY KEY,
    value       BLOB
);
```

### Block Index (SQLite)

```sql
CREATE TABLE block_index (
    hash        BLOB PRIMARY KEY,
    prev_hash   BLOB NOT NULL,
    height      INTEGER NOT NULL,
    timestamp   INTEGER NOT NULL,
    nbits       INTEGER NOT NULL,
    nonce       INTEGER NOT NULL,
    status      INTEGER NOT NULL,
    file_num    INTEGER,
    file_offset INTEGER,
    block_size  INTEGER,
    chainwork   BLOB
);
CREATE INDEX idx_block_height ON block_index(height);
```

### Transaction Index (SQLite)

```sql
CREATE TABLE tx_index (
    txid        BLOB PRIMARY KEY,
    file_num    INTEGER NOT NULL,
    file_offset INTEGER NOT NULL,
    block_hash  BLOB NOT NULL
);
```

## P2P Message Flow

### Connection Establishment

```
Node A                          Node B
  |                               |
  |--- VERSION (height, services) -->|
  |                               |
  |<-- VERSION (height, services) ---|
  |                               |
  |--- VERACK ------------------>|
  |                               |
  |<-- VERACK -------------------|
  |                               |
  | (handshake complete)          |
  |--- SENDHEADERS -------------->|
  |--- SENDCMPCT ---------------->|
  |--- FEEFILTER ---------------->|
```

### Block Relay

```
Miner                        Peer A                    Peer B
  |                            |                         |
  | (mines block)              |                         |
  |--- INV(block_hash) ------->|                         |
  |                            |--- INV(block_hash) ---->|
  |<-- GETDATA(block_hash) ----|                         |
  |                            |<-- GETDATA(block_hash) -|
  |--- BLOCK(full_block) ----->|                         |
  |                            |--- BLOCK(full_block) -->|
```

### Initial Block Download (IBD)

```
New Node                      Seed Node
  |                              |
  |--- GETHEADERS(locator) ----->|
  |<-- HEADERS(up to 2000) -----|
  |--- GETDATA(block_hashes) -->|
  |<-- BLOCK(block_1) ----------|
  |<-- BLOCK(block_2) ----------|
  | ...                          |
  |--- GETHEADERS(locator) ----->|
  | (repeat until caught up)     |
```

## RPC Request Lifecycle

1. Client sends HTTP POST with JSON-RPC body to port 9334.
2. `RpcServer::on_read()` accumulates data in a per-connection buffer.
3. When `\r\n\r\n` is found, `process_request()` is called.
4. `check_auth()` validates Basic auth against stored credentials.
5. `check_rate_limit()` enforces per-IP request limits.
6. JSON body is parsed: `{"method": "...", "params": [...], "id": N}`.
7. `dispatch()` looks up the method in the registered handler map.
8. The handler executes (may acquire chain state locks).
9. Result is wrapped in `{"result": ..., "error": null, "id": N}`.
10. HTTP response is sent back with appropriate status code.
11. Connection is kept alive or closed per HTTP/1.1 rules.

## Build System

FlowCoin uses CMake 3.20+ with the following build targets:

- `flowcoind`: Full node daemon
- `flowcoin-cli`: RPC command-line client
- `flowcoin-tx`: Offline transaction utility
- `flowcoin_tests`: Unit test binary (assert-based)
- `flowcoin_bench`: Performance benchmark binary

All vendored dependencies are compiled from source with no external
package requirements beyond a C++20 compiler and pthread.

Deterministic build support:
- No `-ffast-math` (IEEE 754 compliance required for consensus)
- File prefix maps for reproducible debug info
- Deterministic archive creation flags
- RPATH disabled

## Security Considerations

- **Determinism**: All consensus-critical computation produces identical
  results across platforms.
- **Cryptography**: Ed25519 for signatures, keccak256d for block IDs,
  merkle roots, and address hashing, RandomX for proof-of-work,
  SLIP-0010 for HD key derivation.
- **Network**: All peer messages are checksummed (keccak256d truncated
  to 4 bytes). Misbehaving peers are scored and banned at threshold.
- **Wallet**: HD-derived from a single seed (SLIP-0010). Keys currently
  stored unencrypted in `wallet.dat` — back up the file with ordinary
  filesystem permissions. Per-block mining address rotation; keypool
  for address pre-generation.

## Configuration System

FlowCoin supports configuration through command-line arguments and a
configuration file (`flowcoin.conf`). The config system uses a hierarchical
key-value store with the following precedence:

1. Command-line arguments (highest priority)
2. Configuration file
3. Compiled defaults (lowest priority)

### Key Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-datadir` | `~/.flowcoin` | Data directory path |
| `-port` | 9333 | P2P port |
| `-rpcport` | 9334 | JSON-RPC port |
| `-rpcuser` | (required) | RPC username |
| `-rpcpassword` | (required) | RPC password |
| `-maxconnections` | 125 | Maximum peer connections |
| `-dbcache` | 300 | UTXO cache size (MB) |
| `-prune` | 0 | Enable pruning (target MB, 0=disabled) |
| `-txindex` | 0 | Enable transaction index |
| `-rest` | 0 | Enable REST API |
| `-testnet` | 0 | Use testnet |
| `-regtest` | 0 | Use regtest |
| `-debug` | (none) | Debug log categories |
| `-printtoconsole` | 0 | Print logs to stdout |
| `-listen` | 1 | Accept incoming connections |
| `-discover` | 1 | Discover own IP via UPnP/NAT-PMP |
| `-maxmempool` | 300 | Mempool size limit (MB) |
| `-mempoolexpiry` | 336 | Mempool tx expiry (hours) |
| `-blockmaxweight` | 4000000 | Maximum block weight for mining |
| `-blockmintxfee` | 0.00001 | Minimum fee rate for block inclusion |
| `-walletdir` | (datadir) | Wallet file directory |
| `-spendzeroconfchange` | 1 | Spend unconfirmed change |
| `-fallbackfee` | 0.0002 | Fallback fee rate |
| `-mintxfee` | 0.00001 | Minimum transaction fee |
| `-assumevalid` | (none) | Skip signature validation before this hash |
| `-checkpoints` | 1 | Use built-in checkpoints |
| `-par` | 0 | Script verification threads (0=auto) |

### Network-Specific Defaults

Each network (mainnet, testnet, regtest) has different default parameters:

**Mainnet**: Full validation, real difficulty, DNS seeds enabled.
**Testnet**: Full validation, reduced difficulty, test DNS seeds.
**Regtest**: Instant blocks, minimum difficulty, no external connections.

## Error Handling

FlowCoin uses two error handling strategies:

### Result<T> Type

For expected failure modes (parse errors, validation failures):

```cpp
Result<Block> result = parse_block(data);
if (!result.ok()) {
    log_error(result.error_message());
    return;
}
Block& block = result.value();
```

### ValidationState

For consensus validation with structured error reporting:

```cpp
ValidationState state;
if (!check_block(block, state)) {
    // state.reject_reason() -> "bad-prevblk"
    // state.debug_message() -> detailed context
    ban_peer(peer, state.reject_reason());
}
```

### Exceptions

Used sparingly, only for:
- RPC method handlers (caught at dispatch layer, converted to JSON error)
- Initialization failures (fatal, causes clean shutdown)
- Out-of-memory conditions (fatal)

## Logging System

Hierarchical logging with categories:

| Category | Description |
|----------|-------------|
| `net` | P2P network messages |
| `mempool` | Transaction pool operations |
| `validation` | Block/tx validation |
| `mining` | Mining operations |
| `rpc` | RPC server activity |
| `wallet` | Wallet operations |
| `pow` | Proof-of-work operations |
| `db` | Database operations |
| `lock` | Lock contention tracking |

Log levels: `trace`, `debug`, `info`, `warning`, `error`.

Default output: `debug.log` in the data directory.
Optional: stdout output via `-printtoconsole`.

## Shutdown Sequence

Clean shutdown follows this order:

1. Stop accepting new RPC connections.
2. Stop accepting new P2P connections.
3. Signal mining thread to stop.
4. Wait for in-flight block validation to complete.
5. Flush mempool to disk (if configured).
6. Flush UTXO set to disk.
7. Save block index to ChainDB.
8. Close wallet database.
9. Close all peer connections.
10. Stop libuv event loop.
11. Exit.

## Performance Characteristics

### Block Validation Timing

| Operation | Time (typical) |
|-----------|---------------|
| Header validation | <1 ms |
| PoW hash check (RandomX light mode) | ~10 ms |
| PoW hash check (RandomX full dataset) | ~0.7 ms |
| Block-id hash (keccak256d) | <0.01 ms |
| Transaction signature verification | ~0.1 ms per sig |
| UTXO lookups | ~0.01 ms per input |
| Merkle root computation | ~0.1 ms for 100 txs |

### Sync Performance

| Phase | Rate |
|-------|------|
| Header sync | ~10,000 headers/s |
| Block download (IBD) | ~100 blocks/s (network limited) |
| Block validation (IBD) | ~200 blocks/s |

### Storage Growth

| Component | Growth Rate |
|-----------|------------|
| Block files | ~1 MB/block (varies with tx count) |
| UTXO database | ~100 bytes per UTXO |
| Block index | ~200 bytes per block |

## Initial Block Download (IBD)

### Phases

1. **Header Download**: Fetch all block headers from peers.
   Uses `getheaders` messages with exponential step-back locators.
   Validates header-only (checks 1-11, 13-14).
   Builds the in-memory block tree.

2. **Block Download**: Fetch full blocks in parallel from multiple peers.
   Up to 16 blocks in transit simultaneously.
   60-second timeout per block request.
   Blocks are requested in chain order.

3. **Block Validation**: Validate each block fully.
   During IBD, assume-valid optimization can skip signature verification
   for blocks below a trusted hash.

4. **UTXO Construction**: Build the UTXO set from all blocks.
   Batched SQLite transactions for performance.
   Periodic cache flushes to limit memory usage.

### IBD Detection

A node considers itself in IBD if:
- Chain tip is more than 144 blocks behind the best known header.
- No blocks have been received in the last 30 minutes.

During IBD:
- Transaction relay is paused (saves bandwidth).
- Block-only relay mode is used.
- Mining is disabled.
- RPC methods that depend on chain tip may return stale data.

### Assume-Valid

The `-assumevalid` flag specifies a block hash. For all blocks before
this hash:
- Signature verification is skipped.
- Script evaluation is skipped.

This optimization is safe under the assumption that if a block is buried
deep in the chain with the most cumulative work, it was validated by
the network when it was mined.

## Reorg Handling

### Fork Detection

A fork is detected when a block arrives whose parent is not the current tip
but is in the block tree. The reorganization algorithm:

1. Find the fork point (common ancestor of old tip and new tip).
2. Compare cumulative work of the two chains.
3. If new chain has more work, reorganize:
   a. Disconnect blocks from old tip down to fork point.
   b. Connect blocks from fork point up to new tip.
4. If old chain has equal or more work, reject the new chain.

### Block Disconnection

For each block disconnected (in reverse order):

1. **UTXO rollback**: Re-add spent outputs, remove created outputs.
   Uses the BlockUndo data stored during connection.
2. **Mempool recovery**: Return transactions from disconnected blocks
   to the mempool (if they are still valid).
3. **Block index update**: Mark block as no longer part of the active chain.

### Reorg Limits

- The FINALITY_DEPTH (6 blocks) is the recommended confirmation depth
  for considering transactions final.

## Wallet Architecture

### HD Key Derivation

FlowCoin uses SLIP-0010 (Ed25519 variant of BIP-32) for hierarchical
deterministic key derivation:

```
Master seed (256 bits)
  |
  +-- m/44'/9555'/0'/0/0  (first receive address)
  +-- m/44'/9555'/0'/0/1  (second receive address)
  +-- m/44'/9555'/0'/0/2  (third receive address)
  |   ...
  +-- m/44'/9555'/0'/1/0  (first change address)
  +-- m/44'/9555'/0'/1/1  (second change address)
  |   ...
```

Path components:
- `44'`: BIP-44 purpose
- `9555'`: FlowCoin coin type (SLIP-44)
- `0'`: Account 0
- `0/N`: External (receive) addresses
- `1/N`: Internal (change) addresses

### Keypool

The wallet pre-generates a pool of keys (default 100) to avoid
expensive key derivation during time-sensitive operations:

- Mining: needs a fresh address immediately when a block is found.
- Receiving: needs to show the user an address without delay.
- Change: needs a change address during transaction construction.

The keypool is refilled in the background whenever its size drops
below a threshold.

### Coin Selection

FlowCoin implements three coin selection algorithms:

1. **Branch and Bound**: Finds the exact combination of UTXOs that
   minimizes waste (change close to zero). Exponential worst case
   but fast in practice with a timeout.

2. **Knapsack**: Approximation algorithm that tries random subsets.
   Falls back to selecting the largest UTXOs first.

3. **Smallest First**: Simple greedy algorithm that selects UTXOs
   from smallest to largest until the target is met.

The wallet tries algorithms in order, falling back to the next
if the previous fails or times out.

### Address Formats

FlowCoin uses Bech32 v0 — BIP-173 format — with network-specific HRPs.
Witness version 0 means the checksum polynomial is the original
Bech32 constant (not the Bech32m constant used for witness v1+, per
BIP-350), which makes the on-wire bytes structurally identical to a
Bitcoin P2WPKH address (`bc1q...`) except for the HRP:

| Network | HRP | Example |
|---------|-----|---------|
| Mainnet | `fl` | `fl1qdd2j0j3zz0s7q4xzu4huznu7zr5udt3sgg73kv` |
| Testnet | `tfl` | `tfl1q…` |
| Regtest | `rfl` | `rfl1q…` |

Address payload: 20-byte `keccak256d(pubkey)[0..20]`, encoded as a
v0 witness program in Bech32. That gives 42-character addresses,
the same length as Bitcoin P2WPKH.

## REST API Details

The REST API provides read-only HTTP access to blockchain data.
All endpoints are prefixed with `/rest/`.

### Response Formats

Each endpoint supports three formats via file extension:

| Extension | Content-Type | Description |
|-----------|-------------|-------------|
| `.json` | `application/json` | JSON-encoded response |
| `.bin` | `application/octet-stream` | Raw binary serialization |
| `.hex` | `text/plain` | Hex-encoded binary data |

### Endpoint Details

#### GET /rest/block/<hash>.<format>

Returns the full block including all transactions.

JSON fields:
- `hash`: Block hash (hex)
- `height`: Block height
- `version`: Block version
- `prev_hash`: Previous block hash
- `merkle_root`: Merkle root of transactions
- `timestamp`: Block timestamp (Unix seconds)
- `nbits`: Compact difficulty target
- `nonce`: Mining nonce
- `tx`: Array of transaction objects
- `size`: Serialized block size
- `weight`: Block weight

#### GET /rest/tx/<txid>.<format>

Returns a single transaction.

JSON fields:
- `txid`: Transaction ID
- `version`: Transaction version
- `vin`: Array of inputs (prevout, signature, pubkey)
- `vout`: Array of outputs (amount, pubkey_hash)
- `locktime`: Lock time

#### GET /rest/chaininfo.json

Returns current chain state.

JSON fields:
- `chain`: Network name
- `blocks`: Current height
- `bestblockhash`: Tip block hash
- `difficulty`: Current difficulty
- `mediantime`: Median time of last 11 blocks
- `chainwork`: Total cumulative work (hex)

#### GET /rest/mempool/info.json

Returns mempool statistics.

JSON fields:
- `size`: Number of transactions
- `bytes`: Total serialized size
- `usage`: Memory usage
- `maxmempool`: Configured maximum size
- `mempoolminfee`: Current minimum fee rate

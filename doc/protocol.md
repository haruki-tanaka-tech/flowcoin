# FlowCoin Protocol Specification v1.0

## 1. Overview

FlowCoin is a CPU-only Proof-of-Work cryptocurrency that combines Bitcoin's
proven economic model (21M supply, 10-minute blocks, halving schedule) with
a memory-hard PoW and modern signatures.

The protocol uses:
- **RandomX** (from tevador, the same PoW family used by Monero since Nov 2019) for proof-of-work
- **keccak256d** (double Keccak-256, padding byte 0x01) for block IDs, merkle roots,
  transaction IDs, and address derivation
- **Ed25519** signatures (RFC 8032) instead of secp256k1 ECDSA
- **Bech32 v0** addresses with the `fl` human-readable prefix (structurally
  identical to Bitcoin P2WPKH `bc1q...` format, modulo the HRP)
- **Bitcoin-Core-compatible** P2P wire format and JSON-RPC on-disk layout,
  so existing Bitcoin tooling can read our traffic and data directories with
  only magic-byte / hash-function changes

This document specifies the complete protocol: consensus rules, block format,
transaction format, network protocol, and storage format.

## 2. Consensus Rules

### 2.1 Block Header (188 bytes)

The block header is a fixed 188-byte structure consisting of 92 bytes of unsigned
data followed by a 32-byte Ed25519 public key and a 64-byte signature.

| Offset | Size | Field            | Type      | Description                            |
|--------|------|------------------|-----------|----------------------------------------|
| 0      | 32   | prev_hash        | uint256   | Hash of the previous block header      |
| 32     | 32   | merkle_root      | uint256   | Merkle root of all transactions        |
| 64     | 8    | height           | uint64_le | Block height (0 = genesis)             |
| 72     | 8    | timestamp        | int64_le  | Unix timestamp (seconds since epoch)   |
| 80     | 4    | nbits            | uint32_le | Compact difficulty target              |
| 84     | 4    | nonce            | uint32_le | Mining nonce                           |
| 88     | 4    | version          | uint32_le | Block version (currently 1)            |
| 92     | 32   | miner_pubkey     | bytes32   | Ed25519 public key of the miner        |
| 124    | 64   | miner_sig        | bytes64   | Ed25519 signature over bytes [0..91]   |

Total: 188 bytes.

Each block carries two distinct hashes:

```
block_id = keccak256d(header[0..91])              # cheap, used for chain refs,
                                                   #   P2P, merkle, RPC, indexing
pow_hash = RandomX(header[0..91], pow_seed)       # CPU-only memory-hard PoW,
                                                   #   compared against target
```

where `keccak256d(x) = Keccak-256(Keccak-256(x))` using the original Keccak
padding byte `0x01` (not the `0x06` used by NIST SHA-3).

`pow_seed` is the block hash at `rx_seed_height(height)` — an earlier block
from the chain itself. The seed rotates every 2,048 blocks with a 64-block
lag so nodes agree on the seed well before rotation takes effect and reorgs
across an epoch boundary don't thrash the RandomX cache.

### 2.2 Block Validation

Every block must pass all validation checks to be accepted:

1. **Version check**: `block.version == 1` (current protocol version).

2. **Height check**: `block.height == parent.height + 1`, or `height == 0` for genesis.

3. **Previous hash**: `block.prev_hash == parent.get_hash()`.

4. **Timestamp bounds**:
   - `block.timestamp > median_time_past(11)` (median of last 11 block timestamps)
   - `block.timestamp <= current_time + 7200` (no more than 2 hours in the future)

5. **Difficulty target**: `block.nbits` must equal the expected difficulty:
   - At retarget boundaries (height % 2016 == 0): recalculated from the last 2016 blocks
   - Otherwise: inherited from parent

6. **Proof-of-Work**: `RandomX(header[0..91], pow_seed) < target_from_nbits(block.nbits)`,
   where `pow_seed = block_id(chain[rx_seed_height(block.height)])`.

7. **Merkle root**: `block.merkle_root == compute_merkle_root(block.vtx)`.

8. **Signature verification**: Ed25519 verify `miner_sig` over `header[0..91]` with
    `miner_pubkey`.

9. **Coinbase validation**: First transaction must be a valid coinbase:
    - Exactly one input with null prevout
    - Output amount <= block_reward + total_fees
    - Height encoded in coinbase input's pubkey field (BIP34 style)

10. **Transaction validation**: All non-coinbase transactions must:
    - Have valid Ed25519 signatures for all inputs
    - Reference existing unspent outputs
    - Total output amount <= total input amount
    - Not double-spend within the same block

### 2.3 Difficulty Adjustment

FlowCoin uses Bitcoin's difficulty adjustment algorithm, retargeting
against the RandomX work-per-block rate.

Retarget occurs every 2016 blocks. The new target is calculated as:

```
actual_timespan = last_block.timestamp - first_block.timestamp
actual_timespan = clamp(actual_timespan, RETARGET_TIMESPAN/4, RETARGET_TIMESPAN*4)
new_target = old_target * actual_timespan / RETARGET_TIMESPAN
new_target = min(new_target, pow_limit)
```

Where:
- `RETARGET_TIMESPAN = 2016 * 600 = 1,209,600 seconds` (2 weeks)
- `pow_limit` is decoded from `INITIAL_NBITS = 0x1f00ffff`
- Clamping factor is 4x (difficulty can change by at most 4x per period)

The compact target format (nbits) follows Bitcoin's encoding:
```
mantissa = nbits & 0x7FFFFF
exponent = (nbits >> 24) & 0xFF
target = mantissa << (8 * (exponent - 3))
```

### 2.4 Block Reward

The block subsidy follows Bitcoin's halving schedule:

```
reward = INITIAL_REWARD >> (height / HALVING_INTERVAL)
```

Where:
- `INITIAL_REWARD = 50 * 10^8` (50 FLC in atomic units)
- `HALVING_INTERVAL = 210,000 blocks` (~4 years at 10-minute blocks)
- `MAX_SUPPLY = 21,000,000 FLC`
- Minimum reward: 1 atomic unit. Below this, subsidy is zero.

Halving schedule:

| Era | Block Range       | Reward (FLC) | Cumulative Supply |
|-----|-------------------|---------------|-------------------|
| 1   | 0 - 209,999       | 50.0          | 10,500,000        |
| 2   | 210,000 - 419,999 | 25.0          | 15,750,000        |
| 3   | 420,000 - 629,999 | 12.5          | 18,375,000        |
| 4   | 630,000 - 839,999 | 6.25          | 19,687,500        |
| ... | ...               | ...           | ...               |

## 3. Network Protocol

### 3.1 Wire Format

All messages use a 24-byte header followed by a variable-length payload:

```
[4 bytes] magic:        uint32_le (mainnet: 0xF9BEB4D9)
[12 bytes] command:     ASCII, null-padded to 12 bytes
[4 bytes] payload_size: uint32_le
[4 bytes] checksum:     first 4 bytes of Keccak256(payload)
```

Maximum payload size: 32,000,000 bytes (matching MAX_BLOCK_SIZE).

### 3.2 Messages

| Command      | Payload                              | Direction   |
|-------------|--------------------------------------|-------------|
| version     | VersionMessage                       | Both        |
| verack      | (empty)                              | Both        |
| ping        | 8 bytes: nonce                       | Both        |
| pong        | 8 bytes: nonce (echo)                | Both        |
| getaddr     | (empty)                              | Both        |
| addr        | varint(count) + count*AddrEntry      | Both        |
| inv         | varint(count) + count*InvItem        | Both        |
| getdata     | varint(count) + count*InvItem        | Both        |
| block       | Serialized CBlock                    | Both        |
| tx          | Serialized CTransaction              | Both        |
| getblocks   | version + locator_hashes + hash_stop | Out         |
| getheaders  | version + locator_hashes + hash_stop | Out         |
| headers     | varint(count) + count*Header308      | In          |
| notfound    | varint(count) + count*InvItem        | In          |
| reject      | message + code + reason [+ hash]     | Both        |
| sendheaders | (empty)                              | Both        |
| sendcmpct   | announce(1) + version(8)             | Both        |
| cmpctblock  | Header308 + nonce + short_ids + pre  | Both        |
| getblocktxn | block_hash + indices                 | Out         |
| blocktxn    | block_hash + transactions            | In          |
| feefilter   | 8 bytes: min_fee_rate                | Both        |

### 3.3 Handshake

The connection handshake follows Bitcoin's protocol:

```
Outbound initiates:
  Outbound -> VERSION
  Inbound  -> VERSION
  Inbound  -> VERACK
  Outbound -> VERACK
```

After both sides exchange VERSION + VERACK, the connection is in HANDSHAKE_DONE state.

The VERSION message contains:
- Protocol version (uint32): currently 1
- Services bitfield (uint64): NODE_NETWORK = 0x01
- Timestamp (int64): current Unix time
- Receiver address (CNetAddr)
- Sender address (CNetAddr)
- Nonce (uint64): random, for self-connection detection
- User agent (string): e.g., "/FlowCoin:1.0.0/"
- Start height (uint64): sender's best chain height

Self-connection detection: if the received nonce matches our own, disconnect.

### 3.4 Block Propagation

FlowCoin supports three block propagation modes:

1. **INV-based** (default): announce block hash via INV, peer requests via GETDATA
2. **Headers-first**: send block header directly via HEADERS message
3. **Compact blocks**: send header + short transaction IDs, peer reconstructs
   from its mempool; missing transactions requested via GETBLOCKTXN

Compact blocks use 6-byte short transaction IDs computed as:
```
short_id = Keccak256(block_hash || nonce || txid)[0..5]
```

### 3.5 Transaction Relay

Transactions propagate through the network via inventory announcements:

1. Node receives a new transaction
2. Validates it against the mempool and UTXO set
3. If accepted, adds to mempool and queues an INV announcement
4. INV announcements are batched ("trickled") every ~5 seconds per peer
5. Peers that set a fee filter receive only transactions above their threshold
6. Each transaction is announced at most once per peer

Orphan transactions (those referencing unknown parent transactions) are held
in an orphan pool (max 100 entries) and retried when parents arrive.

### 3.6 Address Propagation

Address management follows Bitcoin Core's addrman design:

- Addresses are stored in two tables: New (unverified) and Tried (connected successfully)
- On receiving an `addr` message, fresh addresses (< 10 min old) are relayed to 2 random peers
- On receiving `getaddr`, respond with ~23% of known addresses (max 1000)
- Nodes self-advertise their listening address every 24 hours
- Feeler connections test reachability of New table entries every 2 minutes

## 4. Transaction Format

### 4.1 Structure

A transaction consists of:

```
[4 bytes]  version:   uint32_le (currently 1)
[varint]   vin_count: number of inputs
[inputs]   vin:       array of CTxIn
[varint]   vout_count: number of outputs
[outputs]  vout:      array of CTxOut
[8 bytes]  locktime:  int64_le
```

**CTxIn** (128 bytes per input):
```
[32 bytes] prevout.txid:  uint256 (hash of the referenced transaction)
[4 bytes]  prevout.index: uint32_le (output index in that transaction)
[32 bytes] pubkey:        Ed25519 public key
[64 bytes] signature:     Ed25519 signature
```

For coinbase transactions, prevout is null (all zeros) and the pubkey field
encodes the block height in its first 8 bytes (BIP34 style).

**CTxOut** (40 bytes per output):
```
[8 bytes]  amount:      int64_le (in atomic units, 1 FLC = 10^8)
[32 bytes] pubkey_hash: Keccak256(recipient_pubkey)
```

### 4.2 Script

FlowCoin uses a simplified Pay-to-Public-Key-Hash (P2PKH) model with Ed25519:

To spend an output:
1. Provide the Ed25519 public key matching the output's pubkey_hash
2. Provide an Ed25519 signature over the transaction's signature hash
3. Verification: `Keccak256(pubkey) == output.pubkey_hash` AND `Ed25519_verify(sig, sighash, pubkey)`

There is no script interpreter; the verification is hardcoded.

### 4.3 Signature Hash

The signature hash (sighash) for each input is computed over:

```
sighash = Keccak256(
    tx.version ||
    // For each input (with the current input's signature zeroed):
    vin[i].prevout.txid || vin[i].prevout.index || vin[i].pubkey ||
    // For each output:
    vout[j].amount || vout[j].pubkey_hash ||
    tx.locktime
)
```

The signature field of the current input being signed is set to all zeros
during sighash computation.

## 5. Wallet

### 5.1 HD Derivation (SLIP-0010)

FlowCoin uses SLIP-0010 (Ed25519 variant of BIP32) for hierarchical deterministic
key derivation:

- Master key: derived from a BIP39 mnemonic seed via HMAC-SHA512
- Derivation path: `m/44'/9555'/account'/change'/index'`
  - 44' = BIP44 purpose
  - 9555' = FlowCoin coin type (registered)
  - All levels use hardened derivation (Ed25519 requires this)

### 5.2 Address Format

Addresses use **Bech32 v0** (BIP-173; not Bech32m) with:
- Human-readable prefix (HRP): `"fl"`
- Witness version: 0
- Witness program: 20 bytes — `keccak256d(pubkey)[0..20]`

Per BIP-350, witness version 0 uses the original Bech32 checksum
polynomial; witness v1+ would use Bech32m. That matches Bitcoin's
P2WPKH (`bc1q...`) format exactly, modulo the HRP: 42 characters,
same checksum, same encoding.

Example address: `fl1qdd2j0j3zz0s7q4xzu4huznu7zr5udt3sgg73kv`

### 5.3 Key Management

- **wallet.dat**: SQLite database storing encrypted private keys, HD chain state,
  transaction history, and address book
- **Keypool**: pre-generated pool of 100 keys for fresh receiving addresses
- **Encryption**: AES-256-CBC with a key derived from the wallet passphrase via
  Keccak256(passphrase || salt), with 100,000 iterations of key stretching
- **Backup**: wallet.dat can be copied while the node is running (SQLite WAL mode)
- **Import**: supports importing raw private keys and watching-only public keys

Each mined block uses a fresh address from the keypool, ensuring that the
coinbase output is always to a previously-unused address.

## 6. Storage

### 6.1 Block Files (blk*.dat)

Blocks are stored in flat files named `blk00000.dat`, `blk00001.dat`, etc.

Each file:
- Maximum size: 128 MB
- New file started when current file exceeds the limit
- Blocks are written sequentially (append-only)
- Block position recorded as (file_number, byte_offset)

File format:
```
For each block:
    [4 bytes] magic: network magic bytes
    [4 bytes] block_size: uint32_le
    [block_size bytes] serialized_block
```

Pruning: old block files can be deleted while retaining the UTXO set and
recent blocks. The node tracks which files are prunable.

### 6.2 UTXO Set (SQLite)

The UTXO set is stored in a SQLite database (`chainstate.db`):

```sql
CREATE TABLE utxos (
    txid BLOB NOT NULL,
    vout_index INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    pubkey_hash BLOB NOT NULL,
    height INTEGER NOT NULL,
    is_coinbase INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (txid, vout_index)
);

CREATE INDEX idx_utxo_pubkey_hash ON utxos(pubkey_hash);
CREATE INDEX idx_utxo_height ON utxos(height);
```

SQLite is used in WAL mode for concurrent read access during block validation.

## 7. Initial Block Download

### 7.1 Header-First Sync

1. Connect to peers and exchange version messages
2. Send `getheaders` with our current tip as the locator
3. Receive up to 2000 headers per message
4. Validate each header (difficulty, timestamp, height sequence)
5. Continue requesting headers until fully synced

### 7.2 Block Download Pipeline

1. Identify blocks we have headers for but not full blocks
2. Request full blocks from multiple peers in parallel
3. Validate and accept blocks in height order
4. Update the UTXO set

Target: download blocks from up to 8 peers simultaneously, with a sliding
window of 1024 blocks in flight.

### 7.3 Assume-Valid Optimization

For blocks below a hardcoded assume-valid hash, skip:
- Full signature verification (Ed25519 checks)

This speeds up initial sync. The assume-valid hash is updated
with each software release after sufficient network confirmation.

## 8. Genesis Block

The genesis block has the following fields:

```
height:        0
timestamp:     1776902400 (23/Apr/2026)
prev_hash:     0x0000000000000000000000000000000000000000000000000000000000000000
nbits:         0x1f00ffff
version:       1
nonce:         [computed at launch]
```

Coinbase message: `"Strait of Hormuz closed, oil hits $144 as energy crisis crushes miners 23/Apr/2026 - FlowCoin: CPU-only proof-of-work"` (encoded in the coinbase input pubkey field)

The genesis block reward of 50 FLC is unspendable (no valid private key for
the genesis coinbase address).

The genesis block hash and merkle root are hardcoded in the consensus parameters
and verified at node startup.

## 9. Mempool Policy

### 9.1 Transaction Acceptance

Transactions are accepted into the mempool if they pass these checks:

1. **Format validity**: Well-formed serialization, version == 1
2. **Not duplicate**: Not already in the mempool or blockchain
3. **Input existence**: All referenced outputs exist in the UTXO set or mempool
4. **No double-spend**: No input is already spent by another mempool transaction
5. **Amount validity**: Total outputs <= total inputs (no inflation)
6. **Signature validity**: All Ed25519 signatures verify correctly
7. **Minimum fee**: Fee rate >= 1 atomic unit per byte
8. **Dust threshold**: No output below 546 atomic units
9. **Size limit**: Transaction serialized size <= 100,000 bytes
10. **Locktime**: Transaction locktime has been reached (by height or time)

### 9.2 Mempool Limits

- Maximum mempool size: 300 MB
- Transaction expiry: 14 days (1,209,600 seconds)
- Maximum orphan transactions: 100
- Orphan expiry: 20 minutes
- Maximum transaction size: 100,000 bytes

When the mempool exceeds its size limit, transactions with the lowest fee rate
are evicted first. Fee-rate calculation uses ancestor-aware fee rates to support
child-pays-for-parent (CPFP) scenarios.

### 9.3 Replace-by-Fee

A transaction can replace an existing mempool transaction if:

1. It spends at least one of the same inputs
2. Its fee rate is at least 10% higher than the replaced transaction
3. It does not introduce new unconfirmed inputs
4. The total fees of the replacement exceed the total fees of all replaced
   transactions plus the minimum relay fee for the replacement

## 10. RPC Interface

### 10.1 Blockchain RPCs

| Method              | Parameters          | Description                          |
|---------------------|---------------------|--------------------------------------|
| getblockchaininfo   | -                   | Chain height, difficulty, model dims |
| getbestblockhash    | -                   | Hash of the tip block                |
| getblock            | hash, verbosity     | Block data at given hash             |
| getblockheader      | hash, verbose       | Block header at given hash           |
| getblockcount       | -                   | Current chain height                 |
| getdifficulty       | -                   | Current difficulty as float          |
| gettxout            | txid, n             | UTXO for given outpoint              |
| getmempoolinfo      | -                   | Mempool size, tx count, fees         |
| getrawmempool       | verbose              | List of mempool transaction IDs      |
| verifychain         | checklevel, nblocks  | Verify chain integrity               |

### 10.2 Mining RPCs

| Method              | Parameters          | Description                          |
|---------------------|---------------------|--------------------------------------|
| getblocktemplate    | -                   | Block template for miners            |
| submitblock         | hex_data            | Submit a mined block                 |
| getmininginfo       | -                   | Mining status, hashrate, difficulty  |
| getnetworkhashps    | nblocks, height     | Estimated network hash rate          |
| startmining         | address             | Start the internal miner             |
| stopmining          | -                   | Stop the internal miner              |

### 10.3 Wallet RPCs

| Method              | Parameters          | Description                          |
|---------------------|---------------------|--------------------------------------|
| getbalance          | -                   | Total confirmed balance              |
| getnewaddress       | label               | Generate a fresh receiving address   |
| sendtoaddress       | address, amount     | Create and broadcast a transaction   |
| listtransactions    | count, skip         | Transaction history                  |
| listunspent         | minconf, maxconf    | Available UTXOs                      |
| dumpprivkey         | address             | Export private key (WIF format)       |
| importprivkey       | key, label          | Import a private key                 |
| encryptwallet       | passphrase          | Encrypt the wallet                   |
| walletpassphrase    | passphrase, timeout | Unlock the wallet temporarily        |
| backupwallet        | destination         | Copy wallet.dat to destination       |

### 10.4 Network RPCs

| Method              | Parameters          | Description                          |
|---------------------|---------------------|--------------------------------------|
| getpeerinfo         | -                   | Connected peer details               |
| getnetworkinfo      | -                   | Network status and statistics        |
| addnode             | ip:port, command    | Add/remove/connect to a node         |
| disconnectnode      | ip:port             | Disconnect from a peer               |
| getconnectioncount  | -                   | Number of connected peers            |
| ping                | -                   | Ping all connected peers             |

## 11. Compact Block Protocol Details

### 11.1 Short Transaction ID Computation

Short IDs are computed using Keccak-256 with a per-block nonce:

```
input = block_hash || nonce || txid
short_id = Keccak256(input)[0..5]  // First 6 bytes (48 bits)
```

The 48-bit short ID has a collision probability of approximately 1 in 2^48
per transaction pair, which is negligible for typical block sizes.

### 11.2 Compact Block Reconstruction

When a node receives a compact block:

1. Extract prefilled transactions (always includes the coinbase)
2. For each short ID, search the mempool for a matching transaction
3. If all transactions are found, reconstruct the full block
4. If any are missing, request them via `getblocktxn`
5. Upon receiving `blocktxn`, complete the reconstruction
6. Validate the reconstructed block normally

### 11.3 High-Bandwidth vs Low-Bandwidth Mode

- **High-bandwidth**: compact blocks sent immediately without INV/GETDATA round-trip
- **Low-bandwidth**: only INV is sent; peer requests compact block via GETDATA

Peers signal their preference via the `sendcmpct` message:
- `announce = 1`: high-bandwidth mode (receive unsolicited compact blocks)
- `announce = 0`: low-bandwidth mode (receive only INV announcements)

## 12. Error Handling and Misbehavior

### 12.1 Misbehavior Scoring

Each peer accumulates a misbehavior score. Specific violations add points:

| Violation                        | Points |
|----------------------------------|--------|
| Invalid message format           | 10     |
| Duplicate version message        | 10     |
| Invalid block header             | 10     |
| Invalid block (full validation)  | 20     |
| Oversized message                | 50     |
| Wrong magic bytes                | 50     |
| Too many addresses per message   | 20     |
| Oversized inv message            | 20     |
| Invalid compact block            | 10-20  |
| Negative fee filter              | 10     |
| Excessive fee filter             | 10     |

When a peer's score reaches 100, they are banned for 24 hours and disconnected.

### 12.2 Ban Duration

Default ban duration: 86,400 seconds (24 hours).
Bans are persisted across restarts via the ban list stored in `banlist.dat`.
Expired bans are swept every 5 minutes.

### 12.3 Connection Limits

| Parameter            | Value |
|----------------------|-------|
| Max outbound peers   | 8     |
| Max inbound peers    | 117   |
| Max total peers      | 125   |
| Handshake timeout    | 60s   |
| Idle timeout         | 1200s |
| Max per-IP inbound   | 3     |
| Max per-/16 outbound | 2     |

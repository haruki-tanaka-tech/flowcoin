# FlowCoin Protocol Specification v1.0

## 1. Overview

FlowCoin is a Proof-of-Training (PoT) blockchain where miners train a neural network
(ResonanceNet V5) and submit weight updates as proof of computational work. The protocol
combines elements of Bitcoin's economic model (21M supply, 10-minute blocks, halving schedule)
with a novel consensus mechanism that makes mining computationally useful.

Instead of computing trillions of SHA-256 hashes, FlowCoin miners perform gradient descent
on a shared neural network. The training hash, derived from the weight delta and evaluation
dataset, must satisfy a difficulty target analogous to Bitcoin's proof-of-work requirement.

The result is a blockchain that:
- Produces a continuously improving AI model as a public good
- Uses Keccak-256 (SHA-3 finalist) for all hashing instead of SHA-256d
- Implements Ed25519 signatures instead of secp256k1 ECDSA
- Uses bech32m addresses with the "fl" human-readable prefix

This document specifies the complete protocol: consensus rules, block format,
transaction format, network protocol, and storage format.

## 2. Consensus Rules

### 2.1 Block Header (308 bytes)

The block header is a fixed 308-byte structure consisting of 244 bytes of unsigned
data followed by a 64-byte Ed25519 signature.

| Offset | Size | Field            | Type      | Description                            |
|--------|------|------------------|-----------|----------------------------------------|
| 0      | 32   | prev_hash        | uint256   | Hash of the previous block header      |
| 32     | 32   | merkle_root      | uint256   | Merkle root of all transactions        |
| 64     | 32   | training_hash    | uint256   | Keccak256(delta_hash || dataset_hash)  |
| 96     | 32   | dataset_hash     | uint256   | Keccak256(evaluation_dataset)          |
| 128    | 8    | height           | uint64_le | Block height (0 = genesis)             |
| 136    | 8    | timestamp        | int64_le  | Unix timestamp (seconds since epoch)   |
| 144    | 4    | nbits            | uint32_le | Compact difficulty target              |
| 148    | 4    | val_loss         | float32   | IEEE 754 validation loss after training|
| 152    | 4    | prev_val_loss    | float32   | Parent block's validation loss         |
| 156    | 4    | d_model          | uint32_le | Model embedding dimension              |
| 160    | 4    | n_layers         | uint32_le | Number of transformer layers           |
| 164    | 4    | d_ff             | uint32_le | Feed-forward intermediate dimension    |
| 168    | 4    | n_heads          | uint32_le | Number of attention heads              |
| 172    | 4    | gru_dim          | uint32_le | MinGRU hidden dimension                |
| 176    | 4    | n_slots          | uint32_le | Number of slot memory entries           |
| 180    | 4    | train_steps      | uint32_le | Training steps performed               |
| 184    | 4    | stagnation       | uint32_le | Consecutive non-improving blocks       |
| 188    | 4    | delta_offset     | uint32_le | Byte offset into delta payload         |
| 192    | 4    | delta_length     | uint32_le | Byte length of compressed delta        |
| 196    | 4    | sparse_count     | uint32_le | Non-zero elements in sparse delta      |
| 200    | 4    | sparse_threshold | float32   | Sparsification threshold used          |
| 204    | 4    | nonce            | uint32_le | Mining nonce                           |
| 208    | 4    | version          | uint32_le | Block version (currently 1)            |
| 212    | 32   | miner_pubkey     | bytes32   | Ed25519 public key of the miner        |
| 244    | 64   | miner_sig        | bytes64   | Ed25519 signature over bytes [0..243]  |

Total: 308 bytes.

The block hash is computed as:
```
block_hash = Keccak256d(header[0..307])
```
where Keccak256d(x) = Keccak256(Keccak256(x)).

### 2.2 Block Validation (16 checks)

Every block must pass all 16 validation checks to be accepted:

1. **Version check**: `block.version == 1` (current protocol version).

2. **Height check**: `block.height == parent.height + 1`, or `height == 0` for genesis.

3. **Previous hash**: `block.prev_hash == parent.get_hash()`.

4. **Timestamp bounds**:
   - `block.timestamp > median_time_past(11)` (median of last 11 block timestamps)
   - `block.timestamp <= current_time + 7200` (no more than 2 hours in the future)

5. **Minimum block interval**: `block.timestamp >= parent.timestamp + 60` (1 minute minimum).

6. **Difficulty target**: `block.nbits` must equal the expected difficulty:
   - At retarget boundaries (height % 2016 == 0): recalculated from the last 2016 blocks
   - Otherwise: inherited from parent

7. **Training hash validity**:
   ```
   expected = Keccak256(block.delta_hash || block.dataset_hash)
   assert(block.training_hash == expected)
   assert(block.training_hash < target_from_nbits(block.nbits))
   ```

8. **Model dimensions**: `(d_model, n_layers, d_ff, n_heads, gru_dim, n_slots)` must
   match `compute_growth(height)`.

9. **Validation loss**: `0.0 < block.val_loss <= 100.0`.

10. **Previous val_loss**: `block.prev_val_loss == parent.val_loss`.

11. **Stagnation counter**:
    - If `parent.val_loss >= parent.prev_val_loss`: `block.stagnation == parent.stagnation + 1`
    - Otherwise: `block.stagnation == 0`

12. **Minimum training steps**: `block.train_steps >= compute_min_steps(height)`.

13. **Merkle root**: `block.merkle_root == compute_merkle_root(block.vtx)`.

14. **Signature verification**: Ed25519 verify `miner_sig` over `header[0..243]` with
    `miner_pubkey`.

15. **Coinbase validation**: First transaction must be a valid coinbase:
    - Exactly one input with null prevout
    - Output amount <= block_reward + total_fees
    - Height encoded in coinbase input's pubkey field (BIP34 style)

16. **Transaction validation**: All non-coinbase transactions must:
    - Have valid Ed25519 signatures for all inputs
    - Reference existing unspent outputs
    - Total output amount <= total input amount
    - Not double-spend within the same block

### 2.3 Difficulty Adjustment

FlowCoin uses Bitcoin's difficulty adjustment algorithm with Keccak-256 hashing.

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
- `INITIAL_REWARD = 50 * 10^8` (50 FLOW in atomic units)
- `HALVING_INTERVAL = 210,000 blocks` (~4 years at 10-minute blocks)
- `MAX_SUPPLY = 21,000,000 FLOW`
- Minimum reward: 1 atomic unit. Below this, subsidy is zero.

Halving schedule:

| Era | Block Range       | Reward (FLOW) | Cumulative Supply |
|-----|-------------------|---------------|-------------------|
| 1   | 0 - 209,999       | 50.0          | 10,500,000        |
| 2   | 210,000 - 419,999 | 25.0          | 15,750,000        |
| 3   | 420,000 - 629,999 | 12.5          | 18,375,000        |
| 4   | 630,000 - 839,999 | 6.25          | 19,687,500        |
| ... | ...               | ...           | ...               |

### 2.5 Model Growth Schedule

The neural network grows CONTINUOUSLY -- every block adds parameters.
There are no phases, no plateaus, and no cap on slots.

**Dimension Growth (blocks 0-511)**

Dimensions grow linearly with block height, then freeze:

```
d_model(h)  = 512 + h             (capped at 1024)
n_layers(h) = 8 + floor(h / 32)   (capped at 24)
d_ff(h)     = 2 * d_model(h)
n_heads(h)  = floor(d_model(h) / 64)
gru_dim(h)  = d_model(h)
```

At block 512, dimensions reach their maximum (d=1024, L=24) and freeze.

**Slot Growth (every block, no cap)**

Slots grow at every block height, with no upper bound:

```
n_slots(h) = 1024 + h * 4
```

| Block     | d_model | n_layers | n_slots   | ~Params  |
|-----------|---------|----------|-----------|----------|
| 0         | 512     | 8        | 1,024     | ~13M     |
| 100       | 612     | 11       | 1,424     | ~35M     |
| 500       | 1,012   | 23       | 3,024     | ~180M    |
| 512+      | 1,024   | 24       | growing   | growing  |
| 10,000    | 1,024   | 24       | 41,024    | ~3B      |
| 100,000   | 1,024   | 24       | 401,024   | ~30B     |
| 1,000,000 | 1,024   | 24       | 4,001,024 | ~300B    |

Inference remains O(1) because only top_k=2 slots are active per token,
regardless of total slot count.

**Weight Expansion**

When dimensions increase (blocks 0-511), existing weights are preserved and expanded:
- New rows/columns are initialized from the deterministic weight initializer
- Existing learned weights occupy the top-left submatrix of the expanded tensor
- This preserves all training progress while allowing the model to utilize
  the additional capacity

## 3. Proof-of-Training

### 3.1 Training Hash

The training hash serves as the proof-of-work equivalent. It is computed as:

```
training_hash = Keccak256(delta_hash || dataset_hash)
```

Where:
- `delta_hash = Keccak256(compressed_delta_payload)` -- hash of the compressed weight delta
- `dataset_hash = Keccak256(evaluation_dataset)` -- hash of the deterministic eval data

A block is valid if and only if: `training_hash < target`

This means the miner must find a combination of training parameters that produces
a delta whose hash, combined with the dataset hash, is below the difficulty target.
Different training runs produce different deltas (due to random initialization, batch
ordering, etc.), so miners must actually perform the training to generate candidates.

### 3.2 Forward Evaluation

Validation of the training result requires a deterministic forward pass:

1. Load the cumulative model state (sum of all prior deltas)
2. Apply the candidate delta from the current block
3. Run forward inference on the evaluation dataset
4. The resulting val_loss must match `block.val_loss` within floating-point tolerance

All nodes must produce identical evaluation results. This is achieved by:
- Using IEEE 754 single-precision arithmetic without -ffast-math
- Deterministic operation ordering (no parallelism in the eval path)
- Fixed evaluation dataset derived from the block height

### 3.3 Validation Data Generation

The evaluation dataset is generated deterministically using Keccak-256 in counter mode:

```
for i in 0..EVAL_TOKENS:
    eval_data[i*4..(i+1)*4] = Keccak256(height || counter)[0..3]
    counter++
```

Where:
- `EVAL_TOKENS = 4096`
- `EVAL_SEQ_LEN = 256` (tokens per forward pass)
- This produces 16 forward passes per evaluation

All nodes generate identical evaluation data for the same block height,
ensuring consensus on the val_loss computation.

### 3.4 Delta Payload Format

The weight delta is the difference between the model weights before and after training.
It is compressed for storage efficiency.

**Sparse Format** (when most values are near zero):
```
[4 bytes] magic: 0x53504152 ("SPAR")
[4 bytes] total_elements: uint32_le
[4 bytes] nonzero_count: uint32_le
[4 bytes] sparse_threshold: float32
For each nonzero element:
    [4 bytes] index: uint32_le
    [4 bytes] value: float32
```

**Dense Format** (when many values are significant):
```
[4 bytes] magic: 0x44454E53 ("DENS")
[4 bytes] total_elements: uint32_le
[total_elements * 4 bytes] values: float32[]
```

Both formats are then compressed with Zstandard (zstd) at compression level 3.

The final delta payload stored in the block is:
```
[zstd_compressed(sparse_or_dense_payload)]
```

Maximum delta size: 100 MB (after compression).

## 4. ResonanceNet V5 Architecture

### 4.1 Layer Structure

Each layer of the ResonanceNet V5 model consists of:

1. **Multi-Head Self-Attention** (causal):
   - Q, K, V projections: d_model -> d_model
   - n_heads attention heads, each with d_head = d_model / n_heads
   - Causal mask prevents attending to future positions
   - Output projection: d_model -> d_model

2. **MinGRU Recurrence**:
   - Gate: Linear(d_model, gru_dim) + sigmoid
   - Candidate: Linear(d_model, gru_dim) + tanh
   - State update: h_t = gate * h_{t-1} + (1 - gate) * candidate
   - Output: Linear(gru_dim, d_model)
   - O(1) state per token (constant memory regardless of sequence length)

3. **Feed-Forward Network**:
   - Up projection: Linear(d_model, d_ff)
   - Activation: GELU
   - Down projection: Linear(d_ff, d_model)

4. **Multi-Scale Convolution**:
   - Three parallel 1D causal convolutions with kernel sizes 3, 5, 7
   - Each produces d_model/3 channels
   - Concatenated and projected back to d_model
   - Captures local n-gram patterns complementing attention's global patterns

5. **Layer Normalization** (pre-norm style):
   - Applied before each sub-layer
   - RMSNorm variant for efficiency

6. **Slot Memory** (read-only per layer):
   - n_slots memory vectors of dimension d_model
   - Cross-attention from the hidden states to slot memory
   - Provides persistent knowledge storage separate from sequence context
   - Slots grow every block (no cap)

### 4.2 Weight Initialization

All weights are initialized deterministically from a seed derived from the genesis
block hash:

```
seed = Keccak256("FlowCoin ResonanceNet V5 Init" || genesis_hash)
rng = DeterministicRNG(seed)
```

For each parameter tensor:
```
fan_in = input_dimension
fan_out = output_dimension
std = sqrt(2.0 / (fan_in + fan_out))  // Glorot uniform
weight[i] = rng.next_normal(0.0, std)
```

This ensures all nodes start with identical initial weights.

### 4.3 Model Growth

When the model dimensions increase at a growth event:

1. The new parameter tensors are allocated at the larger dimensions
2. Existing weights are copied into the top-left submatrix
3. New rows/columns are initialized using the deterministic initializer
   with a seed derived from `Keccak256(growth_event_height || param_name)`
4. The model state checkpoint is updated to reflect the new dimensions

## 5. Network Protocol

### 5.1 Wire Format

All messages use a 24-byte header followed by a variable-length payload:

```
[4 bytes] magic:        uint32_le (mainnet: 0xF9BEB4D9)
[12 bytes] command:     ASCII, null-padded to 12 bytes
[4 bytes] payload_size: uint32_le
[4 bytes] checksum:     first 4 bytes of Keccak256(payload)
```

Maximum payload size: 32,000,000 bytes (matching MAX_BLOCK_SIZE).

### 5.2 Messages

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

### 5.3 Handshake

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

### 5.4 Block Propagation

FlowCoin supports three block propagation modes:

1. **INV-based** (default): announce block hash via INV, peer requests via GETDATA
2. **Headers-first**: send block header directly via HEADERS message
3. **Compact blocks**: send header + short transaction IDs, peer reconstructs
   from its mempool; missing transactions requested via GETBLOCKTXN

Compact blocks use 6-byte short transaction IDs computed as:
```
short_id = Keccak256(block_hash || nonce || txid)[0..5]
```

### 5.5 Transaction Relay

Transactions propagate through the network via inventory announcements:

1. Node receives a new transaction
2. Validates it against the mempool and UTXO set
3. If accepted, adds to mempool and queues an INV announcement
4. INV announcements are batched ("trickled") every ~5 seconds per peer
5. Peers that set a fee filter receive only transactions above their threshold
6. Each transaction is announced at most once per peer

Orphan transactions (those referencing unknown parent transactions) are held
in an orphan pool (max 100 entries) and retried when parents arrive.

### 5.6 Address Propagation

Address management follows Bitcoin Core's addrman design:

- Addresses are stored in two tables: New (unverified) and Tried (connected successfully)
- On receiving an `addr` message, fresh addresses (< 10 min old) are relayed to 2 random peers
- On receiving `getaddr`, respond with ~23% of known addresses (max 1000)
- Nodes self-advertise their listening address every 24 hours
- Feeler connections test reachability of New table entries every 2 minutes

## 6. Transaction Format

### 6.1 Structure

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
[8 bytes]  amount:      int64_le (in atomic units, 1 FLOW = 10^8)
[32 bytes] pubkey_hash: Keccak256(recipient_pubkey)
```

### 6.2 Script

FlowCoin uses a simplified Pay-to-Public-Key-Hash (P2PKH) model with Ed25519:

To spend an output:
1. Provide the Ed25519 public key matching the output's pubkey_hash
2. Provide an Ed25519 signature over the transaction's signature hash
3. Verification: `Keccak256(pubkey) == output.pubkey_hash` AND `Ed25519_verify(sig, sighash, pubkey)`

There is no script interpreter; the verification is hardcoded.

### 6.3 Signature Hash

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

## 7. Wallet

### 7.1 HD Derivation (SLIP-0010)

FlowCoin uses SLIP-0010 (Ed25519 variant of BIP32) for hierarchical deterministic
key derivation:

- Master key: derived from a BIP39 mnemonic seed via HMAC-SHA512
- Derivation path: `m/44'/9555'/account'/change'/index'`
  - 44' = BIP44 purpose
  - 9555' = FlowCoin coin type (registered)
  - All levels use hardened derivation (Ed25519 requires this)

### 7.2 Address Format

Addresses use Bech32m encoding (BIP350) with:
- Human-readable prefix (HRP): `"fl"`
- Witness version: 0
- Witness program: 20 bytes (first 20 bytes of Keccak256(pubkey))

Example address: `fl1qw508d6qejxtdg4y5r3zarvaryvg6gdjs`

### 7.3 Key Management

- **wallet.dat**: SQLite database storing encrypted private keys, HD chain state,
  transaction history, and address book
- **Keypool**: pre-generated pool of 100 keys for fresh receiving addresses
- **Encryption**: AES-256-CBC with a key derived from the wallet passphrase via
  Keccak256(passphrase || salt), with 100,000 iterations of key stretching
- **Backup**: wallet.dat can be copied while the node is running (SQLite WAL mode)
- **Import**: supports importing raw private keys and watching-only public keys

Each mined block uses a fresh address from the keypool, ensuring that the
coinbase output is always to a previously-unused address.

## 8. Storage

### 8.1 Block Files (blk*.dat)

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

### 8.2 UTXO Set (SQLite)

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

### 8.3 Model State

The cumulative model state (sum of all deltas) is checkpointed periodically:

- Checkpoint interval: every 1000 blocks
- Format: raw float32 arrays in the order defined by the model architecture
- File: `model_checkpoint_NNNNNN.bin` where NNNNNN is the block height
- Size: proportional to parameter count (initially ~160 KB, growing to ~100 MB)

During initial block download, model checkpoints can be downloaded from peers
via the assume-valid optimization to avoid replaying all training from genesis.

## 9. Initial Block Download

### 9.1 Header-First Sync

1. Connect to peers and exchange version messages
2. Send `getheaders` with our current tip as the locator
3. Receive up to 2000 headers per message
4. Validate each header (difficulty, timestamp, height sequence)
5. Continue requesting headers until fully synced

### 9.2 Block Download Pipeline

1. Identify blocks we have headers for but not full blocks
2. Request full blocks from multiple peers in parallel
3. Validate and accept blocks in height order
4. Apply each block's delta to the cumulative model state
5. Update the UTXO set

Target: download blocks from up to 8 peers simultaneously, with a sliding
window of 1024 blocks in flight.

### 9.3 Assume-Valid Optimization

For blocks below a hardcoded assume-valid hash, skip:
- Full signature verification (Ed25519 checks)
- Training hash validation (expensive forward pass)

This dramatically speeds up initial sync. The assume-valid hash is updated
with each software release after sufficient network confirmation.

### 9.4 Model Checkpoints

During sync, if a trusted model checkpoint is available at a recent height,
the node can:
1. Download the checkpoint file
2. Verify its hash matches the expected value
3. Load the model state directly
4. Only replay deltas from the checkpoint height forward

This avoids replaying millions of training steps during initial sync.

## 10. Genesis Block

The genesis block has the following fields:

```
height:        0
timestamp:     [TBD at launch]
prev_hash:     0x0000000000000000000000000000000000000000000000000000000000000000
nbits:         0x1f00ffff
version:       1
d_model:       512
n_layers:      8
d_ff:          1024
n_heads:       8
gru_dim:       512
n_slots:       1024
val_loss:      100.0
prev_val_loss: 100.0
train_steps:   0
stagnation:    0
nonce:         [computed at launch]
```

Coinbase message: `"FlowCoin Genesis"` (encoded in the coinbase input pubkey field)

The genesis block reward of 50 FLOW is unspendable (no valid private key for
the genesis coinbase address).

The genesis block hash and merkle root are hardcoded in the consensus parameters
and verified at node startup.

## 11. Mempool Policy

### 11.1 Transaction Acceptance

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

### 11.2 Mempool Limits

- Maximum mempool size: 300 MB
- Transaction expiry: 14 days (1,209,600 seconds)
- Maximum orphan transactions: 100
- Orphan expiry: 20 minutes
- Maximum transaction size: 100,000 bytes

When the mempool exceeds its size limit, transactions with the lowest fee rate
are evicted first. Fee-rate calculation uses ancestor-aware fee rates to support
child-pays-for-parent (CPFP) scenarios.

### 11.3 Replace-by-Fee

A transaction can replace an existing mempool transaction if:

1. It spends at least one of the same inputs
2. Its fee rate is at least 10% higher than the replaced transaction
3. It does not introduce new unconfirmed inputs
4. The total fees of the replacement exceed the total fees of all replaced
   transactions plus the minimum relay fee for the replacement

## 12. RPC Interface

### 12.1 Blockchain RPCs

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

### 12.2 Mining RPCs

| Method              | Parameters          | Description                          |
|---------------------|---------------------|--------------------------------------|
| getblocktemplate    | -                   | Block template for miners            |
| submitblock         | hex_data            | Submit a mined block                 |
| getmininginfo       | -                   | Mining status, hashrate, difficulty  |
| getnetworkhashps    | nblocks, height     | Estimated network hash rate          |
| startmining         | address             | Start the internal miner             |
| stopmining          | -                   | Stop the internal miner              |
| gettraininginfo     | -                   | Model state, val_loss, dimensions    |

### 12.3 Wallet RPCs

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

### 12.4 Network RPCs

| Method              | Parameters          | Description                          |
|---------------------|---------------------|--------------------------------------|
| getpeerinfo         | -                   | Connected peer details               |
| getnetworkinfo      | -                   | Network status and statistics        |
| addnode             | ip:port, command    | Add/remove/connect to a node         |
| disconnectnode      | ip:port             | Disconnect from a peer               |
| getconnectioncount  | -                   | Number of connected peers            |
| ping                | -                   | Ping all connected peers             |

## 13. Compact Block Protocol Details

### 13.1 Short Transaction ID Computation

Short IDs are computed using Keccak-256 with a per-block nonce:

```
input = block_hash || nonce || txid
short_id = Keccak256(input)[0..5]  // First 6 bytes (48 bits)
```

The 48-bit short ID has a collision probability of approximately 1 in 2^48
per transaction pair, which is negligible for typical block sizes.

### 13.2 Compact Block Reconstruction

When a node receives a compact block:

1. Extract prefilled transactions (always includes the coinbase)
2. For each short ID, search the mempool for a matching transaction
3. If all transactions are found, reconstruct the full block
4. If any are missing, request them via `getblocktxn`
5. Upon receiving `blocktxn`, complete the reconstruction
6. Validate the reconstructed block normally

### 13.3 High-Bandwidth vs Low-Bandwidth Mode

- **High-bandwidth**: compact blocks sent immediately without INV/GETDATA round-trip
- **Low-bandwidth**: only INV is sent; peer requests compact block via GETDATA

Peers signal their preference via the `sendcmpct` message:
- `announce = 1`: high-bandwidth mode (receive unsolicited compact blocks)
- `announce = 0`: low-bandwidth mode (receive only INV announcements)

## 14. Error Handling and Misbehavior

### 14.1 Misbehavior Scoring

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

### 14.2 Ban Duration

Default ban duration: 86,400 seconds (24 hours).
Bans are persisted across restarts via the ban list stored in `banlist.dat`.
Expired bans are swept every 5 minutes.

### 14.3 Connection Limits

| Parameter            | Value |
|----------------------|-------|
| Max outbound peers   | 8     |
| Max inbound peers    | 117   |
| Max total peers      | 125   |
| Handshake timeout    | 60s   |
| Idle timeout         | 1200s |
| Max per-IP inbound   | 3     |
| Max per-/16 outbound | 2     |

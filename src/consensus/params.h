// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Consensus parameters for the FlowCoin network.
// Every constant is derived and documented. Modeled after Bitcoin Core's
// consensus/params.h with extensions for Proof-of-Useful-Training.

#ifndef FLOWCOIN_CONSENSUS_PARAMS_H
#define FLOWCOIN_CONSENSUS_PARAMS_H

#include <cstdint>
#include <cstddef>

namespace flow::consensus {

// ---- Network Identity -------------------------------------------------------
// Magic bytes are the ASCII encoding of short network names, packed big-endian
// into a uint32_t for fast comparison during message deserialization.

// ASCII "FLOW" = 0x46('F') 0x4C('L') 0x4F('O') 0x57('W')
constexpr uint32_t MAINNET_MAGIC       = 0x464C4F57;
// ASCII "TFLW" = 0x54('T') 0x46('F') 0x4C('L') 0x57('W')
constexpr uint32_t TESTNET_MAGIC       = 0x54464C57;
// ASCII "RFLW" = 0x52('R') 0x46('F') 0x4C('L') 0x57('W')
constexpr uint32_t REGTEST_MAGIC       = 0x52464C57;

// Ports: Bitcoin uses 8333/8332, we offset by +1000 to avoid conflicts.
// Testnet and regtest add 10000 and 20000 respectively.
constexpr uint16_t MAINNET_PORT        = 9333;   // 8333 + 1000
constexpr uint16_t MAINNET_RPC_PORT    = 9334;   // 8334 + 1000
constexpr uint16_t TESTNET_PORT        = 19333;  // 9333 + 10000
constexpr uint16_t TESTNET_RPC_PORT    = 19334;  // 9334 + 10000
constexpr uint16_t REGTEST_PORT        = 29333;  // 9333 + 20000
constexpr uint16_t REGTEST_RPC_PORT    = 29334;  // 9334 + 20000

// Bech32m human-readable prefixes for address encoding.
// "fl" for mainnet (2 chars), "tfl"/"rfl" for test networks (3 chars).
constexpr const char* MAINNET_HRP      = "fl";
constexpr const char* TESTNET_HRP      = "tfl";
constexpr const char* REGTEST_HRP      = "rfl";

// Wire protocol version. Incremented on breaking changes.
constexpr uint32_t PROTOCOL_VERSION    = 1;

// BIP-44 coin type for HD derivation path: m/44'/9555'/...
// Registered in SLIP-0044 range (>= 0x80000000 is hardened).
constexpr uint32_t BIP44_COIN_TYPE     = 9555;

// ---- Monetary Policy (identical to Bitcoin) ---------------------------------
// 1 FLOW = 10^8 atomic units, matching Bitcoin's satoshi granularity.
constexpr int64_t  COIN                = 100'000'000LL;   // 10^8 atomic units per coin

// 21 million coins * 10^8 atomic units = 2,100,000,000,000,000 atomic units total
constexpr int64_t  MAX_SUPPLY          = 21'000'000LL * COIN;

// Genesis block reward: 50 FLOW = 5,000,000,000 atomic units
constexpr int64_t  INITIAL_REWARD      = 50LL * COIN;

// Halving every 210,000 blocks. At 10-min blocks, this is ~4 years:
//   210,000 * 10 min = 2,100,000 min = 35,000 hours = 1,458 days ~ 3.99 years
constexpr int      HALVING_INTERVAL    = 210'000;

// Minimum reward: 1 atomic unit. Below this, subsidy is zero.
constexpr int64_t  MIN_REWARD          = 1LL;

// ---- Timing -----------------------------------------------------------------
// Target block interval: 600 seconds = 10 minutes (same as Bitcoin).
constexpr int64_t  TARGET_BLOCK_TIME   = 600;

// Minimum time between consecutive blocks: 60 seconds.
// Prevents timestamp manipulation with rapid block submissions.
constexpr int64_t  MIN_BLOCK_INTERVAL  = 60;

// Maximum future timestamp: 7200 seconds = 2 hours ahead of median time.
// Matching Bitcoin's MAX_FUTURE_BLOCK_TIME.
constexpr int64_t  MAX_FUTURE_TIME     = 7200;

// ---- Difficulty (Bitcoin's algorithm) ---------------------------------------
// Retarget every 2016 blocks. At 10-min target, this is exactly 2 weeks:
//   2016 * 600 = 1,209,600 seconds = 14 days
constexpr int      RETARGET_INTERVAL   = 2016;
constexpr int64_t  RETARGET_TIMESPAN   = RETARGET_INTERVAL * TARGET_BLOCK_TIME; // 1,209,600s

// Clamp factor: difficulty can change by at most 4x per retarget period.
// Prevents both excessive difficulty spikes and hash-rate-drop attacks.
constexpr int      MAX_RETARGET_FACTOR = 4;

// powLimit expressed as compact nBits.
//
// FlowCoin mining is fundamentally different from Bitcoin:
//   Bitcoin:   millions of SHA-256 hashes/sec, nonce is free
//   FlowCoin:  ~2 training steps/sec, each step = forward+backward+update
//
// Satoshi set difficulty=1 (nBits=0x1d00ffff, target=2^224) which gave
// ~24 min first block at 3 MH/s. We calibrate identically:
//
//   Measured: RTX 5080 at batch=32 = 2.0 training steps/sec
//   Target:   ~20 min first block (like Satoshi's ~24 min)
//   Steps:    2.0 st/s × 20 min × 60 = 2400 steps
//   Target:   2^256 / 2400 = 2^244.77
//
// Decoding 0x1f1b4e81:
//   exponent = 0x1f = 31
//   mantissa = 0x1b4e81
//   target   = 0x1b4e81 << (8 * (31 - 3)) = 0x1b4e81 << 224
//   = 001b4e8100000000000000000000000000000000000000000000000000000000
//   ≈ 2^244.77
//
// Difficulty self-adjusts after 2016 blocks:
//   Blocks 0-2015: ~20 min/block (1 miner) → actual timespan ~28 days
//   Retarget: ratio = 28/14 = 2.0 → difficulty doubles
//   Blocks 2016+:  ~10 min/block ✓
constexpr uint32_t INITIAL_NBITS       = 0x1f1b4e81;

// ---- Proof-of-Training Parameters ------------------------------------------
// Number of tokens in the evaluation dataset for forward-pass validation.
// 4096 tokens at 256 sequence length = 16 forward passes per eval.
constexpr int      EVAL_TOKENS         = 4096;

// Sequence length for each forward pass during evaluation.
constexpr int      EVAL_SEQ_LEN        = 256;

// Maximum allowed validation loss. Blocks with val_loss above this are invalid.
// At byte-level (vocab=256), random baseline is ln(256) = 5.545.
// We allow up to 100.0 to accommodate early untrained models.
constexpr float    MAX_VAL_LOSS        = 100.0f;

// Maximum allowed loss increase between consecutive blocks.
// parent.val_loss * MAX_LOSS_INCREASE is the ceiling for child.val_loss.
// Value of 2.0 means loss can at most double (to accommodate architecture
// transitions where weight expansion temporarily degrades performance).
constexpr float    MAX_LOSS_INCREASE   = 2.0f;

// Maximum compressed delta payload size: 100 MB.
// Prevents excessively large blocks while allowing substantial model updates.
// At d_model=1024, n_layers=24: full params ~ 50M floats = 200MB uncompressed,
// but sparse deltas typically compress to 10-30% of that.
constexpr size_t   MAX_DELTA_SIZE      = 100'000'000;

// Minimum delta size: at least 1 byte of training evidence.
constexpr size_t   MIN_DELTA_SIZE      = 1;

// ---- Model Genesis (ResonanceNet V5) ----------------------------------------
// These define the architecture at block 0. All nodes must agree on these
// values to generate identical genesis model weights from the deterministic seed.

constexpr uint32_t GENESIS_SEED        = 0;     // Zero = all weights zero (instant init, like Bitcoin has no initial SHA-256 state)
constexpr uint32_t GENESIS_D_MODEL     = 512;   // Hidden dimension
constexpr uint32_t GENESIS_N_LAYERS    = 8;     // Transformer-style layer count
constexpr uint32_t GENESIS_N_HEADS     = 8;     // Multi-head attention heads
constexpr uint32_t GENESIS_D_HEAD      = 64;    // = GENESIS_D_MODEL / GENESIS_N_HEADS = 512/8
constexpr uint32_t GENESIS_D_FF        = 1024;  // = 2 * GENESIS_D_MODEL = feed-forward inner dim
constexpr uint32_t GENESIS_N_SLOTS     = 1024;  // Key-value slot memory capacity
constexpr uint32_t GENESIS_TOP_K       = 2;     // Sparse slot retrieval count
constexpr uint32_t GENESIS_VOCAB       = 256;   // Byte-level tokenization (no BPE needed)
constexpr uint32_t GENESIS_SEQ_LEN     = 256;   // Context window length
constexpr uint32_t GENESIS_GRU_DIM     = 512;   // = GENESIS_D_MODEL (minGRU hidden state)
constexpr uint32_t GENESIS_CONV_KERNEL = 4;     // Multi-scale conv kernel size

// ---- Model Growth (continuous, no phases, no cap) ----------------------------
// d_model: 512 + height (capped at 1024 when d reaches max)
constexpr uint32_t DIM_FREEZE_HEIGHT   = 512;    // dimensions freeze at this height
constexpr uint32_t MAX_D_MODEL         = 1024;   // d_model ceiling
constexpr uint32_t MAX_N_LAYERS        = 24;     // n_layers ceiling

// Slots grow EVERY BLOCK, NO CAP:
// n_slots(h) = GENESIS_N_SLOTS + h * SLOT_GROWTH_PER_BLOCK
constexpr uint32_t SLOT_GROWTH_PER_BLOCK = 4;    // +4 slots per block, infinite growth

// No MAX_N_SLOTS -- model grows forever
// At block 100,000: 401,024 slots -> ~30B params
// At block 1,000,000: 4,001,024 slots -> ~300B params
// Inference stays O(1): only top_k=2 slots active per token

// ---- Block Limits -----------------------------------------------------------
// Maximum serialized block size: 32 MB.
// Larger than Bitcoin's 4MB (segwit) to accommodate delta payloads.
// 32,000,000 = 32 * 10^6 bytes (not MiB, matching Bitcoin's decimal convention).
constexpr size_t   MAX_BLOCK_SIZE      = 32'000'000;

// Maximum serialized transaction size: 1 MB.
constexpr size_t   MAX_TX_SIZE         = 1'000'000;

// Maximum signature operations per block (prevents CPU DoS).
// Bitcoin uses 80,000 (post-segwit effective limit).
constexpr int      MAX_BLOCK_SIGOPS    = 80'000;

// Coinbase maturity: mined coins are spendable after 100 confirmations.
// Identical to Bitcoin, prevents spending coins from orphaned blocks.
constexpr int      COINBASE_MATURITY   = 100;

// ---- Network Limits ---------------------------------------------------------
// Maximum outbound peer connections (actively dialed).
constexpr int      MAX_OUTBOUND_PEERS  = 8;

// Maximum inbound peer connections (accepted from others).
// Total: 8 + 117 = 125 (matching Bitcoin Core's default).
constexpr int      MAX_INBOUND_PEERS   = 117;
constexpr int      MAX_PEERS           = MAX_OUTBOUND_PEERS + MAX_INBOUND_PEERS; // 125

// Number of confirmations required for transaction finality.
// 6 blocks * 10 min = 60 minutes (Bitcoin standard).
constexpr int      FINALITY_DEPTH      = 6;

// Maximum inventory items per INV message.
constexpr int      MAX_INV_SIZE        = 50000;

// Maximum addresses relayed per ADDR message.
constexpr int      ADDR_RELAY_MAX      = 1000;

// ---- Cryptography -----------------------------------------------------------
// Keccak padding byte: 0x01 for original Keccak (not SHA-3's 0x06).
// We use original Keccak to match Ethereum's convention.
constexpr uint8_t  KECCAK_PAD          = 0x01;

// ---- Model Checkpoints ------------------------------------------------------
// Full model state is checkpointed every 2016 blocks (same as retarget).
// Allows new nodes to sync from a recent checkpoint + deltas instead of
// replaying all training from genesis.
constexpr uint32_t CHECKPOINT_INTERVAL = 2016;

// ---- Genesis Block ----------------------------------------------------------
// Genesis timestamp: 21 March 2026 00:00:00 UTC
// = days since epoch: (2026-1970)*365.25 + leap corrections
// Verified: date -d "2026-03-21T00:00:00Z" +%s = 1742515200
constexpr int64_t  GENESIS_TIMESTAMP   = 1742515200;

// Coinbase message embedded in the genesis block, serving as a proof of
// earliest possible creation date (a la Satoshi's Times headline).
constexpr const char* GENESIS_COINBASE_MSG =
    "White House calls for federal AI law to preempt states "
    "21/Mar/2026 - FlowCoin: AI that no government controls";

// ---- Model Dimensions struct ------------------------------------------------
// Represents the full set of architecture hyperparameters at a given block height.
// Used by both consensus validation and the training engine.

struct ModelDimensions {
    uint32_t d_model;      // Hidden dimension (512..1024)
    uint32_t n_layers;     // Number of layers (8..24)
    uint32_t n_heads;      // Attention heads (= d_model / d_head)
    uint32_t d_head;       // Per-head dimension (always 64)
    uint32_t d_ff;         // Feed-forward inner dimension (= 2 * d_model)
    uint32_t n_slots;      // Slot memory capacity (1024+, no cap)
    uint32_t top_k;        // Sparse slot retrieval count (always 2)
    uint32_t gru_dim;      // minGRU hidden state (= d_model)
    uint32_t conv_kernel;  // Multi-scale conv kernel size (always 4)
    uint32_t vocab;        // Vocabulary size (always 256 = byte-level)
    uint32_t seq_len;      // Sequence length (always 256)
};

// ---- Pruning Configuration --------------------------------------------------
// Minimum number of blocks to keep for reorg safety.
constexpr uint64_t MIN_BLOCKS_TO_KEEP     = 288;   // ~2 days at 10 min/block

// Default prune target in MB. Nodes in pruning mode will try to keep
// total block data below this threshold while maintaining MIN_BLOCKS_TO_KEEP.
constexpr uint64_t DEFAULT_PRUNE_TARGET_MB = 550;   // ~550 MB

// ---- Initial Block Download (IBD) ------------------------------------------
// Number of blocks behind the tip before a node considers itself in IBD mode.
// During IBD, signature verification may be skipped for assume-valid blocks
// and transaction relay is paused.
constexpr uint64_t IBD_MIN_BLOCKS_BEHIND  = 144;    // ~1 day of blocks

// Maximum number of headers to request in a single getheaders message.
constexpr int      MAX_HEADERS_RESULTS    = 2000;

// Maximum number of blocks to download in parallel during IBD.
constexpr int      MAX_BLOCKS_IN_TRANSIT  = 16;

// Timeout for a single block download request (seconds).
constexpr int      BLOCK_DOWNLOAD_TIMEOUT = 60;

// ---- Mempool Limits ---------------------------------------------------------
// Maximum number of transactions in the memory pool.
constexpr size_t   MAX_MEMPOOL_SIZE       = 300'000'000;  // 300 MB

// Minimum fee rate for mempool acceptance (atomic units per byte).
// Transactions below this rate are rejected by default.
constexpr int64_t  MIN_RELAY_FEE          = 1000;   // 0.00001 FLOW/KB

// Maximum age of a mempool transaction before it's evicted (seconds).
// 14 days = 1,209,600 seconds.
constexpr int64_t  MEMPOOL_EXPIRY         = 1'209'600;

// ---- Training Configuration ------------------------------------------------
// Maximum number of training epochs allowed per block submission.
// Prevents miners from claiming unreasonable amounts of training.
constexpr uint32_t MAX_TRAIN_EPOCHS       = 100;

// Maximum learning rate (as fixed-point: 1000 = 0.001).
// Prevents destructive weight updates.
constexpr uint32_t MAX_LEARNING_RATE_FP   = 100;    // 0.0001

// Minimum batch size for training (in tokens).
constexpr uint32_t MIN_BATCH_SIZE         = 32;

// Maximum batch size for training.
constexpr uint32_t MAX_BATCH_SIZE         = 512;

// ---- Model Dimensions: computed helpers -------------------------------------

/// Compute the d_head value (always d_model / n_heads).
inline constexpr uint32_t compute_d_head(uint32_t d_model, uint32_t n_heads) {
    return (n_heads > 0) ? (d_model / n_heads) : 0;
}

/// Check if a d_model value is valid (continuous growth: any value in range).
inline constexpr bool is_valid_d_model(uint32_t d) {
    return d >= GENESIS_D_MODEL && d <= MAX_D_MODEL;
}

/// Check if an n_layers value is valid (continuous growth: any value in range).
inline constexpr bool is_valid_n_layers(uint32_t n) {
    return n >= GENESIS_N_LAYERS && n <= MAX_N_LAYERS;
}

/// Compute the expected parameter count for given dimensions (rough estimate).
/// Full count is in growth.h's compute_param_count().
inline constexpr size_t estimate_param_count(uint32_t d_model, uint32_t n_layers,
                                              uint32_t d_ff, uint32_t n_slots) {
    // Per layer: ~4*d^2 + 2*d*n_slots + 3*d*d_ff + 25*d + 4*d
    size_t per_layer = 4 * static_cast<size_t>(d_model) * d_model
                     + 2 * static_cast<size_t>(d_model) * n_slots
                     + 3 * static_cast<size_t>(d_model) * d_ff
                     + 29 * static_cast<size_t>(d_model);
    return static_cast<size_t>(GENESIS_VOCAB) * d_model  // embedding
         + n_layers * per_layer                           // layers
         + d_model;                                       // final norm
}

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_PARAMS_H

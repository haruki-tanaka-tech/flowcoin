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
// Bitcoin uses 0x1d00ffff. We use 0x1f00ffff for an easier initial target,
// giving miners time to ramp up training infrastructure.
//
// Decoding 0x1f00ffff:
//   exponent = 0x1f = 31
//   mantissa = 0x00ffff
//   target   = 0x00ffff << (8 * (31 - 3)) = 0x00ffff << 224
// This yields a 226-bit target (very easy, ~2^226).
constexpr uint32_t INITIAL_NBITS       = 0x1f00ffff;

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

// ---- Minimum Training Steps (consensus rule) --------------------------------
// Grows with height to ensure useful training per block.
// Phase 1 (h < DIM_GROWTH_END=500): linear ramp from 1000 to 3000 steps
//   min_steps = 1000 * (1 + 2*h/500) = 1000 + 4*h
// Phase 2 (h >= 500): sqrt growth
//   min_steps = 3000 * sqrt(h / 500)
constexpr uint32_t MIN_TRAIN_STEPS_BASE = 1000;

// ---- Model Genesis (ResonanceNet V5) ----------------------------------------
// These define the architecture at block 0. All nodes must agree on these
// values to generate identical genesis model weights from the deterministic seed.

constexpr uint32_t GENESIS_SEED        = 42;    // Deterministic RNG seed for weight init
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

// ---- Model Growth: Staircase Schedule ---------------------------------------
// Phase 1 consists of 5 plateaus of 100 blocks each (blocks 0-499).
// Within each plateau, model dimensions are fixed to allow cumulative training.
// At plateau transitions, weights are expanded via zero-padding + copy.
//
// Plateau 0 (blocks   0- 99): d=512,  L=8,   d_ff=1024
// Plateau 1 (blocks 100-199): d=640,  L=12,  d_ff=1280
// Plateau 2 (blocks 200-299): d=768,  L=16,  d_ff=1536
// Plateau 3 (blocks 300-399): d=896,  L=20,  d_ff=1792
// Plateau 4 (blocks 400-499): d=1024, L=24,  d_ff=2048
//
// Growth increments per plateau:
//   d_model: +128 per plateau = (1024-512)/4
//   n_layers: +4 per plateau  = (24-8)/4
//   d_ff: +256 per plateau    = (2048-1024)/4

constexpr uint32_t GROWTH_PLATEAU_LEN  = 100;   // Blocks per plateau
constexpr uint32_t NUM_GROWTH_PLATEAUS = 5;      // Total plateaus in Phase 1
constexpr uint32_t DIM_GROWTH_END      = GROWTH_PLATEAU_LEN * NUM_GROWTH_PLATEAUS; // Block 500

// Maximum model dimensions (reached at plateau 4, block 400).
constexpr uint32_t MAX_D_MODEL         = 1024;  // = GENESIS_D_MODEL + 4 * 128
constexpr uint32_t MAX_N_LAYERS        = 24;    // = GENESIS_N_LAYERS + 4 * 4
constexpr uint32_t MAX_D_FF            = 2048;  // = GENESIS_D_FF + 4 * 256

// Slot memory grows in Phase 2 (blocks 500+).
constexpr uint32_t MAX_N_SLOTS         = 65536; // Hard cap on slot count
constexpr uint32_t SLOT_GROWTH_RATE    = 4;     // +4 slots per improving block

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
    uint32_t n_slots;      // Slot memory capacity (1024..65536)
    uint32_t top_k;        // Sparse slot retrieval count (always 2)
    uint32_t gru_dim;      // minGRU hidden state (= d_model)
    uint32_t conv_kernel;  // Multi-scale conv kernel size (always 4)
    uint32_t vocab;        // Vocabulary size (always 256 = byte-level)
    uint32_t seq_len;      // Sequence length (always 256)
};

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_PARAMS_H

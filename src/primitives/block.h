// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Block header and block primitives for FlowCoin.
//
// The block header contains standard blockchain fields plus Proof-of-Training
// fields: val_loss, prev_val_loss, training_hash, dataset_hash, model
// architecture dimensions, delta metadata, and the miner's Ed25519 identity.
//
// Header layout (fixed 308 bytes):
//   Bytes   0- 31: prev_hash        (32 bytes)
//   Bytes  32- 63: merkle_root      (32 bytes)
//   Bytes  64- 95: training_hash    (32 bytes)
//   Bytes  96-127: dataset_hash     (32 bytes)
//   Bytes 128-135: height           (8 bytes, LE)
//   Bytes 136-143: timestamp        (8 bytes, LE)
//   Bytes 144-147: nbits            (4 bytes, LE)
//   Bytes 148-151: val_loss         (4 bytes, IEEE 754 float)
//   Bytes 152-155: prev_val_loss    (4 bytes, IEEE 754 float)
//   Bytes 156-159: d_model          (4 bytes, LE)
//   Bytes 160-163: n_layers         (4 bytes, LE)
//   Bytes 164-167: d_ff             (4 bytes, LE)
//   Bytes 168-171: n_heads          (4 bytes, LE)
//   Bytes 172-175: gru_dim          (4 bytes, LE)
//   Bytes 176-179: n_slots          (4 bytes, LE)
//   Bytes 180-183: train_steps      (4 bytes, LE)
//   Bytes 184-187: stagnation       (4 bytes, LE)
//   Bytes 188-191: delta_offset     (4 bytes, LE)
//   Bytes 192-195: delta_length     (4 bytes, LE)
//   Bytes 196-199: sparse_count     (4 bytes, LE)
//   Bytes 200-203: sparse_threshold (4 bytes, IEEE 754 float)
//   Bytes 204-207: nonce            (4 bytes, LE)
//   Bytes 208-211: version          (4 bytes, LE)
//   Bytes 212-243: miner_pubkey     (32 bytes)
//   Bytes 244-307: miner_sig        (64 bytes)
//
// The unsigned portion (for signing) is bytes 0-243 (244 bytes).
// The block hash is keccak256d(bytes 0-243).

#ifndef FLOWCOIN_PRIMITIVES_BLOCK_H
#define FLOWCOIN_PRIMITIVES_BLOCK_H

#include "../util/types.h"
#include "transaction.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// Block header (308 bytes fixed)
// ---------------------------------------------------------------------------

struct CBlockHeader {
    // --- Chain linkage ---
    uint256  prev_hash;          //!< Hash of the previous block header
    uint256  merkle_root;        //!< Merkle root of transaction IDs
    uint256  training_hash;      //!< Hash binding the training proof (model state)
    uint256  dataset_hash;       //!< Hash of the evaluation dataset used

    // --- Metadata ---
    uint64_t height;             //!< Block height (0 = genesis)
    int64_t  timestamp;          //!< Block creation time (Unix seconds)
    uint32_t nbits;              //!< Difficulty target in compact form
    float    val_loss;           //!< Validation loss achieved by miner
    float    prev_val_loss;      //!< Parent's validation loss (for continuity)

    // --- Architecture dimensions (must match compute_growth) ---
    uint32_t d_model;
    uint32_t n_layers;
    uint32_t d_ff;
    uint32_t n_heads;
    uint32_t gru_dim;
    uint32_t n_slots;

    // --- Training metadata ---
    uint32_t train_steps;        //!< Number of training steps performed
    uint32_t stagnation;         //!< Consecutive blocks without val_loss improvement

    // --- Delta reference ---
    uint32_t delta_offset;       //!< Byte offset of delta payload in block body
    uint32_t delta_length;       //!< Length of compressed delta payload
    uint32_t sparse_count;       //!< Number of non-zero elements in sparse delta
    float    sparse_threshold;   //!< Threshold used for sparsification

    // --- Mining identity ---
    uint32_t nonce;              //!< Mining nonce
    uint32_t version;            //!< Block version

    std::array<uint8_t, 32> miner_pubkey;  //!< Miner's Ed25519 public key
    std::array<uint8_t, 64> miner_sig;     //!< Ed25519 signature over unsigned header

    CBlockHeader() :
        height(0), timestamp(0), nbits(0),
        val_loss(0.0f), prev_val_loss(0.0f),
        d_model(0), n_layers(0), d_ff(0), n_heads(0), gru_dim(0), n_slots(0),
        train_steps(0), stagnation(0),
        delta_offset(0), delta_length(0), sparse_count(0), sparse_threshold(0.0f),
        nonce(0), version(1),
        miner_pubkey{}, miner_sig{} {}

    /** Serialize the unsigned portion of the header (bytes 0-243, 244 bytes).
     *  This is the data that gets signed and hashed. */
    std::vector<uint8_t> get_unsigned_data() const;

    /** Compute the block hash: keccak256d of the unsigned header data. */
    uint256 get_hash() const;

    /** Compute the training hash used for PoW comparison.
     *  This is the same as get_hash() — the training proof is bound into
     *  the header via the training_hash field, and the PoW target is checked
     *  against the block hash itself. */
    uint256 get_training_hash() const;
};

// ---------------------------------------------------------------------------
// Full block = header + transactions + delta payload
// ---------------------------------------------------------------------------

struct CBlock : public CBlockHeader {
    std::vector<CTransaction>  vtx;             //!< Transactions (vtx[0] = coinbase)
    std::vector<uint8_t>       delta_payload;   //!< Compressed sparse delta

    CBlock() = default;

    /** Construct a block from a header (no body). */
    explicit CBlock(const CBlockHeader& header) : CBlockHeader(header) {}
};

} // namespace flow

#endif // FLOWCOIN_PRIMITIVES_BLOCK_H

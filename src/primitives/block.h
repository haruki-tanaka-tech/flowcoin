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
#include <string>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// Block header constants
// ---------------------------------------------------------------------------

/// Fixed serialized size of a block header (bytes).
static constexpr size_t BLOCK_HEADER_SIZE = 308;

/// Size of the unsigned portion of the header (bytes 0-243).
static constexpr size_t BLOCK_HEADER_UNSIGNED_SIZE = 244;

/// Maximum block weight (for future weight-based accounting).
static constexpr size_t MAX_BLOCK_WEIGHT = 4'000'000;

/// Weight units per byte of non-delta data.
static constexpr int WITNESS_SCALE_FACTOR = 4;

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
     *  keccak256(training_hash || dataset_hash) — binds both training proof
     *  fields into a single hash for target comparison. */
    uint256 get_training_hash() const;

    /** Serialize the full 308-byte header (unsigned portion + signature). */
    std::vector<uint8_t> serialize() const;

    /** Deserialize a 308-byte header from raw bytes.
     *  @return true on success. */
    bool deserialize(const uint8_t* data, size_t len);

    /** Check if the training hash meets the difficulty target.
     *  @param target  256-bit target value (block hash must be less than this).
     *  @return true if the block hash is below the target. */
    bool is_proof_of_training_valid(const uint256& target) const;

    /** Check if this is a null/empty header (all zeros). */
    bool is_null() const { return prev_hash.is_null() && height == 0 && version == 0; }

    /** Get the header as a hex string for display. */
    std::string get_hash_hex() const;

    /** Compute block weight (header + serialized tx data).
     *  Used for block size limits with weight-based accounting. */
    size_t get_header_weight() const { return BLOCK_HEADER_SIZE * WITNESS_SCALE_FACTOR; }

    /** Compare two headers by height. */
    bool operator<(const CBlockHeader& other) const { return height < other.height; }
    bool operator==(const CBlockHeader& other) const { return get_hash() == other.get_hash(); }
    bool operator!=(const CBlockHeader& other) const { return !(*this == other); }
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

    /** Serialize the full block (header + CompactSize(n_tx) + txs + delta). */
    std::vector<uint8_t> serialize() const;

    /** Deserialize a full block from raw bytes.
     *  @return true on success. */
    bool deserialize(const uint8_t* data, size_t len);
    bool deserialize(const std::vector<uint8_t>& data) {
        return deserialize(data.data(), data.size());
    }

    /** Get total serialized block size in bytes. */
    size_t get_block_size() const;

    /** Compute block weight for weight-based accounting.
     *  weight = header_weight + transaction_weight + delta_weight
     *  Delta payload counts as 1 weight unit per byte (discounted).
     *  All other data counts as WITNESS_SCALE_FACTOR weight units per byte. */
    size_t get_block_weight() const;

    /** Construct a coinbase transaction.
     *  @param height       Block height (encoded in coinbase).
     *  @param reward       Block reward + fees in atomic units.
     *  @param miner_pubkey Miner's public key for reward output.
     *  @param coinbase_msg Optional message to embed.
     *  @return The constructed coinbase transaction. */
    static CTransaction make_coinbase(uint64_t height, Amount reward,
                                       const std::array<uint8_t, 32>& miner_pubkey,
                                       const std::string& coinbase_msg = "");

    /** Get the coinbase transaction (first transaction).
     *  @return Pointer to the coinbase tx, or nullptr if vtx is empty. */
    const CTransaction* get_coinbase() const {
        return vtx.empty() ? nullptr : &vtx[0];
    }

    /** Recompute the merkle root from the current transactions and compare
     *  with the stored merkle_root field.
     *  @return true if the stored merkle_root matches the computed one. */
    bool verify_merkle_root() const;

    /** Compute the merkle root from the current transactions. */
    uint256 compute_merkle_root() const;

    /** Check if this block has any transactions. */
    bool has_transactions() const { return !vtx.empty(); }

    /** Get the number of transactions. */
    size_t get_tx_count() const { return vtx.size(); }

    /** Get total output value of all transactions (excluding coinbase). */
    Amount get_total_output_value() const;

    /** Get the coinbase output value (block reward + fees). */
    Amount get_coinbase_value() const {
        auto* cb = get_coinbase();
        return cb ? cb->get_value_out() : 0;
    }

    /** Extract the block header (strips transactions and delta). */
    CBlockHeader get_header() const {
        return static_cast<const CBlockHeader&>(*this);
    }

    /** Check basic structural validity without context.
     *  Verifies: non-empty vtx, vtx[0] is coinbase, no other coinbase txs,
     *  serialized size within limits, merkle root matches. */
    bool check_block() const;

    /** Get a string representation for logging. */
    std::string to_string() const;
};

// ---------------------------------------------------------------------------
// CBlockLocator: sparse list of block hashes for getheaders
// ---------------------------------------------------------------------------
// Used during Initial Block Download to efficiently communicate chain position.
// Contains an exponentially-spaced list of block hashes:
//   - Hashes 0-9: every block (last 10 blocks)
//   - Hashes 10+: exponentially increasing step-back
//   - Final hash: genesis block

struct CBlockLocator {
    std::vector<uint256> hashes;  //!< Ordered list of block hashes (tip first)

    CBlockLocator() = default;

    /** Construct a locator with the given hash list. */
    explicit CBlockLocator(std::vector<uint256> hashes_in)
        : hashes(std::move(hashes_in)) {}

    /** Check if this locator is empty. */
    bool is_null() const { return hashes.empty(); }

    /** Serialize the locator (version + CompactSize + hashes). */
    std::vector<uint8_t> serialize() const;

    /** Deserialize a locator from raw bytes. */
    bool deserialize(const uint8_t* data, size_t len);
};

// ---------------------------------------------------------------------------
// CBlockIndex forward declaration
// ---------------------------------------------------------------------------

struct CBlockIndex;

/// Build a block locator from a chain tip.
/// Uses exponential step-back: first 10 hashes are consecutive,
/// then each subsequent hash is 2x farther back, ending at genesis.
CBlockLocator build_locator(const CBlockIndex* tip);

/// Compute the block weight for a list of transactions + delta.
size_t compute_block_weight(const CBlockHeader& header,
                             const std::vector<CTransaction>& vtx,
                             const std::vector<uint8_t>& delta_payload);

} // namespace flow

#endif // FLOWCOIN_PRIMITIVES_BLOCK_H

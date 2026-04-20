// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Block header and block primitives for FlowCoin.
//
// FlowCoin uses two distinct hashes per block:
//
//   block_id  = keccak256d(header[0..91])      -- cheap, used for chain refs,
//                                                 P2P, merkle, RPC, indexing.
//   pow_hash  = RandomX(header[0..91], seed)   -- CPU-only memory-hard PoW,
//                                                 compared against target.
//
// `get_hash()` returns the block_id. `get_pow_hash(seed)` returns the PoW hash;
// the caller provides the seed, which is the block hash at the seed height
// computed by `flow::consensus::rx_seed_height(height)`.
//
// Header layout (fixed 188 bytes):
//   Bytes   0- 31: prev_hash        (32 bytes)
//   Bytes  32- 63: merkle_root      (32 bytes)
//   Bytes  64- 71: height           (8 bytes, LE)
//   Bytes  72- 79: timestamp        (8 bytes, LE)
//   Bytes  80- 83: nbits            (4 bytes, LE)
//   Bytes  84- 87: nonce            (4 bytes, LE)
//   Bytes  88- 91: version          (4 bytes, LE)
//   Bytes  92-123: miner_pubkey     (32 bytes)
//   Bytes 124-187: miner_sig        (64 bytes)
//
// The unsigned portion (for signing and hashing) is bytes 0-91 (92 bytes).
// Miner signs bytes 0-91 with Ed25519.

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
static constexpr size_t BLOCK_HEADER_SIZE = 188;

/// Size of the unsigned portion of the header (bytes 0-91).
static constexpr size_t BLOCK_HEADER_UNSIGNED_SIZE = 92;

/// Maximum block weight (for future weight-based accounting).
static constexpr size_t MAX_BLOCK_WEIGHT = 4'000'000;

/// Weight units per byte.
static constexpr int WITNESS_SCALE_FACTOR = 4;

// ---------------------------------------------------------------------------
// Block header (188 bytes fixed)
// ---------------------------------------------------------------------------

struct CBlockHeader {
    // --- Chain linkage ---
    uint256  prev_hash;          //!< Hash of the previous block header
    uint256  merkle_root;        //!< Merkle root of transaction IDs

    // --- Metadata ---
    uint64_t height = 0;         //!< Block height (0 = genesis)
    int64_t  timestamp = 0;      //!< Block creation time (Unix seconds)
    uint32_t nbits = 0;          //!< Difficulty target in compact form
    uint32_t nonce = 0;          //!< PoW nonce -- iterated by miner
    uint32_t version = 1;        //!< Block version

    // --- Mining identity ---
    std::array<uint8_t, 32> miner_pubkey{};  //!< Miner's Ed25519 public key
    std::array<uint8_t, 64> miner_sig{};     //!< Ed25519 signature over unsigned header

    CBlockHeader() = default;

    /** Serialize the unsigned portion of the header (bytes 0-91, 92 bytes).
     *  This is the data that gets signed, hashed, and fed to RandomX. */
    std::vector<uint8_t> get_unsigned_data() const;

    /** Block ID: keccak256d of the unsigned header data. Cheap, used for
     *  chain references, P2P relay, merkle proofs, and indexing. */
    uint256 get_hash() const;

    /** PoW hash: RandomX(unsigned_data, seed). Expensive (single hash ~1 ms in
     *  light mode). `seed` must be the block hash at the RandomX seed height
     *  for this block (see flow::consensus::rx_seed_height). */
    uint256 get_pow_hash(const uint256& seed) const;

    /** Serialize the full 188-byte header (unsigned portion + pubkey + signature). */
    std::vector<uint8_t> serialize() const;

    /** Deserialize a 188-byte header from raw bytes.
     *  @return true on success. */
    bool deserialize(const uint8_t* data, size_t len);

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
// Full block = header + transactions
// ---------------------------------------------------------------------------

struct CBlock : public CBlockHeader {
    std::vector<CTransaction>  vtx;             //!< Transactions (vtx[0] = coinbase)

    CBlock() = default;

    /** Construct a block from a header (no body). */
    explicit CBlock(const CBlockHeader& header) : CBlockHeader(header) {}

    /** Serialize the full block (header + CompactSize(n_tx) + txs). */
    std::vector<uint8_t> serialize() const;

    /** Deserialize a full block from raw bytes.
     *  @return true on success. */
    bool deserialize(const uint8_t* data, size_t len);
    bool deserialize(const std::vector<uint8_t>& data) {
        return deserialize(data.data(), data.size());
    }

    /** Get total serialized block size in bytes. */
    size_t get_block_size() const;

    /** Compute block weight for weight-based accounting. */
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

    /** Extract the block header (strips transactions). */
    CBlockHeader get_header() const {
        return static_cast<const CBlockHeader&>(*this);
    }

    /** Check basic structural validity without context.
     *  Verifies: non-empty vtx, vtx[0] is coinbase, no other coinbase txs,
     *  serialized size within limits, merkle root matches. */
    bool check_block() const;

    /** Get a string representation for logging. */
    std::string to_string() const;

    // --- Block analysis ---

    struct BlockAnalysis {
        uint64_t height;
        uint256 hash;
        uint256 prev_hash;
        double difficulty;
        int64_t timestamp;
        size_t tx_count;
        size_t total_size;
        size_t total_weight;
        Amount total_output_value;
        Amount total_input_value;
        Amount total_fees;
        Amount coinbase_value;
        uint32_t nonce;
        int total_sigops;
        int p2pkh_count;
        int multisig_count;
        int op_return_count;
        int64_t time_since_prev;
    };
    BlockAnalysis analyze() const;

    // --- Block comparison ---

    struct BlockDiff {
        bool same_height;
        bool same_prev;
        bool same_txs;
        int shared_tx_count;
        int unique_a_count;
        int unique_b_count;
    };
    static BlockDiff compare(const CBlock& a, const CBlock& b);

    // --- Coinbase creation helpers ---

    static CTransaction create_coinbase(uint64_t height, Amount reward,
                                          const std::array<uint8_t, 32>& miner_pubkey,
                                          const std::string& extra_data = "");

    static CTransaction create_coinbase_multi(
        uint64_t height, Amount reward,
        const std::vector<std::pair<std::array<uint8_t, 32>, Amount>>& payees);

    // --- Merkle proof generation ---

    struct MerkleProof {
        uint256 txid;
        uint256 root;
        std::vector<uint256> branch;
        uint32_t index;

        bool verify() const;
        std::vector<uint8_t> serialize() const;
        static MerkleProof deserialize(const uint8_t* data, size_t len);
    };
    MerkleProof get_tx_proof(uint32_t tx_index) const;
    bool verify_tx_proof(const MerkleProof& proof) const;
};

// ---------------------------------------------------------------------------
// CBlockLocator: sparse list of block hashes for getheaders
// ---------------------------------------------------------------------------

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
CBlockLocator build_locator(const CBlockIndex* tip);

/// Compute the block weight for a list of transactions.
size_t compute_block_weight(const CBlockHeader& header,
                             const std::vector<CTransaction>& vtx);

} // namespace flow

#endif // FLOWCOIN_PRIMITIVES_BLOCK_H

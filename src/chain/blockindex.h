// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// In-memory block tree: CBlockIndex nodes, BlockTree container.
// Modeled after Bitcoin Core's CBlockIndex / CBlockTreeDB.

#ifndef FLOWCOIN_CHAIN_BLOCKINDEX_H
#define FLOWCOIN_CHAIN_BLOCKINDEX_H

#include "util/types.h"
#include "consensus/params.h"
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <unordered_map>
#include <vector>

// Forward declarations for types defined in other modules
namespace flow {
struct CBlockHeader;
}

namespace flow::consensus {
struct BlockContext;
}

namespace flow {

// ---- Block validation status flags (bitmask) --------------------------------

enum BlockStatus : uint32_t {
    BLOCK_VALID_UNKNOWN      = 0,
    BLOCK_HEADER_VALID       = 1 << 0,  // Header passed checks 1-11, 13-14
    BLOCK_DATA_STORED        = 1 << 1,  // Full block data stored on disk
    BLOCK_FULLY_VALIDATED    = 1 << 2,  // All 15+ checks passed
    BLOCK_FAILED             = 1 << 3,  // Validation failed
    BLOCK_FAILED_CHILD       = 1 << 4,  // Descendant of a failed block
};

// ---- Disk position for a block in blk*.dat files ----------------------------

struct BlockPos {
    int file_num = -1;     // which blk?????.dat file
    uint32_t offset = 0;   // byte offset within file
    uint32_t size = 0;     // block data size (excluding 8-byte header: magic + size)

    bool is_null() const { return file_num < 0; }
};

// ---- In-memory index entry for one block ------------------------------------

struct CBlockIndex {
    // Identity
    uint256     hash;               // block hash (keccak256d of unsigned header)
    uint256     prev_hash;          // parent block hash

    // Chain position
    uint64_t    height = 0;
    int64_t     timestamp = 0;

    // PoUT (Proof-of-Useful-Training)
    float       val_loss = 0.0f;
    float       prev_val_loss = 0.0f;
    uint32_t    train_steps = 0;

    // Difficulty
    uint32_t    nbits = 0;

    // Model architecture fields
    uint32_t    d_model = 0;
    uint32_t    n_layers = 0;
    uint32_t    d_ff = 0;
    uint32_t    n_slots = 0;
    uint32_t    n_heads = 0;
    uint32_t    gru_dim = 0;
    uint32_t    stagnation_count = 0;

    // Merkle root
    uint256     merkle_root;

    // Miner identity
    PubKey      miner_pubkey;

    // Derived values (computed, not stored in header)
    uint32_t    improving_blocks = 0;  // cumulative improving blocks up to this block
    uint32_t    status = BLOCK_VALID_UNKNOWN;

    // Disk position
    BlockPos    pos;

    // Tree linkage (pointer to parent in the block tree)
    CBlockIndex* prev = nullptr;

    // Number of transactions in this block (0 if header-only)
    int         n_tx = 0;

    // Populate from a block header
    void set_from_header(const CBlockHeader& hdr);

    // Build a BlockContext for validating a child of this block.
    // adjusted_time: the current adjusted network time.
    consensus::BlockContext make_child_context(int64_t adjusted_time) const;

    // Returns true if this block improved validation loss compared to its parent
    bool is_improving() const {
        return val_loss < prev_val_loss;
    }
};

// ---- Hash function for uint256 keys in unordered_map ------------------------

struct Uint256Hasher {
    size_t operator()(const uint256& h) const {
        // Use first 8 bytes as hash -- block hashes are already well-distributed
        uint64_t val;
        std::memcpy(&val, h.data(), sizeof(val));
        return static_cast<size_t>(val);
    }
};

// ---- The block tree: hash -> CBlockIndex ------------------------------------
// All CBlockIndex objects are owned by this tree. Pointer stability is
// guaranteed by storing objects in a deque of unique_ptr.

class BlockTree {
public:
    // Insert a new block index entry from a header.
    // Returns pointer to the entry. If hash already exists, returns existing.
    CBlockIndex* insert(const CBlockHeader& header);

    // Insert a pre-populated CBlockIndex (used for genesis).
    // Takes ownership of the object. Returns raw pointer.
    CBlockIndex* insert_genesis(std::unique_ptr<CBlockIndex> idx);

    // Look up by hash. Returns nullptr if not found.
    CBlockIndex* find(const uint256& hash) const;

    // Get the genesis block
    CBlockIndex* genesis() const { return genesis_; }

    // Get the tip of the best chain (highest height / most cumulative work)
    CBlockIndex* best_tip() const { return best_tip_; }

    // Update the best tip
    void set_best_tip(CBlockIndex* tip) { best_tip_ = tip; }

    // Total number of block index entries
    size_t size() const { return index_.size(); }

    // ---- Extended tree operations ------------------------------------------

    /// Find the common ancestor of two block index entries.
    /// Returns nullptr if they share no common ancestor (shouldn't happen
    /// if both are in the same tree rooted at genesis).
    CBlockIndex* find_fork(CBlockIndex* a, CBlockIndex* b) const;

    /// Get the ancestor of a block at a specific height.
    /// Returns nullptr if the block is below the requested height.
    CBlockIndex* get_ancestor(CBlockIndex* block, uint64_t height) const;

    /// Build the chain path from one block to another (common ancestor to target).
    /// Returns blocks in order from oldest to newest. Empty if no path exists.
    std::vector<CBlockIndex*> get_path(CBlockIndex* from, CBlockIndex* to) const;

    /// Get all tips (leaf nodes with no children in the tree).
    /// A tip is a block index entry that no other entry's prev pointer
    /// points to. This includes the best tip and any competing forks.
    std::vector<CBlockIndex*> get_all_tips() const;

    /// Get all blocks at a specific height.
    /// May return multiple blocks if there are forks at that height.
    std::vector<CBlockIndex*> get_at_height(uint64_t height) const;

    /// Check if block A is an ancestor of block B.
    bool is_ancestor(const CBlockIndex* ancestor, const CBlockIndex* descendant) const;

    /// Get the chain of block indices from genesis to the given block.
    /// Returns indices in order from genesis (first) to the block (last).
    std::vector<CBlockIndex*> get_chain(CBlockIndex* block) const;

    /// Compute the depth of a block (distance from the best tip).
    /// Returns 0 for the best tip itself.
    /// Returns -1 if the block is not on the best chain.
    int64_t get_depth(const CBlockIndex* block) const;

    /// Remove all blocks that have BLOCK_FAILED status.
    /// Returns the number of entries removed.
    size_t prune_failed();

    /// Get memory usage statistics for the tree.
    struct TreeStats {
        size_t total_entries;
        size_t validated_entries;
        size_t stored_entries;
        size_t failed_entries;
        size_t header_only_entries;
        uint64_t max_height;
        size_t fork_count;
        size_t memory_bytes;
    };

    TreeStats get_stats() const;

private:
    std::deque<std::unique_ptr<CBlockIndex>> storage_;
    std::unordered_map<uint256, CBlockIndex*, Uint256Hasher> index_;
    CBlockIndex* genesis_ = nullptr;
    CBlockIndex* best_tip_ = nullptr;
};

} // namespace flow

#endif // FLOWCOIN_CHAIN_BLOCKINDEX_H

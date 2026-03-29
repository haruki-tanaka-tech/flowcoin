// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// In-memory block tree: CBlockIndex nodes, BlockTree container.

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

// Forward declarations
namespace flow {
struct CBlockHeader;
}

namespace flow::consensus {
struct BlockContext;
}

namespace flow {

// ---- Block validation status flags ----------------------------------------

enum BlockStatus : uint32_t {
    BLOCK_VALID_UNKNOWN      = 0,
    BLOCK_HEADER_VALID       = 1 << 0,
    BLOCK_DATA_STORED        = 1 << 1,
    BLOCK_FULLY_VALIDATED    = 1 << 2,
    BLOCK_FAILED             = 1 << 3,
    BLOCK_FAILED_CHILD       = 1 << 4,
};

// ---- Disk position --------------------------------------------------------

struct BlockPos {
    int file_num = -1;
    uint32_t offset = 0;
    uint32_t size = 0;

    bool is_null() const { return file_num < 0; }
};

// ---- In-memory index entry ------------------------------------------------

struct CBlockIndex {
    // Identity
    uint256     hash;
    uint256     prev_hash;

    // Chain position
    uint64_t    height = 0;
    int64_t     timestamp = 0;

    // Difficulty
    uint32_t    nbits = 0;

    // PoW nonce
    uint32_t    nonce = 0;

    // Merkle root
    uint256     merkle_root;

    // Miner identity
    PubKey      miner_pubkey;

    // Derived values
    uint32_t    status = BLOCK_VALID_UNKNOWN;

    // Disk position (block data in blk*.dat)
    BlockPos    pos;

    // Disk position (undo data in rev*.dat)
    int         undo_file = -1;
    uint32_t    undo_pos  = 0;

    /// Check whether this block has undo data stored on disk.
    bool has_undo() const { return undo_file >= 0; }

    // Tree linkage
    CBlockIndex* prev = nullptr;

    // Number of transactions in this block (0 if header-only)
    int         n_tx = 0;

    // Populate from a block header
    void set_from_header(const CBlockHeader& hdr);

    // Build a BlockContext for validating a child of this block.
    consensus::BlockContext make_child_context(int64_t adjusted_time) const;
};

// ---- Hash function for uint256 keys ---------------------------------------

struct Uint256Hasher {
    size_t operator()(const uint256& h) const {
        uint64_t val;
        std::memcpy(&val, h.data(), sizeof(val));
        return static_cast<size_t>(val);
    }
};

// ---- The block tree -------------------------------------------------------

class BlockTree {
public:
    CBlockIndex* insert(const CBlockHeader& header);
    CBlockIndex* insert_genesis(std::unique_ptr<CBlockIndex> idx);
    CBlockIndex* insert_with_hash(std::unique_ptr<CBlockIndex> idx, const uint256& hash);
    CBlockIndex* find(const uint256& hash) const;

    CBlockIndex* genesis() const { return genesis_; }
    CBlockIndex* best_tip() const { return best_tip_; }
    void set_best_tip(CBlockIndex* tip) { best_tip_ = tip; }

    size_t size() const { return index_.size(); }

    // Extended tree operations
    CBlockIndex* find_fork(CBlockIndex* a, CBlockIndex* b) const;
    CBlockIndex* get_ancestor(CBlockIndex* block, uint64_t height) const;
    std::vector<CBlockIndex*> get_path(CBlockIndex* from, CBlockIndex* to) const;
    std::vector<CBlockIndex*> get_all_tips() const;
    std::vector<CBlockIndex*> get_at_height(uint64_t height) const;
    bool is_ancestor(const CBlockIndex* ancestor, const CBlockIndex* descendant) const;
    std::vector<CBlockIndex*> get_chain(CBlockIndex* block) const;
    int64_t get_depth(const CBlockIndex* block) const;
    size_t prune_failed();

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

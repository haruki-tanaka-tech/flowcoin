// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// In-memory block tree: maps block hashes to metadata.
// Does NOT store full blocks — only headers + status.

#pragma once

#include "core/types.h"
#include "primitives/block.h"

#include <memory>
#include <unordered_map>
#include <vector>

namespace flow {

// Status flags for a block index entry
enum class BlockStatus : uint32_t {
    HEADER_VALID  = 1,  // header passed validation
    DATA_STORED   = 2,  // full block data is on disk
    FULLY_VALID   = 4,  // all checks passed, in active chain
};

struct CBlockIndex {
    Hash256   hash;
    Hash256   prev_hash;
    uint64_t  height{0};
    int64_t   timestamp{0};
    float     val_loss{0.0f};
    uint32_t  nbits{0};
    uint32_t  d_model{0};
    uint32_t  n_layers{0};
    uint32_t  d_ff{0};
    uint32_t  n_experts{0};
    uint32_t  n_heads{0};
    uint32_t  rank{0};
    uint32_t  stagnation_count{0};
    uint32_t  improving_blocks{0}; // cumulative improving blocks up to this block
    uint32_t  status{0};

    CBlockIndex* prev{nullptr}; // pointer to parent in the tree

    bool has_status(BlockStatus s) const {
        return (status & static_cast<uint32_t>(s)) != 0;
    }
    void add_status(BlockStatus s) {
        status |= static_cast<uint32_t>(s);
    }

    // Build from a block header
    static CBlockIndex from_header(const CBlockHeader& header);
};

// The block tree: all known block headers indexed by hash.
class BlockTree {
public:
    // Add a block index entry. Returns pointer to the stored entry.
    // Returns nullptr if the block already exists.
    CBlockIndex* insert(const CBlockIndex& index);

    // Lookup by hash. Returns nullptr if not found.
    CBlockIndex* find(const Hash256& hash);
    const CBlockIndex* find(const Hash256& hash) const;

    // Get the tip with the most work (highest height).
    const CBlockIndex* get_best_tip() const;

    // Get the chain from genesis to a given tip as a vector of pointers.
    std::vector<const CBlockIndex*> get_chain(const CBlockIndex* tip) const;

    size_t size() const { return entries_.size(); }

private:
    // Use unique_ptr for stable pointers (prev pointers won't dangle)
    std::vector<std::unique_ptr<CBlockIndex>> storage_;
    std::unordered_map<std::string, CBlockIndex*> entries_; // hex(hash) → ptr
};

} // namespace flow

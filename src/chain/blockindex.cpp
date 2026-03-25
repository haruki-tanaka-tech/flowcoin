// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "chain/blockindex.h"
#include "primitives/block.h"
#include "consensus/validation.h"
#include "consensus/growth.h"
#include <algorithm>

namespace flow {

// ---------------------------------------------------------------------------
// CBlockIndex::set_from_header
// ---------------------------------------------------------------------------

void CBlockIndex::set_from_header(const CBlockHeader& hdr) {
    hash            = hdr.get_hash();
    prev_hash       = hdr.prev_hash;
    height          = hdr.height;
    timestamp       = hdr.timestamp;
    val_loss        = hdr.val_loss;
    prev_val_loss   = hdr.prev_val_loss;
    nbits           = hdr.nbits;
    d_model         = hdr.d_model;
    n_layers        = hdr.n_layers;
    d_ff            = hdr.d_ff;
    n_slots         = hdr.n_slots;
    n_heads         = hdr.n_heads;
    gru_dim         = hdr.gru_dim;
    stagnation_count = hdr.stagnation;
    merkle_root     = hdr.merkle_root;
    miner_pubkey    = PubKey(hdr.miner_pubkey.data());
}

// ---------------------------------------------------------------------------
// CBlockIndex::make_child_context
// ---------------------------------------------------------------------------

consensus::BlockContext CBlockIndex::make_child_context(int64_t adjusted_time) const {
    consensus::BlockContext ctx{};

    ctx.prev_hash        = hash;
    ctx.prev_height      = height;
    ctx.prev_timestamp   = timestamp;
    ctx.prev_val_loss    = val_loss;
    ctx.prev_nbits       = nbits;
    ctx.improving_blocks = improving_blocks;
    ctx.adjusted_time    = adjusted_time;

    // Child block height
    uint64_t child_height = height + 1;

    // Compute expected model dimensions for the child block
    ctx.expected_dims = consensus::compute_growth(child_height);



    // For difficulty: at retarget boundaries the caller needs to compute
    // the new target. For now, carry forward the parent's nbits.
    // The full difficulty retarget logic lives in consensus/difficulty.
    ctx.expected_nbits = nbits;

    return ctx;
}

// ---------------------------------------------------------------------------
// BlockTree::insert
// ---------------------------------------------------------------------------

CBlockIndex* BlockTree::insert(const CBlockHeader& header) {
    uint256 block_hash = header.get_hash();

    // Check if already exists
    auto it = index_.find(block_hash);
    if (it != index_.end()) {
        return it->second;
    }

    // Create new entry
    auto idx = std::make_unique<CBlockIndex>();
    idx->set_from_header(header);

    // Link to parent
    auto parent_it = index_.find(header.prev_hash);
    if (parent_it != index_.end()) {
        idx->prev = parent_it->second;

        // Compute cumulative improving blocks
        idx->improving_blocks = parent_it->second->improving_blocks;
        if (idx->val_loss < idx->prev_val_loss) {
            idx->improving_blocks++;
        }
    }

    // Track genesis
    if (header.height == 0) {
        genesis_ = idx.get();
    }

    CBlockIndex* raw_ptr = idx.get();
    index_[block_hash] = raw_ptr;
    storage_.push_back(std::move(idx));

    return raw_ptr;
}

// ---------------------------------------------------------------------------
// BlockTree::insert_genesis
// ---------------------------------------------------------------------------

CBlockIndex* BlockTree::insert_genesis(std::unique_ptr<CBlockIndex> idx) {
    uint256 block_hash = idx->hash;

    auto it = index_.find(block_hash);
    if (it != index_.end()) {
        return it->second;
    }

    genesis_ = idx.get();
    CBlockIndex* raw_ptr = idx.get();
    index_[block_hash] = raw_ptr;
    storage_.push_back(std::move(idx));

    return raw_ptr;
}

// ---------------------------------------------------------------------------
// BlockTree::find
// ---------------------------------------------------------------------------

CBlockIndex* BlockTree::find(const uint256& hash) const {
    auto it = index_.find(hash);
    if (it != index_.end()) {
        return it->second;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// BlockTree::find_fork — common ancestor of two blocks
// ---------------------------------------------------------------------------

CBlockIndex* BlockTree::find_fork(CBlockIndex* a, CBlockIndex* b) const {
    if (!a || !b) return nullptr;

    while (a && b && a != b) {
        if (a->height > b->height) {
            a = a->prev;
        } else if (b->height > a->height) {
            b = b->prev;
        } else {
            a = a->prev;
            b = b->prev;
        }
    }

    return (a == b) ? a : nullptr;
}

// ---------------------------------------------------------------------------
// BlockTree::get_ancestor — ancestor at a specific height
// ---------------------------------------------------------------------------

CBlockIndex* BlockTree::get_ancestor(CBlockIndex* block, uint64_t height) const {
    if (!block) return nullptr;
    if (block->height < height) return nullptr;

    CBlockIndex* walk = block;
    while (walk && walk->height > height) {
        walk = walk->prev;
    }

    return (walk && walk->height == height) ? walk : nullptr;
}

// ---------------------------------------------------------------------------
// BlockTree::get_path — ordered path between two blocks
// ---------------------------------------------------------------------------

std::vector<CBlockIndex*> BlockTree::get_path(CBlockIndex* from,
                                                CBlockIndex* to) const {
    std::vector<CBlockIndex*> path;
    if (!from || !to) return path;

    // Build path from 'to' back to 'from'
    CBlockIndex* walk = to;
    while (walk && walk != from) {
        path.push_back(walk);
        walk = walk->prev;
    }

    if (walk == from) {
        path.push_back(from);
        std::reverse(path.begin(), path.end());
    } else {
        path.clear();  // 'from' is not an ancestor of 'to'
    }

    return path;
}

// ---------------------------------------------------------------------------
// BlockTree::get_all_tips — leaf nodes in the tree
// ---------------------------------------------------------------------------

std::vector<CBlockIndex*> BlockTree::get_all_tips() const {
    // A tip is a block that no other block references as prev.
    // Build a set of all blocks that are referenced as prev.
    std::unordered_map<CBlockIndex*, bool> has_child;

    for (const auto& [hash, idx] : index_) {
        if (idx->prev) {
            has_child[idx->prev] = true;
        }
    }

    std::vector<CBlockIndex*> tips;
    for (const auto& [hash, idx] : index_) {
        if (has_child.find(idx) == has_child.end()) {
            tips.push_back(idx);
        }
    }

    // Sort by height descending (best tips first)
    std::sort(tips.begin(), tips.end(),
              [](const CBlockIndex* a, const CBlockIndex* b) {
                  return a->height > b->height;
              });

    return tips;
}

// ---------------------------------------------------------------------------
// BlockTree::get_at_height — all blocks at a specific height
// ---------------------------------------------------------------------------

std::vector<CBlockIndex*> BlockTree::get_at_height(uint64_t height) const {
    std::vector<CBlockIndex*> result;
    for (const auto& [hash, idx] : index_) {
        if (idx->height == height) {
            result.push_back(idx);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// BlockTree::is_ancestor
// ---------------------------------------------------------------------------

bool BlockTree::is_ancestor(const CBlockIndex* ancestor,
                             const CBlockIndex* descendant) const {
    if (!ancestor || !descendant) return false;
    if (ancestor->height > descendant->height) return false;

    const CBlockIndex* walk = descendant;
    while (walk && walk->height > ancestor->height) {
        walk = walk->prev;
    }

    return walk == ancestor;
}

// ---------------------------------------------------------------------------
// BlockTree::get_chain — genesis to block
// ---------------------------------------------------------------------------

std::vector<CBlockIndex*> BlockTree::get_chain(CBlockIndex* block) const {
    std::vector<CBlockIndex*> chain;
    CBlockIndex* walk = block;
    while (walk) {
        chain.push_back(walk);
        walk = walk->prev;
    }
    std::reverse(chain.begin(), chain.end());
    return chain;
}

// ---------------------------------------------------------------------------
// BlockTree::get_depth
// ---------------------------------------------------------------------------

int64_t BlockTree::get_depth(const CBlockIndex* block) const {
    if (!block || !best_tip_) return -1;

    // Check if block is on the best chain
    if (block->height > best_tip_->height) return -1;

    const CBlockIndex* walk = best_tip_;
    while (walk && walk->height > block->height) {
        walk = walk->prev;
    }

    if (walk == block) {
        return static_cast<int64_t>(best_tip_->height - block->height);
    }

    return -1;  // Not on the best chain
}

// ---------------------------------------------------------------------------
// BlockTree::prune_failed
// ---------------------------------------------------------------------------

size_t BlockTree::prune_failed() {
    std::vector<uint256> to_remove;

    for (const auto& [hash, idx] : index_) {
        if (idx->status & BLOCK_FAILED) {
            to_remove.push_back(hash);
        }
    }

    for (const auto& hash : to_remove) {
        index_.erase(hash);
    }

    // Clean up storage (leave null entries; deque doesn't support efficient removal)
    // The memory will be reclaimed when the deque is destroyed.

    return to_remove.size();
}

// ---------------------------------------------------------------------------
// BlockTree::get_stats
// ---------------------------------------------------------------------------

BlockTree::TreeStats BlockTree::get_stats() const {
    TreeStats stats{};
    stats.total_entries = index_.size();

    uint64_t max_h = 0;
    for (const auto& [hash, idx] : index_) {
        if (idx->status & BLOCK_FULLY_VALIDATED) stats.validated_entries++;
        if (idx->status & BLOCK_DATA_STORED) stats.stored_entries++;
        if (idx->status & BLOCK_FAILED) stats.failed_entries++;
        if ((idx->status & BLOCK_HEADER_VALID) &&
            !(idx->status & BLOCK_DATA_STORED)) {
            stats.header_only_entries++;
        }
        if (idx->height > max_h) max_h = idx->height;
    }

    stats.max_height = max_h;

    // Count forks: tips - 1 (if there's a main chain and forks)
    auto tips = get_all_tips();
    stats.fork_count = tips.size() > 1 ? tips.size() - 1 : 0;

    // Memory estimate
    stats.memory_bytes = storage_.size() * sizeof(std::unique_ptr<CBlockIndex>);
    stats.memory_bytes += storage_.size() * sizeof(CBlockIndex);
    stats.memory_bytes += index_.size() * (sizeof(uint256) + sizeof(CBlockIndex*) + 32);

    return stats;
}

} // namespace flow

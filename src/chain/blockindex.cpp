// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "chain/blockindex.h"
#include "primitives/block.h"
#include "consensus/validation.h"
#include "consensus/growth.h"

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
    train_steps     = hdr.train_steps;
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
    ctx.expected_dims = consensus::compute_growth(child_height, improving_blocks);

    // Compute minimum training steps for the child block
    ctx.min_train_steps = consensus::compute_min_steps(child_height);

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

} // namespace flow

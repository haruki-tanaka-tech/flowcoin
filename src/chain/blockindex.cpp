// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "blockindex.h"
#include <algorithm>

namespace flow {

CBlockIndex CBlockIndex::from_header(const CBlockHeader& header) {
    CBlockIndex idx;
    idx.hash = header.get_hash();
    idx.prev_hash = header.prev_hash;
    idx.height = header.height;
    idx.timestamp = header.timestamp;
    idx.val_loss = header.val_loss;
    idx.nbits = header.nbits;
    idx.d_model = header.d_model;
    idx.n_layers = header.n_layers;
    idx.d_ff = header.d_ff;
    idx.n_experts = header.n_experts;
    idx.n_heads = header.n_heads;
    idx.rank = header.rank;
    idx.stagnation_count = header.stagnation_count;
    return idx;
}

CBlockIndex* BlockTree::insert(const CBlockIndex& index) {
    auto key = index.hash.to_hex();
    if (entries_.count(key)) {
        return nullptr; // already exists
    }

    auto ptr = std::make_unique<CBlockIndex>(index);
    CBlockIndex* raw = ptr.get();

    // Link to parent
    auto parent_it = entries_.find(index.prev_hash.to_hex());
    if (parent_it != entries_.end()) {
        raw->prev = parent_it->second;
    }

    entries_[key] = raw;
    storage_.push_back(std::move(ptr));
    return raw;
}

CBlockIndex* BlockTree::find(const Hash256& hash) {
    auto it = entries_.find(hash.to_hex());
    return (it != entries_.end()) ? it->second : nullptr;
}

const CBlockIndex* BlockTree::find(const Hash256& hash) const {
    auto it = entries_.find(hash.to_hex());
    return (it != entries_.end()) ? it->second : nullptr;
}

const CBlockIndex* BlockTree::get_best_tip() const {
    const CBlockIndex* best = nullptr;
    for (const auto& [key, idx] : entries_) {
        if (!best || idx->height > best->height) {
            best = idx;
        }
    }
    return best;
}

std::vector<const CBlockIndex*> BlockTree::get_chain(const CBlockIndex* tip) const {
    std::vector<const CBlockIndex*> chain;
    const CBlockIndex* current = tip;
    while (current) {
        chain.push_back(current);
        current = current->prev;
    }
    std::reverse(chain.begin(), chain.end());
    return chain;
}

} // namespace flow

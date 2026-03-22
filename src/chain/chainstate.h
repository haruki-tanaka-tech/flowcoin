// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Chain state: manages the active chain, accepts blocks, handles reorgs.
// Owns the block tree, UTXO set, and block store.

#pragma once

#include "blockindex.h"
#include "utxo.h"
#include "blockstore.h"
#include "chaindb.h"
#include "consensus/validation.h"

#include <string>
#include <functional>

namespace flow {

class ChainState {
public:
    // Initialize chain state with a data directory.
    // Creates subdirectories for blocks and databases.
    explicit ChainState(const std::string& data_dir);

    // Accept a new block. Validates, stores, updates UTXO, extends chain.
    // Returns validation state.
    consensus::ValidationState accept_block(const CBlock& block);

    // Get the current chain tip.
    const CBlockIndex* tip() const { return tip_; }

    // Get chain height (tip height, or -1 if no blocks).
    int64_t height() const { return tip_ ? static_cast<int64_t>(tip_->height) : -1; }

    // Get the block tree.
    const BlockTree& block_tree() const { return tree_; }
    BlockTree& block_tree() { return tree_; }

    // Get the UTXO set.
    const UtxoSet& utxo_set() const { return *utxo_; }

    // Get a serialized block by hash (for P2P relay).
    std::vector<uint8_t> get_block_data(const Hash256& hash) const;

    // Initialize genesis block.
    void init_genesis(const CBlock& genesis);

    // Build BlockContext for validating a new block on top of the given parent.
    consensus::BlockContext build_context(const CBlockIndex* parent) const;

private:
    std::string data_dir_;
    BlockTree tree_;
    std::unique_ptr<UtxoSet> utxo_;
    std::unique_ptr<BlockStore> store_;
    std::unique_ptr<ChainDb> chaindb_;
    CBlockIndex* tip_{nullptr};

    // Block data cache: hash_hex → serialized block (for P2P relay)
    std::unordered_map<std::string, std::vector<uint8_t>> block_cache_;

    // Connect a block to the active chain (update UTXO, advance tip).
    Result<Ok> connect_block(const CBlock& block, CBlockIndex* index);
};

} // namespace flow

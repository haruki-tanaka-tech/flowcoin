// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "chainstate.h"
#include "consensus/params.h"
#include "consensus/growth.h"
#include "consensus/reward.h"
#include "crypto/sign.h"
#include "core/hash.h"
#include "core/time.h"

#include <spdlog/spdlog.h>
#include <algorithm>
#include <filesystem>

namespace flow {

ChainState::ChainState(const std::string& data_dir) : data_dir_(data_dir) {
    std::filesystem::create_directories(data_dir);

    utxo_ = std::make_unique<UtxoSet>(data_dir + "/utxo.db");
    store_ = std::make_unique<BlockStore>(data_dir + "/blocks");
    chaindb_ = std::make_unique<ChainDb>(data_dir + "/chain.db");

    // Load existing block index from database
    auto stored = chaindb_->load_all();
    if (!stored.empty()) {
        spdlog::info("Loading {} blocks from chain.db...", stored.size());
        for (const auto& idx : stored) {
            tree_.insert(idx);
        }

        // Restore tip
        Hash256 tip_hash = chaindb_->load_tip();
        if (!tip_hash.is_zero()) {
            tip_ = tree_.find(tip_hash);
        }
        if (!tip_ && !stored.empty()) {
            // Fallback: highest block is tip
            tip_ = tree_.find(stored.back().hash);
        }

        if (tip_) {
            spdlog::info("Chain loaded: height={}, tip={}",
                tip_->height, tip_->hash.to_hex().substr(0, 16));
        }
    }
}

void ChainState::init_genesis(const CBlock& genesis) {
    // If chain already loaded from DB, skip genesis
    if (tip_ != nullptr) return;

    auto index = CBlockIndex::from_header(genesis.header);
    index.add_status(BlockStatus::HEADER_VALID);
    index.add_status(BlockStatus::DATA_STORED);
    index.add_status(BlockStatus::FULLY_VALID);
    index.improving_blocks = 0;

    CBlockIndex* inserted = tree_.insert(index);
    if (!inserted) return;

    // Store block data
    auto block_data = genesis.serialize();
    store_->write_block(block_data);
    block_cache_[inserted->hash.to_hex()] = block_data;

    // Persist to chain.db
    chaindb_->store_index(*inserted);
    chaindb_->store_tip(inserted->hash);

    // Connect UTXO
    utxo_->connect_block(genesis.vtx, 0);

    tip_ = inserted;
}

std::vector<uint8_t> ChainState::get_block_data(const Hash256& hash) const {
    auto it = block_cache_.find(hash.to_hex());
    if (it != block_cache_.end()) return it->second;
    return {};
}

consensus::BlockContext ChainState::build_context(const CBlockIndex* parent) const {
    consensus::BlockContext ctx;
    ctx.parent_hash = parent->hash;
    ctx.parent_height = parent->height;
    ctx.parent_timestamp = parent->timestamp;
    ctx.parent_val_loss = parent->val_loss;
    ctx.parent_nbits = parent->nbits;
    ctx.parent_d_model = parent->d_model;
    ctx.parent_n_layers = parent->n_layers;
    ctx.parent_d_ff = parent->d_ff;
    ctx.parent_n_experts = parent->n_experts;
    ctx.parent_n_heads = parent->n_heads;
    ctx.parent_rank = parent->rank;
    ctx.improving_blocks = parent->improving_blocks;
    ctx.current_time = get_time();
    ctx.expected_dataset_hash = Hash256::ZERO;

    // Compute median time past (BIP 113): median of last 11 block timestamps
    std::vector<int64_t> timestamps;
    const CBlockIndex* walk = parent;
    for (int i = 0; i < 11 && walk; ++i) {
        timestamps.push_back(walk->timestamp);
        walk = walk->prev;
    }
    if (!timestamps.empty()) {
        std::sort(timestamps.begin(), timestamps.end());
        ctx.median_time_past = timestamps[timestamps.size() / 2];
    }

    return ctx;
}

consensus::ValidationState ChainState::accept_block(const CBlock& block) {
    consensus::ValidationState state;

    const CBlockIndex* parent = tree_.find(block.header.prev_hash);
    if (!parent) {
        state.invalid("orphan-block");
        return state;
    }

    auto ctx = build_context(parent);
    state = consensus::check_block(block, ctx);
    if (!state.valid) return state;

    auto index = CBlockIndex::from_header(block.header);
    index.add_status(BlockStatus::HEADER_VALID);
    index.add_status(BlockStatus::FULLY_VALID);

    bool improving = block.header.val_loss < parent->val_loss;
    index.improving_blocks = parent->improving_blocks + (improving ? 1 : 0);

    CBlockIndex* inserted = tree_.insert(index);
    if (!inserted) {
        state.invalid("duplicate-block");
        return state;
    }

    // Store block data
    auto block_data = block.serialize();
    store_->write_block(block_data);
    block_cache_[inserted->hash.to_hex()] = block_data;
    // Keep cache bounded to last 1000 blocks
    while (block_cache_.size() > 1000) {
        block_cache_.erase(block_cache_.begin());
    }
    inserted->add_status(BlockStatus::DATA_STORED);

    // Persist block index to chain.db
    chaindb_->store_index(*inserted);

    // Connect to active chain if it extends the tip
    if (inserted->height > (tip_ ? tip_->height : 0)) {
        auto result = connect_block(block, inserted);
        if (!result) {
            state.invalid("connect-failed: " + result.error_message());
            return state;
        }
    }

    return state;
}

Result<Ok> ChainState::connect_block(const CBlock& block, CBlockIndex* index) {
    // Verify coinbase reward
    if (!block.vtx.empty() && block.vtx[0].is_coinbase()) {
        Amount expected = consensus::get_block_subsidy(index->height);
        Amount actual{0};
        for (const auto& out : block.vtx[0].vout) {
            actual += out.amount;
        }
        if (actual > expected) {
            return Error{"bad-coinbase-amount"};
        }
    }

    // Verify transaction signatures (skip coinbase)
    for (size_t t = 0; t < block.vtx.size(); ++t) {
        const auto& tx = block.vtx[t];
        if (tx.is_coinbase()) continue;

        // Compute signing hash
        auto sign_data = tx.signing_data();
        Hash256 sighash = keccak256d(sign_data.data(), sign_data.size());

        for (size_t i = 0; i < tx.vin.size(); ++i) {
            const auto& in = tx.vin[i];

            // Look up the UTXO being spent
            auto utxo_entry = utxo_->get(in.prevout);
            if (!utxo_entry) {
                return Error{"tx-input-missing: " + in.prevout.txid.to_hex()};
            }

            // Coinbase maturity: cannot spend coinbase until 100 confirmations
            if (utxo_entry->is_coinbase) {
                uint64_t confirmations = index->height - utxo_entry->height;
                if (confirmations < consensus::COINBASE_MATURITY) {
                    return Error{"coinbase-not-mature"};
                }
            }

            // Verify pubkey_hash matches: keccak256d(pubkey)[0..19] == utxo.pubkey_hash
            Hash256 pk_hash = keccak256d(in.pubkey.bytes(), 32);
            Blob<20> computed_pkh;
            std::memcpy(computed_pkh.bytes(), pk_hash.bytes(), 20);
            if (computed_pkh != utxo_entry->pubkey_hash) {
                return Error{"tx-wrong-key"};
            }

            // Verify Ed25519 signature
            if (!crypto::verify(in.pubkey, sighash.bytes(), 32, in.sig)) {
                return Error{"tx-bad-signature"};
            }
        }

        // Verify no negative outputs and total inputs >= total outputs
        Amount total_in{0};
        for (const auto& in : tx.vin) {
            auto entry = utxo_->get(in.prevout);
            if (entry) total_in += entry->amount;
        }
        Amount total_out{0};
        for (const auto& out : tx.vout) {
            if (out.amount.value < 0) return Error{"tx-negative-output"};
            total_out += out.amount;
        }
        if (total_out > total_in) {
            return Error{"tx-overspend"};
        }
    }

    // Update UTXO set
    auto result = utxo_->connect_block(block.vtx, index->height);
    if (!result) return result;

    tip_ = index;
    chaindb_->store_tip(index->hash);

    return Ok{};
}

} // namespace flow

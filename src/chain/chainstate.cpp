// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// ChainState implementation with full integration:
// - ModelState: applies training deltas on connect, undoes on disconnect
// - TxIndex: indexes transactions on connect, deindexes on disconnect
// - Assume-valid: skips Check 15 for blocks below a hardcoded hash
// - Proper reorganization with model state rollback

#include "chain/chainstate.h"
#include "consensus/eval.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "hash/keccak.h"
#include "hash/merkle.h"
#include "util/time.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>

namespace flow {

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

ChainState::ChainState(const std::string& datadir)
    : datadir_(datadir)
    , utxo_(datadir + "/utxo.db")
    , store_(datadir)
    , model_state_(datadir)
{
    assume_valid_hash_.set_null();
}

// ---------------------------------------------------------------------------
// init — create genesis if needed, initialize model state and tx index
// ---------------------------------------------------------------------------

bool ChainState::init() {
    // Initialize model state (loads from checkpoint or creates from genesis)
    if (!model_state_.init()) {
        fprintf(stderr, "ChainState: model state initialization failed\n");
        return false;
    }

    // Initialize optional transaction index
    if (txindex_enabled_) {
        txindex_ = std::make_unique<TxIndex>(datadir_ + "/txindex.db");
        if (!txindex_->is_open()) {
            fprintf(stderr, "ChainState: warning: transaction index "
                    "failed to open, continuing without it\n");
            txindex_.reset();
        }
    }

    // If the block tree is empty, create the genesis block
    if (tree_.size() == 0) {
        CBlock genesis = create_genesis_block();
        uint256 genesis_hash = genesis.get_hash();

        // Build the CBlockIndex manually for genesis (no parent context)
        auto idx = std::make_unique<CBlockIndex>();
        idx->set_from_header(genesis);
        idx->hash = genesis_hash;
        idx->height = 0;
        idx->prev = nullptr;
        idx->improving_blocks = 0;
        idx->n_tx = static_cast<int>(genesis.vtx.size());
        idx->status = BLOCK_HEADER_VALID | BLOCK_FULLY_VALIDATED;

        // Store genesis block to disk
        BlockPos pos = store_.write_block(genesis);
        if (pos.is_null()) {
            fprintf(stderr, "ChainState: failed to write genesis block to disk\n");
            return false;
        }
        idx->pos = pos;
        idx->status |= BLOCK_DATA_STORED;

        // Insert into block tree
        CBlockIndex* genesis_idx = tree_.insert_genesis(std::move(idx));

        // Connect genesis UTXO (coinbase output)
        utxo_.begin_transaction();
        for (size_t tx_i = 0; tx_i < genesis.vtx.size(); ++tx_i) {
            const CTransaction& tx = genesis.vtx[tx_i];
            uint256 txid = tx.get_txid();

            for (uint32_t vout = 0; vout < tx.vout.size(); ++vout) {
                const CTxOut& out = tx.vout[vout];
                UTXOEntry entry;
                entry.value = out.amount;
                entry.pubkey_hash = out.pubkey_hash;
                entry.height = 0;
                entry.is_coinbase = tx.is_coinbase();
                utxo_.add(txid, vout, entry);
            }
        }
        utxo_.commit_transaction();

        // Process genesis block through model state (no delta, but registers height 0)
        model_state_.process_block(genesis, 0);

        // Index genesis transactions
        if (txindex_) {
            txindex_->index_block(genesis, 0, genesis_hash);
        }

        // Set as the best tip
        update_tip(genesis_idx);

        fprintf(stderr, "ChainState: genesis block created (height 0)\n");
    }

    return true;
}

// ---------------------------------------------------------------------------
// create_genesis_block
// ---------------------------------------------------------------------------

CBlock ChainState::create_genesis_block() const {
    using namespace consensus;

    CBlock genesis;

    // -- Header fields --
    genesis.prev_hash.set_null();
    genesis.height      = 0;
    genesis.timestamp   = GENESIS_TIMESTAMP;
    genesis.nbits       = INITIAL_NBITS;
    genesis.version     = 1;

    // PoUT fields: genesis has max loss (untrained model)
    genesis.val_loss        = MAX_VAL_LOSS;
    genesis.prev_val_loss   = MAX_VAL_LOSS;
    genesis.train_steps     = 0;
    genesis.stagnation      = 0;

    // Model architecture: genesis dimensions
    genesis.d_model  = GENESIS_D_MODEL;
    genesis.n_layers = GENESIS_N_LAYERS;
    genesis.d_ff     = GENESIS_D_FF;
    genesis.n_heads  = GENESIS_N_HEADS;
    genesis.gru_dim  = GENESIS_GRU_DIM;
    genesis.n_slots  = GENESIS_N_SLOTS;

    // No delta payload in genesis
    genesis.delta_offset    = 0;
    genesis.delta_length    = 0;
    genesis.sparse_count    = 0;
    genesis.sparse_threshold = 0.0f;
    genesis.nonce           = 0;

    // No real miner for genesis
    genesis.miner_pubkey.fill(0);
    genesis.miner_sig.fill(0);

    // Training/dataset hashes are null for genesis
    genesis.training_hash.set_null();
    genesis.dataset_hash.set_null();

    // -- Coinbase transaction --
    CTransaction coinbase;
    coinbase.version = 1;
    coinbase.locktime = 0;

    // Coinbase input: null prevout, script_sig = genesis message
    CTxIn cb_in;
    cb_in.prevout.txid.set_null();
    cb_in.prevout.index = 0;
    cb_in.signature.fill(0);

    // Embed the genesis message as the pubkey field (repurposed for coinbase)
    const char* msg = GENESIS_COINBASE_MSG;
    size_t msg_len = std::strlen(msg);
    uint256 msg_hash = keccak256(reinterpret_cast<const uint8_t*>(msg), msg_len);
    std::memcpy(cb_in.pubkey.data(), msg_hash.data(), 32);

    coinbase.vin.push_back(cb_in);

    // Coinbase output: INITIAL_REWARD to a null pubkey_hash (unspendable genesis)
    CTxOut cb_out;
    cb_out.amount = INITIAL_REWARD;
    cb_out.pubkey_hash.fill(0);
    coinbase.vout.push_back(cb_out);

    genesis.vtx.push_back(coinbase);

    // No delta payload
    genesis.delta_payload.clear();

    // Compute merkle root from the single coinbase transaction
    std::vector<uint256> txids;
    txids.push_back(coinbase.get_txid());
    genesis.merkle_root = compute_merkle_root(txids);

    return genesis;
}

// ---------------------------------------------------------------------------
// is_assumed_valid — check if a block is at or below the assume-valid point
// ---------------------------------------------------------------------------

bool ChainState::is_assumed_valid(const CBlockIndex* idx) const {
    if (assume_valid_hash_.is_null()) {
        return false;  // assume-valid not configured
    }

    if (!idx) {
        return false;
    }

    // Check if this block IS the assume-valid block
    if (idx->hash == assume_valid_hash_) {
        return true;
    }

    // Check if the assume-valid block is an ancestor of this block.
    // Walk up from this block. If we find the assume-valid hash, then
    // this block is ABOVE the assume-valid point (not below).
    // We need the opposite: is this block AT OR BELOW the assume-valid point?
    //
    // Strategy: find the assume-valid block in our tree. If it exists and
    // its height >= this block's height, then this block is at or below it
    // (assuming they are on the same chain).
    CBlockIndex* av_idx = tree_.find(assume_valid_hash_);
    if (!av_idx) {
        return false;  // assume-valid block not yet in our tree
    }

    // If the assume-valid block is at a higher height than this block,
    // and both are on the same chain, then this block is below assume-valid.
    // For simplicity and safety, we check: is this block an ancestor of
    // the assume-valid block?
    if (idx->height > av_idx->height) {
        return false;  // This block is above the assume-valid block
    }

    // Walk from assume-valid block backwards to see if we reach idx
    CBlockIndex* walk = av_idx;
    while (walk && walk->height > idx->height) {
        walk = walk->prev;
    }

    return walk == idx;
}

// ---------------------------------------------------------------------------
// get_eval_function — determine whether to run Check 15
// ---------------------------------------------------------------------------

consensus::EvalFunction ChainState::get_eval_function(
        const CBlockIndex* parent) const {
    // If we're doing IBD (far from tip), skip Check 15 for performance
    // unless assume-valid is specifically configured.
    // The assume-valid optimization: skip Check 15 for blocks at or below
    // the assume-valid hash.

    if (parent && is_assumed_valid(parent)) {
        // Parent is at or below assume-valid — skip forward evaluation
        return nullptr;
    }

    // Use the global eval engine if available
    consensus::EvalEngine* engine = consensus::EvalEngine::instance();
    if (engine) {
        return &consensus::EvalEngine::eval_function_adapter;
    }

    // No eval engine available (shouldn't happen after init)
    return nullptr;
}

// ---------------------------------------------------------------------------
// accept_header
// ---------------------------------------------------------------------------

CBlockIndex* ChainState::accept_header(const CBlockHeader& header,
                                        consensus::ValidationState& state) {
    std::lock_guard<std::mutex> lock(cs_main_);

    uint256 block_hash = header.get_hash();

    // Check if we already have this header
    CBlockIndex* existing = tree_.find(block_hash);
    if (existing) {
        return existing;
    }

    // Genesis block cannot be accepted via this path
    if (header.height == 0) {
        state.invalid(consensus::ValidationResult::HEADER_INVALID,
                      "bad-genesis", "cannot accept genesis via accept_header");
        return nullptr;
    }

    // Look up the parent
    CBlockIndex* parent = tree_.find(header.prev_hash);
    if (!parent) {
        state.invalid(consensus::ValidationResult::HEADER_INVALID,
                      "bad-prevblk", "parent block not found in tree");
        return nullptr;
    }

    // Check if parent is marked as failed
    if (parent->status & BLOCK_FAILED) {
        state.invalid(consensus::ValidationResult::HEADER_INVALID,
                      "bad-prevblk", "parent block is invalid");
        return nullptr;
    }

    // Build context for header validation
    int64_t adjusted_time = get_adjusted_time();
    consensus::BlockContext ctx = parent->make_child_context(adjusted_time);

    // Validate header
    if (!consensus::check_header(header, ctx, state)) {
        return nullptr;
    }

    // Insert into the block tree
    CBlockIndex* idx = tree_.insert(header);
    idx->status |= BLOCK_HEADER_VALID;

    return idx;
}

// ---------------------------------------------------------------------------
// accept_block — full block validation + storage + chain connection
// ---------------------------------------------------------------------------

bool ChainState::accept_block(const CBlock& block,
                               consensus::ValidationState& state) {
    std::lock_guard<std::mutex> lock(cs_main_);

    uint256 block_hash = block.get_hash();

    // Check if we already have this block fully validated
    CBlockIndex* existing = tree_.find(block_hash);
    if (existing && (existing->status & BLOCK_FULLY_VALIDATED)) {
        return true;
    }

    // Genesis block cannot be accepted via this path
    if (block.height == 0) {
        state.invalid(consensus::ValidationResult::BLOCK_INVALID,
                      "bad-genesis", "cannot accept genesis via accept_block");
        return false;
    }

    // Look up the parent
    CBlockIndex* parent = tree_.find(block.prev_hash);
    if (!parent) {
        state.invalid(consensus::ValidationResult::BLOCK_INVALID,
                      "bad-prevblk", "parent block not found");
        return false;
    }

    if (parent->status & BLOCK_FAILED) {
        state.invalid(consensus::ValidationResult::BLOCK_INVALID,
                      "bad-prevblk", "parent block is invalid");
        return false;
    }

    int64_t adjusted_time = get_adjusted_time();
    consensus::BlockContext ctx = parent->make_child_context(adjusted_time);

    // Determine the eval function based on assume-valid status
    consensus::EvalFunction eval_fn = get_eval_function(parent);

    // Run full block validation with the appropriate eval function
    if (!consensus::check_block(block, ctx, state, eval_fn)) {
        CBlockIndex* idx = tree_.find(block_hash);
        if (idx) {
            idx->status |= BLOCK_FAILED;
        }
        return false;
    }

    // Ensure the header is in the block tree
    CBlockIndex* idx = existing;
    if (!idx) {
        idx = tree_.insert(block);
    }

    idx->status |= BLOCK_HEADER_VALID;
    idx->n_tx = static_cast<int>(block.vtx.size());

    // Store block to disk
    BlockPos pos = store_.write_block(block);
    if (pos.is_null()) {
        state.error("disk-write-failed");
        return false;
    }
    idx->pos = pos;
    idx->status |= BLOCK_DATA_STORED;

    // Connect the block to the active chain if it extends the best tip
    CBlockIndex* current_tip = tree_.best_tip();

    if (!current_tip || idx->height > current_tip->height) {
        if (parent == current_tip) {
            // Simple case: extends the current tip directly
            if (!connect_block(block, idx)) {
                state.error("connect-block-failed");
                idx->status |= BLOCK_FAILED;
                return false;
            }
        } else {
            // Reorg case: the new block is on a longer fork.
            // Disconnect blocks from current tip back to the fork point,
            // then connect blocks from fork point to the new tip.

            // Find the fork point (common ancestor)
            CBlockIndex* fork_a = current_tip;
            CBlockIndex* fork_b = idx;

            while (fork_a && fork_b && fork_a != fork_b) {
                if (fork_a->height > fork_b->height) {
                    fork_a = fork_a->prev;
                } else if (fork_b->height > fork_a->height) {
                    fork_b = fork_b->prev;
                } else {
                    fork_a = fork_a->prev;
                    fork_b = fork_b->prev;
                }
            }

            if (!fork_a || fork_a != fork_b) {
                state.error("reorg-no-fork-point");
                return false;
            }

            CBlockIndex* fork_point = fork_a;
            uint64_t disconnect_count = current_tip->height - fork_point->height;
            uint64_t connect_count = idx->height - fork_point->height;

            fprintf(stderr, "ChainState: reorganizing chain: "
                    "disconnect %lu blocks, connect %lu blocks "
                    "(fork at height %lu)\n",
                    static_cast<unsigned long>(disconnect_count),
                    static_cast<unsigned long>(connect_count),
                    static_cast<unsigned long>(fork_point->height));

            // Disconnect from current tip back to fork point
            while (tree_.best_tip() != fork_point) {
                if (!disconnect_tip()) {
                    state.error("reorg-disconnect-failed");
                    return false;
                }
            }

            // Build the connect path from fork_point to new tip
            std::vector<CBlockIndex*> connect_path;
            CBlockIndex* walk = idx;
            while (walk && walk != fork_point) {
                connect_path.push_back(walk);
                walk = walk->prev;
            }
            std::reverse(connect_path.begin(), connect_path.end());

            // Connect each block in order
            for (CBlockIndex* connect_idx : connect_path) {
                CBlock connect_block_data;
                if (!store_.read_block(connect_idx->pos, connect_block_data)) {
                    state.error("reorg-read-failed");
                    return false;
                }
                if (!connect_block(connect_block_data, connect_idx)) {
                    state.error("reorg-connect-failed");
                    connect_idx->status |= BLOCK_FAILED;
                    return false;
                }
            }

            fprintf(stderr, "ChainState: reorganization complete, "
                    "new tip at height %lu\n",
                    static_cast<unsigned long>(tree_.best_tip()->height));
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// connect_block — apply block's UTXO changes + model state + tx index
// ---------------------------------------------------------------------------

bool ChainState::connect_block(const CBlock& block, CBlockIndex* index) {
    // === UTXO updates ===
    utxo_.begin_transaction();

    for (size_t tx_i = 0; tx_i < block.vtx.size(); ++tx_i) {
        const CTransaction& tx = block.vtx[tx_i];
        uint256 txid = tx.get_txid();

        // Spend inputs (skip coinbase)
        if (!tx.is_coinbase()) {
            for (const CTxIn& in : tx.vin) {
                UTXOEntry spent_entry;
                if (!utxo_.get(in.prevout.txid, in.prevout.index, spent_entry)) {
                    fprintf(stderr, "connect_block: UTXO not found for input "
                            "at height %lu, tx %zu\n",
                            static_cast<unsigned long>(index->height), tx_i);
                    utxo_.rollback_transaction();
                    return false;
                }

                // Check coinbase maturity
                if (spent_entry.is_coinbase) {
                    if (index->height < spent_entry.height + consensus::COINBASE_MATURITY) {
                        fprintf(stderr, "connect_block: premature coinbase spend "
                                "at height %lu (created at %lu, maturity %d)\n",
                                static_cast<unsigned long>(index->height),
                                static_cast<unsigned long>(spent_entry.height),
                                consensus::COINBASE_MATURITY);
                        utxo_.rollback_transaction();
                        return false;
                    }
                }

                utxo_.remove(in.prevout.txid, in.prevout.index);
            }
        }

        // Add outputs as new UTXOs
        for (uint32_t vout = 0; vout < tx.vout.size(); ++vout) {
            const CTxOut& out = tx.vout[vout];
            if (out.amount > 0) {
                UTXOEntry entry;
                entry.value = out.amount;
                entry.pubkey_hash = out.pubkey_hash;
                entry.height = index->height;
                entry.is_coinbase = tx.is_coinbase();
                utxo_.add(txid, vout, entry);
            }
        }
    }

    utxo_.commit_transaction();

    // === Model state: apply training delta ===
    if (!model_state_.process_block(block, index->height)) {
        fprintf(stderr, "connect_block: model state update failed at height %lu\n",
                static_cast<unsigned long>(index->height));
        // Model state failure is non-fatal for UTXO consistency,
        // but we log it prominently. The model may need to be
        // rebuilt from a checkpoint.
    }

    // === Transaction index ===
    if (txindex_) {
        uint256 block_hash = block.get_hash();
        if (!txindex_->index_block(block, index->height, block_hash)) {
            fprintf(stderr, "connect_block: tx index update failed at height %lu\n",
                    static_cast<unsigned long>(index->height));
            // Non-fatal — the tx index is optional
        }
    }

    // Mark block as fully validated and update the tip
    index->status |= BLOCK_FULLY_VALIDATED;
    update_tip(index);

    return true;
}

// ---------------------------------------------------------------------------
// disconnect_tip — reverse UTXO changes + model state + tx index
// ---------------------------------------------------------------------------

bool ChainState::disconnect_tip() {
    CBlockIndex* tip_idx = tree_.best_tip();
    if (!tip_idx || !tip_idx->prev) {
        fprintf(stderr, "disconnect_tip: cannot disconnect genesis or null tip\n");
        return false;
    }

    // Read the tip block from disk
    CBlock tip_block;
    if (!store_.read_block(tip_idx->pos, tip_block)) {
        fprintf(stderr, "disconnect_tip: failed to read block at height %lu\n",
                static_cast<unsigned long>(tip_idx->height));
        return false;
    }

    // === UTXO undo ===
    utxo_.begin_transaction();

    // Process transactions in reverse order
    for (int tx_i = static_cast<int>(tip_block.vtx.size()) - 1; tx_i >= 0; --tx_i) {
        const CTransaction& tx = tip_block.vtx[static_cast<size_t>(tx_i)];
        uint256 txid = tx.get_txid();

        // Remove outputs (undo the UTXOs we created)
        for (uint32_t vout = 0; vout < tx.vout.size(); ++vout) {
            utxo_.remove(txid, vout);
        }

        // Restore spent inputs (skip coinbase)
        if (!tx.is_coinbase()) {
            for (size_t vin_i = 0; vin_i < tx.vin.size(); ++vin_i) {
                const CTxIn& txin = tx.vin[vin_i];

                // Find the block that contains the spent transaction
                CBlockIndex* source_idx = nullptr;
                {
                    CBlockIndex* walk = tip_idx->prev;
                    while (walk) {
                        CBlock walk_block;
                        if (store_.read_block(walk->pos, walk_block)) {
                            for (const CTransaction& wtx : walk_block.vtx) {
                                if (wtx.get_txid() == txin.prevout.txid) {
                                    if (txin.prevout.index < wtx.vout.size()) {
                                        const CTxOut& orig_out = wtx.vout[txin.prevout.index];
                                        UTXOEntry restore_entry;
                                        restore_entry.value = orig_out.amount;
                                        restore_entry.pubkey_hash = orig_out.pubkey_hash;
                                        restore_entry.height = walk->height;
                                        restore_entry.is_coinbase = wtx.is_coinbase();
                                        utxo_.add(txin.prevout.txid,
                                                  txin.prevout.index, restore_entry);
                                        source_idx = walk;
                                    }
                                    break;
                                }
                            }
                        }
                        if (source_idx) break;
                        walk = walk->prev;
                    }
                }

                if (!source_idx) {
                    fprintf(stderr, "disconnect_tip: could not find source tx for "
                            "input %zu of tx %d at height %lu\n",
                            vin_i, tx_i,
                            static_cast<unsigned long>(tip_idx->height));
                    utxo_.rollback_transaction();
                    return false;
                }
            }
        }
    }

    utxo_.commit_transaction();

    // === Model state: undo last delta ===
    if (!model_state_.undo_block()) {
        fprintf(stderr, "disconnect_tip: model state undo failed at height %lu\n",
                static_cast<unsigned long>(tip_idx->height));
        // Non-fatal for UTXO consistency, but the model state is now
        // inconsistent. A checkpoint reload may be required.
    }

    // === Transaction index: remove entries for this block ===
    if (txindex_) {
        if (!txindex_->deindex_block(tip_idx->height)) {
            fprintf(stderr, "disconnect_tip: tx deindex failed at height %lu\n",
                    static_cast<unsigned long>(tip_idx->height));
            // Non-fatal
        }
    }

    // Move the tip back to the parent
    update_tip(tip_idx->prev);

    return true;
}

// ---------------------------------------------------------------------------
// get_adjusted_time
// ---------------------------------------------------------------------------

int64_t ChainState::get_adjusted_time() const {
    return GetTime();
}

// ---------------------------------------------------------------------------
// update_tip
// ---------------------------------------------------------------------------

void ChainState::update_tip(CBlockIndex* new_tip) {
    tree_.set_best_tip(new_tip);
    if (new_tip) {
        fprintf(stderr, "ChainState: new tip at height %lu, hash=...\n",
                static_cast<unsigned long>(new_tip->height));
    }
}

// ---------------------------------------------------------------------------
// get_chain_to
// ---------------------------------------------------------------------------

std::vector<CBlockIndex*> ChainState::get_chain_to(CBlockIndex* tip_idx) const {
    std::vector<CBlockIndex*> chain;
    CBlockIndex* walk = tip_idx;
    while (walk) {
        chain.push_back(walk);
        walk = walk->prev;
    }
    std::reverse(chain.begin(), chain.end());
    return chain;
}

} // namespace flow

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// ChainState implementation with full integration:
// - ModelState: applies training deltas on connect, undoes on disconnect
// - TxIndex: indexes transactions on connect, deindexes on disconnect
// - Assume-valid: skips Check 15 for blocks below a hardcoded hash
// - Proper reorganization with model state rollback

#include "chain/chainstate.h"
#include "chain/chaindb.h"
#include "consensus/difficulty.h"
#include "consensus/genesis.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "hash/keccak.h"
#include "hash/merkle.h"
#include "util/arith_uint256.h"
#include "util/time.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <sys/stat.h>
#include "logging.h"

namespace flow {

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

ChainState::ChainState(const std::string& datadir)
    : datadir_(datadir)
    , utxo_(datadir + "/utxo.db")
    , store_(datadir)
    
{
    assume_valid_hash_.set_null();
}

// ---------------------------------------------------------------------------
// init — create genesis if needed, initialize model state and tx index
// ---------------------------------------------------------------------------

bool ChainState::init() {
    // Initialize model state (loads from checkpoint or creates from genesis)
    // Initialize optional transaction index
    if (txindex_enabled_) {
        txindex_ = std::make_unique<TxIndex>(datadir_ + "/txindex.db");
        if (!txindex_->is_open()) {
            LogError("chain", "warning: transaction index "
                    "failed to open, continuing without it");
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
        idx->n_tx = static_cast<int>(genesis.vtx.size());
        idx->status = BLOCK_HEADER_VALID | BLOCK_FULLY_VALIDATED;

        // Store genesis block to disk
        BlockPos pos = store_.write_block(genesis);
        if (pos.is_null()) {
            LogError("chain", "failed to write genesis block to disk");
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
        // Index genesis transactions
        if (txindex_) {
            txindex_->index_block(genesis, 0, genesis_hash);
        }

        // Set as the best tip
        update_tip(genesis_idx);

        LogInfo("chain", "genesis block created (height 0)");
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

    // Model architecture: genesis dimensions

    // No delta payload in genesis
    genesis.nonce           = 0;

    // Genesis creator's Ed25519 public key (proof of authorship)
    static constexpr uint8_t GENESIS_PUBKEY[32] = {
        0x36, 0x4a, 0x0a, 0x94, 0x80, 0x08, 0x56, 0x8a,
        0x1c, 0xe2, 0xfd, 0x77, 0x6b, 0x61, 0xc2, 0x26,
        0x4c, 0x21, 0x36, 0x70, 0xda, 0xeb, 0xfe, 0x1d,
        0x5d, 0xf8, 0x32, 0xba, 0x0c, 0xb5, 0xbb, 0x62
    };
    std::memcpy(genesis.miner_pubkey.data(), GENESIS_PUBKEY, 32);
    genesis.miner_sig.fill(0);

    // Training/dataset hashes are null for genesis
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
    const char* msg = consensus::GENESIS_COINBASE_MSG;
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
    
    // Run full block validation with the appropriate eval function
    if (!consensus::check_block(block, ctx, state)) {
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

            LogInfo("chain", "reorganizing chain: "
                    "disconnect %lu blocks, connect %lu blocks "
                    "(fork at height %lu)",
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

            LogInfo("chain", "reorganization complete, "
                    "new tip at height %lu",
                    static_cast<unsigned long>(tree_.best_tip()->height));
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// connect_block — apply block's UTXO changes + model state + tx index
// ---------------------------------------------------------------------------

bool ChainState::connect_block(const CBlock& block, CBlockIndex* index) {
    // === Generate undo data BEFORE modifying UTXO set ===
    // Capture the state of all UTXOs that will be spent by this block.
    // This undo data enables efficient disconnection during reorgs.
    BlockUndo undo = generate_undo(block);

    // === Compute input sums for fee validation ===
    std::vector<Amount> tx_input_sums;
    tx_input_sums.reserve(block.vtx.size());

    for (size_t tx_i = 0; tx_i < block.vtx.size(); ++tx_i) {
        const CTransaction& tx = block.vtx[tx_i];

        if (tx.is_coinbase()) {
            tx_input_sums.push_back(0);
            continue;
        }

        Amount input_sum = 0;
        for (const CTxIn& in : tx.vin) {
            UTXOEntry spent_entry;
            if (!utxo_.get(in.prevout.txid, in.prevout.index, spent_entry)) {
                LogError("chain", "connect_block: UTXO not found for input "
                        "at height %lu, tx %zu",
                        static_cast<unsigned long>(index->height), tx_i);
                return false;
            }
            input_sum += spent_entry.value;
        }
        tx_input_sums.push_back(input_sum);
    }

    // === Validate coinbase against subsidy + fees ===
    Amount fees = consensus::compute_block_fees(block, tx_input_sums);
    Amount subsidy = consensus::compute_block_reward(index->height);
    Amount max_coinbase = subsidy + fees;

    if (block.vtx[0].get_value_out() > max_coinbase) {
        LogError("chain", "connect_block: coinbase exceeds subsidy + fees "
                "at height %lu (coinbase=%ld, max=%ld)",
                static_cast<unsigned long>(index->height),
                static_cast<long>(block.vtx[0].get_value_out()),
                static_cast<long>(max_coinbase));
        return false;
    }

    // === Verify inputs > outputs for each non-coinbase tx (no negative fees) ===
    for (size_t tx_i = 1; tx_i < block.vtx.size(); ++tx_i) {
        Amount out_sum = block.vtx[tx_i].get_value_out();
        if (tx_input_sums[tx_i] < out_sum) {
            LogError("chain", "connect_block: tx %zu has input_sum < output_sum "
                    "at height %lu", tx_i,
                    static_cast<unsigned long>(index->height));
            return false;
        }
    }

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
                    LogError("chain", "connect_block: UTXO not found for input "
                            "at height %lu, tx %zu",
                            static_cast<unsigned long>(index->height), tx_i);
                    utxo_.rollback_transaction();
                    return false;
                }

                // Check coinbase maturity
                if (spent_entry.is_coinbase) {
                    if (index->height < spent_entry.height + consensus::COINBASE_MATURITY) {
                        LogError("chain", "connect_block: premature coinbase spend "
                                "at height %lu (created at %lu, maturity %d)",
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

    // === Save undo data to disk for reorg support ===
    {
        std::vector<uint8_t> undo_bytes = undo.serialize();
        if (!undo_bytes.empty()) {
            if (!store_.write_undo(index->height, undo_bytes)) {
                LogError("chain", "connect_block: failed to write undo data "
                        "at height %lu",
                        static_cast<unsigned long>(index->height));
                // Non-fatal: reorgs past this point will use the slow path
            }
        }
    }

    // === Model state: apply training delta ===
    // === Transaction index ===
    if (txindex_) {
        uint256 block_hash = block.get_hash();
        if (!txindex_->index_block(block, index->height, block_hash)) {
            LogError("chain", "connect_block: tx index update failed at height %lu",
                    static_cast<unsigned long>(index->height));
            // Non-fatal — the tx index is optional
        }
    }

    // Mark block as fully validated and update the tip
    index->status |= BLOCK_FULLY_VALIDATED;
    update_tip(index);

    // === Persist block index entry and tip to ChainDB ===
    persist_block_index(index);
    persist_tip();

    // === Auto-flush periodically ===
    maybe_flush();

    return true;
}

// ---------------------------------------------------------------------------
// disconnect_tip — reverse UTXO changes + model state + tx index
// ---------------------------------------------------------------------------

bool ChainState::disconnect_tip() {
    CBlockIndex* tip_idx = tree_.best_tip();
    if (!tip_idx || !tip_idx->prev) {
        LogError("chain", "disconnect_tip: cannot disconnect genesis or null tip");
        return false;
    }

    // Read the tip block from disk
    CBlock tip_block;
    if (!store_.read_block(tip_idx->pos, tip_block)) {
        LogError("chain", "disconnect_tip: failed to read block at height %lu",
                static_cast<unsigned long>(tip_idx->height));
        return false;
    }

    // === Try the fast path: use pre-computed undo data ===
    std::vector<uint8_t> undo_bytes;
    if (store_.read_undo(tip_idx->height, undo_bytes)) {
        BlockUndo undo;
        if (BlockUndo::deserialize(undo_bytes.data(), undo_bytes.size(), undo)) {
            // Fast disconnect using undo data
            if (disconnect_block(tip_block, undo)) {
                persist_tip();
                return true;
            }
            LogError("chain", "disconnect_tip: fast disconnect failed, "
                    "falling back to slow path at height %lu",
                    static_cast<unsigned long>(tip_idx->height));
        }
    }

    // === Slow path: scan the chain for source transactions ===
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
                    LogError("chain", "disconnect_tip: could not find source tx for "
                            "input %zu of tx %d at height %lu",
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
    // === Transaction index: remove entries for this block ===
    if (txindex_) {
        if (!txindex_->deindex_block(tip_idx->height)) {
            LogError("chain", "disconnect_tip: tx deindex failed at height %lu",
                    static_cast<unsigned long>(tip_idx->height));
            // Non-fatal
        }
    }

    // Move the tip back to the parent
    update_tip(tip_idx->prev);
    persist_tip();

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
        LogInfo("chain", "new tip at height %lu, hash=...",
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

// ---------------------------------------------------------------------------
// load_from_disk — full startup sequence
// ---------------------------------------------------------------------------

bool ChainState::load_from_disk() {
    std::lock_guard<std::mutex> lock(cs_main_);

    // Step 1: Open/create ChainDB
    std::string chaindb_path = datadir_ + "/chaindb.db";
    try {
        chaindb_ = std::make_unique<ChainDB>(chaindb_path);
    } catch (const std::exception& e) {
        LogError("chain", "failed to open ChainDB: %s", e.what());
        return false;
    }

    if (!chaindb_->is_open()) {
        LogInfo("chain", "ChainDB not open after construction");
        return false;
    }

    // Step 2: Load all block indices from DB
    size_t db_count = chaindb_->count();
    if (db_count == 0) {
        LogInfo("chain", "empty ChainDB, starting fresh");
        return true;  // Will create genesis in init()
    }

    LogInfo("chain", "loading %zu block indices from disk", db_count);

    // Step 3: Reconstruct BlockTree from loaded indices
    if (!rebuild_tree_from_db()) {
        LogError("chain", "failed to rebuild block tree from DB");
        return false;
    }

    // Step 4: Verify tip matches stored tip
    uint256 stored_tip_hash = chaindb_->load_tip();
    uint64_t stored_height = chaindb_->load_height();

    CBlockIndex* stored_tip = tree_.find(stored_tip_hash);
    if (!stored_tip) {
        LogInfo("chain", "stored tip not found in tree, "
                "attempting crash recovery");

        // Step 5: Crash recovery
        CBlockIndex* recovered = recover_tip();
        if (!recovered) {
            LogError("chain", "crash recovery failed, "
                    "no valid tip found");
            return false;
        }

        update_tip(recovered);
        persist_tip();

        LogInfo("chain", "recovered tip at height %lu",
                static_cast<unsigned long>(recovered->height));
    } else {
        // Verify the stored tip is fully validated
        if (!(stored_tip->status & BLOCK_FULLY_VALIDATED)) {
            LogInfo("chain", "stored tip at height %lu not fully "
                    "validated, walking back",
                    static_cast<unsigned long>(stored_tip->height));

            CBlockIndex* walk = stored_tip;
            while (walk && !(walk->status & BLOCK_FULLY_VALIDATED)) {
                walk = walk->prev;
            }

            if (!walk) {
                LogInfo("chain", "no fully validated block found");
                return false;
            }

            update_tip(walk);
            persist_tip();
        } else {
            update_tip(stored_tip);
        }

        LogInfo("chain", "loaded tip at height %lu "
                "(stored height was %lu)",
                static_cast<unsigned long>(tip() ? tip()->height : 0),
                static_cast<unsigned long>(stored_height));
    }

    return true;
}

// ---------------------------------------------------------------------------
// rebuild_tree_from_db
// ---------------------------------------------------------------------------

bool ChainState::rebuild_tree_from_db() {
    auto indices = chaindb_->load_all_indices();
    if (indices.empty()) return false;

    // Insert all into tree, linking parents
    chaindb_->begin_batch();

    for (auto& loaded_idx : indices) {
        // Check if this block is already in the tree
        CBlockIndex* existing = tree_.find(loaded_idx.hash);
        if (existing) continue;

        // Create a block header from the loaded index to insert into the tree
        CBlockHeader hdr;
        hdr.prev_hash       = loaded_idx.prev_hash;
        hdr.height          = loaded_idx.height;
        hdr.timestamp       = loaded_idx.timestamp;
        hdr.nbits           = loaded_idx.nbits;
        hdr.merkle_root     = loaded_idx.merkle_root;
        std::memcpy(hdr.miner_pubkey.data(), loaded_idx.miner_pubkey.data(), 32);

        // Insert into tree (handles parent linking)
        CBlockIndex* idx = nullptr;
        if (loaded_idx.height == 0) {
            auto genesis_idx = std::make_unique<CBlockIndex>();
            *genesis_idx = loaded_idx;
            genesis_idx->prev = nullptr;
            idx = tree_.insert_genesis(std::move(genesis_idx));
        } else {
            idx = tree_.insert(hdr);
        }

        if (idx) {
            // Copy over non-header fields
            idx->status = loaded_idx.status;
            idx->pos = loaded_idx.pos;
            idx->n_tx = loaded_idx.n_tx;
            // improving_blocks removed in PoW transition
        }
    }

    chaindb_->commit_batch();

    LogInfo("chain", "rebuilt tree with %zu entries", tree_.size());
    return tree_.size() > 0;
}

// ---------------------------------------------------------------------------
// save_to_disk
// ---------------------------------------------------------------------------

bool ChainState::save_to_disk() {
    if (!chaindb_) return false;

    persist_tip();
    store_.flush();

    return true;
}

// ---------------------------------------------------------------------------
// flush
// ---------------------------------------------------------------------------

bool ChainState::flush() {
    if (!chaindb_) return true;

    store_.flush();
    persist_tip();
    blocks_since_flush_ = 0;

    LogInfo("chain", "flushed to disk at height %lu",
            static_cast<unsigned long>(height()));

    return true;
}

// ---------------------------------------------------------------------------
// maybe_flush
// ---------------------------------------------------------------------------

void ChainState::maybe_flush() {
    blocks_since_flush_++;
    if (blocks_since_flush_ >= FLUSH_INTERVAL) {
        flush();
    }
}

// ---------------------------------------------------------------------------
// persist_block_index
// ---------------------------------------------------------------------------

void ChainState::persist_block_index(const CBlockIndex* idx) {
    if (!chaindb_ || !idx) return;
    chaindb_->save_block_index(*idx);
}

// ---------------------------------------------------------------------------
// persist_tip
// ---------------------------------------------------------------------------

void ChainState::persist_tip() {
    if (!chaindb_) return;

    CBlockIndex* t = tip();
    if (t) {
        chaindb_->save_tip(t->hash);
        chaindb_->save_height(t->height);
    }
}

// ---------------------------------------------------------------------------
// find_fork_point
// ---------------------------------------------------------------------------

CBlockIndex* ChainState::find_fork_point(CBlockIndex* tip_a,
                                           CBlockIndex* tip_b) const {
    if (!tip_a || !tip_b) return nullptr;

    CBlockIndex* a = tip_a;
    CBlockIndex* b = tip_b;

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
// recover_tip — crash recovery
// ---------------------------------------------------------------------------

CBlockIndex* ChainState::recover_tip() {
    // Find the highest fully-validated block in the tree.
    // Walk from all leaf nodes backward to find the best tip.
    CBlockIndex* best = nullptr;

    // Simple approach: iterate all indices and find the highest validated one.
    // This is O(n) but only runs during crash recovery.
    auto loaded = chaindb_->load_all_indices();
    for (const auto& idx : loaded) {
        if (idx.status & BLOCK_FULLY_VALIDATED) {
            CBlockIndex* tree_idx = tree_.find(idx.hash);
            if (tree_idx) {
                if (!best || tree_idx->height > best->height) {
                    best = tree_idx;
                }
            }
        }
    }

    return best;
}

// ---------------------------------------------------------------------------
// reorganize_to — full reorg to a new tip
// ---------------------------------------------------------------------------

bool ChainState::reorganize_to(CBlockIndex* new_tip,
                                 consensus::ValidationState& state) {
    std::lock_guard<std::mutex> lock(cs_main_);

    CBlockIndex* current = tip();
    if (!current || !new_tip) {
        state.error("reorg-null-tip");
        return false;
    }

    if (new_tip == current) {
        return true;  // Already at this tip
    }

    // Find fork point
    CBlockIndex* fork_point = find_fork_point(current, new_tip);
    if (!fork_point) {
        state.error("reorg-no-fork-point");
        return false;
    }

    uint64_t disconnect_count = current->height - fork_point->height;
    uint64_t connect_count = new_tip->height - fork_point->height;

    LogInfo("chain", "reorganizing: disconnect %lu, connect %lu "
            "(fork at height %lu)",
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

    // Build the connect path from fork_point to new_tip
    std::vector<CBlockIndex*> connect_path;
    CBlockIndex* walk = new_tip;
    while (walk && walk != fork_point) {
        connect_path.push_back(walk);
        walk = walk->prev;
    }
    std::reverse(connect_path.begin(), connect_path.end());

    // Connect each block in order
    for (CBlockIndex* connect_idx : connect_path) {
        // Read block from disk
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

    persist_tip();

    LogInfo("chain", "reorganization complete, "
            "new tip at height %lu",
            static_cast<unsigned long>(tree_.best_tip()->height));

    return true;
}

// ---------------------------------------------------------------------------
// BlockUndo serialization
// ---------------------------------------------------------------------------

std::vector<uint8_t> ChainState::BlockUndo::serialize() const {
    std::vector<uint8_t> out;

    // Number of spent outputs (4 bytes LE)
    uint32_t count = static_cast<uint32_t>(spent_outputs.size());
    out.push_back(static_cast<uint8_t>(count));
    out.push_back(static_cast<uint8_t>(count >> 8));
    out.push_back(static_cast<uint8_t>(count >> 16));
    out.push_back(static_cast<uint8_t>(count >> 24));

    for (const auto& so : spent_outputs) {
        // txid (32 bytes)
        out.insert(out.end(), so.txid.begin(), so.txid.end());

        // vout (4 bytes LE)
        out.push_back(static_cast<uint8_t>(so.vout));
        out.push_back(static_cast<uint8_t>(so.vout >> 8));
        out.push_back(static_cast<uint8_t>(so.vout >> 16));
        out.push_back(static_cast<uint8_t>(so.vout >> 24));

        // value (8 bytes LE)
        int64_t val = so.entry.value;
        for (int i = 0; i < 8; ++i) {
            out.push_back(static_cast<uint8_t>(val >> (i * 8)));
        }

        // pubkey_hash (32 bytes)
        out.insert(out.end(), so.entry.pubkey_hash.begin(),
                   so.entry.pubkey_hash.end());

        // height (8 bytes LE)
        uint64_t h = so.entry.height;
        for (int i = 0; i < 8; ++i) {
            out.push_back(static_cast<uint8_t>(h >> (i * 8)));
        }

        // is_coinbase (1 byte)
        out.push_back(so.entry.is_coinbase ? 1 : 0);
    }

    return out;
}

bool ChainState::BlockUndo::deserialize(const uint8_t* data, size_t len,
                                          BlockUndo& out) {
    if (len < 4) return false;
    size_t pos = 0;

    // Count
    uint32_t count = static_cast<uint32_t>(data[pos])
                   | (static_cast<uint32_t>(data[pos + 1]) << 8)
                   | (static_cast<uint32_t>(data[pos + 2]) << 16)
                   | (static_cast<uint32_t>(data[pos + 3]) << 24);
    pos += 4;

    // Each entry: 32 (txid) + 4 (vout) + 8 (value) + 32 (pkh) + 8 (height) + 1 (cb) = 85 bytes
    static constexpr size_t ENTRY_SIZE = 32 + 4 + 8 + 32 + 8 + 1;
    if (len < 4 + static_cast<size_t>(count) * ENTRY_SIZE) return false;

    out.spent_outputs.resize(count);
    for (uint32_t i = 0; i < count; ++i) {
        auto& so = out.spent_outputs[i];

        // txid
        std::memcpy(so.txid.data(), data + pos, 32);
        pos += 32;

        // vout
        so.vout = static_cast<uint32_t>(data[pos])
                | (static_cast<uint32_t>(data[pos + 1]) << 8)
                | (static_cast<uint32_t>(data[pos + 2]) << 16)
                | (static_cast<uint32_t>(data[pos + 3]) << 24);
        pos += 4;

        // value
        int64_t val = 0;
        for (int j = 0; j < 8; ++j) {
            val |= static_cast<int64_t>(data[pos + j]) << (j * 8);
        }
        so.entry.value = val;
        pos += 8;

        // pubkey_hash
        std::memcpy(so.entry.pubkey_hash.data(), data + pos, 32);
        pos += 32;

        // height
        uint64_t h = 0;
        for (int j = 0; j < 8; ++j) {
            h |= static_cast<uint64_t>(data[pos + j]) << (j * 8);
        }
        so.entry.height = h;
        pos += 8;

        // is_coinbase
        so.entry.is_coinbase = (data[pos] != 0);
        pos += 1;
    }

    return true;
}

// ---------------------------------------------------------------------------
// generate_undo — capture UTXO state before connecting a block
// ---------------------------------------------------------------------------

ChainState::BlockUndo ChainState::generate_undo(const CBlock& block) const {
    BlockUndo undo;

    for (size_t tx_i = 0; tx_i < block.vtx.size(); ++tx_i) {
        const CTransaction& tx = block.vtx[tx_i];

        // Skip coinbase (no inputs to spend)
        if (tx.is_coinbase()) continue;

        for (const CTxIn& in : tx.vin) {
            UTXOEntry entry;
            if (utxo_.get(in.prevout.txid, in.prevout.index, entry)) {
                BlockUndo::SpentOutput so;
                so.txid = in.prevout.txid;
                so.vout = in.prevout.index;
                so.entry = entry;
                undo.spent_outputs.push_back(std::move(so));
            }
        }
    }

    return undo;
}

// ---------------------------------------------------------------------------
// disconnect_block — disconnect using pre-computed undo data
// ---------------------------------------------------------------------------

bool ChainState::disconnect_block(const CBlock& block, const BlockUndo& undo) {
    CBlockIndex* tip_idx = tree_.best_tip();
    if (!tip_idx) return false;

    // UTXO undo: remove outputs, restore inputs
    utxo_.begin_transaction();

    // Process transactions in reverse order
    for (int tx_i = static_cast<int>(block.vtx.size()) - 1; tx_i >= 0; --tx_i) {
        const CTransaction& tx = block.vtx[static_cast<size_t>(tx_i)];
        uint256 txid = tx.get_txid();

        // Remove outputs created by this tx
        for (uint32_t vout = 0; vout < tx.vout.size(); ++vout) {
            utxo_.remove(txid, vout);
        }
    }

    // Restore all spent outputs from undo data
    for (const auto& so : undo.spent_outputs) {
        utxo_.add(so.txid, so.vout, so.entry);
    }

    utxo_.commit_transaction();

    // Model state: undo last delta
    // Transaction index: remove entries
    if (txindex_) {
        txindex_->deindex_block(tip_idx->height);
    }

    // Move tip back
    update_tip(tip_idx->prev);

    return true;
}

// ---------------------------------------------------------------------------
// set_pruning_enabled
// ---------------------------------------------------------------------------

void ChainState::set_pruning_enabled(bool enabled, uint64_t prune_target_height) {
    pruning_enabled_ = enabled;
    prune_target_height_ = prune_target_height;
}

// ---------------------------------------------------------------------------
// prune — delete old block/undo data
// ---------------------------------------------------------------------------

bool ChainState::prune() {
    if (!pruning_enabled_) return true;

    CBlockIndex* t = tip();
    if (!t) return true;

    // Keep at least REORG_WINDOW blocks
    uint64_t current_height = t->height;
    if (current_height <= REORG_WINDOW) return true;

    uint64_t prune_below = current_height - REORG_WINDOW;

    // If a target height is configured, use the lower of the two
    if (prune_target_height_ > 0 && prune_target_height_ < prune_below) {
        prune_below = prune_target_height_;
    }

    // Prune block files
    store_.prune_files(prune_below);

    // Prune block index entries from ChainDB
    if (chaindb_) {
        size_t pruned = chaindb_->prune_below(prune_below);
        if (pruned > 0) {
            LogInfo("chain", "pruned %zu block index entries below "
                    "height %lu", pruned,
                    static_cast<unsigned long>(prune_below));
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// accept_headers — batch header acceptance for IBD
// ---------------------------------------------------------------------------

int ChainState::accept_headers_batch(const std::vector<CBlockHeader>& headers,
                                       consensus::ValidationState& state) {
    std::lock_guard<std::mutex> lock(cs_main_);

    int accepted = 0;

    for (const auto& header : headers) {
        uint256 block_hash = header.get_hash();

        // Skip if already in tree
        CBlockIndex* existing = tree_.find(block_hash);
        if (existing) {
            accepted++;
            continue;
        }

        // Genesis cannot be accepted via batch
        if (header.height == 0) {
            continue;
        }

        // Look up parent
        CBlockIndex* parent = tree_.find(header.prev_hash);
        if (!parent) {
            // Parent not yet available; stop processing this batch.
            // The caller will request the missing headers.
            break;
        }

        if (parent->status & BLOCK_FAILED) {
            state.invalid(consensus::ValidationResult::HEADER_INVALID,
                          "bad-prevblk", "parent marked failed in batch");
            break;
        }

        // Build validation context
        int64_t adjusted_time = get_adjusted_time();
        consensus::BlockContext ctx = parent->make_child_context(adjusted_time);

        // Validate header
        consensus::ValidationState per_header_state;
        if (!consensus::check_header(header, ctx, per_header_state)) {
            // Mark the header as failed and continue to the next.
            // Don't abort the entire batch for one bad header.
            LogError("chain", "batch header rejected at height %lu: %s",
                    static_cast<unsigned long>(header.height),
                    per_header_state.to_string().c_str());
            continue;
        }

        // Insert into block tree
        CBlockIndex* idx = tree_.insert(header);
        idx->status |= BLOCK_HEADER_VALID;
        accepted++;

        // Persist periodically during large batches
        if (accepted % 500 == 0) {
            persist_block_index(idx);
        }
    }

    // Persist the last accepted header
    if (accepted > 0) {
        CBlockIndex* last = tree_.best_tip();
        if (last) {
            persist_block_index(last);
        }
    }

    return accepted;
}

// ---------------------------------------------------------------------------
// accept_block_full — full pipeline: header + tx validation + connection
// ---------------------------------------------------------------------------

bool ChainState::accept_block_full(const CBlock& block,
                                     consensus::ValidationState& state) {
    std::lock_guard<std::mutex> lock(cs_main_);

    uint256 block_hash = block.get_hash();

    // Check if already fully validated
    CBlockIndex* existing = tree_.find(block_hash);
    if (existing && (existing->status & BLOCK_FULLY_VALIDATED)) {
        return true;
    }

    // Step 1: Accept header (if not already)
    CBlockIndex* idx = existing;
    if (!idx) {
        // Unlock temporarily for header acceptance (it takes its own lock
        // in the non-batch path). Since we already hold cs_main_, we do
        // the header validation inline.
        if (block.height == 0) {
            state.invalid(consensus::ValidationResult::BLOCK_INVALID,
                          "bad-genesis", "cannot accept genesis via accept_block_full");
            return false;
        }

        CBlockIndex* parent = tree_.find(block.prev_hash);
        if (!parent) {
            state.invalid(consensus::ValidationResult::BLOCK_INVALID,
                          "bad-prevblk", "parent not found");
            return false;
        }

        if (parent->status & BLOCK_FAILED) {
            state.invalid(consensus::ValidationResult::BLOCK_INVALID,
                          "bad-prevblk", "parent is invalid");
            return false;
        }

        int64_t adjusted_time = get_adjusted_time();
        consensus::BlockContext ctx = parent->make_child_context(adjusted_time);

        if (!consensus::check_header(block, ctx, state)) {
            return false;
        }

        idx = tree_.insert(block);
        idx->status |= BLOCK_HEADER_VALID;
    }

    // Step 2: Store block data to disk
    if (!(idx->status & BLOCK_DATA_STORED)) {
        BlockPos pos = store_.write_block(block);
        if (pos.is_null()) {
            state.error("disk-write-failed");
            return false;
        }
        idx->pos = pos;
        idx->status |= BLOCK_DATA_STORED;
    }

    idx->n_tx = static_cast<int>(block.vtx.size());

    // Step 3: Determine if this block is on the best chain
    CBlockIndex* current_tip = tree_.best_tip();

    bool on_best_chain = false;
    if (!current_tip) {
        on_best_chain = true;
    } else if (idx->height > current_tip->height) {
        on_best_chain = true;
    }

    if (!on_best_chain) {
        // This block is on a fork — store it but don't connect.
        // It might become the best chain later if more blocks build on it.
        persist_block_index(idx);
        return true;
    }

    // Step 4: Connect to the active chain
    CBlockIndex* parent = idx->prev;
    if (parent == current_tip) {
        // Simple case: extends current tip
        if (!connect_block(block, idx)) {
            state.error("connect-block-failed");
            idx->status |= BLOCK_FAILED;
            return false;
        }
    } else {
        // Reorg case: find fork point and reorganize
        CBlockIndex* fork_point = find_fork_point(current_tip, idx);
        if (!fork_point) {
            state.error("no-fork-point");
            return false;
        }

        uint64_t disconnect_count = current_tip->height - fork_point->height;
        uint64_t connect_count = idx->height - fork_point->height;

        LogInfo("chain", "accept_block_full triggering reorg: "
                "disconnect %lu, connect %lu (fork at height %lu)",
                static_cast<unsigned long>(disconnect_count),
                static_cast<unsigned long>(connect_count),
                static_cast<unsigned long>(fork_point->height));

        // Disconnect back to fork point
        while (tree_.best_tip() != fork_point) {
            if (!disconnect_tip()) {
                state.error("reorg-disconnect-failed");
                return false;
            }
        }

        // Build connect path
        std::vector<CBlockIndex*> connect_path;
        CBlockIndex* walk = idx;
        while (walk && walk != fork_point) {
            connect_path.push_back(walk);
            walk = walk->prev;
        }
        std::reverse(connect_path.begin(), connect_path.end());

        // Connect each block
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
    }

    return true;
}

// ---------------------------------------------------------------------------
// reorganize — full reorganization with statistics
// ---------------------------------------------------------------------------

// ReorgStats is defined in chainstate.h as ChainState::ReorgStats

ChainState::ReorgStats ChainState::reorganize(const CBlockIndex* new_tip_const) {
    auto t0 = std::chrono::steady_clock::now();

    ReorgStats stats;
    stats.blocks_disconnected = 0;
    stats.blocks_connected = 0;
    stats.reorg_time_ms = 0;
    stats.fork_height = 0;
    stats.old_tip.set_null();
    stats.new_tip.set_null();

    std::lock_guard<std::mutex> lock(cs_main_);

    CBlockIndex* current = tip();
    // Cast away const for internal tree operations
    CBlockIndex* new_tip_idx = tree_.find(new_tip_const->hash);

    if (!current || !new_tip_idx) {
        return stats;
    }

    stats.old_tip = current->hash;
    stats.new_tip = new_tip_idx->hash;

    // Find fork point
    CBlockIndex* fork = find_fork_point(current, new_tip_idx);
    if (!fork) {
        LogInfo("chain", "reorganize: no fork point found");
        return stats;
    }

    stats.fork_height = fork->height;

    // Compute chain work for both tips
    // Chain work = sum of difficulty at each block on the chain.
    // We use height as a proxy here; in a full implementation,
    // chain work is computed from nbits at each block.
    uint64_t current_work = current->height;
    uint64_t new_work = new_tip_idx->height;

    // Only reorganize if the new chain has strictly more work
    if (new_work <= current_work) {
        LogInfo("chain", "reorganize: new chain does not have more work "
                "(%lu <= %lu)",
                static_cast<unsigned long>(new_work),
                static_cast<unsigned long>(current_work));
        return stats;
    }

    LogInfo("chain", "reorganizing chain\n"
            "  Old tip: height=%lu\n"
            "  New tip: height=%lu\n"
            "  Fork:    height=%lu\n"
            "  Blocks to disconnect: %lu\n"
            "  Blocks to connect:    %lu",
            static_cast<unsigned long>(current->height),
            static_cast<unsigned long>(new_tip_idx->height),
            static_cast<unsigned long>(fork->height),
            static_cast<unsigned long>(current->height - fork->height),
            static_cast<unsigned long>(new_tip_idx->height - fork->height));

    // Step 1: Disconnect from current tip to fork point
    while (tree_.best_tip() != fork) {
        if (!disconnect_tip()) {
            LogError("chain", "reorganize: disconnect failed at height %lu",
                    static_cast<unsigned long>(tree_.best_tip()->height));
            break;
        }
        stats.blocks_disconnected++;
    }

    // Step 2: Build connect path from fork to new tip
    std::vector<CBlockIndex*> connect_path;
    CBlockIndex* walk = new_tip_idx;
    while (walk && walk != fork) {
        connect_path.push_back(walk);
        walk = walk->prev;
    }
    std::reverse(connect_path.begin(), connect_path.end());

    // Step 3: Connect each block
    for (CBlockIndex* connect_idx : connect_path) {
        CBlock block_data;
        if (!store_.read_block(connect_idx->pos, block_data)) {
            LogError("chain", "reorganize: failed to read block at height %lu",
                    static_cast<unsigned long>(connect_idx->height));
            break;
        }

        if (!connect_block(block_data, connect_idx)) {
            LogError("chain", "reorganize: connect failed at height %lu",
                    static_cast<unsigned long>(connect_idx->height));
            connect_idx->status |= BLOCK_FAILED;
            break;
        }

        stats.blocks_connected++;
    }

    // Step 4: Persist and flush
    persist_tip();
    flush();

    auto t1 = std::chrono::steady_clock::now();
    stats.reorg_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        t1 - t0).count();

    LogInfo("chain", "reorganization complete in %ld ms\n"
            "  Disconnected: %d blocks\n"
            "  Connected:    %d blocks\n"
            "  New tip:      height=%lu",
            static_cast<long>(stats.reorg_time_ms),
            stats.blocks_disconnected,
            stats.blocks_connected,
            static_cast<unsigned long>(tree_.best_tip() ? tree_.best_tip()->height : 0));

    return stats;
}

// ---------------------------------------------------------------------------
// compute_chain_work — total work from genesis to tip
// ---------------------------------------------------------------------------

arith_uint256 ChainState::compute_chain_work(const CBlockIndex* chain_tip) const {
    arith_uint256 total_work;
    total_work.SetCompact(0);

    const CBlockIndex* walk = chain_tip;
    while (walk) {
        // Work for each block is approximately 2^256 / (target + 1).
        // We compute target from nbits.
        arith_uint256 target;
        if (consensus::derive_target(walk->nbits, target)) {
            // work = 2^256 / (target + 1)
            // To avoid overflow, we compute:
            //   work = (~target / (target + 1)) + 1
            arith_uint256 one;
            one.SetCompact(0);
            // Simple approximation: use 1 << (256 - log2(target))
            // For now, use the inverse of the target as a work approximation.
            arith_uint256 work = ~target;
            work = work / (target + one);
            work = work + one;
            total_work = total_work + work;
        } else {
            // If target derivation fails, add minimal work (1)
            arith_uint256 one;
            one.SetCompact(0x01000000);
            total_work = total_work + one;
        }

        walk = walk->prev;
    }

    return total_work;
}

// ---------------------------------------------------------------------------
// find_fork — find fork point between two tips (public interface)
// ---------------------------------------------------------------------------

const CBlockIndex* ChainState::find_fork(const CBlockIndex* tip_a,
                                            const CBlockIndex* tip_b) const {
    if (!tip_a || !tip_b) return nullptr;

    const CBlockIndex* a = tip_a;
    const CBlockIndex* b = tip_b;

    // Walk both chains backward until they meet
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
// periodic_flush — flush UTXO cache to disk
// ---------------------------------------------------------------------------

void ChainState::periodic_flush() {
    std::lock_guard<std::mutex> lock(cs_main_);

    // Flush UTXO set
    utxo_.flush();

    // Flush block store
    store_.flush();

    // Persist current tip
    persist_tip();

    LogInfo("chain", "periodic flush at height %lu",
            static_cast<unsigned long>(height()));
}

// ---------------------------------------------------------------------------
// periodic_compact — compact databases
// ---------------------------------------------------------------------------

void ChainState::periodic_compact() {
    std::lock_guard<std::mutex> lock(cs_main_);

    // Compact the UTXO database (SQLite VACUUM or incremental_vacuum)
    utxo_.compact();

    // Compact the ChainDB
    if (chaindb_) {
        chaindb_->compact();
    }

    // Compact the transaction index
    if (txindex_) {
        txindex_->compact();
    }

    LogInfo("chain", "databases compacted at height %lu",
            static_cast<unsigned long>(height()));
}

// ---------------------------------------------------------------------------
// check_consistency — verify chain state consistency
// ---------------------------------------------------------------------------

bool ChainState::check_consistency() const {
    std::lock_guard<std::mutex> lock(cs_main_);

    CBlockIndex* t = tip();
    if (!t) {
        LogInfo("chain", "consistency check: no tip");
        return false;
    }

    // Verify the chain is continuous from tip back to genesis
    CBlockIndex* walk = t;
    uint64_t expected_height = t->height;
    int blocks_checked = 0;

    while (walk) {
        // Height must match
        if (walk->height != expected_height) {
            LogInfo("chain", "consistency check: height gap at block %lu "
                    "(expected %lu)",
                    static_cast<unsigned long>(walk->height),
                    static_cast<unsigned long>(expected_height));
            return false;
        }

        // Block must be fully validated
        if (!(walk->status & BLOCK_FULLY_VALIDATED)) {
            LogInfo("chain", "consistency check: block at height %lu "
                    "not fully validated (status=0x%x)",
                    static_cast<unsigned long>(walk->height), walk->status);
            return false;
        }

        // Block must have data stored
        if (!(walk->status & BLOCK_DATA_STORED)) {
            LogInfo("chain", "consistency check: block at height %lu "
                    "has no stored data",
                    static_cast<unsigned long>(walk->height));
            return false;
        }

        // Parent pointer must be consistent
        if (walk->prev) {
            if (walk->prev->height + 1 != walk->height) {
                LogError("chain", "consistency check: parent height mismatch "
                        "at block %lu",
                        static_cast<unsigned long>(walk->height));
                return false;
            }
        }

        if (expected_height == 0) break;
        expected_height--;
        walk = walk->prev;
        blocks_checked++;

        // Limit deep checks to avoid scanning the entire chain
        if (blocks_checked >= 10000) {
            break;
        }
    }

    // Verify the UTXO count is reasonable
    size_t utxo_count = utxo_.size();
    if (utxo_count == 0 && t->height > 0) {
        LogInfo("chain", "consistency check: UTXO set is empty "
                "but chain height is %lu",
                static_cast<unsigned long>(t->height));
        return false;
    }

    // Verify stored tip matches tree tip
    if (chaindb_) {
        uint256 stored_hash = chaindb_->load_tip();
        if (!stored_hash.is_null() && stored_hash != t->hash) {
            LogInfo("chain", "consistency check: stored tip hash "
                    "does not match tree tip");
            return false;
        }
    }

    LogInfo("chain", "consistency check passed (%d blocks verified, "
            "%zu UTXOs, height %lu)",
            blocks_checked,
            utxo_count,
            static_cast<unsigned long>(t->height));

    return true;
}

// ---------------------------------------------------------------------------
// get_block_at_height — retrieve block at a specific height
// ---------------------------------------------------------------------------

bool ChainState::get_block_at_height(uint64_t target_height, CBlock& block) const {
    std::lock_guard<std::mutex> lock(cs_main_);

    CBlockIndex* t = tip();
    if (!t || target_height > t->height) {
        return false;
    }

    // Walk back from tip to find the block at the target height
    CBlockIndex* walk = t;
    while (walk && walk->height > target_height) {
        walk = walk->prev;
    }

    if (!walk || walk->height != target_height) {
        return false;
    }

    if (walk->pos.is_null()) {
        return false;
    }

    return store_.read_block(walk->pos, block);
}

// ---------------------------------------------------------------------------
// get_block_index_at_height — retrieve block index at a specific height
// ---------------------------------------------------------------------------

CBlockIndex* ChainState::get_block_index_at_height(uint64_t target_height) const {
    CBlockIndex* t = tip();
    if (!t || target_height > t->height) {
        return nullptr;
    }

    CBlockIndex* walk = t;
    while (walk && walk->height > target_height) {
        walk = walk->prev;
    }

    if (!walk || walk->height != target_height) {
        return nullptr;
    }

    return walk;
}

// ---------------------------------------------------------------------------
// get_headers_from — get up to max_count headers starting from start_hash
// ---------------------------------------------------------------------------

std::vector<CBlockHeader> ChainState::get_headers_from(
        const uint256& start_hash, int max_count) const {

    std::lock_guard<std::mutex> lock(cs_main_);

    std::vector<CBlockHeader> headers;
    if (max_count <= 0) return headers;

    CBlockIndex* start = tree_.find(start_hash);
    if (!start) return headers;

    // Walk forward by finding children. Since we only have prev pointers,
    // we need to walk from the tip backward to build a forward path.
    CBlockIndex* t = tip();
    if (!t) return headers;

    // Check if start is an ancestor of tip
    CBlockIndex* walk = t;
    std::vector<CBlockIndex*> forward_chain;
    while (walk && walk != start) {
        forward_chain.push_back(walk);
        walk = walk->prev;
    }

    if (walk != start) {
        // start_hash is not on the main chain
        return headers;
    }

    std::reverse(forward_chain.begin(), forward_chain.end());

    // Return up to max_count headers
    int count = 0;
    for (CBlockIndex* idx : forward_chain) {
        if (count >= max_count) break;

        CBlock block;
        if (store_.read_block(idx->pos, block)) {
            headers.push_back(static_cast<CBlockHeader>(block));
        }
        count++;
    }

    return headers;
}

// ---------------------------------------------------------------------------
// get_locator — build a block locator (exponentially-spaced block hashes)
// ---------------------------------------------------------------------------

std::vector<uint256> ChainState::get_locator() const {
    std::lock_guard<std::mutex> lock(cs_main_);

    std::vector<uint256> locator;
    CBlockIndex* walk = tip();

    if (!walk) return locator;

    int step = 1;
    int count = 0;

    while (walk) {
        locator.push_back(walk->hash);
        count++;

        // After the first 10 entries, double the step size each time.
        // This gives O(log(height)) entries that cover the whole chain.
        if (count >= 10) {
            step *= 2;
        }

        for (int i = 0; i < step && walk; ++i) {
            walk = walk->prev;
        }
    }

    return locator;
}

// ---------------------------------------------------------------------------
// find_locator_fork — find the highest block in the locator that we have
// ---------------------------------------------------------------------------

CBlockIndex* ChainState::find_locator_fork(const std::vector<uint256>& locator) const {
    std::lock_guard<std::mutex> lock(cs_main_);

    for (const auto& hash : locator) {
        CBlockIndex* idx = tree_.find(hash);
        if (idx && (idx->status & BLOCK_FULLY_VALIDATED)) {
            return idx;
        }
    }

    return nullptr;  // No common block found
}

// ---------------------------------------------------------------------------
// utxo_stats — compute UTXO set statistics
// ---------------------------------------------------------------------------

struct UTXOStats {
    size_t count;
    Amount total_value;
    size_t coinbase_count;
    Amount coinbase_value;
    uint64_t min_height;
    uint64_t max_height;
};

ChainState::UTXOStatistics ChainState::get_utxo_stats() const {
    std::lock_guard<std::mutex> lock(cs_main_);

    UTXOStatistics stats;
    stats.count = utxo_.size();
    stats.total_value = 0;
    stats.coinbase_count = 0;
    stats.coinbase_value = 0;
    stats.min_height = UINT64_MAX;
    stats.max_height = 0;

    // Iterate the UTXO set to compute aggregate statistics
    utxo_.for_each([&](const uint256& /*txid*/, uint32_t /*vout*/, const UTXOEntry& entry) {
        stats.total_value += entry.value;

        if (entry.is_coinbase) {
            stats.coinbase_count++;
            stats.coinbase_value += entry.value;
        }

        if (entry.height < stats.min_height) {
            stats.min_height = entry.height;
        }
        if (entry.height > stats.max_height) {
            stats.max_height = entry.height;
        }
    });

    if (stats.count == 0) {
        stats.min_height = 0;
    }

    return stats;
}

// ═══════════════════════════════════════════════════════════════════════════
// Coin age and priority computation
// ═══════════════════════════════════════════════════════════════════════════

double ChainState::compute_tx_priority(const CTransaction& tx,
                                         uint64_t current_height) const {
    if (tx.is_coinbase()) return 0.0;

    double total_priority = 0.0;

    for (const auto& in : tx.vin) {
        UTXOEntry entry;
        if (!utxo_.get(in.prevout.txid, in.prevout.index, entry)) {
            continue;  // UTXO not found, skip
        }

        // Coin age = current_height - creation_height
        uint64_t age = 0;
        if (current_height > entry.height) {
            age = current_height - entry.height;
        }

        // Priority contribution = value * age
        double value_d = static_cast<double>(entry.value);
        double age_d = static_cast<double>(age);
        total_priority += value_d * age_d;
    }

    // Normalize by transaction size for fair comparison
    size_t tx_size = tx.get_serialize_size();
    if (tx_size > 0) {
        total_priority /= static_cast<double>(tx_size);
    }

    return total_priority;
}

// ═══════════════════════════════════════════════════════════════════════════
// Chain statistics
// ═══════════════════════════════════════════════════════════════════════════

ChainState::ChainStats ChainState::get_chain_stats() const {
    std::lock_guard<std::mutex> lock(cs_main_);

    ChainStats stats{};

    CBlockIndex* t = tip();
    if (!t) {
        return stats;
    }

    stats.height = t->height;
    stats.tip_hash = t->hash;
    stats.utxo_count = utxo_.size();

    // Compute total supply from UTXO set
    UTXOStatistics utxo_stats = get_utxo_stats();
    stats.total_supply = utxo_stats.total_value;

    // Compute cumulative fees: total_minted - current_supply
    Amount total_minted = consensus::compute_total_supply(t->height);
    if (total_minted > stats.total_supply) {
        stats.total_fees_collected = total_minted - stats.total_supply;
    } else {
        stats.total_fees_collected = 0;
    }

    // Difficulty from current tip
    arith_uint256 target;
    if (consensus::derive_target(t->nbits, target)) {
        // difficulty = powLimit / target
        arith_uint256 pow_limit;
        pow_limit.SetCompact(consensus::INITIAL_NBITS);
        if (!target.IsNull()) {
            // Approximate difficulty as ratio
            // For display: difficulty = powLimit_mantissa / target_mantissa * 2^(exp_diff*8)
            stats.difficulty = static_cast<double>(pow_limit.GetCompact() >> 24) /
                              static_cast<double>((t->nbits >> 24) > 0 ? (t->nbits >> 24) : 1);
        }
    }

    // Chain work
    stats.chain_work = compute_chain_work(t);

    // Block tree stats
    stats.total_blocks = tree_.size();

    // Transaction count from tip
    stats.total_transactions = 0;

    // PoW - no model info


    // Median time past: median of last 11 block timestamps
    {
        std::vector<int64_t> timestamps;
        CBlockIndex* walk = t;
        for (int i = 0; i < 11 && walk; i++) {
            timestamps.push_back(walk->timestamp);
            walk = walk->prev;
        }
        if (!timestamps.empty()) {
            std::sort(timestamps.begin(), timestamps.end());
            stats.median_time_past = timestamps[timestamps.size() / 2];
        }
    }

    // Average block time and tx count for last 100 blocks
    {
        double total_time = 0.0;
        double total_txs = 0.0;
        int block_count = 0;

        CBlockIndex* walk = t;
        CBlockIndex* prev_walk = nullptr;

        while (walk && block_count < 100) {
            if (prev_walk) {
                int64_t delta = prev_walk->timestamp - walk->timestamp;
                if (delta > 0) {
                    total_time += static_cast<double>(delta);
                }
            }
            total_txs += static_cast<double>(walk->n_tx);
            prev_walk = walk;
            walk = walk->prev;
            block_count++;
        }

        if (block_count > 1) {
            stats.avg_block_time_last_100 = total_time / static_cast<double>(block_count - 1);
        }
        if (block_count > 0) {
            stats.avg_tx_per_block_last_100 = total_txs / static_cast<double>(block_count);
        }
    }

    // Estimate blocks disk bytes from block store
    stats.blocks_disk_bytes = 0;
    {
        // Approximate: walk the chain and sum the block sizes
        // For efficiency, only check the last 100 blocks and extrapolate
        CBlockIndex* walk = t;
        size_t sampled_bytes = 0;
        int sampled_count = 0;

        while (walk && sampled_count < 100) {
            if (!walk->pos.is_null()) {
                CBlock blk;
                if (store_.read_block(walk->pos, blk)) {
                    sampled_bytes += blk.get_block_size();
                    sampled_count++;
                }
            }
            walk = walk->prev;
        }

        if (sampled_count > 0) {
            double avg_block_size = static_cast<double>(sampled_bytes) /
                                     static_cast<double>(sampled_count);
            stats.blocks_disk_bytes = static_cast<size_t>(
                avg_block_size * static_cast<double>(stats.total_blocks));
        }
    }

    return stats;
}

// ═══════════════════════════════════════════════════════════════════════════
// Block verification with detailed results
// ═══════════════════════════════════════════════════════════════════════════

ChainState::VerifyResult ChainState::verify_block_detailed(
        const CBlock& block) const {

    auto t0 = std::chrono::steady_clock::now();

    VerifyResult result;
    result.valid = true;
    result.checks_passed = 0;
    result.checks_total = 0;

    auto check = [&](bool condition, const std::string& name,
                     const std::string& err_msg) {
        result.checks_total++;
        if (condition) {
            result.checks_passed++;
        } else {
            result.valid = false;
            result.errors.push_back(name + ": " + err_msg);
        }
    };

    auto warn = [&](bool condition, const std::string& msg) {
        if (!condition) {
            result.warnings.push_back(msg);
        }
    };

    // Check 1: Block has transactions
    check(!block.vtx.empty(), "check-txs", "block has no transactions");

    // Check 2: First transaction is coinbase
    if (!block.vtx.empty()) {
        check(block.vtx[0].is_coinbase(), "check-coinbase",
              "first transaction is not a coinbase");
    }

    // Check 3: No other transaction is coinbase
    {
        bool no_extra_coinbase = true;
        for (size_t i = 1; i < block.vtx.size(); i++) {
            if (block.vtx[i].is_coinbase()) {
                no_extra_coinbase = false;
                break;
            }
        }
        check(no_extra_coinbase, "check-single-coinbase",
              "multiple coinbase transactions found");
    }

    // Check 4: Block size within limits
    size_t block_size = block.get_block_size();
    check(block_size <= consensus::MAX_BLOCK_SIZE, "check-block-size",
          "block size " + std::to_string(block_size) + " exceeds limit " +
          std::to_string(consensus::MAX_BLOCK_SIZE));

    // Check 5: Each transaction passes basic checks
    {
        bool all_txs_valid = true;
        for (size_t i = 0; i < block.vtx.size(); i++) {
            if (!block.vtx[i].check_transaction()) {
                all_txs_valid = false;
                result.errors.push_back("check-tx-" + std::to_string(i) +
                                        ": transaction failed basic validity");
            }
        }
        result.checks_total++;
        if (all_txs_valid) result.checks_passed++;
        else result.valid = false;
    }

    // Check 6: Merkle root
    check(block.verify_merkle_root(), "check-merkle-root",
          "merkle root does not match computed root");

    // Check 7: No duplicate transactions
    {
        bool no_dupes = true;
        std::vector<uint256> txids;
        txids.reserve(block.vtx.size());
        for (const auto& tx : block.vtx) {
            uint256 txid = tx.get_txid();
            for (const auto& existing : txids) {
                if (txid == existing) {
                    no_dupes = false;
                    break;
                }
            }
            if (!no_dupes) break;
            txids.push_back(txid);
        }
        check(no_dupes, "check-dup-txids", "duplicate transaction found");
    }

    // Check 8: Height consistency
    if (block.height > 0) {
        CBlockIndex* parent = tree_.find(block.prev_hash);
        if (parent) {
            check(block.height == parent->height + 1, "check-height",
                  "height does not follow parent");
        } else {
            result.warnings.push_back("parent block not found for height check");
        }
    }

    // Check 9: Timestamp validation
    {
        int64_t now = get_adjusted_time();
        check(block.timestamp <= now + consensus::MAX_FUTURE_TIME,
              "check-timestamp-future",
              "block timestamp too far in the future");
    }

    // Check 10: Version
    check(block.version >= 1, "check-version",
          "block version is zero");

    // Check 11: Difficulty target validity
    {
        arith_uint256 target;
        check(consensus::derive_target(block.nbits, target), "check-nbits",
              "invalid difficulty target encoding");
    }

    // PoW: no val_loss, delta, or architecture checks

    // Check 15: Coinbase reward
    if (!block.vtx.empty() && block.vtx[0].is_coinbase()) {
        Amount reward = consensus::compute_block_reward(block.height);
        Amount coinbase_value = block.vtx[0].get_value_out();
        // Coinbase can include fees, so it should be >= reward (but we
        // can only check upper bound with context)
        warn(coinbase_value >= reward,
             "coinbase output less than expected block reward");
    }

    // Warnings for suboptimal blocks
    warn(block.vtx.size() > 1, "block contains only the coinbase transaction");
    // PoW: no delta payload warnings

    auto t1 = std::chrono::steady_clock::now();
    result.verify_time_ms = std::chrono::duration_cast<
        std::chrono::milliseconds>(t1 - t0).count();

    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// UTXO snapshot creation and loading
// ═══════════════════════════════════════════════════════════════════════════

ChainState::UTXOSnapshot ChainState::create_utxo_snapshot() const {
    std::lock_guard<std::mutex> lock(cs_main_);

    UTXOSnapshot snapshot;
    CBlockIndex* t = tip();
    if (!t) {
        snapshot.height = 0;
        snapshot.utxo_count = 0;
        snapshot.total_value = 0;
        return snapshot;
    }

    snapshot.height = t->height;
    snapshot.block_hash = t->hash;
    snapshot.utxo_count = 0;
    snapshot.total_value = 0;

    // Serialize all UTXOs
    std::vector<uint8_t> serialized;
    serialized.reserve(utxo_.size() * 85);  // approximate entry size

    utxo_.for_each([&](const uint256& txid, uint32_t vout, const UTXOEntry& entry) {
        // txid (32 bytes)
        serialized.insert(serialized.end(), txid.begin(), txid.end());

        // vout (4 bytes LE)
        serialized.push_back(static_cast<uint8_t>(vout));
        serialized.push_back(static_cast<uint8_t>(vout >> 8));
        serialized.push_back(static_cast<uint8_t>(vout >> 16));
        serialized.push_back(static_cast<uint8_t>(vout >> 24));

        // value (8 bytes LE)
        int64_t val = entry.value;
        for (int i = 0; i < 8; i++) {
            serialized.push_back(static_cast<uint8_t>(val >> (i * 8)));
        }

        // pubkey_hash (32 bytes)
        serialized.insert(serialized.end(),
                           entry.pubkey_hash.begin(), entry.pubkey_hash.end());

        // height (8 bytes LE)
        uint64_t h = entry.height;
        for (int i = 0; i < 8; i++) {
            serialized.push_back(static_cast<uint8_t>(h >> (i * 8)));
        }

        // is_coinbase (1 byte)
        serialized.push_back(entry.is_coinbase ? 1 : 0);

        snapshot.utxo_count++;
        snapshot.total_value += entry.value;
    });

    snapshot.serialized_utxos = std::move(serialized);
    snapshot.utxo_set_hash = compute_utxo_set_hash();

    return snapshot;
}

bool ChainState::load_utxo_snapshot(const UTXOSnapshot& snapshot) {
    std::lock_guard<std::mutex> lock(cs_main_);

    if (snapshot.serialized_utxos.empty()) {
        return false;
    }

    // Each entry: 32 (txid) + 4 (vout) + 8 (value) + 32 (pkh) + 8 (height) + 1 (cb) = 85
    static constexpr size_t ENTRY_SIZE = 85;

    if (snapshot.serialized_utxos.size() % ENTRY_SIZE != 0) {
        LogError("chain", "load_utxo_snapshot: invalid serialized size %zu "
                "(not a multiple of %zu)",
                snapshot.serialized_utxos.size(), ENTRY_SIZE);
        return false;
    }

    size_t expected_count = snapshot.serialized_utxos.size() / ENTRY_SIZE;
    if (expected_count != snapshot.utxo_count) {
        LogError("chain", "load_utxo_snapshot: count mismatch: header says %zu, "
                "data has %zu entries",
                snapshot.utxo_count, expected_count);
        return false;
    }

    utxo_.begin_transaction();

    const uint8_t* data = snapshot.serialized_utxos.data();
    size_t pos = 0;
    size_t loaded = 0;

    for (size_t i = 0; i < expected_count; i++) {
        uint256 txid;
        std::memcpy(txid.data(), data + pos, 32);
        pos += 32;

        uint32_t vout = static_cast<uint32_t>(data[pos])
                      | (static_cast<uint32_t>(data[pos + 1]) << 8)
                      | (static_cast<uint32_t>(data[pos + 2]) << 16)
                      | (static_cast<uint32_t>(data[pos + 3]) << 24);
        pos += 4;

        UTXOEntry entry;

        int64_t val = 0;
        for (int j = 0; j < 8; j++) {
            val |= static_cast<int64_t>(data[pos + j]) << (j * 8);
        }
        entry.value = val;
        pos += 8;

        std::memcpy(entry.pubkey_hash.data(), data + pos, 32);
        pos += 32;

        uint64_t h = 0;
        for (int j = 0; j < 8; j++) {
            h |= static_cast<uint64_t>(data[pos + j]) << (j * 8);
        }
        entry.height = h;
        pos += 8;

        entry.is_coinbase = (data[pos] != 0);
        pos += 1;

        utxo_.add(txid, vout, entry);
        loaded++;
    }

    utxo_.commit_transaction();

    LogInfo("chain", "load_utxo_snapshot: loaded %zu UTXOs at height %lu",
            loaded, static_cast<unsigned long>(snapshot.height));

    return true;
}

uint256 ChainState::compute_utxo_set_hash() const {
    // Compute a hash over the entire UTXO set for snapshot verification.
    // We concatenate (txid || vout || value || height) for each UTXO in
    // lexicographic order of (txid, vout), then hash the result.

    // Collect all entries
    struct UTXOKey {
        uint256 txid;
        uint32_t vout;
        Amount value;
        uint64_t height;
    };

    std::vector<UTXOKey> entries;
    entries.reserve(utxo_.size());

    utxo_.for_each([&](const uint256& txid, uint32_t vout, const UTXOEntry& entry) {
        UTXOKey key;
        key.txid = txid;
        key.vout = vout;
        key.value = entry.value;
        key.height = entry.height;
        entries.push_back(key);
    });

    // Sort by (txid, vout) for deterministic ordering
    std::sort(entries.begin(), entries.end(),
              [](const UTXOKey& a, const UTXOKey& b) {
                  if (a.txid < b.txid) return true;
                  if (b.txid < a.txid) return false;
                  return a.vout < b.vout;
              });

    // Serialize and hash
    std::vector<uint8_t> hash_input;
    hash_input.reserve(entries.size() * 52);  // 32 + 4 + 8 + 8 = 52 per entry

    for (const auto& e : entries) {
        hash_input.insert(hash_input.end(), e.txid.begin(), e.txid.end());

        hash_input.push_back(static_cast<uint8_t>(e.vout));
        hash_input.push_back(static_cast<uint8_t>(e.vout >> 8));
        hash_input.push_back(static_cast<uint8_t>(e.vout >> 16));
        hash_input.push_back(static_cast<uint8_t>(e.vout >> 24));

        int64_t val = e.value;
        for (int i = 0; i < 8; i++) {
            hash_input.push_back(static_cast<uint8_t>(val >> (i * 8)));
        }

        uint64_t h = e.height;
        for (int i = 0; i < 8; i++) {
            hash_input.push_back(static_cast<uint8_t>(h >> (i * 8)));
        }
    }

    return keccak256(hash_input.data(), hash_input.size());
}

// ═══════════════════════════════════════════════════════════════════════════
// Chain traversal helpers
// ═══════════════════════════════════════════════════════════════════════════

std::vector<CBlockHeader> ChainState::get_headers_range(
        uint64_t start, uint64_t end) const {
    std::lock_guard<std::mutex> lock(cs_main_);

    std::vector<CBlockHeader> headers;

    CBlockIndex* t = tip();
    if (!t || start > t->height) return headers;

    if (end > t->height) end = t->height;

    // Walk from tip to end, collecting blocks
    // First build path from tip to start
    std::vector<CBlockIndex*> path;
    CBlockIndex* walk = t;
    while (walk && walk->height >= start) {
        if (walk->height <= end) {
            path.push_back(walk);
        }
        if (walk->height == 0) break;
        walk = walk->prev;
    }

    std::reverse(path.begin(), path.end());

    headers.reserve(path.size());
    for (CBlockIndex* idx : path) {
        CBlock blk;
        if (!idx->pos.is_null() && store_.read_block(idx->pos, blk)) {
            headers.push_back(blk.get_header());
        }
    }

    return headers;
}

std::vector<uint256> ChainState::get_hashes_range(
        uint64_t start, uint64_t end) const {
    std::lock_guard<std::mutex> lock(cs_main_);

    std::vector<uint256> hashes;

    CBlockIndex* t = tip();
    if (!t || start > t->height) return hashes;

    if (end > t->height) end = t->height;

    // Collect hashes by walking backwards from tip
    std::vector<std::pair<uint64_t, uint256>> collected;
    CBlockIndex* walk = t;
    while (walk && walk->height >= start) {
        if (walk->height <= end) {
            collected.emplace_back(walk->height, walk->hash);
        }
        if (walk->height == 0) break;
        walk = walk->prev;
    }

    // Reverse to get ascending order
    std::reverse(collected.begin(), collected.end());

    hashes.reserve(collected.size());
    for (const auto& pair : collected) {
        hashes.push_back(pair.second);
    }

    return hashes;
}

uint64_t ChainState::find_common_ancestor_height(
        const uint256& hash_a, const uint256& hash_b) const {
    std::lock_guard<std::mutex> lock(cs_main_);

    CBlockIndex* idx_a = tree_.find(hash_a);
    CBlockIndex* idx_b = tree_.find(hash_b);

    if (!idx_a || !idx_b) return 0;

    const CBlockIndex* fork = find_fork(idx_a, idx_b);
    return fork ? fork->height : 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// Mempool interaction — valid transaction selection for next block
// ═══════════════════════════════════════════════════════════════════════════

std::vector<uint256> ChainState::get_valid_mempool_txids(
        const std::vector<CTransaction>& mempool_txs) const {
    std::lock_guard<std::mutex> lock(cs_main_);

    std::vector<uint256> valid_txids;
    valid_txids.reserve(mempool_txs.size());

    CBlockIndex* t = tip();
    if (!t) return valid_txids;

    uint64_t next_height = t->height + 1;
    int64_t next_time = get_adjusted_time();

    for (const auto& tx : mempool_txs) {
        // Skip coinbase transactions
        if (tx.is_coinbase()) continue;

        // Check basic transaction validity
        if (!tx.check_transaction()) continue;

        // Check locktime finality
        if (!tx.is_final(next_height, next_time)) continue;

        // Check that all inputs exist in the UTXO set
        bool all_inputs_available = true;
        Amount input_sum = 0;

        for (const auto& in : tx.vin) {
            UTXOEntry entry;
            if (!utxo_.get(in.prevout.txid, in.prevout.index, entry)) {
                all_inputs_available = false;
                break;
            }

            // Check coinbase maturity
            if (entry.is_coinbase) {
                if (next_height < entry.height + consensus::COINBASE_MATURITY) {
                    all_inputs_available = false;
                    break;
                }
            }

            input_sum += entry.value;
        }

        if (!all_inputs_available) continue;

        // Check that inputs >= outputs (no negative fees)
        Amount output_sum = tx.get_value_out();
        if (input_sum < output_sum) continue;

        valid_txids.push_back(tx.get_txid());
    }

    return valid_txids;
}

// ---------------------------------------------------------------------------
// has_utxo_for_tx — check if any UTXO exists for a transaction ID
// ---------------------------------------------------------------------------

bool ChainState::has_utxo_for_tx(const uint256& txid) const {
    // Check outputs 0..255 (practical limit)
    for (uint32_t vout = 0; vout < 256; ++vout) {
        UTXOEntry entry;
        if (utxo_.get(txid, vout, entry)) {
            return true;
        }
        // If output 0 doesn't exist, likely no outputs for this tx
        if (vout == 0) {
            // Could still have been fully spent, so we can't short-circuit
            // But for a quick check, if output 0 is not in UTXO set,
            // all outputs may have been spent. Continue checking a few more.
        }
        if (vout > 4) break;  // Most transactions have <= 5 outputs
    }
    return false;
}

// ---------------------------------------------------------------------------
// Convenience methods for kernel code
// ---------------------------------------------------------------------------

bool ChainState::get_header(uint64_t h, CBlockHeader& hdr) const {
    CBlockIndex* idx = get_block_index_at_height(h);
    if (!idx) return false;
    CBlock block;
    if (!get_block_at_height(h, block)) return false;
    hdr = static_cast<CBlockHeader>(block);
    return true;
}

uint32_t ChainState::get_next_nbits() const {
    CBlockIndex* t = tip();
    if (!t) return consensus::INITIAL_NBITS;
    return t->nbits;
}

bool ChainState::accept_genesis() {
    return init();
}

bool ChainState::load() {
    return load_from_disk();
}

bool ChainState::has_undo_data(uint64_t) const {
    // For now, assume undo data is always available within reorg window
    return true;
}

bool ChainState::can_disconnect(uint64_t h) const {
    if (!tip()) return false;
    return h <= tip()->height && h > 0;
}

} // namespace flow


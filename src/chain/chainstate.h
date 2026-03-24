// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// ChainState: main blockchain state coordinator.
// Owns the block tree (in-memory index), the UTXO set (SQLite), the
// flat-file block store, the model state (consensus model + checkpoints),
// and the optional transaction index. Handles genesis creation, header
// acceptance, full block validation, chain connection/disconnection,
// reorganization, and assume-valid optimization.

#ifndef FLOWCOIN_CHAIN_CHAINSTATE_H
#define FLOWCOIN_CHAIN_CHAINSTATE_H

#include "chain/blockindex.h"
#include "chain/blockstore.h"
#include "chain/chaindb.h"
#include "chain/modelstate.h"
#include "chain/txindex.h"
#include "chain/utxo.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace flow {

class ChainState {
public:
    /// Construct a ChainState rooted at the given data directory.
    /// The directory should contain (or will be populated with):
    ///   blocks/blk00000.dat, ...    (flat-file block storage)
    ///   utxo.db                     (SQLite UTXO database)
    ///   model/                      (consensus model checkpoints)
    ///   txindex.db                  (optional transaction index)
    explicit ChainState(const std::string& datadir);

    /// Initialize the chain state. Creates the genesis block if the
    /// block tree is empty. Initializes model state and optional tx index.
    /// Returns true on success.
    bool init();

    /// Accept a new block header (used during IBD header sync).
    /// Validates header-only (checks 1-11, 13-14).
    /// Returns pointer to the new or existing block index entry,
    /// or nullptr if validation fails.
    CBlockIndex* accept_header(const CBlockHeader& header,
                               consensus::ValidationState& state);

    /// Accept a full block (from a peer or miner).
    /// Validates fully (all checks), stores block to disk, and connects
    /// to the active chain if it extends the best tip.
    /// Returns true on success.
    bool accept_block(const CBlock& block, consensus::ValidationState& state);

    /// Connect a block to the active chain (update UTXO set + model state).
    /// The block must already be stored on disk and indexed.
    bool connect_block(const CBlock& block, CBlockIndex* index);

    /// Disconnect the current tip block (for reorg).
    /// Reverses UTXO changes and model state from the tip block.
    bool disconnect_tip();

    /// Full reorganization to a new tip.
    /// Finds fork point, disconnects blocks, connects new chain.
    /// Returns true on success. On failure, the chain state may be
    /// at the fork point (partial reorg).
    bool reorganize_to(CBlockIndex* new_tip, consensus::ValidationState& state);

    /// Flush UTXO changes and block index to disk.
    /// Called periodically during IBD and before shutdown.
    bool flush();

    /// Full startup sequence:
    ///   1. Open/create ChainDB
    ///   2. Load all block indices from DB
    ///   3. Reconstruct BlockTree from loaded indices
    ///   4. Verify tip matches stored tip
    ///   5. If mismatch: crash recovery (walk back to find valid tip)
    ///   6. Load UTXO set
    ///   7. Initialize ModelState
    bool load_from_disk();

    /// Save all persistent state to disk.
    bool save_to_disk();

    /// Undo data for block disconnection during reorg.
    struct BlockUndo {
        /// For each input spent in the block: the UTXOEntry that was consumed.
        struct SpentOutput {
            uint256 txid;
            uint32_t vout;
            UTXOEntry entry;
        };
        std::vector<SpentOutput> spent_outputs;

        /// Serialize to bytes for storage.
        std::vector<uint8_t> serialize() const;

        /// Deserialize from bytes.
        static bool deserialize(const uint8_t* data, size_t len, BlockUndo& out);
    };

    /// Generate undo data for a block being connected.
    /// Must be called before connect_block modifies the UTXO set.
    BlockUndo generate_undo(const CBlock& block) const;

    /// Disconnect a block using pre-computed undo data.
    /// Faster than disconnect_tip() which must scan the chain for source txs.
    bool disconnect_block(const CBlock& block, const BlockUndo& undo);

    /// Enable/disable pruning mode.
    void set_pruning_enabled(bool enabled, uint64_t prune_target_height = 0);

    /// Check if pruning is enabled.
    bool is_pruning_enabled() const { return pruning_enabled_; }

    /// Run pruning: delete old block/undo data below the prune height.
    /// Keeps at least REORG_WINDOW blocks of undo data.
    bool prune();

    /// Get the ChainDB (persistent block index).
    ChainDB* chain_db() { return chaindb_.get(); }
    const ChainDB* chain_db() const { return chaindb_.get(); }

    // --- Accessors ---

    BlockTree&       block_tree()       { return tree_; }
    const BlockTree& block_tree() const { return tree_; }
    UTXOSet&         utxo_set()         { return utxo_; }
    BlockStore&      block_store()      { return store_; }
    ModelState&      model_state()      { return model_state_; }
    const ModelState& model_state() const { return model_state_; }
    TxIndex*         tx_index()        { return txindex_.get(); }
    const TxIndex*   tx_index() const  { return txindex_.get(); }

    CBlockIndex* tip() const { return tree_.best_tip(); }
    uint64_t height() const { return tip() ? tip()->height : 0; }

    /// Get the data directory path.
    const std::string& datadir() const { return datadir_; }

    /// Enable/disable the transaction index.
    void set_txindex_enabled(bool enabled) { txindex_enabled_ = enabled; }

    /// Set the assume-valid block hash. Blocks at or below this hash
    /// skip Check 15 (forward evaluation) during validation, allowing
    /// faster IBD. Set to null to disable.
    void set_assume_valid(const uint256& hash) { assume_valid_hash_ = hash; }
    const uint256& assume_valid_hash() const { return assume_valid_hash_; }

    /// Check if a block hash is at or below the assume-valid point
    bool is_assumed_valid(const CBlockIndex* idx) const;

    /// Reorg safety window: keep at least this many blocks of undo data.
    static constexpr uint64_t REORG_WINDOW = 100;

    /// Flush interval: write UTXO and chaindb changes every N blocks.
    static constexpr uint64_t FLUSH_INTERVAL = 500;

private:
    std::string datadir_;
    BlockTree   tree_;
    UTXOSet     utxo_;
    BlockStore  store_;
    ModelState  model_state_;
    std::unique_ptr<TxIndex> txindex_;
    std::unique_ptr<ChainDB> chaindb_;
    bool        txindex_enabled_ = true;
    bool        pruning_enabled_ = false;
    uint64_t    prune_target_height_ = 0;
    uint64_t    blocks_since_flush_ = 0;
    uint256     assume_valid_hash_;  // null = disabled
    mutable std::mutex cs_main_;  // Main lock for chain state access

    /// Create the genesis block with the hardcoded parameters.
    CBlock create_genesis_block() const;

    /// Get the current adjusted network time.
    /// For now, returns the system wall clock time.
    int64_t get_adjusted_time() const;

    /// Update the active chain tip to the given block index.
    void update_tip(CBlockIndex* new_tip);

    /// Build the chain of blocks from genesis to the given tip,
    /// returned in order from oldest to newest (genesis first).
    std::vector<CBlockIndex*> get_chain_to(CBlockIndex* tip) const;

    /// Determine the EvalFunction to use for block validation.
    /// Returns nullptr if Check 15 should be skipped (IBD / assume-valid).
    consensus::EvalFunction get_eval_function(const CBlockIndex* parent) const;

    /// Persist a block index entry to ChainDB.
    void persist_block_index(const CBlockIndex* idx);

    /// Persist the chain tip to ChainDB.
    void persist_tip();

    /// Find the fork point (common ancestor) between two chain tips.
    CBlockIndex* find_fork_point(CBlockIndex* tip_a, CBlockIndex* tip_b) const;

    /// Crash recovery: walk back from the stored tip to find the highest
    /// block that is both in the block tree and fully validated.
    CBlockIndex* recover_tip();

    /// Reconstruct the in-memory BlockTree from ChainDB entries.
    bool rebuild_tree_from_db();

    /// Auto-flush if enough blocks have been connected since last flush.
    void maybe_flush();
};

} // namespace flow

#endif // FLOWCOIN_CHAIN_CHAINSTATE_H

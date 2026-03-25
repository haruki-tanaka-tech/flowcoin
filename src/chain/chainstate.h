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
#include "util/arith_uint256.h"
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace flow {

class Mempool;

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

    /// Access the mempool (may be nullptr if not set).
    Mempool* mempool() { return mempool_; }
    const Mempool* mempool() const { return mempool_; }
    void set_mempool(Mempool* mp) { mempool_ = mp; }

    /// Check if a UTXO exists for a given transaction ID (any output).
    bool has_utxo_for_tx(const uint256& txid) const;

    /// Convenience aliases used by kernel code.
    uint64_t get_height() const { return height(); }
    uint256 get_tip_hash() const { return tip() ? tip()->hash : uint256(); }
    bool get_header(uint64_t h, CBlockHeader& hdr) const;
    bool get_utxo(const uint256& txid, uint32_t vout, UTXOEntry& entry) const {
        return utxo_.get(txid, vout, entry);
    }
    uint32_t get_next_nbits() const;
    bool read_block(uint64_t h, CBlock& block) const { return get_block_at_height(h, block); }
    bool accept_genesis();
    bool load();
    bool has_undo_data(uint64_t h) const;
    bool can_disconnect(uint64_t h) const;

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
    Mempool*    mempool_ = nullptr;
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

public:
    // ═══ Extended chain state operations ═══

    /// Accept multiple headers in batch (for IBD).
    /// Returns the number of headers successfully accepted.
    int accept_headers_batch(const std::vector<CBlockHeader>& headers,
                              consensus::ValidationState& state);

    /// Full block acceptance pipeline: header + tx validation + connection.
    bool accept_block_full(const CBlock& block, consensus::ValidationState& state);

    /// Full reorganization with statistics tracking.
    struct ReorgStats {
        int blocks_disconnected;
        int blocks_connected;
        int64_t reorg_time_ms;
        uint64_t fork_height;
        uint256 old_tip;
        uint256 new_tip;
    };
    ReorgStats reorganize(const CBlockIndex* new_tip);

    /// Compute total chain work from genesis to tip.
    arith_uint256 compute_chain_work(const CBlockIndex* tip) const;

    /// Find fork point between two chain tips (public const interface).
    const CBlockIndex* find_fork(const CBlockIndex* tip_a,
                                   const CBlockIndex* tip_b) const;

    /// Flush UTXO cache and block store to disk.
    void periodic_flush();

    /// Compact all databases (SQLite VACUUM).
    void periodic_compact();

    /// Verify chain state consistency (block index, UTXO, tip).
    bool check_consistency() const;

    /// Retrieve a block at a specific height.
    bool get_block_at_height(uint64_t height, CBlock& block) const;

    /// Get block index entry at a specific height.
    CBlockIndex* get_block_index_at_height(uint64_t height) const;

    /// Get headers starting from a hash, up to max_count.
    std::vector<CBlockHeader> get_headers_from(const uint256& start_hash,
                                                 int max_count) const;

    /// Build a block locator (exponentially-spaced block hashes).
    std::vector<uint256> get_locator() const;

    /// Find the highest block in a locator that we have.
    CBlockIndex* find_locator_fork(const std::vector<uint256>& locator) const;

    /// UTXO set aggregate statistics.
    struct UTXOStatistics {
        size_t count;
        Amount total_value;
        size_t coinbase_count;
        Amount coinbase_value;
        uint64_t min_height;
        uint64_t max_height;
    };
    UTXOStatistics get_utxo_stats() const;

    // ═══ Coin age and priority ═══

    /// Compute priority for a transaction (sum of coin_age for all inputs).
    double compute_tx_priority(const CTransaction& tx, uint64_t current_height) const;

    // ═══ Chain statistics ═══

    struct ChainStats {
        uint64_t height;
        uint256 tip_hash;
        size_t utxo_count;
        Amount total_supply;
        Amount total_fees_collected;
        double difficulty;
        arith_uint256 chain_work;
        size_t total_transactions;
        size_t total_blocks;
        size_t blocks_disk_bytes;
        float current_val_loss;
        size_t model_params;
        uint256 model_hash;
        int64_t median_time_past;
        double avg_block_time_last_100;
        double avg_tx_per_block_last_100;
    };
    ChainStats get_chain_stats() const;

    // ═══ Block verification with detailed results ═══

    struct VerifyResult {
        bool valid;
        int checks_passed;
        int checks_total;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
        int64_t verify_time_ms;
    };
    VerifyResult verify_block_detailed(const CBlock& block) const;

    // ═══ UTXO snapshot ═══

    struct UTXOSnapshot {
        uint64_t height;
        uint256 block_hash;
        uint256 utxo_set_hash;
        size_t utxo_count;
        Amount total_value;
        std::vector<uint8_t> serialized_utxos;
    };
    UTXOSnapshot create_utxo_snapshot() const;
    bool load_utxo_snapshot(const UTXOSnapshot& snapshot);
    uint256 compute_utxo_set_hash() const;

    // ═══ Chain traversal helpers ═══

    std::vector<CBlockHeader> get_headers_range(uint64_t start, uint64_t end) const;
    std::vector<uint256> get_hashes_range(uint64_t start, uint64_t end) const;
    uint64_t find_common_ancestor_height(const uint256& hash_a,
                                           const uint256& hash_b) const;

    // ═══ Mempool interaction ═══

    /// Check which mempool transactions would be valid in next block.
    std::vector<uint256> get_valid_mempool_txids(
        const std::vector<CTransaction>& mempool_txs) const;
};

} // namespace flow

#endif // FLOWCOIN_CHAIN_CHAINSTATE_H

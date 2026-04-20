// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Base class for optional chain indexes (TxIndex, BlockFilterIndex, etc.).
// Indexes run in a background thread, processing blocks as they are
// connected to the active chain. Each index maintains its own SQLite
// database and tracks its sync height independently.

#ifndef FLOWCOIN_INDEX_BASE_H
#define FLOWCOIN_INDEX_BASE_H

#include "primitives/block.h"
#include "util/types.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;

namespace flow {

class ChainState;

// ============================================================================
// BaseIndex: abstract base class for all optional chain indexes
// ============================================================================

class BaseIndex {
public:
    // Sync state machine
    enum class State : uint8_t {
        IDLE,       // Created but not started
        SYNCING,    // Background thread catching up to chain tip
        SYNCED,     // Fully caught up with the active chain
        IDX_ERROR,  // Unrecoverable error encountered
    };

    // ---- Construction / destruction ----------------------------------------

    /// Create an index with a human-readable name and database path.
    /// The database file is created if it does not exist.
    BaseIndex(const std::string& name, const std::string& db_path);

    virtual ~BaseIndex();

    // Non-copyable, non-movable
    BaseIndex(const BaseIndex&) = delete;
    BaseIndex& operator=(const BaseIndex&) = delete;
    BaseIndex(BaseIndex&&) = delete;
    BaseIndex& operator=(BaseIndex&&) = delete;

    // ---- Lifecycle ---------------------------------------------------------

    /// Start the background sync thread. Returns false on init failure.
    bool start();

    /// Signal the background thread to stop and block until it exits.
    /// Flushes all pending writes before returning.
    void stop();

    /// Check if the index has fully caught up with the active chain tip.
    bool is_synced() const;

    /// Get the current sync state.
    State state() const;

    // ---- Sync progress -----------------------------------------------------

    /// The highest block height this index has processed.
    uint64_t best_height() const;

    /// Sync progress as a fraction in [0.0, 1.0].
    /// Returns 1.0 if the chain height is 0 or the index is synced.
    double sync_progress() const;

    /// Set the chain height used for progress calculation.
    void set_chain_height(uint64_t height);

    // ---- Chain notifications -----------------------------------------------

    /// Called by the chain state coordinator when a block is connected.
    /// Queues the block for background processing.
    void block_connected(const CBlock& block, uint64_t height);

    /// Called when a block is disconnected (reorg).
    /// Queues the undo operation for background processing.
    void block_disconnected(const CBlock& block, uint64_t height);

    // ---- Identity ----------------------------------------------------------

    /// Get the human-readable index name (for logging).
    const std::string& name() const { return name_; }

    /// Get the database path.
    const std::string& db_path() const { return db_path_; }

    // ---- Batch processing --------------------------------------------------

    /// Begin a database transaction for batching writes.
    void begin_batch();

    /// Commit the current batch transaction.
    void commit_batch();

    /// Rollback the current batch transaction.
    void rollback_batch();

protected:
    // ---- Subclass hooks (pure virtual) -------------------------------------

    /// Write index data for a newly connected block.
    /// Called with the database transaction active.
    virtual bool write_block(const CBlock& block, uint64_t height) = 0;

    /// Undo index data for a disconnected block (reorg).
    virtual bool undo_block(const CBlock& block, uint64_t height) = 0;

    /// Initialize the index-specific database tables.
    /// Called once during start() after the meta table is created.
    virtual bool init_db() = 0;

    // ---- Database handle ---------------------------------------------------

    sqlite3* db_ = nullptr;

    // ---- State tracking ----------------------------------------------------

    std::string name_;
    std::string db_path_;
    std::atomic<State> state_{State::IDLE};
    std::atomic<uint64_t> best_height_{0};
    std::atomic<uint64_t> chain_height_{0};
    mutable std::mutex mutex_;

    // ---- Persistence helpers -----------------------------------------------

    /// Save the best processed height to the meta table.
    bool save_best_height(uint64_t height);

    /// Load the best processed height from the meta table.
    uint64_t load_best_height() const;

    /// Create the shared meta table (best_height, index name).
    bool create_meta_table();

    /// Open the SQLite database. Returns false on failure.
    bool open_db();

    /// Close the SQLite database.
    void close_db();

    /// Execute a raw SQL statement (no result set).
    bool exec_sql(const char* sql);

private:
    // ---- Background thread -------------------------------------------------

    struct BlockEvent {
        CBlock block;
        uint64_t height;
        bool connected;  // true = connect, false = disconnect
    };

    std::thread worker_;
    std::atomic<bool> shutdown_{false};
    std::deque<BlockEvent> queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;

    /// Background thread entry point.
    void thread_main();

    /// Process all queued events.
    void process_queue();

    /// Process a single event.
    bool process_event(const BlockEvent& event);

    // Prepared statements for meta table
    sqlite3_stmt* stmt_save_height_ = nullptr;
    sqlite3_stmt* stmt_load_height_ = nullptr;

    /// Prepare internal meta statements.
    void prepare_meta_stmts();

    /// Finalize internal meta statements.
    void finalize_meta_stmts();

    // Batch tracking
    bool in_batch_ = false;
    int batch_count_ = 0;
    static constexpr int BATCH_SIZE = 256;
};

/// Convert State enum to string for logging.
const char* index_state_name(BaseIndex::State s);

} // namespace flow

#endif // FLOWCOIN_INDEX_BASE_H

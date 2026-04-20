// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Persistent block index database backed by SQLite.
// Stores all CBlockIndex entries and chain metadata so that
// the in-memory block tree can be reconstructed on startup
// without re-scanning flat-file block data.
//
// Table schema:
//   block_index:  one row per accepted block header
//   chain_meta:   key-value store for tip hash, height, etc.

#ifndef FLOWCOIN_CHAIN_CHAINDB_H
#define FLOWCOIN_CHAIN_CHAINDB_H

#include "chain/blockindex.h"
#include "util/types.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;

namespace flow {

class ChainDB {
public:
    /// Open or create the block index database at the given path.
    /// Creates tables and indices on first run.
    explicit ChainDB(const std::string& db_path);
    ~ChainDB();

    // Non-copyable
    ChainDB(const ChainDB&) = delete;
    ChainDB& operator=(const ChainDB&) = delete;

    /// Returns true if the database was opened successfully.
    bool is_open() const { return db_ != nullptr; }

    // ---- Block index persistence -------------------------------------------

    /// Save a block index entry to the database.
    /// Inserts or replaces the row keyed by hash.
    bool save_block_index(const CBlockIndex& index);

    /// Load all block index entries from the database.
    /// Returns a vector of CBlockIndex objects with prev_hash populated
    /// but prev pointer set to nullptr (caller must re-link the tree).
    std::vector<CBlockIndex> load_all_indices() const;

    /// Load a single block index entry by hash.
    /// Returns true if found, populating the output parameter.
    bool load_block_index(const uint256& hash, CBlockIndex& out) const;

    /// Delete a block index entry by hash.
    bool delete_block_index(const uint256& hash);

    // ---- Chain metadata ----------------------------------------------------

    /// Save the active chain tip hash.
    bool save_tip(const uint256& hash);

    /// Load the active chain tip hash. Returns null hash if not set.
    uint256 load_tip() const;

    /// Save the best chain height.
    bool save_height(uint64_t height);

    /// Load the best chain height. Returns 0 if not set.
    uint64_t load_height() const;

    /// Save arbitrary metadata by key.
    bool save_meta(const std::string& key, const uint8_t* data, size_t len);

    /// Load arbitrary metadata by key.
    /// Returns empty vector if key not found.
    std::vector<uint8_t> load_meta(const std::string& key) const;

    // ---- Batch operations (for IBD performance) ----------------------------

    /// Begin a SQLite transaction. Multiple save_block_index calls
    /// between begin_batch/commit_batch are batched into one transaction.
    void begin_batch();

    /// Commit the current batch transaction.
    void commit_batch();

    /// Roll back the current batch (on error).
    void rollback_batch();

    // ---- Pruning -----------------------------------------------------------

    /// Delete all block index entries below the given height.
    /// Returns the number of entries pruned.
    size_t prune_below(uint64_t height);

    // ---- Statistics --------------------------------------------------------

    /// Total number of block index entries in the database.
    size_t count() const;

    /// Highest height stored in the database.
    uint64_t max_height() const;

    /// Lowest height stored in the database.
    uint64_t min_height() const;

    /// Total database file size on disk (bytes).
    size_t disk_usage() const;

    /// Compact the database (SQLite incremental vacuum).
    void compact();

private:
    sqlite3* db_ = nullptr;
    std::string db_path_;

    // Prepared statements
    sqlite3_stmt* stmt_save_ = nullptr;
    sqlite3_stmt* stmt_load_all_ = nullptr;
    sqlite3_stmt* stmt_load_one_ = nullptr;
    sqlite3_stmt* stmt_delete_ = nullptr;
    sqlite3_stmt* stmt_save_meta_ = nullptr;
    sqlite3_stmt* stmt_load_meta_ = nullptr;
    sqlite3_stmt* stmt_count_ = nullptr;
    sqlite3_stmt* stmt_max_height_ = nullptr;
    sqlite3_stmt* stmt_min_height_ = nullptr;
    sqlite3_stmt* stmt_prune_ = nullptr;

    /// Create tables and indices if they don't exist.
    void init_tables();

    /// Prepare all SQL statements.
    void prepare_statements();

    /// Finalize all prepared statements.
    void finalize_statements();

    /// Populate a CBlockIndex from a query result row.
    /// The statement must be positioned on a valid row (after sqlite3_step == SQLITE_ROW).
    void read_index_from_row(sqlite3_stmt* stmt, CBlockIndex& idx) const;
};

} // namespace flow

#endif // FLOWCOIN_CHAIN_CHAINDB_H

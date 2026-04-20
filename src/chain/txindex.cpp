// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Transaction index implementation backed by SQLite.
// Provides O(1) lookup of transaction location by txid.

#include "chain/txindex.h"

#include <sqlite3.h>

#include <cstdio>
#include <cstring>
#include "logging.h"

namespace flow {

// ════════════════════════════════════════════════════════════════════════════
// Construction / Destruction
// ════════════════════════════════════════════════════════════════════════════

TxIndex::TxIndex(const std::string& db_path) {
    int rc = sqlite3_open(db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        LogError("db", "failed to open database %s: %s",
                db_path.c_str(),
                db_ ? sqlite3_errmsg(db_) : "out of memory");
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }

    // Enable WAL mode for concurrent readers
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);

    // Synchronous = NORMAL for better performance (still safe with WAL)
    sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);

    init_tables();
    prepare_statements();
}

TxIndex::~TxIndex() {
    finalize_statements();
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Table initialization
// ════════════════════════════════════════════════════════════════════════════

void TxIndex::init_tables() {
    if (!db_) return;

    const char* sql =
        "CREATE TABLE IF NOT EXISTS tx_index ("
        "  txid BLOB PRIMARY KEY,"
        "  block_height INTEGER NOT NULL,"
        "  block_hash BLOB NOT NULL,"
        "  tx_pos INTEGER NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_tx_block_height "
        "  ON tx_index(block_height);";

    char* errmsg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        LogError("db", "table creation failed: %s",
                errmsg ? errmsg : "unknown error");
        sqlite3_free(errmsg);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Prepared statements
// ════════════════════════════════════════════════════════════════════════════

void TxIndex::prepare_statements() {
    if (!db_) return;

    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO tx_index "
        "(txid, block_height, block_hash, tx_pos) VALUES (?, ?, ?, ?)",
        -1, &stmt_insert_, nullptr);

    sqlite3_prepare_v2(db_,
        "DELETE FROM tx_index WHERE block_height = ?",
        -1, &stmt_delete_by_height_, nullptr);

    sqlite3_prepare_v2(db_,
        "SELECT block_height, block_hash, tx_pos FROM tx_index WHERE txid = ?",
        -1, &stmt_find_, nullptr);

    sqlite3_prepare_v2(db_,
        "SELECT MAX(block_height) FROM tx_index",
        -1, &stmt_best_height_, nullptr);
}

void TxIndex::finalize_statements() {
    if (stmt_insert_) { sqlite3_finalize(stmt_insert_); stmt_insert_ = nullptr; }
    if (stmt_delete_by_height_) { sqlite3_finalize(stmt_delete_by_height_); stmt_delete_by_height_ = nullptr; }
    if (stmt_find_) { sqlite3_finalize(stmt_find_); stmt_find_ = nullptr; }
    if (stmt_best_height_) { sqlite3_finalize(stmt_best_height_); stmt_best_height_ = nullptr; }
}

// ════════════════════════════════════════════════════════════════════════════
// index_block — add all transactions in a block to the index
// ════════════════════════════════════════════════════════════════════════════

bool TxIndex::index_block(const CBlock& block, uint64_t height,
                           const uint256& block_hash) {
    if (!db_ || !stmt_insert_) {
        return false;
    }

    // Begin transaction for batch insert
    sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, nullptr);

    for (uint32_t tx_i = 0; tx_i < block.vtx.size(); tx_i++) {
        const CTransaction& tx = block.vtx[tx_i];
        uint256 txid = tx.get_txid();

        sqlite3_reset(stmt_insert_);

        // Bind txid (32 bytes)
        sqlite3_bind_blob(stmt_insert_, 1, txid.data(), 32, SQLITE_STATIC);

        // Bind block_height
        sqlite3_bind_int64(stmt_insert_, 2, static_cast<sqlite3_int64>(height));

        // Bind block_hash (32 bytes)
        sqlite3_bind_blob(stmt_insert_, 3, block_hash.data(), 32, SQLITE_STATIC);

        // Bind tx_pos
        sqlite3_bind_int(stmt_insert_, 4, static_cast<int>(tx_i));

        int rc = sqlite3_step(stmt_insert_);
        if (rc != SQLITE_DONE) {
            LogError("db", "insert failed at height %lu, tx %u: %s",
                    static_cast<unsigned long>(height), tx_i,
                    sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr);
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// deindex_block — remove all transactions at a given height
// ════════════════════════════════════════════════════════════════════════════

bool TxIndex::deindex_block(uint64_t height) {
    if (!db_ || !stmt_delete_by_height_) {
        return false;
    }

    sqlite3_reset(stmt_delete_by_height_);
    sqlite3_bind_int64(stmt_delete_by_height_, 1,
                        static_cast<sqlite3_int64>(height));

    int rc = sqlite3_step(stmt_delete_by_height_);
    if (rc != SQLITE_DONE) {
        LogError("db", "delete failed at height %lu: %s",
                static_cast<unsigned long>(height),
                sqlite3_errmsg(db_));
        return false;
    }

    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// find — look up a transaction by txid
// ════════════════════════════════════════════════════════════════════════════

TxIndex::TxLocation TxIndex::find(const uint256& txid) const {
    TxLocation loc{};
    loc.found = false;

    if (!db_ || !stmt_find_) {
        return loc;
    }

    sqlite3_reset(stmt_find_);
    sqlite3_bind_blob(stmt_find_, 1, txid.data(), 32, SQLITE_STATIC);

    int rc = sqlite3_step(stmt_find_);
    if (rc == SQLITE_ROW) {
        loc.block_height = static_cast<uint64_t>(sqlite3_column_int64(stmt_find_, 0));

        const void* hash_data = sqlite3_column_blob(stmt_find_, 1);
        int hash_len = sqlite3_column_bytes(stmt_find_, 1);
        if (hash_data && hash_len == 32) {
            std::memcpy(loc.block_hash.data(),
                        static_cast<const uint8_t*>(hash_data), 32);
        }

        loc.tx_index = static_cast<uint32_t>(sqlite3_column_int(stmt_find_, 2));
        loc.found = true;
    }

    return loc;
}

// ════════════════════════════════════════════════════════════════════════════
// get_best_height — highest indexed block
// ════════════════════════════════════════════════════════════════════════════

uint64_t TxIndex::get_best_height() const {
    if (!db_ || !stmt_best_height_) {
        return 0;
    }

    sqlite3_reset(stmt_best_height_);
    int rc = sqlite3_step(stmt_best_height_);
    if (rc == SQLITE_ROW && sqlite3_column_type(stmt_best_height_, 0) != SQLITE_NULL) {
        return static_cast<uint64_t>(sqlite3_column_int64(stmt_best_height_, 0));
    }

    return 0;
}

void TxIndex::compact() {
    if (!db_) return;
    char* errmsg = nullptr;
    sqlite3_exec(db_, "PRAGMA incremental_vacuum;", nullptr, nullptr, &errmsg);
    if (errmsg) sqlite3_free(errmsg);
}

} // namespace flow

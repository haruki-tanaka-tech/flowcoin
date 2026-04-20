// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "index/txindex.h"
#include "hash/keccak.h"

#include <sqlite3.h>

#include <cassert>
#include <cstring>

namespace flow {

// ============================================================================
// Construction / destruction
// ============================================================================

TxIndexImpl::TxIndexImpl(const std::string& db_path)
    : BaseIndex("txindex", db_path) {
}

TxIndexImpl::~TxIndexImpl() {
    finalize_statements();
}

// ============================================================================
// Database initialization
// ============================================================================

bool TxIndexImpl::init_db() {
    // Create the tx_index table
    const char* create_table =
        "CREATE TABLE IF NOT EXISTS tx_index ("
        "  txid BLOB NOT NULL,"
        "  block_hash BLOB NOT NULL,"
        "  block_height INTEGER NOT NULL,"
        "  tx_pos INTEGER NOT NULL,"
        "  tx_data BLOB,"
        "  PRIMARY KEY (txid)"
        ")";
    if (!exec_sql(create_table)) return false;

    // Create index on block height for efficient undo operations
    const char* create_idx =
        "CREATE INDEX IF NOT EXISTS idx_tx_height ON tx_index(block_height)";
    if (!exec_sql(create_idx)) return false;

    // Create index on block hash for block-level queries
    const char* create_bhash_idx =
        "CREATE INDEX IF NOT EXISTS idx_tx_block_hash ON tx_index(block_hash)";
    if (!exec_sql(create_bhash_idx)) return false;

    prepare_statements();
    return true;
}

// ============================================================================
// Prepared statements
// ============================================================================

void TxIndexImpl::prepare_statements() {
    if (!db_) return;

    const char* insert_sql =
        "INSERT OR REPLACE INTO tx_index "
        "(txid, block_hash, block_height, tx_pos, tx_data) "
        "VALUES (?, ?, ?, ?, ?)";
    sqlite3_prepare_v2(db_, insert_sql, -1, &stmt_insert_, nullptr);

    const char* find_sql =
        "SELECT block_hash, block_height, tx_pos, tx_data "
        "FROM tx_index WHERE txid = ?";
    sqlite3_prepare_v2(db_, find_sql, -1, &stmt_find_, nullptr);

    const char* delete_sql =
        "DELETE FROM tx_index WHERE block_height = ?";
    sqlite3_prepare_v2(db_, delete_sql, -1, &stmt_delete_, nullptr);

    const char* has_sql =
        "SELECT 1 FROM tx_index WHERE txid = ? LIMIT 1";
    sqlite3_prepare_v2(db_, has_sql, -1, &stmt_has_, nullptr);

    const char* by_height_sql =
        "SELECT txid FROM tx_index WHERE block_height = ? ORDER BY tx_pos";
    sqlite3_prepare_v2(db_, by_height_sql, -1, &stmt_by_height_, nullptr);

    const char* count_sql =
        "SELECT COUNT(*) FROM tx_index";
    sqlite3_prepare_v2(db_, count_sql, -1, &stmt_count_, nullptr);

    const char* block_hash_sql =
        "SELECT block_hash FROM tx_index WHERE txid = ?";
    sqlite3_prepare_v2(db_, block_hash_sql, -1, &stmt_block_hash_, nullptr);
}

void TxIndexImpl::finalize_statements() {
    auto finalize = [](sqlite3_stmt*& s) {
        if (s) { sqlite3_finalize(s); s = nullptr; }
    };
    finalize(stmt_insert_);
    finalize(stmt_find_);
    finalize(stmt_delete_);
    finalize(stmt_has_);
    finalize(stmt_by_height_);
    finalize(stmt_count_);
    finalize(stmt_block_hash_);
}

// ============================================================================
// Write / undo block
// ============================================================================

bool TxIndexImpl::write_block(const CBlock& block, uint64_t height) {
    if (!stmt_insert_) return false;

    uint256 block_hash = block.get_hash();

    for (uint32_t i = 0; i < block.vtx.size(); ++i) {
        const CTransaction& tx = block.vtx[i];
        uint256 txid = tx.get_txid();
        std::vector<uint8_t> tx_data = tx.serialize();

        sqlite3_reset(stmt_insert_);

        // Bind txid (BLOB, 32 bytes)
        sqlite3_bind_blob(stmt_insert_, 1,
                          txid.data(), static_cast<int>(txid.size()),
                          SQLITE_TRANSIENT);

        // Bind block_hash (BLOB, 32 bytes)
        sqlite3_bind_blob(stmt_insert_, 2,
                          block_hash.data(), static_cast<int>(block_hash.size()),
                          SQLITE_TRANSIENT);

        // Bind block_height
        sqlite3_bind_int64(stmt_insert_, 3, static_cast<int64_t>(height));

        // Bind tx_pos
        sqlite3_bind_int(stmt_insert_, 4, static_cast<int>(i));

        // Bind tx_data
        sqlite3_bind_blob(stmt_insert_, 5,
                          tx_data.data(), static_cast<int>(tx_data.size()),
                          SQLITE_TRANSIENT);

        int rc = sqlite3_step(stmt_insert_);
        if (rc != SQLITE_DONE) {
            return false;
        }
    }

    return true;
}

bool TxIndexImpl::undo_block(const CBlock& /*block*/, uint64_t height) {
    if (!stmt_delete_) return false;

    sqlite3_reset(stmt_delete_);
    sqlite3_bind_int64(stmt_delete_, 1, static_cast<int64_t>(height));
    int rc = sqlite3_step(stmt_delete_);
    return rc == SQLITE_DONE;
}

// ============================================================================
// Lookups
// ============================================================================

TxIndexImpl::TxResult TxIndexImpl::find_tx(const uint256& txid) const {
    TxResult result;
    result.found = false;

    if (!stmt_find_) return result;

    std::lock_guard<std::mutex> lock(mutex_);

    sqlite3_reset(stmt_find_);
    sqlite3_bind_blob(stmt_find_, 1, txid.data(), static_cast<int>(txid.size()),
                      SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt_find_);
    if (rc != SQLITE_ROW) return result;

    // block_hash
    const void* bh = sqlite3_column_blob(stmt_find_, 0);
    int bh_len = sqlite3_column_bytes(stmt_find_, 0);
    if (bh && bh_len == 32) {
        std::memcpy(result.block_hash.data(), bh, 32);
    }

    // block_height
    result.block_height = static_cast<uint64_t>(sqlite3_column_int64(stmt_find_, 1));

    // tx_pos
    result.tx_pos = static_cast<uint32_t>(sqlite3_column_int(stmt_find_, 2));

    // tx_data
    const void* td = sqlite3_column_blob(stmt_find_, 3);
    int td_len = sqlite3_column_bytes(stmt_find_, 3);
    if (td && td_len > 0) {
        const auto* td_bytes = static_cast<const uint8_t*>(td);
        result.tx.deserialize(std::vector<uint8_t>(td_bytes, td_bytes + td_len));
    }

    result.found = true;
    return result;
}

std::vector<TxIndexImpl::TxResult> TxIndexImpl::find_txs(
    const std::vector<uint256>& txids) const {
    std::vector<TxResult> results;
    results.reserve(txids.size());

    for (const auto& txid : txids) {
        results.push_back(find_tx(txid));
    }

    return results;
}

int TxIndexImpl::get_confirmations(const uint256& txid, uint64_t chain_height) const {
    TxResult result = find_tx(txid);
    if (!result.found) return -1;
    if (chain_height < result.block_height) return 0;
    return static_cast<int>(chain_height - result.block_height + 1);
}

bool TxIndexImpl::has_tx(const uint256& txid) const {
    if (!stmt_has_) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    sqlite3_reset(stmt_has_);
    sqlite3_bind_blob(stmt_has_, 1, txid.data(), static_cast<int>(txid.size()),
                      SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt_has_);
    return rc == SQLITE_ROW;
}

std::vector<uint256> TxIndexImpl::get_txids_at_height(uint64_t height) const {
    std::vector<uint256> result;
    if (!stmt_by_height_) return result;

    std::lock_guard<std::mutex> lock(mutex_);

    sqlite3_reset(stmt_by_height_);
    sqlite3_bind_int64(stmt_by_height_, 1, static_cast<int64_t>(height));

    while (sqlite3_step(stmt_by_height_) == SQLITE_ROW) {
        const void* data = sqlite3_column_blob(stmt_by_height_, 0);
        int len = sqlite3_column_bytes(stmt_by_height_, 0);
        if (data && len == 32) {
            uint256 txid;
            std::memcpy(txid.data(), data, 32);
            result.push_back(txid);
        }
    }

    return result;
}

uint64_t TxIndexImpl::count() const {
    if (!stmt_count_) return 0;

    std::lock_guard<std::mutex> lock(mutex_);

    sqlite3_reset(stmt_count_);
    int rc = sqlite3_step(stmt_count_);
    if (rc == SQLITE_ROW) {
        return static_cast<uint64_t>(sqlite3_column_int64(stmt_count_, 0));
    }
    return 0;
}

bool TxIndexImpl::get_block_hash(const uint256& txid, uint256& block_hash) const {
    if (!stmt_block_hash_) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    sqlite3_reset(stmt_block_hash_);
    sqlite3_bind_blob(stmt_block_hash_, 1, txid.data(),
                      static_cast<int>(txid.size()), SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt_block_hash_);
    if (rc != SQLITE_ROW) return false;

    const void* bh = sqlite3_column_blob(stmt_block_hash_, 0);
    int bh_len = sqlite3_column_bytes(stmt_block_hash_, 0);
    if (!bh || bh_len != 32) return false;

    std::memcpy(block_hash.data(), bh, 32);
    return true;
}

} // namespace flow

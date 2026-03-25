// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "chain/utxo.h"

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <sys/stat.h>

#include "sqlite3.h"
#include "logging.h"

namespace flow {

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

UTXOSet::UTXOSet(const std::string& db_path)
    : db_path_(db_path) {
    int rc = sqlite3_open(db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::string err = db_ ? sqlite3_errmsg(db_) : "unknown error";
        if (db_) sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("UTXOSet: failed to open database: " + err);
    }

    // Enable WAL mode for concurrent reads
    char* errmsg = nullptr;
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &errmsg);
    if (errmsg) sqlite3_free(errmsg);

    // Synchronous = NORMAL for performance (WAL provides crash safety)
    sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, &errmsg);
    if (errmsg) sqlite3_free(errmsg);

    // Page size for performance
    sqlite3_exec(db_, "PRAGMA page_size=4096;", nullptr, nullptr, &errmsg);
    if (errmsg) sqlite3_free(errmsg);

    init_tables();
    prepare_statements();
}

UTXOSet::~UTXOSet() {
    finalize_statements();
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// ---------------------------------------------------------------------------
// init_tables
// ---------------------------------------------------------------------------

void UTXOSet::init_tables() {
    const char* sql =
        "CREATE TABLE IF NOT EXISTS utxos ("
        "    txid BLOB NOT NULL,"
        "    vout INTEGER NOT NULL,"
        "    value INTEGER NOT NULL,"
        "    pubkey_hash BLOB NOT NULL,"
        "    height INTEGER NOT NULL,"
        "    is_coinbase INTEGER NOT NULL,"
        "    PRIMARY KEY (txid, vout)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_utxo_pubkey_hash ON utxos(pubkey_hash);";

    char* errmsg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        if (errmsg) sqlite3_free(errmsg);
        throw std::runtime_error("UTXOSet: failed to create tables: " + err);
    }
}

// ---------------------------------------------------------------------------
// prepare_statements
// ---------------------------------------------------------------------------

void UTXOSet::prepare_statements() {
    auto prepare = [this](const char* sql, sqlite3_stmt** stmt) {
        int rc = sqlite3_prepare_v2(db_, sql, -1, stmt, nullptr);
        if (rc != SQLITE_OK) {
            throw std::runtime_error(
                std::string("UTXOSet: failed to prepare statement: ")
                + sqlite3_errmsg(db_));
        }
    };

    prepare("INSERT OR REPLACE INTO utxos (txid, vout, value, pubkey_hash, height, is_coinbase) "
            "VALUES (?, ?, ?, ?, ?, ?);",
            &stmt_add_);

    prepare("DELETE FROM utxos WHERE txid = ? AND vout = ?;",
            &stmt_remove_);

    prepare("SELECT value, pubkey_hash, height, is_coinbase FROM utxos "
            "WHERE txid = ? AND vout = ?;",
            &stmt_get_);

    prepare("SELECT 1 FROM utxos WHERE txid = ? AND vout = ? LIMIT 1;",
            &stmt_exists_);

    prepare("SELECT COALESCE(SUM(value), 0) FROM utxos WHERE pubkey_hash = ?;",
            &stmt_balance_);

    prepare("SELECT txid, vout, value, height, is_coinbase FROM utxos "
            "WHERE pubkey_hash = ?;",
            &stmt_by_script_);

    prepare("SELECT COUNT(*) FROM utxos;",
            &stmt_count_);

    prepare("SELECT COALESCE(SUM(value), 0) FROM utxos;",
            &stmt_total_value_);

    prepare("SELECT COUNT(*) FROM utxos WHERE height = ?;",
            &stmt_count_height_);
}

// ---------------------------------------------------------------------------
// finalize_statements
// ---------------------------------------------------------------------------

void UTXOSet::finalize_statements() {
    auto finalize = [](sqlite3_stmt*& stmt) {
        if (stmt) {
            sqlite3_finalize(stmt);
            stmt = nullptr;
        }
    };

    finalize(stmt_add_);
    finalize(stmt_remove_);
    finalize(stmt_get_);
    finalize(stmt_exists_);
    finalize(stmt_balance_);
    finalize(stmt_by_script_);
    finalize(stmt_count_);
    finalize(stmt_total_value_);
    finalize(stmt_count_height_);
}

// ---------------------------------------------------------------------------
// add
// ---------------------------------------------------------------------------

bool UTXOSet::add(const uint256& txid, uint32_t vout, const UTXOEntry& entry) {
    sqlite3_reset(stmt_add_);

    sqlite3_bind_blob(stmt_add_, 1, txid.data(), 32, SQLITE_STATIC);
    sqlite3_bind_int(stmt_add_, 2, static_cast<int>(vout));
    sqlite3_bind_int64(stmt_add_, 3, entry.value);
    sqlite3_bind_blob(stmt_add_, 4, entry.pubkey_hash.data(), 32, SQLITE_STATIC);
    sqlite3_bind_int64(stmt_add_, 5, static_cast<int64_t>(entry.height));
    sqlite3_bind_int(stmt_add_, 6, entry.is_coinbase ? 1 : 0);

    int rc = sqlite3_step(stmt_add_);
    return rc == SQLITE_DONE;
}

// ---------------------------------------------------------------------------
// remove
// ---------------------------------------------------------------------------

bool UTXOSet::remove(const uint256& txid, uint32_t vout) {
    sqlite3_reset(stmt_remove_);

    sqlite3_bind_blob(stmt_remove_, 1, txid.data(), 32, SQLITE_STATIC);
    sqlite3_bind_int(stmt_remove_, 2, static_cast<int>(vout));

    int rc = sqlite3_step(stmt_remove_);
    if (rc != SQLITE_DONE) return false;

    // sqlite3_changes returns the number of rows deleted
    return sqlite3_changes(db_) > 0;
}

// ---------------------------------------------------------------------------
// get
// ---------------------------------------------------------------------------

bool UTXOSet::get(const uint256& txid, uint32_t vout, UTXOEntry& entry) const {
    sqlite3_reset(stmt_get_);

    sqlite3_bind_blob(stmt_get_, 1, txid.data(), 32, SQLITE_STATIC);
    sqlite3_bind_int(stmt_get_, 2, static_cast<int>(vout));

    int rc = sqlite3_step(stmt_get_);
    if (rc != SQLITE_ROW) return false;

    entry.value = sqlite3_column_int64(stmt_get_, 0);

    const void* pkh = sqlite3_column_blob(stmt_get_, 1);
    int pkh_len = sqlite3_column_bytes(stmt_get_, 1);
    if (pkh && pkh_len == 32) {
        std::memcpy(entry.pubkey_hash.data(), pkh, 32);
    } else {
        entry.pubkey_hash.fill(0);
    }

    entry.height = static_cast<uint64_t>(sqlite3_column_int64(stmt_get_, 2));
    entry.is_coinbase = sqlite3_column_int(stmt_get_, 3) != 0;

    return true;
}

// ---------------------------------------------------------------------------
// exists
// ---------------------------------------------------------------------------

bool UTXOSet::exists(const uint256& txid, uint32_t vout) const {
    sqlite3_reset(stmt_exists_);

    sqlite3_bind_blob(stmt_exists_, 1, txid.data(), 32, SQLITE_STATIC);
    sqlite3_bind_int(stmt_exists_, 2, static_cast<int>(vout));

    int rc = sqlite3_step(stmt_exists_);
    return rc == SQLITE_ROW;
}

// ---------------------------------------------------------------------------
// get_balance
// ---------------------------------------------------------------------------

Amount UTXOSet::get_balance(const std::array<uint8_t, 32>& pubkey_hash) const {
    sqlite3_reset(stmt_balance_);

    sqlite3_bind_blob(stmt_balance_, 1, pubkey_hash.data(), 32, SQLITE_STATIC);

    int rc = sqlite3_step(stmt_balance_);
    if (rc != SQLITE_ROW) return 0;

    return sqlite3_column_int64(stmt_balance_, 0);
}

// ---------------------------------------------------------------------------
// get_utxos_for_script
// ---------------------------------------------------------------------------

std::vector<std::pair<std::pair<uint256, uint32_t>, UTXOEntry>>
UTXOSet::get_utxos_for_script(const std::array<uint8_t, 32>& pubkey_hash) const {
    std::vector<std::pair<std::pair<uint256, uint32_t>, UTXOEntry>> results;

    sqlite3_reset(stmt_by_script_);
    sqlite3_bind_blob(stmt_by_script_, 1, pubkey_hash.data(), 32, SQLITE_STATIC);

    while (sqlite3_step(stmt_by_script_) == SQLITE_ROW) {
        uint256 txid;
        const void* txid_blob = sqlite3_column_blob(stmt_by_script_, 0);
        int txid_len = sqlite3_column_bytes(stmt_by_script_, 0);
        if (txid_blob && txid_len == 32) {
            std::memcpy(txid.data(), txid_blob, 32);
        }

        uint32_t vout = static_cast<uint32_t>(sqlite3_column_int(stmt_by_script_, 1));

        UTXOEntry entry;
        entry.pubkey_hash = pubkey_hash;
        entry.value = sqlite3_column_int64(stmt_by_script_, 2);
        entry.height = static_cast<uint64_t>(sqlite3_column_int64(stmt_by_script_, 3));
        entry.is_coinbase = sqlite3_column_int(stmt_by_script_, 4) != 0;

        results.push_back({{txid, vout}, entry});
    }

    return results;
}

// ---------------------------------------------------------------------------
// Transaction support
// ---------------------------------------------------------------------------

void UTXOSet::begin_transaction() {
    char* errmsg = nullptr;
    sqlite3_exec(db_, "BEGIN TRANSACTION;", nullptr, nullptr, &errmsg);
    if (errmsg) {
        LogError("db", "begin_transaction failed: %s", errmsg);
        sqlite3_free(errmsg);
    }
}

void UTXOSet::commit_transaction() {
    char* errmsg = nullptr;
    sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &errmsg);
    if (errmsg) {
        LogError("db", "commit_transaction failed: %s", errmsg);
        sqlite3_free(errmsg);
    }
}

void UTXOSet::rollback_transaction() {
    char* errmsg = nullptr;
    sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, &errmsg);
    if (errmsg) {
        LogError("db", "rollback_transaction failed: %s", errmsg);
        sqlite3_free(errmsg);
    }
}

// ---------------------------------------------------------------------------
// Cache operations
// ---------------------------------------------------------------------------

void UTXOSet::set_cache_enabled(bool enabled) {
    if (cache_enabled_ && !enabled) {
        // Flushing when disabling cache
        flush_cache();
    }
    cache_enabled_ = enabled;
}

size_t UTXOSet::cache_size() const {
    return cache_.size();
}

size_t UTXOSet::dirty_count() const {
    size_t count = 0;
    for (const auto& [key, entry] : cache_) {
        if (entry.dirty) count++;
    }
    return count;
}

void UTXOSet::clear_cache() {
    cache_.clear();
}

bool UTXOSet::flush_entry(const CacheKey& key, const CacheEntry& entry) {
    if (entry.removed) {
        sqlite3_reset(stmt_remove_);
        sqlite3_bind_blob(stmt_remove_, 1, key.txid.data(), 32, SQLITE_STATIC);
        sqlite3_bind_int(stmt_remove_, 2, static_cast<int>(key.vout));
        int rc = sqlite3_step(stmt_remove_);
        return rc == SQLITE_DONE;
    } else {
        sqlite3_reset(stmt_add_);
        sqlite3_bind_blob(stmt_add_, 1, key.txid.data(), 32, SQLITE_STATIC);
        sqlite3_bind_int(stmt_add_, 2, static_cast<int>(key.vout));
        sqlite3_bind_int64(stmt_add_, 3, entry.entry.value);
        sqlite3_bind_blob(stmt_add_, 4, entry.entry.pubkey_hash.data(), 32, SQLITE_STATIC);
        sqlite3_bind_int64(stmt_add_, 5, static_cast<int64_t>(entry.entry.height));
        sqlite3_bind_int(stmt_add_, 6, entry.entry.is_coinbase ? 1 : 0);
        int rc = sqlite3_step(stmt_add_);
        return rc == SQLITE_DONE;
    }
}

void UTXOSet::flush_cache() {
    if (cache_.empty()) return;

    begin_transaction();

    for (auto& [key, entry] : cache_) {
        if (entry.dirty) {
            flush_entry(key, entry);
            entry.dirty = false;
        }
    }

    commit_transaction();

    // Remove entries that were marked for deletion
    for (auto it = cache_.begin(); it != cache_.end(); ) {
        if (it->second.removed) {
            it = cache_.erase(it);
        } else {
            ++it;
        }
    }

    // Evict if cache exceeds max size
    while (cache_.size() > MAX_CACHE_SIZE) {
        // Simple eviction: remove first non-dirty entry
        bool evicted = false;
        for (auto it = cache_.begin(); it != cache_.end(); ++it) {
            if (!it->second.dirty) {
                cache_.erase(it);
                evicted = true;
                break;
            }
        }
        if (!evicted) break;  // All entries are dirty, can't evict
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

size_t UTXOSet::total_count() const {
    // Flush cache first for accurate count? No, we count DB + cache.
    sqlite3_reset(stmt_count_);
    int rc = sqlite3_step(stmt_count_);
    if (rc != SQLITE_ROW) return 0;
    size_t db_count = static_cast<size_t>(sqlite3_column_int64(stmt_count_, 0));

    // Adjust for cached but not-yet-flushed entries
    size_t cache_adds = 0;
    size_t cache_removes = 0;
    for (const auto& [key, entry] : cache_) {
        if (entry.dirty) {
            if (entry.removed) {
                cache_removes++;
            } else {
                cache_adds++;
            }
        }
    }

    return db_count + cache_adds - cache_removes;
}

Amount UTXOSet::total_value() const {
    sqlite3_reset(stmt_total_value_);
    int rc = sqlite3_step(stmt_total_value_);
    if (rc != SQLITE_ROW) return 0;
    return sqlite3_column_int64(stmt_total_value_, 0);
}

size_t UTXOSet::count_for_height(uint64_t height) const {
    sqlite3_reset(stmt_count_height_);
    sqlite3_bind_int64(stmt_count_height_, 1, static_cast<int64_t>(height));

    int rc = sqlite3_step(stmt_count_height_);
    if (rc != SQLITE_ROW) return 0;
    return static_cast<size_t>(sqlite3_column_int64(stmt_count_height_, 0));
}

size_t UTXOSet::disk_usage() const {
    struct stat st;
    if (::stat(db_path_.c_str(), &st) == 0) {
        return static_cast<size_t>(st.st_size);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// UTXOCursor
// ---------------------------------------------------------------------------

UTXOSet::UTXOCursor::UTXOCursor(const UTXOSet& owner)
    : owner_(owner)
{
    const char* sql =
        "SELECT txid, vout, value, pubkey_hash, height, is_coinbase "
        "FROM utxos ORDER BY txid, vout;";

    int rc = sqlite3_prepare_v2(owner_.db_, sql, -1, &stmt_, nullptr);
    if (rc != SQLITE_OK) {
        stmt_ = nullptr;
    }
}

UTXOSet::UTXOCursor::~UTXOCursor() {
    if (stmt_) {
        sqlite3_finalize(stmt_);
        stmt_ = nullptr;
    }
}

bool UTXOSet::UTXOCursor::next(uint256& txid, uint32_t& vout, UTXOEntry& entry) {
    if (!stmt_) return false;

    int rc = sqlite3_step(stmt_);
    if (rc != SQLITE_ROW) return false;

    // txid
    const void* txid_blob = sqlite3_column_blob(stmt_, 0);
    int txid_len = sqlite3_column_bytes(stmt_, 0);
    if (txid_blob && txid_len == 32) {
        std::memcpy(txid.data(), txid_blob, 32);
    } else {
        txid.set_null();
    }

    // vout
    vout = static_cast<uint32_t>(sqlite3_column_int(stmt_, 1));

    // value
    entry.value = sqlite3_column_int64(stmt_, 2);

    // pubkey_hash
    const void* pkh = sqlite3_column_blob(stmt_, 3);
    int pkh_len = sqlite3_column_bytes(stmt_, 3);
    if (pkh && pkh_len == 32) {
        std::memcpy(entry.pubkey_hash.data(), pkh, 32);
    } else {
        entry.pubkey_hash.fill(0);
    }

    // height
    entry.height = static_cast<uint64_t>(sqlite3_column_int64(stmt_, 4));

    // is_coinbase
    entry.is_coinbase = sqlite3_column_int(stmt_, 5) != 0;

    return true;
}

void UTXOSet::UTXOCursor::reset() {
    if (stmt_) {
        sqlite3_reset(stmt_);
    }
}

UTXOSet::UTXOCursor UTXOSet::get_cursor() const {
    return UTXOCursor(*this);
}

// ---------------------------------------------------------------------------
// compact — run SQLite VACUUM to reclaim space
// ---------------------------------------------------------------------------

void UTXOSet::compact() {
    if (!db_) return;
    char* errmsg = nullptr;
    sqlite3_exec(db_, "PRAGMA incremental_vacuum;", nullptr, nullptr, &errmsg);
    if (errmsg) sqlite3_free(errmsg);
}

// ---------------------------------------------------------------------------
// for_each — iterate all UTXOs via cursor
// ---------------------------------------------------------------------------

void UTXOSet::for_each(std::function<void(const uint256&, uint32_t, const UTXOEntry&)> fn) const {
    UTXOCursor cursor = get_cursor();
    uint256 txid;
    uint32_t vout;
    UTXOEntry entry;
    while (cursor.next(txid, vout, entry)) {
        fn(txid, vout, entry);
    }
}

std::vector<std::pair<std::pair<uint256, uint32_t>, UTXOEntry>> UTXOSet::get_all() const {
    std::vector<std::pair<std::pair<uint256, uint32_t>, UTXOEntry>> result;
    for_each([&](const uint256& txid, uint32_t vout, const UTXOEntry& entry) {
        result.push_back({{txid, vout}, entry});
    });
    return result;
}

} // namespace flow

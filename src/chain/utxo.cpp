// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "chain/utxo.h"

#include <cstdio>
#include <cstring>
#include <stdexcept>

#include "sqlite3.h"

namespace flow {

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

UTXOSet::UTXOSet(const std::string& db_path) {
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
        fprintf(stderr, "UTXOSet: begin_transaction failed: %s\n", errmsg);
        sqlite3_free(errmsg);
    }
}

void UTXOSet::commit_transaction() {
    char* errmsg = nullptr;
    sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &errmsg);
    if (errmsg) {
        fprintf(stderr, "UTXOSet: commit_transaction failed: %s\n", errmsg);
        sqlite3_free(errmsg);
    }
}

void UTXOSet::rollback_transaction() {
    char* errmsg = nullptr;
    sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, &errmsg);
    if (errmsg) {
        fprintf(stderr, "UTXOSet: rollback_transaction failed: %s\n", errmsg);
        sqlite3_free(errmsg);
    }
}

} // namespace flow

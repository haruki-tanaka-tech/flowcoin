// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "wallet/walletdb.h"

#include <cstdio>
#include <cstring>
#include <stdexcept>

#include "sqlite3.h"

namespace flow {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

/// Execute a simple SQL statement; throw on failure.
void exec_sql(sqlite3* db, const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string msg = err ? err : "unknown SQLite error";
        sqlite3_free(err);
        throw std::runtime_error("WalletDB SQL error: " + msg);
    }
}

/// Bind a blob to a prepared statement parameter (1-indexed).
void bind_blob(sqlite3_stmt* stmt, int idx, const void* data, int len) {
    sqlite3_bind_blob(stmt, idx, data, len, SQLITE_TRANSIENT);
}

/// Bind a text string to a prepared statement parameter.
void bind_text(sqlite3_stmt* stmt, int idx, const std::string& s) {
    sqlite3_bind_text(stmt, idx, s.c_str(), static_cast<int>(s.size()),
                      SQLITE_TRANSIENT);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

WalletDB::WalletDB(const std::string& path) {
    int rc = sqlite3_open(path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::string msg = db_ ? sqlite3_errmsg(db_) : "out of memory";
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("WalletDB: cannot open " + path + ": " + msg);
    }

    // Enable WAL mode for better concurrency
    exec_sql(db_, "PRAGMA journal_mode=WAL;");
    exec_sql(db_, "PRAGMA synchronous=NORMAL;");
    exec_sql(db_, "PRAGMA foreign_keys=ON;");

    init_tables();
}

WalletDB::~WalletDB() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Table initialization
// ---------------------------------------------------------------------------

void WalletDB::init_tables() {
    exec_sql(db_,
        "CREATE TABLE IF NOT EXISTS meta ("
        "  key TEXT PRIMARY KEY,"
        "  value BLOB"
        ");");

    exec_sql(db_,
        "CREATE TABLE IF NOT EXISTS keys ("
        "  pubkey BLOB PRIMARY KEY,"
        "  path TEXT,"
        "  encrypted_privkey BLOB"
        ");");

    exec_sql(db_,
        "CREATE TABLE IF NOT EXISTS addresses ("
        "  address TEXT PRIMARY KEY,"
        "  pubkey BLOB,"
        "  hd_index INTEGER,"
        "  created_at INTEGER"
        ");");

    exec_sql(db_,
        "CREATE TABLE IF NOT EXISTS wallet_txs ("
        "  txid BLOB PRIMARY KEY,"
        "  timestamp INTEGER,"
        "  amount INTEGER,"
        "  block_height INTEGER,"
        "  label TEXT"
        ");");
}

// ---------------------------------------------------------------------------
// Master seed management
// ---------------------------------------------------------------------------

bool WalletDB::store_master_seed(const std::vector<uint8_t>& encrypted_seed) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('master_seed', ?);",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_blob(stmt, 1, encrypted_seed.data(),
              static_cast<int>(encrypted_seed.size()));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool WalletDB::load_master_seed(std::vector<uint8_t>& encrypted_seed) const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT value FROM meta WHERE key = 'master_seed';",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return false;
    }

    const void* blob = sqlite3_column_blob(stmt, 0);
    int blob_len = sqlite3_column_bytes(stmt, 0);
    encrypted_seed.assign(static_cast<const uint8_t*>(blob),
                          static_cast<const uint8_t*>(blob) + blob_len);

    sqlite3_finalize(stmt);
    return true;
}

bool WalletDB::has_master_seed() const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM meta WHERE key = 'master_seed';",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    rc = sqlite3_step(stmt);
    bool exists = (rc == SQLITE_ROW && sqlite3_column_int(stmt, 0) > 0);
    sqlite3_finalize(stmt);
    return exists;
}

// ---------------------------------------------------------------------------
// HD chain state
// ---------------------------------------------------------------------------

bool WalletDB::store_hd_index(uint32_t next_index) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('hd_index', ?);",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    // Store as 4-byte big-endian blob
    uint8_t buf[4];
    buf[0] = static_cast<uint8_t>((next_index >> 24) & 0xFF);
    buf[1] = static_cast<uint8_t>((next_index >> 16) & 0xFF);
    buf[2] = static_cast<uint8_t>((next_index >> 8) & 0xFF);
    buf[3] = static_cast<uint8_t>(next_index & 0xFF);
    bind_blob(stmt, 1, buf, 4);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

uint32_t WalletDB::load_hd_index() const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT value FROM meta WHERE key = 'hd_index';",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return 0;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    const uint8_t* blob = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 0));
    int blob_len = sqlite3_column_bytes(stmt, 0);
    uint32_t result = 0;
    if (blob && blob_len >= 4) {
        result = (static_cast<uint32_t>(blob[0]) << 24) |
                 (static_cast<uint32_t>(blob[1]) << 16) |
                 (static_cast<uint32_t>(blob[2]) << 8) |
                 static_cast<uint32_t>(blob[3]);
    }

    sqlite3_finalize(stmt);
    return result;
}

// ---------------------------------------------------------------------------
// Key storage
// ---------------------------------------------------------------------------

bool WalletDB::store_key(const KeyRecord& key) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO keys (pubkey, path, encrypted_privkey) "
        "VALUES (?, ?, ?);",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_blob(stmt, 1, key.pubkey.data(), 32);
    bind_text(stmt, 2, key.derivation_path);
    bind_blob(stmt, 3, key.encrypted_privkey.data(),
              static_cast<int>(key.encrypted_privkey.size()));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool WalletDB::load_key(const std::array<uint8_t, 32>& pubkey,
                         KeyRecord& key) const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT path, encrypted_privkey FROM keys WHERE pubkey = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_blob(stmt, 1, pubkey.data(), 32);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return false;
    }

    key.pubkey = pubkey;
    const char* path_str = reinterpret_cast<const char*>(
        sqlite3_column_text(stmt, 0));
    key.derivation_path = path_str ? path_str : "";

    const void* blob = sqlite3_column_blob(stmt, 1);
    int blob_len = sqlite3_column_bytes(stmt, 1);
    key.encrypted_privkey.assign(
        static_cast<const uint8_t*>(blob),
        static_cast<const uint8_t*>(blob) + blob_len);

    sqlite3_finalize(stmt);
    return true;
}

std::vector<WalletDB::KeyRecord> WalletDB::load_all_keys() const {
    std::vector<KeyRecord> result;

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT pubkey, path, encrypted_privkey FROM keys;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return result;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        KeyRecord key;

        const uint8_t* pk = static_cast<const uint8_t*>(
            sqlite3_column_blob(stmt, 0));
        if (pk && sqlite3_column_bytes(stmt, 0) >= 32) {
            std::memcpy(key.pubkey.data(), pk, 32);
        }

        const char* path_str = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 1));
        key.derivation_path = path_str ? path_str : "";

        const void* blob = sqlite3_column_blob(stmt, 2);
        int blob_len = sqlite3_column_bytes(stmt, 2);
        if (blob && blob_len > 0) {
            key.encrypted_privkey.assign(
                static_cast<const uint8_t*>(blob),
                static_cast<const uint8_t*>(blob) + blob_len);
        }

        result.push_back(std::move(key));
    }

    sqlite3_finalize(stmt);
    return result;
}

// ---------------------------------------------------------------------------
// Address records
// ---------------------------------------------------------------------------

bool WalletDB::store_address(const AddressRecord& addr) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO addresses "
        "(address, pubkey, hd_index, created_at) VALUES (?, ?, ?, ?);",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_text(stmt, 1, addr.address);
    bind_blob(stmt, 2, addr.pubkey.data(), 32);
    sqlite3_bind_int(stmt, 3, static_cast<int>(addr.hd_index));
    sqlite3_bind_int64(stmt, 4, addr.created_at);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::vector<WalletDB::AddressRecord> WalletDB::load_all_addresses() const {
    std::vector<AddressRecord> result;

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT address, pubkey, hd_index, created_at FROM addresses "
        "ORDER BY hd_index ASC;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return result;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AddressRecord addr;

        const char* addr_str = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 0));
        addr.address = addr_str ? addr_str : "";

        const uint8_t* pk = static_cast<const uint8_t*>(
            sqlite3_column_blob(stmt, 1));
        if (pk && sqlite3_column_bytes(stmt, 1) >= 32) {
            std::memcpy(addr.pubkey.data(), pk, 32);
        }

        addr.hd_index = static_cast<uint32_t>(sqlite3_column_int(stmt, 2));
        addr.created_at = sqlite3_column_int64(stmt, 3);

        result.push_back(std::move(addr));
    }

    sqlite3_finalize(stmt);
    return result;
}

bool WalletDB::has_address(const std::string& address) const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM addresses WHERE address = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_text(stmt, 1, address);

    rc = sqlite3_step(stmt);
    bool exists = (rc == SQLITE_ROW && sqlite3_column_int(stmt, 0) > 0);
    sqlite3_finalize(stmt);
    return exists;
}

// ---------------------------------------------------------------------------
// Transaction history
// ---------------------------------------------------------------------------

bool WalletDB::store_tx(const WalletTx& tx) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO wallet_txs "
        "(txid, timestamp, amount, block_height, label) "
        "VALUES (?, ?, ?, ?, ?);",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_blob(stmt, 1, tx.txid.data(), 32);
    sqlite3_bind_int64(stmt, 2, tx.timestamp);
    sqlite3_bind_int64(stmt, 3, tx.amount);
    sqlite3_bind_int64(stmt, 4, static_cast<int64_t>(tx.block_height));
    bind_text(stmt, 5, tx.label);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::vector<WalletDB::WalletTx> WalletDB::load_transactions(
        int count, int skip) const {
    std::vector<WalletTx> result;

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT txid, timestamp, amount, block_height, label "
        "FROM wallet_txs ORDER BY timestamp DESC LIMIT ? OFFSET ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return result;

    sqlite3_bind_int(stmt, 1, count);
    sqlite3_bind_int(stmt, 2, skip);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        WalletTx tx;

        const uint8_t* txid_blob = static_cast<const uint8_t*>(
            sqlite3_column_blob(stmt, 0));
        if (txid_blob && sqlite3_column_bytes(stmt, 0) >= 32) {
            std::memcpy(tx.txid.data(), txid_blob, 32);
        }

        tx.timestamp = sqlite3_column_int64(stmt, 1);
        tx.amount = sqlite3_column_int64(stmt, 2);
        tx.block_height = static_cast<uint64_t>(sqlite3_column_int64(stmt, 3));

        const char* label_str = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 4));
        tx.label = label_str ? label_str : "";

        result.push_back(std::move(tx));
    }

    sqlite3_finalize(stmt);
    return result;
}

} // namespace flow

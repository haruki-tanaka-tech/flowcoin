// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "wallet/walletdb.h"
#include "util/random.h"
#include "util/time.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <sys/stat.h>

#include "sqlite3.h"

namespace flow {

static constexpr int CURRENT_SCHEMA_VERSION = 2;

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

WalletDB::WalletDB(const std::string& path) : db_path_(path) {
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
    migrate_tables();
    prepare_statements();
}

WalletDB::~WalletDB() {
    finalize_statements();
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
        "  encrypted_privkey BLOB,"
        "  hd_index INTEGER DEFAULT 0,"
        "  created_at INTEGER DEFAULT 0"
        ");");

    exec_sql(db_,
        "CREATE TABLE IF NOT EXISTS addresses ("
        "  address TEXT PRIMARY KEY,"
        "  pubkey BLOB,"
        "  hd_index INTEGER,"
        "  created_at INTEGER,"
        "  is_change INTEGER DEFAULT 0"
        ");");

    exec_sql(db_,
        "CREATE TABLE IF NOT EXISTS wallet_txs ("
        "  txid BLOB PRIMARY KEY,"
        "  timestamp INTEGER,"
        "  amount INTEGER,"
        "  block_height INTEGER,"
        "  block_hash BLOB,"
        "  from_address TEXT DEFAULT '',"
        "  to_address TEXT DEFAULT '',"
        "  label TEXT"
        ");");

    exec_sql(db_,
        "CREATE TABLE IF NOT EXISTS labels ("
        "  address TEXT PRIMARY KEY,"
        "  label TEXT"
        ");");

    // Create index for faster transaction queries
    exec_sql(db_,
        "CREATE INDEX IF NOT EXISTS idx_wallet_txs_height "
        "ON wallet_txs(block_height);");

    exec_sql(db_,
        "CREATE INDEX IF NOT EXISTS idx_wallet_txs_timestamp "
        "ON wallet_txs(timestamp);");

    exec_sql(db_,
        "CREATE INDEX IF NOT EXISTS idx_addresses_pubkey "
        "ON addresses(pubkey);");
}

void WalletDB::migrate_tables() {
    // Check if columns exist and add them if missing.
    // This handles upgrades from older wallet versions.

    // Check for block_hash column in wallet_txs
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT block_hash FROM wallet_txs LIMIT 0;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        // Column doesn't exist, add it
        exec_sql(db_, "ALTER TABLE wallet_txs ADD COLUMN block_hash BLOB DEFAULT x'';");
    }
    sqlite3_finalize(stmt);

    // Check for from_address column
    stmt = nullptr;
    rc = sqlite3_prepare_v2(db_,
        "SELECT from_address FROM wallet_txs LIMIT 0;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        exec_sql(db_, "ALTER TABLE wallet_txs ADD COLUMN from_address TEXT DEFAULT '';");
    }
    sqlite3_finalize(stmt);

    // Check for to_address column
    stmt = nullptr;
    rc = sqlite3_prepare_v2(db_,
        "SELECT to_address FROM wallet_txs LIMIT 0;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        exec_sql(db_, "ALTER TABLE wallet_txs ADD COLUMN to_address TEXT DEFAULT '';");
    }
    sqlite3_finalize(stmt);

    // Check for is_change column in addresses
    stmt = nullptr;
    rc = sqlite3_prepare_v2(db_,
        "SELECT is_change FROM addresses LIMIT 0;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        exec_sql(db_, "ALTER TABLE addresses ADD COLUMN is_change INTEGER DEFAULT 0;");
    }
    sqlite3_finalize(stmt);

    // Check for hd_index and created_at columns in keys
    stmt = nullptr;
    rc = sqlite3_prepare_v2(db_,
        "SELECT hd_index FROM keys LIMIT 0;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        exec_sql(db_, "ALTER TABLE keys ADD COLUMN hd_index INTEGER DEFAULT 0;");
    }
    sqlite3_finalize(stmt);

    stmt = nullptr;
    rc = sqlite3_prepare_v2(db_,
        "SELECT created_at FROM keys LIMIT 0;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        exec_sql(db_, "ALTER TABLE keys ADD COLUMN created_at INTEGER DEFAULT 0;");
    }
    sqlite3_finalize(stmt);
}

// ---------------------------------------------------------------------------
// Prepared statements
// ---------------------------------------------------------------------------

void WalletDB::prepare_statements() {
    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO keys (pubkey, path, encrypted_privkey, hd_index, created_at) "
        "VALUES (?, ?, ?, ?, ?);",
        -1, &stmts_.store_key, nullptr);

    sqlite3_prepare_v2(db_,
        "SELECT path, encrypted_privkey, hd_index, created_at FROM keys WHERE pubkey = ?;",
        -1, &stmts_.load_key, nullptr);

    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO addresses "
        "(address, pubkey, hd_index, created_at, is_change) VALUES (?, ?, ?, ?, ?);",
        -1, &stmts_.store_addr, nullptr);

    sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM addresses WHERE address = ?;",
        -1, &stmts_.has_addr, nullptr);

    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO wallet_txs "
        "(txid, timestamp, amount, block_height, block_hash, from_address, to_address, label) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
        -1, &stmts_.store_tx, nullptr);

    sqlite3_prepare_v2(db_,
        "SELECT txid, timestamp, amount, block_height, block_hash, "
        "from_address, to_address, label "
        "FROM wallet_txs ORDER BY timestamp DESC LIMIT ? OFFSET ?;",
        -1, &stmts_.load_txs, nullptr);

    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO labels (address, label) VALUES (?, ?);",
        -1, &stmts_.store_label, nullptr);

    sqlite3_prepare_v2(db_,
        "SELECT label FROM labels WHERE address = ?;",
        -1, &stmts_.load_label, nullptr);

    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?);",
        -1, &stmts_.store_meta, nullptr);

    sqlite3_prepare_v2(db_,
        "SELECT value FROM meta WHERE key = ?;",
        -1, &stmts_.load_meta, nullptr);
}

void WalletDB::finalize_statements() {
    auto fin = [](sqlite3_stmt*& s) {
        if (s) { sqlite3_finalize(s); s = nullptr; }
    };
    fin(stmts_.store_key);
    fin(stmts_.load_key);
    fin(stmts_.store_addr);
    fin(stmts_.has_addr);
    fin(stmts_.store_tx);
    fin(stmts_.load_txs);
    fin(stmts_.store_label);
    fin(stmts_.load_label);
    fin(stmts_.store_meta);
    fin(stmts_.load_meta);
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

bool WalletDB::store_encrypted_seed(const std::vector<uint8_t>& encrypted,
                                     const std::array<uint8_t, 16>& salt) {
    // Store encrypted seed
    if (!store_master_seed(encrypted)) return false;

    // Store salt separately
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('seed_salt', ?);",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_blob(stmt, 1, salt.data(), 16);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool WalletDB::load_encrypted_seed(std::vector<uint8_t>& encrypted,
                                    std::array<uint8_t, 16>& salt) const {
    if (!load_master_seed(encrypted)) return false;

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT value FROM meta WHERE key = 'seed_salt';",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return false;
    }

    const void* blob = sqlite3_column_blob(stmt, 0);
    int blob_len = sqlite3_column_bytes(stmt, 0);
    if (blob && blob_len >= 16) {
        std::memcpy(salt.data(), blob, 16);
    }

    sqlite3_finalize(stmt);
    return true;
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

bool WalletDB::store_hd_change_index(uint32_t next_change_index) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('hd_change_index', ?);",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    uint8_t buf[4];
    buf[0] = static_cast<uint8_t>((next_change_index >> 24) & 0xFF);
    buf[1] = static_cast<uint8_t>((next_change_index >> 16) & 0xFF);
    buf[2] = static_cast<uint8_t>((next_change_index >> 8) & 0xFF);
    buf[3] = static_cast<uint8_t>(next_change_index & 0xFF);
    bind_blob(stmt, 1, buf, 4);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

uint32_t WalletDB::load_hd_change_index() const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT value FROM meta WHERE key = 'hd_change_index';",
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

bool WalletDB::store_hd_chain(const HDChain& chain) {
    auto serialized = chain.serialize();
    return store_meta_blob("hd_chain", serialized);
}

bool WalletDB::load_hd_chain(HDChain& chain) const {
    std::vector<uint8_t> data;
    if (!load_meta_blob("hd_chain", data)) return false;
    if (data.empty()) return false;

    try {
        chain = HDChain::deserialize(data);
        return true;
    } catch (...) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// Key storage
// ---------------------------------------------------------------------------

bool WalletDB::store_key(const KeyRecord& key) {
    if (!stmts_.store_key) return false;

    sqlite3_reset(stmts_.store_key);
    bind_blob(stmts_.store_key, 1, key.pubkey.data(), 32);
    bind_text(stmts_.store_key, 2, key.derivation_path);
    bind_blob(stmts_.store_key, 3, key.encrypted_privkey.data(),
              static_cast<int>(key.encrypted_privkey.size()));
    sqlite3_bind_int(stmts_.store_key, 4, static_cast<int>(key.hd_index));
    sqlite3_bind_int64(stmts_.store_key, 5, key.created_at);

    int rc = sqlite3_step(stmts_.store_key);
    return rc == SQLITE_DONE;
}

bool WalletDB::load_key(const std::array<uint8_t, 32>& pubkey,
                         KeyRecord& key) const {
    if (!stmts_.load_key) return false;

    sqlite3_reset(stmts_.load_key);
    bind_blob(stmts_.load_key, 1, pubkey.data(), 32);

    int rc = sqlite3_step(stmts_.load_key);
    if (rc != SQLITE_ROW) return false;

    key.pubkey = pubkey;
    const char* path_str = reinterpret_cast<const char*>(
        sqlite3_column_text(stmts_.load_key, 0));
    key.derivation_path = path_str ? path_str : "";

    const void* blob = sqlite3_column_blob(stmts_.load_key, 1);
    int blob_len = sqlite3_column_bytes(stmts_.load_key, 1);
    key.encrypted_privkey.assign(
        static_cast<const uint8_t*>(blob),
        static_cast<const uint8_t*>(blob) + blob_len);

    key.hd_index = static_cast<uint32_t>(sqlite3_column_int(stmts_.load_key, 2));
    key.created_at = sqlite3_column_int64(stmts_.load_key, 3);

    return true;
}

std::vector<WalletDB::KeyRecord> WalletDB::load_all_keys() const {
    std::vector<KeyRecord> result;

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT pubkey, path, encrypted_privkey, hd_index, created_at FROM keys;",
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

        key.hd_index = static_cast<uint32_t>(sqlite3_column_int(stmt, 3));
        key.created_at = sqlite3_column_int64(stmt, 4);

        result.push_back(std::move(key));
    }

    sqlite3_finalize(stmt);
    return result;
}

bool WalletDB::has_key(const std::array<uint8_t, 32>& pubkey) const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM keys WHERE pubkey = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_blob(stmt, 1, pubkey.data(), 32);
    rc = sqlite3_step(stmt);
    bool exists = (rc == SQLITE_ROW && sqlite3_column_int(stmt, 0) > 0);
    sqlite3_finalize(stmt);
    return exists;
}

bool WalletDB::delete_key(const std::array<uint8_t, 32>& pubkey) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "DELETE FROM keys WHERE pubkey = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_blob(stmt, 1, pubkey.data(), 32);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

size_t WalletDB::key_count() const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM keys;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return 0;

    rc = sqlite3_step(stmt);
    size_t count = (rc == SQLITE_ROW) ? static_cast<size_t>(sqlite3_column_int64(stmt, 0)) : 0;
    sqlite3_finalize(stmt);
    return count;
}

// ---------------------------------------------------------------------------
// Address records
// ---------------------------------------------------------------------------

bool WalletDB::store_address(const AddressRecord& addr) {
    if (!stmts_.store_addr) return false;

    sqlite3_reset(stmts_.store_addr);
    bind_text(stmts_.store_addr, 1, addr.address);
    bind_blob(stmts_.store_addr, 2, addr.pubkey.data(), 32);
    sqlite3_bind_int(stmts_.store_addr, 3, static_cast<int>(addr.hd_index));
    sqlite3_bind_int64(stmts_.store_addr, 4, addr.created_at);
    sqlite3_bind_int(stmts_.store_addr, 5, addr.is_change ? 1 : 0);

    int rc = sqlite3_step(stmts_.store_addr);
    return rc == SQLITE_DONE;
}

std::vector<WalletDB::AddressRecord> WalletDB::load_all_addresses() const {
    std::vector<AddressRecord> result;

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT address, pubkey, hd_index, created_at, is_change FROM addresses "
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
        addr.is_change = (sqlite3_column_int(stmt, 4) != 0);

        result.push_back(std::move(addr));
    }

    sqlite3_finalize(stmt);
    return result;
}

bool WalletDB::has_address(const std::string& address) const {
    if (!stmts_.has_addr) return false;

    sqlite3_reset(stmts_.has_addr);
    bind_text(stmts_.has_addr, 1, address);

    int rc = sqlite3_step(stmts_.has_addr);
    return (rc == SQLITE_ROW && sqlite3_column_int(stmts_.has_addr, 0) > 0);
}

bool WalletDB::get_pubkey_for_address(const std::string& address,
                                       std::array<uint8_t, 32>& pubkey) const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT pubkey FROM addresses WHERE address = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_text(stmt, 1, address);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return false;
    }

    const uint8_t* pk = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 0));
    if (pk && sqlite3_column_bytes(stmt, 0) >= 32) {
        std::memcpy(pubkey.data(), pk, 32);
    }

    sqlite3_finalize(stmt);
    return true;
}

bool WalletDB::delete_address(const std::string& address) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "DELETE FROM addresses WHERE address = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_text(stmt, 1, address);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

size_t WalletDB::address_count() const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM addresses;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return 0;

    rc = sqlite3_step(stmt);
    size_t count = (rc == SQLITE_ROW) ? static_cast<size_t>(sqlite3_column_int64(stmt, 0)) : 0;
    sqlite3_finalize(stmt);
    return count;
}

// ---------------------------------------------------------------------------
// Transaction history
// ---------------------------------------------------------------------------

bool WalletDB::store_tx(const WalletTx& tx) {
    if (!stmts_.store_tx) return false;

    sqlite3_reset(stmts_.store_tx);
    bind_blob(stmts_.store_tx, 1, tx.txid.data(), 32);
    sqlite3_bind_int64(stmts_.store_tx, 2, tx.timestamp);
    sqlite3_bind_int64(stmts_.store_tx, 3, tx.amount);
    sqlite3_bind_int64(stmts_.store_tx, 4, static_cast<int64_t>(tx.block_height));
    bind_blob(stmts_.store_tx, 5, tx.block_hash.data(), 32);
    bind_text(stmts_.store_tx, 6, tx.from_address);
    bind_text(stmts_.store_tx, 7, tx.to_address);
    bind_text(stmts_.store_tx, 8, tx.label);

    int rc = sqlite3_step(stmts_.store_tx);
    return rc == SQLITE_DONE;
}

bool WalletDB::update_tx_height(const uint256& txid, uint64_t block_height,
                                 const uint256& block_hash) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "UPDATE wallet_txs SET block_height = ?, block_hash = ? WHERE txid = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_int64(stmt, 1, static_cast<int64_t>(block_height));
    bind_blob(stmt, 2, block_hash.data(), 32);
    bind_blob(stmt, 3, txid.data(), 32);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::vector<WalletDB::WalletTx> WalletDB::load_transactions(
        int count, int skip) const {
    std::vector<WalletTx> result;

    if (!stmts_.load_txs) return result;

    sqlite3_reset(stmts_.load_txs);
    sqlite3_bind_int(stmts_.load_txs, 1, count);
    sqlite3_bind_int(stmts_.load_txs, 2, skip);

    while (sqlite3_step(stmts_.load_txs) == SQLITE_ROW) {
        WalletTx tx;

        const uint8_t* txid_blob = static_cast<const uint8_t*>(
            sqlite3_column_blob(stmts_.load_txs, 0));
        if (txid_blob && sqlite3_column_bytes(stmts_.load_txs, 0) >= 32) {
            std::memcpy(tx.txid.data(), txid_blob, 32);
        }

        tx.timestamp = sqlite3_column_int64(stmts_.load_txs, 1);
        tx.amount = sqlite3_column_int64(stmts_.load_txs, 2);
        tx.block_height = static_cast<uint64_t>(sqlite3_column_int64(stmts_.load_txs, 3));

        const uint8_t* bh_blob = static_cast<const uint8_t*>(
            sqlite3_column_blob(stmts_.load_txs, 4));
        if (bh_blob && sqlite3_column_bytes(stmts_.load_txs, 4) >= 32) {
            std::memcpy(tx.block_hash.data(), bh_blob, 32);
        }

        const char* from_str = reinterpret_cast<const char*>(
            sqlite3_column_text(stmts_.load_txs, 5));
        tx.from_address = from_str ? from_str : "";

        const char* to_str = reinterpret_cast<const char*>(
            sqlite3_column_text(stmts_.load_txs, 6));
        tx.to_address = to_str ? to_str : "";

        const char* label_str = reinterpret_cast<const char*>(
            sqlite3_column_text(stmts_.load_txs, 7));
        tx.label = label_str ? label_str : "";

        result.push_back(std::move(tx));
    }

    return result;
}

bool WalletDB::get_transaction(const uint256& txid, WalletTx& tx) const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT txid, timestamp, amount, block_height, block_hash, "
        "from_address, to_address, label "
        "FROM wallet_txs WHERE txid = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_blob(stmt, 1, txid.data(), 32);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return false;
    }

    const uint8_t* txid_blob = static_cast<const uint8_t*>(
        sqlite3_column_blob(stmt, 0));
    if (txid_blob && sqlite3_column_bytes(stmt, 0) >= 32) {
        std::memcpy(tx.txid.data(), txid_blob, 32);
    }

    tx.timestamp = sqlite3_column_int64(stmt, 1);
    tx.amount = sqlite3_column_int64(stmt, 2);
    tx.block_height = static_cast<uint64_t>(sqlite3_column_int64(stmt, 3));

    const uint8_t* bh_blob = static_cast<const uint8_t*>(
        sqlite3_column_blob(stmt, 4));
    if (bh_blob && sqlite3_column_bytes(stmt, 4) >= 32) {
        std::memcpy(tx.block_hash.data(), bh_blob, 32);
    }

    const char* from_str = reinterpret_cast<const char*>(
        sqlite3_column_text(stmt, 5));
    tx.from_address = from_str ? from_str : "";

    const char* to_str = reinterpret_cast<const char*>(
        sqlite3_column_text(stmt, 6));
    tx.to_address = to_str ? to_str : "";

    const char* label_str = reinterpret_cast<const char*>(
        sqlite3_column_text(stmt, 7));
    tx.label = label_str ? label_str : "";

    sqlite3_finalize(stmt);
    return true;
}

bool WalletDB::has_transaction(const uint256& txid) const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM wallet_txs WHERE txid = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_blob(stmt, 1, txid.data(), 32);
    rc = sqlite3_step(stmt);
    bool exists = (rc == SQLITE_ROW && sqlite3_column_int(stmt, 0) > 0);
    sqlite3_finalize(stmt);
    return exists;
}

size_t WalletDB::transaction_count() const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM wallet_txs;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return 0;

    rc = sqlite3_step(stmt);
    size_t count = (rc == SQLITE_ROW) ? static_cast<size_t>(sqlite3_column_int64(stmt, 0)) : 0;
    sqlite3_finalize(stmt);
    return count;
}

std::vector<WalletDB::WalletTx> WalletDB::load_unconfirmed() const {
    std::vector<WalletTx> result;

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT txid, timestamp, amount, block_height, block_hash, "
        "from_address, to_address, label "
        "FROM wallet_txs WHERE block_height = 0 ORDER BY timestamp DESC;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return result;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        WalletTx tx;

        const uint8_t* txid_blob = static_cast<const uint8_t*>(
            sqlite3_column_blob(stmt, 0));
        if (txid_blob && sqlite3_column_bytes(stmt, 0) >= 32) {
            std::memcpy(tx.txid.data(), txid_blob, 32);
        }

        tx.timestamp = sqlite3_column_int64(stmt, 1);
        tx.amount = sqlite3_column_int64(stmt, 2);
        tx.block_height = 0;

        const uint8_t* bh_blob = static_cast<const uint8_t*>(
            sqlite3_column_blob(stmt, 4));
        if (bh_blob && sqlite3_column_bytes(stmt, 4) >= 32) {
            std::memcpy(tx.block_hash.data(), bh_blob, 32);
        }

        const char* from_str = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 5));
        tx.from_address = from_str ? from_str : "";

        const char* to_str = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 6));
        tx.to_address = to_str ? to_str : "";

        const char* label_str = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 7));
        tx.label = label_str ? label_str : "";

        result.push_back(std::move(tx));
    }

    sqlite3_finalize(stmt);
    return result;
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

bool WalletDB::store_label(const std::string& address, const std::string& label) {
    if (!stmts_.store_label) return false;

    sqlite3_reset(stmts_.store_label);
    bind_text(stmts_.store_label, 1, address);
    bind_text(stmts_.store_label, 2, label);

    int rc = sqlite3_step(stmts_.store_label);
    return rc == SQLITE_DONE;
}

std::string WalletDB::load_label(const std::string& address) const {
    if (!stmts_.load_label) return "";

    sqlite3_reset(stmts_.load_label);
    bind_text(stmts_.load_label, 1, address);

    int rc = sqlite3_step(stmts_.load_label);
    std::string label;
    if (rc == SQLITE_ROW) {
        const char* label_str = reinterpret_cast<const char*>(
            sqlite3_column_text(stmts_.load_label, 0));
        label = label_str ? label_str : "";
    }

    return label;
}

std::vector<std::pair<std::string, std::string>> WalletDB::load_all_labels() const {
    std::vector<std::pair<std::string, std::string>> result;

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT address, label FROM labels;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return result;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* addr_str = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 0));
        const char* label_str = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 1));

        std::string addr = addr_str ? addr_str : "";
        std::string label = label_str ? label_str : "";
        result.emplace_back(addr, label);
    }

    sqlite3_finalize(stmt);
    return result;
}

bool WalletDB::delete_label(const std::string& address) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "DELETE FROM labels WHERE address = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_text(stmt, 1, address);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

// ---------------------------------------------------------------------------
// Metadata key-value store
// ---------------------------------------------------------------------------

bool WalletDB::store_meta(const std::string& key, const std::string& value) {
    if (!stmts_.store_meta) return false;

    sqlite3_reset(stmts_.store_meta);
    bind_text(stmts_.store_meta, 1, key);
    bind_blob(stmts_.store_meta, 2, value.data(), static_cast<int>(value.size()));

    int rc = sqlite3_step(stmts_.store_meta);
    return rc == SQLITE_DONE;
}

bool WalletDB::load_meta(const std::string& key, std::string& value) const {
    if (!stmts_.load_meta) return false;

    sqlite3_reset(stmts_.load_meta);
    bind_text(stmts_.load_meta, 1, key);

    int rc = sqlite3_step(stmts_.load_meta);
    if (rc != SQLITE_ROW) return false;

    const void* blob = sqlite3_column_blob(stmts_.load_meta, 0);
    int blob_len = sqlite3_column_bytes(stmts_.load_meta, 0);
    if (blob && blob_len > 0) {
        value.assign(static_cast<const char*>(blob), static_cast<size_t>(blob_len));
    } else {
        value.clear();
    }

    return true;
}

bool WalletDB::store_meta_blob(const std::string& key,
                                const std::vector<uint8_t>& value) {
    if (!stmts_.store_meta) return false;

    sqlite3_reset(stmts_.store_meta);
    bind_text(stmts_.store_meta, 1, key);
    bind_blob(stmts_.store_meta, 2, value.data(), static_cast<int>(value.size()));

    int rc = sqlite3_step(stmts_.store_meta);
    return rc == SQLITE_DONE;
}

bool WalletDB::load_meta_blob(const std::string& key,
                               std::vector<uint8_t>& value) const {
    if (!stmts_.load_meta) return false;

    sqlite3_reset(stmts_.load_meta);
    bind_text(stmts_.load_meta, 1, key);

    int rc = sqlite3_step(stmts_.load_meta);
    if (rc != SQLITE_ROW) return false;

    const void* blob = sqlite3_column_blob(stmts_.load_meta, 0);
    int blob_len = sqlite3_column_bytes(stmts_.load_meta, 0);
    if (blob && blob_len > 0) {
        value.assign(static_cast<const uint8_t*>(blob),
                     static_cast<const uint8_t*>(blob) + blob_len);
    } else {
        value.clear();
    }

    return true;
}

bool WalletDB::has_meta(const std::string& key) const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM meta WHERE key = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_text(stmt, 1, key);
    rc = sqlite3_step(stmt);
    bool exists = (rc == SQLITE_ROW && sqlite3_column_int(stmt, 0) > 0);
    sqlite3_finalize(stmt);
    return exists;
}

bool WalletDB::delete_meta(const std::string& key) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "DELETE FROM meta WHERE key = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_text(stmt, 1, key);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

// ---------------------------------------------------------------------------
// Batch operations
// ---------------------------------------------------------------------------

void WalletDB::begin_batch() {
    if (!in_batch_) {
        exec_sql(db_, "BEGIN TRANSACTION;");
        in_batch_ = true;
    }
}

void WalletDB::commit_batch() {
    if (in_batch_) {
        exec_sql(db_, "COMMIT;");
        in_batch_ = false;
    }
}

void WalletDB::rollback_batch() {
    if (in_batch_) {
        exec_sql(db_, "ROLLBACK;");
        in_batch_ = false;
    }
}

// ---------------------------------------------------------------------------
// Backup
// ---------------------------------------------------------------------------

bool WalletDB::backup(const std::string& dest_path) {
    // Use SQLite's backup API for a consistent copy
    sqlite3* dest_db = nullptr;
    int rc = sqlite3_open(dest_path.c_str(), &dest_db);
    if (rc != SQLITE_OK) {
        if (dest_db) sqlite3_close(dest_db);
        return false;
    }

    sqlite3_backup* backup_handle = sqlite3_backup_init(dest_db, "main", db_, "main");
    if (!backup_handle) {
        sqlite3_close(dest_db);
        return false;
    }

    // Copy all pages in one step
    rc = sqlite3_backup_step(backup_handle, -1);
    sqlite3_backup_finish(backup_handle);
    sqlite3_close(dest_db);

    return (rc == SQLITE_DONE);
}

// ---------------------------------------------------------------------------
// Database info
// ---------------------------------------------------------------------------

int64_t WalletDB::db_size_bytes() const {
    struct stat st;
    if (stat(db_path_.c_str(), &st) == 0) {
        return static_cast<int64_t>(st.st_size);
    }
    return -1;
}

// ===========================================================================
// Database schema migration
// ===========================================================================

bool WalletDB::migrate_schema(int from_version, int to_version) {
    if (from_version >= to_version) {
        return true;  // nothing to do
    }

    // Begin a transaction for the entire migration
    begin_batch();

    bool success = true;

    // Version 0 -> 1: Add locked_coins table and address_book table
    if (from_version < 1 && to_version >= 1) {
        try {
            exec_sql(db_,
                "CREATE TABLE IF NOT EXISTS locked_coins ("
                "  txid BLOB NOT NULL,"
                "  vout INTEGER NOT NULL,"
                "  locked_at INTEGER DEFAULT 0,"
                "  reason TEXT DEFAULT '',"
                "  PRIMARY KEY (txid, vout)"
                ");");

            exec_sql(db_,
                "CREATE TABLE IF NOT EXISTS address_book ("
                "  address TEXT PRIMARY KEY,"
                "  label TEXT DEFAULT '',"
                "  purpose TEXT DEFAULT 'send',"
                "  created_at INTEGER DEFAULT 0"
                ");");

            exec_sql(db_,
                "CREATE INDEX IF NOT EXISTS idx_address_book_label "
                "ON address_book(label);");

            // Update schema version
            store_meta("schema_version", "1");
        } catch (const std::exception& e) {
            fprintf(stderr, "WalletDB: migration 0->1 failed: %s\n", e.what());
            success = false;
        }
    }

    // Version 1 -> 2: Add tx_details table for full transaction storage
    if (success && from_version < 2 && to_version >= 2) {
        try {
            exec_sql(db_,
                "CREATE TABLE IF NOT EXISTS tx_details ("
                "  txid BLOB PRIMARY KEY,"
                "  raw_tx BLOB,"
                "  fee INTEGER DEFAULT 0,"
                "  confirmations INTEGER DEFAULT 0,"
                "  abandoned INTEGER DEFAULT 0,"
                "  conflicted INTEGER DEFAULT 0,"
                "  first_seen INTEGER DEFAULT 0"
                ");");

            exec_sql(db_,
                "CREATE INDEX IF NOT EXISTS idx_tx_details_confirmations "
                "ON tx_details(confirmations);");

            exec_sql(db_,
                "CREATE INDEX IF NOT EXISTS idx_tx_details_first_seen "
                "ON tx_details(first_seen);");

            // Add coin_control table for persistent UTXO locking
            exec_sql(db_,
                "CREATE TABLE IF NOT EXISTS coin_control ("
                "  txid BLOB NOT NULL,"
                "  vout INTEGER NOT NULL,"
                "  frozen INTEGER DEFAULT 0,"
                "  label TEXT DEFAULT '',"
                "  PRIMARY KEY (txid, vout)"
                ");");

            // Add scan_progress table for tracking rescan state
            exec_sql(db_,
                "CREATE TABLE IF NOT EXISTS scan_progress ("
                "  id INTEGER PRIMARY KEY DEFAULT 1,"
                "  current_height INTEGER DEFAULT 0,"
                "  target_height INTEGER DEFAULT 0,"
                "  last_scan_time INTEGER DEFAULT 0,"
                "  found_txs INTEGER DEFAULT 0"
                ");");
            exec_sql(db_,
                "INSERT OR IGNORE INTO scan_progress (id) VALUES (1);");

            store_meta("schema_version", "2");
        } catch (const std::exception& e) {
            fprintf(stderr, "WalletDB: migration 1->2 failed: %s\n", e.what());
            success = false;
        }
    }

    if (success) {
        commit_batch();
    } else {
        rollback_batch();
    }

    return success;
}

bool WalletDB::check_and_migrate() {
    // Read current schema version from meta table
    std::string version_str;
    int current_version = 0;

    if (load_meta("schema_version", version_str) && !version_str.empty()) {
        try {
            current_version = std::stoi(version_str);
        } catch (...) {
            current_version = 0;
        }
    }

    if (current_version >= CURRENT_SCHEMA_VERSION) {
        return true;  // already at current version
    }

    fprintf(stderr, "WalletDB: migrating schema from v%d to v%d\n",
            current_version, CURRENT_SCHEMA_VERSION);

    return migrate_schema(current_version, CURRENT_SCHEMA_VERSION);
}

// ===========================================================================
// Database integrity verification
// ===========================================================================

WalletDB::IntegrityResult WalletDB::verify_integrity() const {
    IntegrityResult result;
    result.passed = true;
    result.orphan_keys = 0;
    result.orphan_addrs = 0;
    result.missing_txids = 0;
    result.duplicate_entries = 0;

    // 1. Run SQLite integrity check
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "PRAGMA integrity_check;", -1, &stmt, nullptr);
    if (rc == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* check_result = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 0));
            if (check_result) {
                std::string msg(check_result);
                if (msg != "ok") {
                    result.passed = false;
                    result.errors.push_back("integrity_check: " + msg);
                }
            }
        }
    }
    sqlite3_finalize(stmt);

    // 2. Check for keys without corresponding addresses
    stmt = nullptr;
    rc = sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM keys k "
        "LEFT JOIN addresses a ON k.pubkey = a.pubkey "
        "WHERE a.address IS NULL;",
        -1, &stmt, nullptr);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            result.orphan_keys = sqlite3_column_int(stmt, 0);
            if (result.orphan_keys > 0) {
                result.errors.push_back(
                    std::to_string(result.orphan_keys) + " keys without addresses");
            }
        }
    }
    sqlite3_finalize(stmt);

    // 3. Check for addresses without corresponding keys
    stmt = nullptr;
    rc = sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM addresses a "
        "LEFT JOIN keys k ON a.pubkey = k.pubkey "
        "WHERE k.pubkey IS NULL;",
        -1, &stmt, nullptr);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            result.orphan_addrs = sqlite3_column_int(stmt, 0);
            if (result.orphan_addrs > 0) {
                result.errors.push_back(
                    std::to_string(result.orphan_addrs) + " addresses without keys");
            }
        }
    }
    sqlite3_finalize(stmt);

    // 4. Check for duplicate pubkeys in the keys table
    stmt = nullptr;
    rc = sqlite3_prepare_v2(db_,
        "SELECT pubkey, COUNT(*) as cnt FROM keys "
        "GROUP BY pubkey HAVING cnt > 1;",
        -1, &stmt, nullptr);
    if (rc == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            result.duplicate_entries++;
        }
        if (result.duplicate_entries > 0) {
            result.errors.push_back(
                std::to_string(result.duplicate_entries) + " duplicate key entries");
        }
    }
    sqlite3_finalize(stmt);

    // 5. Check that the master seed exists
    if (!has_master_seed()) {
        result.passed = false;
        result.errors.push_back("master seed is missing");
    }

    // 6. Verify that the HD index is consistent with key count
    uint32_t hd_idx = load_hd_index();
    size_t key_cnt = key_count();
    // HD index should be >= number of non-imported keys
    // This is an advisory check, not a hard failure
    stmt = nullptr;
    rc = sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM keys WHERE path != 'imported';",
        -1, &stmt, nullptr);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int hd_key_count = sqlite3_column_int(stmt, 0);
            if (static_cast<int>(hd_idx) < hd_key_count) {
                result.errors.push_back(
                    "HD index (" + std::to_string(hd_idx) +
                    ") is less than HD key count (" +
                    std::to_string(hd_key_count) + ")");
            }
        }
    }
    sqlite3_finalize(stmt);

    // Overall pass/fail
    if (!result.errors.empty()) {
        result.passed = false;
    }

    return result;
}

// ===========================================================================
// Database repair
// ===========================================================================

int WalletDB::repair() {
    int fixes = 0;

    // 1. Remove orphan addresses (addresses without keys)
    {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_,
            "DELETE FROM addresses WHERE pubkey NOT IN "
            "(SELECT pubkey FROM keys);",
            -1, &stmt, nullptr);
        if (rc == SQLITE_OK) {
            rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) {
                int changes = sqlite3_changes(db_);
                if (changes > 0) {
                    fprintf(stderr, "WalletDB: repaired %d orphan addresses\n", changes);
                    fixes += changes;
                }
            }
        }
        sqlite3_finalize(stmt);
    }

    // 2. Remove duplicate labels
    {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_,
            "DELETE FROM labels WHERE rowid NOT IN "
            "(SELECT MIN(rowid) FROM labels GROUP BY address);",
            -1, &stmt, nullptr);
        if (rc == SQLITE_OK) {
            rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) {
                int changes = sqlite3_changes(db_);
                if (changes > 0) {
                    fprintf(stderr, "WalletDB: repaired %d duplicate labels\n", changes);
                    fixes += changes;
                }
            }
        }
        sqlite3_finalize(stmt);
    }

    // 3. Fix HD index if it's too low
    {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_,
            "SELECT MAX(hd_index) FROM keys WHERE path != 'imported';",
            -1, &stmt, nullptr);
        if (rc == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                int max_idx = sqlite3_column_int(stmt, 0);
                uint32_t current_hd = load_hd_index();
                if (static_cast<uint32_t>(max_idx) >= current_hd) {
                    store_hd_index(static_cast<uint32_t>(max_idx) + 1);
                    fprintf(stderr, "WalletDB: repaired HD index: %u -> %d\n",
                            current_hd, max_idx + 1);
                    fixes++;
                }
            }
        }
        sqlite3_finalize(stmt);
    }

    // 4. Vacuum the database to reclaim space
    try {
        exec_sql(db_, "VACUUM;");
    } catch (...) {
        // VACUUM can fail if there's an active transaction; ignore
    }

    return fixes;
}

// ===========================================================================
// Database statistics
// ===========================================================================

WalletDB::DBStats WalletDB::get_db_stats() const {
    DBStats stats;

    // File size
    struct stat st;
    if (stat(db_path_.c_str(), &st) == 0) {
        stats.file_size = static_cast<size_t>(st.st_size);
    } else {
        stats.file_size = 0;
    }

    // Table counts
    stats.key_count = static_cast<int>(key_count());
    stats.address_count = static_cast<int>(address_count());
    stats.tx_count = static_cast<int>(transaction_count());

    // Label count
    {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_,
            "SELECT COUNT(*) FROM labels;",
            -1, &stmt, nullptr);
        stats.label_count = 0;
        if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
            stats.label_count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    // Schema version
    std::string version_str;
    if (load_meta("schema_version", version_str)) {
        try {
            stats.schema_version = std::stoi(version_str);
        } catch (...) {
            stats.schema_version = 0;
        }
    } else {
        stats.schema_version = 0;
    }

    // SQLite version
    stats.sqlite_version = sqlite3_libversion();

    // WAL mode check
    {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_,
            "PRAGMA journal_mode;",
            -1, &stmt, nullptr);
        stats.wal_mode = false;
        if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
            const char* mode = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 0));
            if (mode) {
                std::string mode_str(mode);
                std::transform(mode_str.begin(), mode_str.end(),
                               mode_str.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                stats.wal_mode = (mode_str == "wal");
            }
        }
        sqlite3_finalize(stmt);
    }

    // Page size and count
    {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_,
            "PRAGMA page_size;",
            -1, &stmt, nullptr);
        stats.page_size = 0;
        if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
            stats.page_size = static_cast<size_t>(sqlite3_column_int64(stmt, 0));
        }
        sqlite3_finalize(stmt);
    }

    {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_,
            "PRAGMA page_count;",
            -1, &stmt, nullptr);
        stats.page_count = 0;
        if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
            stats.page_count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_,
            "PRAGMA freelist_count;",
            -1, &stmt, nullptr);
        stats.freelist_count = 0;
        if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
            stats.freelist_count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    return stats;
}

// ===========================================================================
// Secure erase
// ===========================================================================

bool WalletDB::secure_erase_key(uint32_t index) {
    // Find the key by HD index
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT pubkey, encrypted_privkey FROM keys WHERE hd_index = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_int(stmt, 1, static_cast<int>(index));

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return false;
    }

    // Get the pubkey for deletion
    std::array<uint8_t, 32> pubkey{};
    const uint8_t* pk = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 0));
    if (pk && sqlite3_column_bytes(stmt, 0) >= 32) {
        std::memcpy(pubkey.data(), pk, 32);
    }

    // Overwrite the encrypted private key with random data before deletion
    const void* enc_blob = sqlite3_column_blob(stmt, 1);
    int enc_len = sqlite3_column_bytes(stmt, 1);
    sqlite3_finalize(stmt);

    if (enc_len > 0) {
        // Write random data over the key
        std::vector<uint8_t> random_data(static_cast<size_t>(enc_len));
        GetRandBytes(random_data.data(), random_data.size());

        sqlite3_stmt* update_stmt = nullptr;
        rc = sqlite3_prepare_v2(db_,
            "UPDATE keys SET encrypted_privkey = ? WHERE hd_index = ?;",
            -1, &update_stmt, nullptr);
        if (rc == SQLITE_OK) {
            bind_blob(update_stmt, 1, random_data.data(),
                      static_cast<int>(random_data.size()));
            sqlite3_bind_int(update_stmt, 2, static_cast<int>(index));
            sqlite3_step(update_stmt);
            sqlite3_finalize(update_stmt);
        }

        // Write zeros
        std::memset(random_data.data(), 0, random_data.size());
        update_stmt = nullptr;
        rc = sqlite3_prepare_v2(db_,
            "UPDATE keys SET encrypted_privkey = ? WHERE hd_index = ?;",
            -1, &update_stmt, nullptr);
        if (rc == SQLITE_OK) {
            bind_blob(update_stmt, 1, random_data.data(),
                      static_cast<int>(random_data.size()));
            sqlite3_bind_int(update_stmt, 2, static_cast<int>(index));
            sqlite3_step(update_stmt);
            sqlite3_finalize(update_stmt);
        }
    }

    // Now delete the key record
    return delete_key(pubkey);
}

bool WalletDB::secure_erase_all_keys() {
    // First overwrite all encrypted private keys with random data
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT pubkey FROM keys;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    std::vector<std::array<uint8_t, 32>> all_pubkeys;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::array<uint8_t, 32> pk{};
        const uint8_t* blob = static_cast<const uint8_t*>(
            sqlite3_column_blob(stmt, 0));
        if (blob && sqlite3_column_bytes(stmt, 0) >= 32) {
            std::memcpy(pk.data(), blob, 32);
            all_pubkeys.push_back(pk);
        }
    }
    sqlite3_finalize(stmt);

    // Overwrite each key with random data then zeros
    for (const auto& pk : all_pubkeys) {
        std::vector<uint8_t> random_data(32);
        GetRandBytes(random_data.data(), random_data.size());

        sqlite3_stmt* update_stmt = nullptr;
        rc = sqlite3_prepare_v2(db_,
            "UPDATE keys SET encrypted_privkey = ? WHERE pubkey = ?;",
            -1, &update_stmt, nullptr);
        if (rc == SQLITE_OK) {
            bind_blob(update_stmt, 1, random_data.data(), 32);
            bind_blob(update_stmt, 2, pk.data(), 32);
            sqlite3_step(update_stmt);
            sqlite3_finalize(update_stmt);
        }
    }

    // Zero-fill pass
    for (const auto& pk : all_pubkeys) {
        std::vector<uint8_t> zeros(32, 0);

        sqlite3_stmt* update_stmt = nullptr;
        rc = sqlite3_prepare_v2(db_,
            "UPDATE keys SET encrypted_privkey = ? WHERE pubkey = ?;",
            -1, &update_stmt, nullptr);
        if (rc == SQLITE_OK) {
            bind_blob(update_stmt, 1, zeros.data(), 32);
            bind_blob(update_stmt, 2, pk.data(), 32);
            sqlite3_step(update_stmt);
            sqlite3_finalize(update_stmt);
        }
    }

    // Delete all keys
    try {
        exec_sql(db_, "DELETE FROM keys;");
    } catch (...) {
        return false;
    }

    // Also securely erase the master seed
    if (has_master_seed()) {
        // Overwrite with random data
        std::vector<uint8_t> random_seed(64);
        GetRandBytes(random_seed.data(), random_seed.size());
        store_master_seed(random_seed);

        // Overwrite with zeros
        std::vector<uint8_t> zero_seed(64, 0);
        store_master_seed(zero_seed);

        // Delete
        delete_meta("master_seed");
    }

    return true;
}

// ===========================================================================
// Locked coins persistence
// ===========================================================================

bool WalletDB::store_locked_coin(const uint256& txid, uint32_t vout,
                                  const std::string& reason) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO locked_coins (txid, vout, locked_at, reason) "
        "VALUES (?, ?, ?, ?);",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        // Table might not exist yet; create it
        try {
            exec_sql(db_,
                "CREATE TABLE IF NOT EXISTS locked_coins ("
                "  txid BLOB NOT NULL,"
                "  vout INTEGER NOT NULL,"
                "  locked_at INTEGER DEFAULT 0,"
                "  reason TEXT DEFAULT '',"
                "  PRIMARY KEY (txid, vout)"
                ");");
        } catch (...) {
            return false;
        }
        rc = sqlite3_prepare_v2(db_,
            "INSERT OR REPLACE INTO locked_coins (txid, vout, locked_at, reason) "
            "VALUES (?, ?, ?, ?);",
            -1, &stmt, nullptr);
        if (rc != SQLITE_OK) return false;
    }

    bind_blob(stmt, 1, txid.data(), 32);
    sqlite3_bind_int(stmt, 2, static_cast<int>(vout));
    sqlite3_bind_int64(stmt, 3, GetTime());
    bind_text(stmt, 4, reason);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool WalletDB::remove_locked_coin(const uint256& txid, uint32_t vout) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "DELETE FROM locked_coins WHERE txid = ? AND vout = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_blob(stmt, 1, txid.data(), 32);
    sqlite3_bind_int(stmt, 2, static_cast<int>(vout));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::vector<std::pair<uint256, uint32_t>> WalletDB::load_locked_coins() const {
    std::vector<std::pair<uint256, uint32_t>> result;

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT txid, vout FROM locked_coins;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return result;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint256 txid;
        const uint8_t* blob = static_cast<const uint8_t*>(
            sqlite3_column_blob(stmt, 0));
        if (blob && sqlite3_column_bytes(stmt, 0) >= 32) {
            std::memcpy(txid.data(), blob, 32);
        }
        uint32_t vout = static_cast<uint32_t>(sqlite3_column_int(stmt, 1));
        result.emplace_back(txid, vout);
    }

    sqlite3_finalize(stmt);
    return result;
}

bool WalletDB::clear_locked_coins() {
    try {
        exec_sql(db_, "DELETE FROM locked_coins;");
        return true;
    } catch (...) {
        return false;
    }
}

// ===========================================================================
// Address book persistence
// ===========================================================================

bool WalletDB::store_address_book_entry(const std::string& address,
                                         const std::string& label,
                                         const std::string& purpose) {
    // Ensure the table exists
    try {
        exec_sql(db_,
            "CREATE TABLE IF NOT EXISTS address_book ("
            "  address TEXT PRIMARY KEY,"
            "  label TEXT DEFAULT '',"
            "  purpose TEXT DEFAULT 'send',"
            "  created_at INTEGER DEFAULT 0"
            ");");
    } catch (...) {}

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO address_book (address, label, purpose, created_at) "
        "VALUES (?, ?, ?, ?);",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_text(stmt, 1, address);
    bind_text(stmt, 2, label);
    bind_text(stmt, 3, purpose);
    sqlite3_bind_int64(stmt, 4, GetTime());

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool WalletDB::delete_address_book_entry(const std::string& address) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "DELETE FROM address_book WHERE address = ?;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bind_text(stmt, 1, address);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::vector<std::tuple<std::string, std::string, std::string>>
WalletDB::load_address_book() const {
    std::vector<std::tuple<std::string, std::string, std::string>> result;

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT address, label, purpose FROM address_book ORDER BY address;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return result;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* addr = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 0));
        const char* lbl = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 1));
        const char* purp = reinterpret_cast<const char*>(
            sqlite3_column_text(stmt, 2));

        result.emplace_back(
            addr ? addr : "",
            lbl ? lbl : "",
            purp ? purp : "send"
        );
    }

    sqlite3_finalize(stmt);
    return result;
}

// ===========================================================================
// Scan progress tracking
// ===========================================================================

bool WalletDB::store_scan_progress(uint64_t current_height,
                                    uint64_t target_height,
                                    int found_txs) {
    try {
        exec_sql(db_,
            "CREATE TABLE IF NOT EXISTS scan_progress ("
            "  id INTEGER PRIMARY KEY DEFAULT 1,"
            "  current_height INTEGER DEFAULT 0,"
            "  target_height INTEGER DEFAULT 0,"
            "  last_scan_time INTEGER DEFAULT 0,"
            "  found_txs INTEGER DEFAULT 0"
            ");");
    } catch (...) {}

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO scan_progress "
        "(id, current_height, target_height, last_scan_time, found_txs) "
        "VALUES (1, ?, ?, ?, ?);",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_int64(stmt, 1, static_cast<int64_t>(current_height));
    sqlite3_bind_int64(stmt, 2, static_cast<int64_t>(target_height));
    sqlite3_bind_int64(stmt, 3, GetTime());
    sqlite3_bind_int(stmt, 4, found_txs);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool WalletDB::load_scan_progress(uint64_t& current_height,
                                   uint64_t& target_height,
                                   int& found_txs) const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_,
        "SELECT current_height, target_height, found_txs "
        "FROM scan_progress WHERE id = 1;",
        -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return false;
    }

    current_height = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
    target_height = static_cast<uint64_t>(sqlite3_column_int64(stmt, 1));
    found_txs = sqlite3_column_int(stmt, 2);

    sqlite3_finalize(stmt);
    return true;
}

} // namespace flow

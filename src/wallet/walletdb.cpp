// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "wallet/walletdb.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <sys/stat.h>

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

} // namespace flow

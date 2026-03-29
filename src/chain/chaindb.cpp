// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Persistent block index database implementation.
// Uses SQLite with WAL mode for crash-safe persistence and
// concurrent read access during IBD.

#include "chain/chaindb.h"
#include "sqlite3.h"

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <sys/stat.h>
#include "logging.h"

namespace flow {

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

ChainDB::ChainDB(const std::string& db_path)
    : db_path_(db_path)
{
    int rc = sqlite3_open(db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::string err = db_ ? sqlite3_errmsg(db_) : "unknown error";
        if (db_) sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("ChainDB: failed to open database: " + err);
    }

    // Enable WAL mode for concurrent reads and crash safety
    char* errmsg = nullptr;
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &errmsg);
    if (errmsg) sqlite3_free(errmsg);

    // FULL synchronous ensures WAL data survives kill -9
    sqlite3_exec(db_, "PRAGMA synchronous=FULL;", nullptr, nullptr, &errmsg);
    if (errmsg) sqlite3_free(errmsg);

    // Larger page size for block index rows
    sqlite3_exec(db_, "PRAGMA page_size=4096;", nullptr, nullptr, &errmsg);
    if (errmsg) sqlite3_free(errmsg);

    // Larger cache for IBD performance (64MB)
    sqlite3_exec(db_, "PRAGMA cache_size=-65536;", nullptr, nullptr, &errmsg);
    if (errmsg) sqlite3_free(errmsg);

    init_tables();
    prepare_statements();
}

ChainDB::~ChainDB() {
    finalize_statements();
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// ---------------------------------------------------------------------------
// init_tables
// ---------------------------------------------------------------------------

void ChainDB::init_tables() {
    const char* sql =
        "CREATE TABLE IF NOT EXISTS block_index ("
        "    hash BLOB PRIMARY KEY,"
        "    prev_hash BLOB NOT NULL,"
        "    height INTEGER NOT NULL,"
        "    timestamp INTEGER NOT NULL,"
        "    nbits INTEGER NOT NULL,"
        "    nonce INTEGER NOT NULL DEFAULT 0,"
        "    status INTEGER NOT NULL,"
        "    file_num INTEGER NOT NULL,"
        "    file_offset INTEGER NOT NULL,"
        "    file_size INTEGER NOT NULL,"
        "    n_tx INTEGER NOT NULL,"
        "    merkle_root BLOB,"
        "    miner_pubkey BLOB,"
        "    undo_file_num INTEGER NOT NULL DEFAULT -1,"
        "    undo_file_offset INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_block_height ON block_index(height);"
        "CREATE INDEX IF NOT EXISTS idx_block_prev ON block_index(prev_hash);"
        "CREATE TABLE IF NOT EXISTS chain_meta ("
        "    key TEXT PRIMARY KEY,"
        "    value BLOB"
        ");";

    char* errmsg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        if (errmsg) sqlite3_free(errmsg);
        throw std::runtime_error("ChainDB: failed to create tables: " + err);
    }

    // Migrate existing databases: add undo columns if missing.
    // ALTER TABLE ADD COLUMN is a no-op if the column already exists in
    // newer SQLite versions, but older ones return an error — ignore it.
    sqlite3_exec(db_,
        "ALTER TABLE block_index ADD COLUMN undo_file_num INTEGER NOT NULL DEFAULT -1;",
        nullptr, nullptr, nullptr);
    sqlite3_exec(db_,
        "ALTER TABLE block_index ADD COLUMN undo_file_offset INTEGER NOT NULL DEFAULT 0;",
        nullptr, nullptr, nullptr);
}

// ---------------------------------------------------------------------------
// prepare_statements
// ---------------------------------------------------------------------------

void ChainDB::prepare_statements() {
    auto prepare = [this](const char* sql, sqlite3_stmt** stmt) {
        int rc = sqlite3_prepare_v2(db_, sql, -1, stmt, nullptr);
        if (rc != SQLITE_OK) {
            throw std::runtime_error(
                std::string("ChainDB: failed to prepare statement: ")
                + sqlite3_errmsg(db_));
        }
    };

    prepare(
        "INSERT OR REPLACE INTO block_index ("
        "    hash, prev_hash, height, timestamp, nbits,"
        "    nonce, status,"
        "    file_num, file_offset, file_size, n_tx,"
        "    merkle_root, miner_pubkey,"
        "    undo_file_num, undo_file_offset"
        ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
        &stmt_save_);

    prepare(
        "SELECT hash, prev_hash, height, timestamp, nbits,"
        "    nonce, status,"
        "    file_num, file_offset, file_size, n_tx,"
        "    merkle_root, miner_pubkey,"
        "    undo_file_num, undo_file_offset"
        " FROM block_index ORDER BY height ASC;",
        &stmt_load_all_);

    prepare(
        "SELECT hash, prev_hash, height, timestamp, nbits,"
        "    nonce, status,"
        "    file_num, file_offset, file_size, n_tx,"
        "    merkle_root, miner_pubkey,"
        "    undo_file_num, undo_file_offset"
        " FROM block_index WHERE hash = ?;",
        &stmt_load_one_);

    prepare(
        "DELETE FROM block_index WHERE hash = ?;",
        &stmt_delete_);

    prepare(
        "INSERT OR REPLACE INTO chain_meta (key, value) VALUES (?, ?);",
        &stmt_save_meta_);

    prepare(
        "SELECT value FROM chain_meta WHERE key = ?;",
        &stmt_load_meta_);

    prepare(
        "SELECT COUNT(*) FROM block_index;",
        &stmt_count_);

    prepare(
        "SELECT MAX(height) FROM block_index;",
        &stmt_max_height_);

    prepare(
        "SELECT MIN(height) FROM block_index;",
        &stmt_min_height_);

    prepare(
        "DELETE FROM block_index WHERE height < ?;",
        &stmt_prune_);
}

// ---------------------------------------------------------------------------
// finalize_statements
// ---------------------------------------------------------------------------

void ChainDB::finalize_statements() {
    auto finalize = [](sqlite3_stmt*& stmt) {
        if (stmt) {
            sqlite3_finalize(stmt);
            stmt = nullptr;
        }
    };

    finalize(stmt_save_);
    finalize(stmt_load_all_);
    finalize(stmt_load_one_);
    finalize(stmt_delete_);
    finalize(stmt_save_meta_);
    finalize(stmt_load_meta_);
    finalize(stmt_count_);
    finalize(stmt_max_height_);
    finalize(stmt_min_height_);
    finalize(stmt_prune_);
}

// ---------------------------------------------------------------------------
// read_index_from_row — populate CBlockIndex from a positioned query row
// ---------------------------------------------------------------------------

void ChainDB::read_index_from_row(sqlite3_stmt* stmt, CBlockIndex& idx) const {
    int col = 0;

    // hash (BLOB, 32 bytes)
    const void* hash_blob = sqlite3_column_blob(stmt, col);
    int hash_len = sqlite3_column_bytes(stmt, col);
    if (hash_blob && hash_len == 32) {
        std::memcpy(idx.hash.data(), hash_blob, 32);
    }
    col++;

    // prev_hash (BLOB, 32 bytes)
    const void* prev_blob = sqlite3_column_blob(stmt, col);
    int prev_len = sqlite3_column_bytes(stmt, col);
    if (prev_blob && prev_len == 32) {
        std::memcpy(idx.prev_hash.data(), prev_blob, 32);
    }
    col++;

    // Scalar fields
    idx.height           = static_cast<uint64_t>(sqlite3_column_int64(stmt, col++));
    idx.timestamp        = sqlite3_column_int64(stmt, col++);
    idx.nbits            = static_cast<uint32_t>(sqlite3_column_int(stmt, col++));
    idx.nonce            = static_cast<uint32_t>(sqlite3_column_int(stmt, col++));
    idx.status           = static_cast<uint32_t>(sqlite3_column_int(stmt, col++));

    // Disk position
    idx.pos.file_num     = sqlite3_column_int(stmt, col++);
    idx.pos.offset       = static_cast<uint32_t>(sqlite3_column_int(stmt, col++));
    idx.pos.size         = static_cast<uint32_t>(sqlite3_column_int(stmt, col++));
    idx.n_tx             = sqlite3_column_int(stmt, col++);

    // merkle_root (BLOB, 32 bytes)
    const void* mroot_blob = sqlite3_column_blob(stmt, col);
    int mroot_len = sqlite3_column_bytes(stmt, col);
    if (mroot_blob && mroot_len == 32) {
        std::memcpy(idx.merkle_root.data(), mroot_blob, 32);
    }
    col++;

    // miner_pubkey (BLOB, 32 bytes)
    const void* mpk_blob = sqlite3_column_blob(stmt, col);
    int mpk_len = sqlite3_column_bytes(stmt, col);
    if (mpk_blob && mpk_len == 32) {
        std::memcpy(idx.miner_pubkey.data(), mpk_blob, 32);
    }
    col++;

    // Undo disk position (rev*.dat)
    idx.undo_file = sqlite3_column_int(stmt, col++);
    idx.undo_pos  = static_cast<uint32_t>(sqlite3_column_int(stmt, col++));

    // prev pointer must be re-linked by caller
    idx.prev = nullptr;
}

// ---------------------------------------------------------------------------
// save_block_index
// ---------------------------------------------------------------------------

bool ChainDB::save_block_index(const CBlockIndex& index) {
    sqlite3_reset(stmt_save_);

    int col = 1;
    sqlite3_bind_blob(stmt_save_, col++, index.hash.data(), 32, SQLITE_STATIC);
    sqlite3_bind_blob(stmt_save_, col++, index.prev_hash.data(), 32, SQLITE_STATIC);
    sqlite3_bind_int64(stmt_save_, col++, static_cast<int64_t>(index.height));
    sqlite3_bind_int64(stmt_save_, col++, index.timestamp);
    sqlite3_bind_int(stmt_save_, col++, static_cast<int>(index.nbits));
    sqlite3_bind_int(stmt_save_, col++, static_cast<int>(index.nonce));
    sqlite3_bind_int(stmt_save_, col++, static_cast<int>(index.status));
    sqlite3_bind_int(stmt_save_, col++, index.pos.file_num);
    sqlite3_bind_int(stmt_save_, col++, static_cast<int>(index.pos.offset));
    sqlite3_bind_int(stmt_save_, col++, static_cast<int>(index.pos.size));
    sqlite3_bind_int(stmt_save_, col++, index.n_tx);
    sqlite3_bind_blob(stmt_save_, col++, index.merkle_root.data(), 32, SQLITE_STATIC);
    sqlite3_bind_blob(stmt_save_, col++, index.miner_pubkey.data(), 32, SQLITE_STATIC);
    sqlite3_bind_int(stmt_save_, col++, index.undo_file);
    sqlite3_bind_int(stmt_save_, col++, static_cast<int>(index.undo_pos));

    int rc = sqlite3_step(stmt_save_);
    return rc == SQLITE_DONE;
}

// ---------------------------------------------------------------------------
// load_all_indices
// ---------------------------------------------------------------------------

std::vector<CBlockIndex> ChainDB::load_all_indices() const {
    std::vector<CBlockIndex> results;

    sqlite3_reset(stmt_load_all_);

    while (sqlite3_step(stmt_load_all_) == SQLITE_ROW) {
        CBlockIndex idx;
        read_index_from_row(stmt_load_all_, idx);
        results.push_back(std::move(idx));
    }

    return results;
}

// ---------------------------------------------------------------------------
// load_block_index
// ---------------------------------------------------------------------------

bool ChainDB::load_block_index(const uint256& hash, CBlockIndex& out) const {
    sqlite3_reset(stmt_load_one_);
    sqlite3_bind_blob(stmt_load_one_, 1, hash.data(), 32, SQLITE_STATIC);

    int rc = sqlite3_step(stmt_load_one_);
    if (rc != SQLITE_ROW) return false;

    read_index_from_row(stmt_load_one_, out);
    return true;
}

// ---------------------------------------------------------------------------
// delete_block_index
// ---------------------------------------------------------------------------

bool ChainDB::delete_block_index(const uint256& hash) {
    sqlite3_reset(stmt_delete_);
    sqlite3_bind_blob(stmt_delete_, 1, hash.data(), 32, SQLITE_STATIC);

    int rc = sqlite3_step(stmt_delete_);
    if (rc != SQLITE_DONE) return false;

    return sqlite3_changes(db_) > 0;
}

// ---------------------------------------------------------------------------
// Chain metadata
// ---------------------------------------------------------------------------

bool ChainDB::save_meta(const std::string& key, const uint8_t* data, size_t len) {
    sqlite3_reset(stmt_save_meta_);
    sqlite3_bind_text(stmt_save_meta_, 1, key.c_str(),
                      static_cast<int>(key.size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt_save_meta_, 2, data,
                      static_cast<int>(len), SQLITE_STATIC);

    int rc = sqlite3_step(stmt_save_meta_);
    return rc == SQLITE_DONE;
}

std::vector<uint8_t> ChainDB::load_meta(const std::string& key) const {
    sqlite3_reset(stmt_load_meta_);
    sqlite3_bind_text(stmt_load_meta_, 1, key.c_str(),
                      static_cast<int>(key.size()), SQLITE_STATIC);

    int rc = sqlite3_step(stmt_load_meta_);
    if (rc != SQLITE_ROW) return {};

    const void* blob = sqlite3_column_blob(stmt_load_meta_, 0);
    int blob_len = sqlite3_column_bytes(stmt_load_meta_, 0);

    if (!blob || blob_len <= 0) return {};

    const auto* bytes = static_cast<const uint8_t*>(blob);
    return {bytes, bytes + blob_len};
}

bool ChainDB::save_tip(const uint256& hash) {
    bool ok = save_meta("tip", hash.data(), 32);
    // Force WAL checkpoint so data survives kill -9
    if (ok && db_) {
        sqlite3_wal_checkpoint_v2(db_, nullptr, SQLITE_CHECKPOINT_TRUNCATE, nullptr, nullptr);
    }
    return ok;
}

uint256 ChainDB::load_tip() const {
    auto data = load_meta("tip");
    uint256 hash;
    if (data.size() == 32) {
        std::memcpy(hash.data(), data.data(), 32);
    } else {
        hash.set_null();
    }
    return hash;
}

bool ChainDB::save_height(uint64_t height) {
    uint8_t buf[8];
    for (int i = 0; i < 8; ++i) {
        buf[i] = static_cast<uint8_t>(height >> (i * 8));
    }
    return save_meta("height", buf, 8);
}

uint64_t ChainDB::load_height() const {
    auto data = load_meta("height");
    if (data.size() != 8) return 0;

    uint64_t height = 0;
    for (int i = 0; i < 8; ++i) {
        height |= static_cast<uint64_t>(data[i]) << (i * 8);
    }
    return height;
}

// ---------------------------------------------------------------------------
// Batch operations
// ---------------------------------------------------------------------------

void ChainDB::begin_batch() {
    char* errmsg = nullptr;
    sqlite3_exec(db_, "BEGIN TRANSACTION;", nullptr, nullptr, &errmsg);
    if (errmsg) {
        LogError("db", "begin_batch failed: %s", errmsg);
        sqlite3_free(errmsg);
    }
}

void ChainDB::commit_batch() {
    char* errmsg = nullptr;
    sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &errmsg);
    if (errmsg) {
        LogError("db", "commit_batch failed: %s", errmsg);
        sqlite3_free(errmsg);
    }
}

void ChainDB::rollback_batch() {
    char* errmsg = nullptr;
    sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, &errmsg);
    if (errmsg) {
        LogError("db", "rollback_batch failed: %s", errmsg);
        sqlite3_free(errmsg);
    }
}

// ---------------------------------------------------------------------------
// Pruning
// ---------------------------------------------------------------------------

size_t ChainDB::prune_below(uint64_t height) {
    sqlite3_reset(stmt_prune_);
    sqlite3_bind_int64(stmt_prune_, 1, static_cast<int64_t>(height));

    int rc = sqlite3_step(stmt_prune_);
    if (rc != SQLITE_DONE) return 0;

    return static_cast<size_t>(sqlite3_changes(db_));
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

size_t ChainDB::count() const {
    sqlite3_reset(stmt_count_);
    int rc = sqlite3_step(stmt_count_);
    if (rc != SQLITE_ROW) return 0;
    return static_cast<size_t>(sqlite3_column_int64(stmt_count_, 0));
}

uint64_t ChainDB::max_height() const {
    sqlite3_reset(stmt_max_height_);
    int rc = sqlite3_step(stmt_max_height_);
    if (rc != SQLITE_ROW) return 0;
    // MAX returns NULL if table is empty
    if (sqlite3_column_type(stmt_max_height_, 0) == SQLITE_NULL) return 0;
    return static_cast<uint64_t>(sqlite3_column_int64(stmt_max_height_, 0));
}

uint64_t ChainDB::min_height() const {
    sqlite3_reset(stmt_min_height_);
    int rc = sqlite3_step(stmt_min_height_);
    if (rc != SQLITE_ROW) return 0;
    if (sqlite3_column_type(stmt_min_height_, 0) == SQLITE_NULL) return 0;
    return static_cast<uint64_t>(sqlite3_column_int64(stmt_min_height_, 0));
}

size_t ChainDB::disk_usage() const {
    struct stat st;
    if (::stat(db_path_.c_str(), &st) == 0) {
        return static_cast<size_t>(st.st_size);
    }
    return 0;
}

void ChainDB::compact() {
    if (!db_) return;
    char* errmsg = nullptr;
    sqlite3_exec(db_, "PRAGMA incremental_vacuum;", nullptr, nullptr, &errmsg);
    if (errmsg) sqlite3_free(errmsg);
}

} // namespace flow

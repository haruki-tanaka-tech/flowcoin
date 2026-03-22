// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "chaindb.h"
#include <sqlite3.h>
#include <cstring>
#include <stdexcept>

namespace flow {

static void check(int rc, sqlite3* db, const char* ctx) {
    if (rc != SQLITE_OK && rc != SQLITE_DONE && rc != SQLITE_ROW) {
        throw std::runtime_error(std::string(ctx) + ": " + sqlite3_errmsg(db));
    }
}

ChainDb::ChainDb(const std::string& db_path) {
    check(sqlite3_open(db_path.c_str(), &db_), db_, "open chain.db");
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
    create_tables();
}

ChainDb::~ChainDb() {
    if (db_) sqlite3_close(db_);
}

void ChainDb::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS block_index (
            hash BLOB PRIMARY KEY,
            prev_hash BLOB NOT NULL,
            height INTEGER NOT NULL,
            timestamp INTEGER NOT NULL,
            val_loss REAL NOT NULL,
            nbits INTEGER NOT NULL,
            d_model INTEGER NOT NULL,
            n_layers INTEGER NOT NULL,
            d_ff INTEGER NOT NULL,
            n_experts INTEGER NOT NULL,
            n_heads INTEGER NOT NULL,
            rank_ INTEGER NOT NULL,
            stagnation_count INTEGER NOT NULL,
            improving_blocks INTEGER NOT NULL,
            status INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_height ON block_index(height);

        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value BLOB
        );
    )";
    check(sqlite3_exec(db_, sql, nullptr, nullptr, nullptr), db_, "create tables");
}

void ChainDb::store_index(const CBlockIndex& idx) {
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO block_index "
        "(hash, prev_hash, height, timestamp, val_loss, nbits, "
        "d_model, n_layers, d_ff, n_experts, n_heads, rank_, "
        "stagnation_count, improving_blocks, status) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
        -1, &stmt, nullptr);

    sqlite3_bind_blob(stmt, 1, idx.hash.bytes(), 32, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, idx.prev_hash.bytes(), 32, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, static_cast<int64_t>(idx.height));
    sqlite3_bind_int64(stmt, 4, idx.timestamp);
    sqlite3_bind_double(stmt, 5, static_cast<double>(idx.val_loss));
    sqlite3_bind_int(stmt, 6, static_cast<int>(idx.nbits));
    sqlite3_bind_int(stmt, 7, static_cast<int>(idx.d_model));
    sqlite3_bind_int(stmt, 8, static_cast<int>(idx.n_layers));
    sqlite3_bind_int(stmt, 9, static_cast<int>(idx.d_ff));
    sqlite3_bind_int(stmt, 10, static_cast<int>(idx.n_experts));
    sqlite3_bind_int(stmt, 11, static_cast<int>(idx.n_heads));
    sqlite3_bind_int(stmt, 12, static_cast<int>(idx.rank));
    sqlite3_bind_int(stmt, 13, static_cast<int>(idx.stagnation_count));
    sqlite3_bind_int(stmt, 14, static_cast<int>(idx.improving_blocks));
    sqlite3_bind_int(stmt, 15, static_cast<int>(idx.status));

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<CBlockIndex> ChainDb::load_all() const {
    std::vector<CBlockIndex> result;

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_,
        "SELECT hash, prev_hash, height, timestamp, val_loss, nbits, "
        "d_model, n_layers, d_ff, n_experts, n_heads, rank_, "
        "stagnation_count, improving_blocks, status "
        "FROM block_index ORDER BY height;",
        -1, &stmt, nullptr);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CBlockIndex idx;
        auto read_blob = [&](int col, uint8_t* dst, int len) {
            const void* b = sqlite3_column_blob(stmt, col);
            if (b && sqlite3_column_bytes(stmt, col) == len) {
                std::memcpy(dst, b, len);
            }
        };

        read_blob(0, idx.hash.bytes(), 32);
        read_blob(1, idx.prev_hash.bytes(), 32);
        idx.height = static_cast<uint64_t>(sqlite3_column_int64(stmt, 2));
        idx.timestamp = sqlite3_column_int64(stmt, 3);
        idx.val_loss = static_cast<float>(sqlite3_column_double(stmt, 4));
        idx.nbits = static_cast<uint32_t>(sqlite3_column_int(stmt, 5));
        idx.d_model = static_cast<uint32_t>(sqlite3_column_int(stmt, 6));
        idx.n_layers = static_cast<uint32_t>(sqlite3_column_int(stmt, 7));
        idx.d_ff = static_cast<uint32_t>(sqlite3_column_int(stmt, 8));
        idx.n_experts = static_cast<uint32_t>(sqlite3_column_int(stmt, 9));
        idx.n_heads = static_cast<uint32_t>(sqlite3_column_int(stmt, 10));
        idx.rank = static_cast<uint32_t>(sqlite3_column_int(stmt, 11));
        idx.stagnation_count = static_cast<uint32_t>(sqlite3_column_int(stmt, 12));
        idx.improving_blocks = static_cast<uint32_t>(sqlite3_column_int(stmt, 13));
        idx.status = static_cast<uint32_t>(sqlite3_column_int(stmt, 14));

        result.push_back(idx);
    }

    sqlite3_finalize(stmt);
    return result;
}

size_t ChainDb::count() const {
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM block_index;", -1, &stmt, nullptr);
    sqlite3_step(stmt);
    size_t n = static_cast<size_t>(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);
    return n;
}

void ChainDb::store_tip(const Hash256& hash) {
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('tip', ?);",
        -1, &stmt, nullptr);
    sqlite3_bind_blob(stmt, 1, hash.bytes(), 32, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

Hash256 ChainDb::load_tip() const {
    Hash256 result;
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_,
        "SELECT value FROM meta WHERE key = 'tip';",
        -1, &stmt, nullptr);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* b = sqlite3_column_blob(stmt, 0);
        if (b && sqlite3_column_bytes(stmt, 0) == 32) {
            std::memcpy(result.bytes(), b, 32);
        }
    }
    sqlite3_finalize(stmt);
    return result;
}

} // namespace flow

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "index/coinstatsindex.h"
#include "hash/keccak.h"

#include <sqlite3.h>

#include <cassert>
#include <chrono>
#include <cstring>

namespace flow {

// ============================================================================
// CoinStats serialization
// ============================================================================

size_t CoinStats::serialized_size() const {
    // height(8) + block_hash(32) + utxo_count(8) + total_amount(8)
    // + utxo_set_hash(32) + disk_size(8) + total_unspendable(8)
    // + computed_at(8)
    return 8 + 32 + 8 + 8 + 32 + 8 + 8 + 8;
}

std::vector<uint8_t> CoinStats::serialize() const {
    std::vector<uint8_t> out;
    out.resize(serialized_size());
    size_t pos = 0;

    auto write_u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            out[pos++] = static_cast<uint8_t>(v & 0xFF);
            v >>= 8;
        }
    };

    auto write_i64 = [&](int64_t v) {
        write_u64(static_cast<uint64_t>(v));
    };

    auto write_blob = [&](const uint8_t* data, size_t len) {
        std::memcpy(&out[pos], data, len);
        pos += len;
    };

    write_u64(height);
    write_blob(block_hash.data(), 32);
    write_u64(utxo_count);
    write_i64(total_amount);
    write_blob(utxo_set_hash.data(), 32);
    write_u64(disk_size);
    write_i64(total_unspendable);
    write_i64(computed_at);

    return out;
}

bool CoinStats::deserialize(const uint8_t* data, size_t len) {
    if (len < serialized_size()) return false;

    size_t pos = 0;

    auto read_u64 = [&]() -> uint64_t {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= static_cast<uint64_t>(data[pos++]) << (i * 8);
        }
        return v;
    };

    auto read_i64 = [&]() -> int64_t {
        return static_cast<int64_t>(read_u64());
    };

    auto read_blob = [&](uint8_t* out, size_t n) {
        std::memcpy(out, &data[pos], n);
        pos += n;
    };

    height = read_u64();
    read_blob(block_hash.data(), 32);
    utxo_count = read_u64();
    total_amount = read_i64();
    read_blob(utxo_set_hash.data(), 32);
    disk_size = read_u64();
    total_unspendable = read_i64();
    computed_at = read_i64();

    return true;
}

// ============================================================================
// CoinStatsIndex construction / destruction
// ============================================================================

CoinStatsIndex::CoinStatsIndex(const std::string& db_path)
    : BaseIndex("coinstatsindex", db_path) {
}

CoinStatsIndex::~CoinStatsIndex() {
    finalize_statements();
}

// ============================================================================
// Database initialization
// ============================================================================

bool CoinStatsIndex::init_db() {
    const char* create_table =
        "CREATE TABLE IF NOT EXISTS coin_stats ("
        "  block_height INTEGER NOT NULL,"
        "  block_hash BLOB NOT NULL,"
        "  utxo_count INTEGER NOT NULL,"
        "  total_amount INTEGER NOT NULL,"
        "  utxo_set_hash BLOB NOT NULL,"
        "  disk_size INTEGER NOT NULL,"
        "  total_unspendable INTEGER NOT NULL,"
        "  computed_at INTEGER NOT NULL,"
        "  PRIMARY KEY (block_height)"
        ")";
    if (!exec_sql(create_table)) return false;

    const char* hash_idx =
        "CREATE INDEX IF NOT EXISTS idx_cs_hash ON coin_stats(block_hash)";
    if (!exec_sql(hash_idx)) return false;

    prepare_statements();

    // Load running stats from the database
    load_running_stats();

    return true;
}

void CoinStatsIndex::prepare_statements() {
    if (!db_) return;

    const char* insert_sql =
        "INSERT OR REPLACE INTO coin_stats "
        "(block_height, block_hash, utxo_count, total_amount, "
        "utxo_set_hash, disk_size, total_unspendable, computed_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_prepare_v2(db_, insert_sql, -1, &stmt_insert_, nullptr);

    const char* find_sql =
        "SELECT block_hash, utxo_count, total_amount, utxo_set_hash, "
        "disk_size, total_unspendable, computed_at "
        "FROM coin_stats WHERE block_height = ?";
    sqlite3_prepare_v2(db_, find_sql, -1, &stmt_find_, nullptr);

    const char* find_by_hash_sql =
        "SELECT block_height, utxo_count, total_amount, utxo_set_hash, "
        "disk_size, total_unspendable, computed_at "
        "FROM coin_stats WHERE block_hash = ?";
    sqlite3_prepare_v2(db_, find_by_hash_sql, -1, &stmt_find_by_hash_, nullptr);

    const char* delete_sql =
        "DELETE FROM coin_stats WHERE block_height = ?";
    sqlite3_prepare_v2(db_, delete_sql, -1, &stmt_delete_, nullptr);

    const char* latest_sql =
        "SELECT block_height, block_hash, utxo_count, total_amount, "
        "utxo_set_hash, disk_size, total_unspendable, computed_at "
        "FROM coin_stats ORDER BY block_height DESC LIMIT 1";
    sqlite3_prepare_v2(db_, latest_sql, -1, &stmt_latest_, nullptr);
}

void CoinStatsIndex::finalize_statements() {
    auto fin = [](sqlite3_stmt*& s) {
        if (s) { sqlite3_finalize(s); s = nullptr; }
    };
    fin(stmt_insert_);
    fin(stmt_find_);
    fin(stmt_find_by_hash_);
    fin(stmt_delete_);
    fin(stmt_latest_);
}

// ============================================================================
// Helpers
// ============================================================================

uint256 CoinStatsIndex::compute_utxo_hash(
    const uint256& txid, uint32_t vout,
    Amount value, const std::array<uint8_t, 32>& pubkey_hash) const {
    // hash = keccak256d(txid || vout_le4 || amount_le8 || pubkey_hash)
    std::vector<uint8_t> data;
    data.reserve(32 + 4 + 8 + 32);

    // txid
    data.insert(data.end(), txid.begin(), txid.end());

    // vout (4 bytes LE)
    data.push_back(static_cast<uint8_t>(vout & 0xFF));
    data.push_back(static_cast<uint8_t>((vout >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>((vout >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((vout >> 24) & 0xFF));

    // amount (8 bytes LE)
    uint64_t v = static_cast<uint64_t>(value);
    for (int i = 0; i < 8; ++i) {
        data.push_back(static_cast<uint8_t>(v & 0xFF));
        v >>= 8;
    }

    // pubkey_hash
    data.insert(data.end(), pubkey_hash.begin(), pubkey_hash.end());

    return keccak256d(data);
}

uint256 CoinStatsIndex::xor_hashes(const uint256& a, const uint256& b) {
    uint256 result;
    for (size_t i = 0; i < 32; ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

bool CoinStatsIndex::load_running_stats() {
    if (!stmt_latest_) return false;

    std::lock_guard<std::mutex> lock(stats_mutex_);

    sqlite3_reset(stmt_latest_);
    int rc = sqlite3_step(stmt_latest_);
    if (rc != SQLITE_ROW) {
        running_stats_ = CoinStats{};
        return false;
    }

    running_stats_.height = static_cast<uint64_t>(
        sqlite3_column_int64(stmt_latest_, 0));

    const void* bh = sqlite3_column_blob(stmt_latest_, 1);
    if (bh) std::memcpy(running_stats_.block_hash.data(), bh, 32);

    running_stats_.utxo_count = static_cast<uint64_t>(
        sqlite3_column_int64(stmt_latest_, 2));
    running_stats_.total_amount = sqlite3_column_int64(stmt_latest_, 3);

    const void* ush = sqlite3_column_blob(stmt_latest_, 4);
    if (ush) std::memcpy(running_stats_.utxo_set_hash.data(), ush, 32);

    running_stats_.disk_size = static_cast<size_t>(
        sqlite3_column_int64(stmt_latest_, 5));
    running_stats_.total_unspendable = sqlite3_column_int64(stmt_latest_, 6);
    running_stats_.computed_at = sqlite3_column_int64(stmt_latest_, 7);

    return true;
}

int64_t CoinStatsIndex::now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

// ============================================================================
// Write / undo
// ============================================================================

bool CoinStatsIndex::write_block(const CBlock& block, uint64_t height) {
    if (!stmt_insert_) return false;

    std::lock_guard<std::mutex> lock(stats_mutex_);

    uint256 block_hash = block.get_hash();

    // Process each transaction
    for (const auto& tx : block.vtx) {
        uint256 txid = tx.get_txid();

        // Remove spent UTXOs from the hash (XOR them out)
        if (!tx.is_coinbase()) {
            for ([[maybe_unused]] const auto& in : tx.vin) {
                // We do not have the UTXO data here, but we can track
                // the count change. For a full implementation, we would
                // need UTXO data. We approximate by only tracking outputs.
                running_stats_.utxo_count--;
            }
        }

        // Add new UTXOs to the hash (XOR them in)
        for (uint32_t i = 0; i < tx.vout.size(); ++i) {
            const auto& out = tx.vout[i];

            if (out.amount <= 0) {
                // OP_RETURN or zero-value: unspendable
                running_stats_.total_unspendable += out.amount;
                continue;
            }

            uint256 utxo_hash = compute_utxo_hash(txid, i, out.amount,
                                                    out.pubkey_hash);
            running_stats_.utxo_set_hash = xor_hashes(
                running_stats_.utxo_set_hash, utxo_hash);

            running_stats_.utxo_count++;
            running_stats_.total_amount += out.amount;
        }
    }

    // Update running stats
    running_stats_.height = height;
    running_stats_.block_hash = block_hash;
    running_stats_.disk_size += block.get_block_size();
    running_stats_.computed_at = now_seconds();

    // Store in database
    sqlite3_reset(stmt_insert_);
    sqlite3_bind_int64(stmt_insert_, 1, static_cast<int64_t>(height));
    sqlite3_bind_blob(stmt_insert_, 2, block_hash.data(), 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt_insert_, 3,
                       static_cast<int64_t>(running_stats_.utxo_count));
    sqlite3_bind_int64(stmt_insert_, 4, running_stats_.total_amount);
    sqlite3_bind_blob(stmt_insert_, 5,
                      running_stats_.utxo_set_hash.data(), 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt_insert_, 6,
                       static_cast<int64_t>(running_stats_.disk_size));
    sqlite3_bind_int64(stmt_insert_, 7, running_stats_.total_unspendable);
    sqlite3_bind_int64(stmt_insert_, 8, running_stats_.computed_at);

    int rc = sqlite3_step(stmt_insert_);
    return rc == SQLITE_DONE;
}

bool CoinStatsIndex::undo_block(const CBlock& block, uint64_t height) {
    if (!stmt_delete_) return false;

    // Delete this height's stats
    sqlite3_reset(stmt_delete_);
    sqlite3_bind_int64(stmt_delete_, 1, static_cast<int64_t>(height));
    int rc = sqlite3_step(stmt_delete_);
    if (rc != SQLITE_DONE) return false;

    // Reload running stats from the previous height
    std::lock_guard<std::mutex> lock(stats_mutex_);

    // Reverse the operations from write_block
    for (const auto& tx : block.vtx) {
        uint256 txid = tx.get_txid();

        // Re-add spent UTXOs (reverse the removal)
        if (!tx.is_coinbase()) {
            for (const auto& in : tx.vin) {
                (void)in;
                running_stats_.utxo_count++;
            }
        }

        // Remove created UTXOs (reverse the addition)
        for (uint32_t i = 0; i < tx.vout.size(); ++i) {
            const auto& out = tx.vout[i];

            if (out.amount <= 0) {
                running_stats_.total_unspendable -= out.amount;
                continue;
            }

            uint256 utxo_hash = compute_utxo_hash(txid, i, out.amount,
                                                    out.pubkey_hash);
            running_stats_.utxo_set_hash = xor_hashes(
                running_stats_.utxo_set_hash, utxo_hash);

            running_stats_.utxo_count--;
            running_stats_.total_amount -= out.amount;
        }
    }

    running_stats_.disk_size -= block.get_block_size();

    if (height > 0) {
        running_stats_.height = height - 1;
        // Load the previous block hash from stored stats
        CoinStats prev;
        if (get_stats(height - 1, prev)) {
            running_stats_.block_hash = prev.block_hash;
        }
    } else {
        running_stats_ = CoinStats{};
    }

    return true;
}

// ============================================================================
// Lookups
// ============================================================================

bool CoinStatsIndex::get_stats(uint64_t height, CoinStats& stats) const {
    if (!stmt_find_) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    sqlite3_reset(stmt_find_);
    sqlite3_bind_int64(stmt_find_, 1, static_cast<int64_t>(height));

    int rc = sqlite3_step(stmt_find_);
    if (rc != SQLITE_ROW) return false;

    stats.height = height;

    const void* bh = sqlite3_column_blob(stmt_find_, 0);
    if (bh) std::memcpy(stats.block_hash.data(), bh, 32);

    stats.utxo_count = static_cast<uint64_t>(
        sqlite3_column_int64(stmt_find_, 1));
    stats.total_amount = sqlite3_column_int64(stmt_find_, 2);

    const void* ush = sqlite3_column_blob(stmt_find_, 3);
    if (ush) std::memcpy(stats.utxo_set_hash.data(), ush, 32);

    stats.disk_size = static_cast<size_t>(
        sqlite3_column_int64(stmt_find_, 4));
    stats.total_unspendable = sqlite3_column_int64(stmt_find_, 5);
    stats.computed_at = sqlite3_column_int64(stmt_find_, 6);

    return true;
}

CoinStats CoinStatsIndex::get_latest() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return running_stats_;
}

bool CoinStatsIndex::get_stats_by_hash(const uint256& block_hash,
                                        CoinStats& stats) const {
    if (!stmt_find_by_hash_) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    sqlite3_reset(stmt_find_by_hash_);
    sqlite3_bind_blob(stmt_find_by_hash_, 1, block_hash.data(), 32,
                      SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt_find_by_hash_);
    if (rc != SQLITE_ROW) return false;

    stats.block_hash = block_hash;
    stats.height = static_cast<uint64_t>(
        sqlite3_column_int64(stmt_find_by_hash_, 0));
    stats.utxo_count = static_cast<uint64_t>(
        sqlite3_column_int64(stmt_find_by_hash_, 1));
    stats.total_amount = sqlite3_column_int64(stmt_find_by_hash_, 2);

    const void* ush = sqlite3_column_blob(stmt_find_by_hash_, 3);
    if (ush) std::memcpy(stats.utxo_set_hash.data(), ush, 32);

    stats.disk_size = static_cast<size_t>(
        sqlite3_column_int64(stmt_find_by_hash_, 4));
    stats.total_unspendable = sqlite3_column_int64(stmt_find_by_hash_, 5);
    stats.computed_at = sqlite3_column_int64(stmt_find_by_hash_, 6);

    return true;
}

bool CoinStatsIndex::get_utxo_hash(uint64_t height, uint256& hash_out) const {
    CoinStats stats;
    if (!get_stats(height, stats)) return false;
    hash_out = stats.utxo_set_hash;
    return true;
}

bool CoinStatsIndex::get_utxo_count(uint64_t height, uint64_t& count_out) const {
    CoinStats stats;
    if (!get_stats(height, stats)) return false;
    count_out = stats.utxo_count;
    return true;
}

bool CoinStatsIndex::get_total_amount(uint64_t height, Amount& amount_out) const {
    CoinStats stats;
    if (!get_stats(height, stats)) return false;
    amount_out = stats.total_amount;
    return true;
}

} // namespace flow

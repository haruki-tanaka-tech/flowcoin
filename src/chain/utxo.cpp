// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "utxo.h"
#include <sqlite3.h>
#include <stdexcept>

namespace flow {

struct UtxoSet::Statements {
    sqlite3_stmt* insert{nullptr};
    sqlite3_stmt* remove{nullptr};
    sqlite3_stmt* select{nullptr};
    sqlite3_stmt* exists{nullptr};
    sqlite3_stmt* count_stmt{nullptr};
};

static void check_sqlite(int rc, sqlite3* db, const char* context) {
    if (rc != SQLITE_OK && rc != SQLITE_DONE && rc != SQLITE_ROW) {
        std::string msg = std::string(context) + ": " + sqlite3_errmsg(db);
        throw std::runtime_error(msg);
    }
}

UtxoSet::UtxoSet(const std::string& db_path)
    : stmts_(std::make_unique<Statements>()) {
    int rc = sqlite3_open(db_path.c_str(), &db_);
    check_sqlite(rc, db_, "open database");

    // WAL mode for concurrent reads
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);

    create_tables();
    prepare_statements();
}

UtxoSet::~UtxoSet() {
    if (stmts_) {
        sqlite3_finalize(stmts_->insert);
        sqlite3_finalize(stmts_->remove);
        sqlite3_finalize(stmts_->select);
        sqlite3_finalize(stmts_->exists);
        sqlite3_finalize(stmts_->count_stmt);
    }
    if (db_) {
        sqlite3_close(db_);
    }
}

void UtxoSet::create_tables() {
    const char* sql =
        "CREATE TABLE IF NOT EXISTS utxos ("
        "  txid BLOB NOT NULL,"
        "  vout INTEGER NOT NULL,"
        "  amount INTEGER NOT NULL,"
        "  pubkey_hash BLOB NOT NULL,"
        "  height INTEGER NOT NULL,"
        "  PRIMARY KEY (txid, vout)"
        ");";
    check_sqlite(sqlite3_exec(db_, sql, nullptr, nullptr, nullptr), db_, "create table");
}

void UtxoSet::prepare_statements() {
    auto prep = [&](const char* sql, sqlite3_stmt** stmt) {
        check_sqlite(sqlite3_prepare_v2(db_, sql, -1, stmt, nullptr), db_, sql);
    };

    prep("INSERT INTO utxos (txid, vout, amount, pubkey_hash, height) "
         "VALUES (?, ?, ?, ?, ?);", &stmts_->insert);

    prep("DELETE FROM utxos WHERE txid = ? AND vout = ?;", &stmts_->remove);

    prep("SELECT amount, pubkey_hash, height FROM utxos WHERE txid = ? AND vout = ?;",
         &stmts_->select);

    prep("SELECT 1 FROM utxos WHERE txid = ? AND vout = ? LIMIT 1;", &stmts_->exists);

    prep("SELECT COUNT(*) FROM utxos;", &stmts_->count_stmt);
}

bool UtxoSet::has(const COutPoint& outpoint) const {
    sqlite3_reset(stmts_->exists);
    sqlite3_bind_blob(stmts_->exists, 1, outpoint.txid.bytes(), 32, SQLITE_STATIC);
    sqlite3_bind_int(stmts_->exists, 2, static_cast<int>(outpoint.vout));

    int rc = sqlite3_step(stmts_->exists);
    return rc == SQLITE_ROW;
}

std::optional<UtxoEntry> UtxoSet::get(const COutPoint& outpoint) const {
    sqlite3_reset(stmts_->select);
    sqlite3_bind_blob(stmts_->select, 1, outpoint.txid.bytes(), 32, SQLITE_STATIC);
    sqlite3_bind_int(stmts_->select, 2, static_cast<int>(outpoint.vout));

    int rc = sqlite3_step(stmts_->select);
    if (rc != SQLITE_ROW) return std::nullopt;

    UtxoEntry entry;
    entry.amount = Amount{static_cast<int64_t>(sqlite3_column_int64(stmts_->select, 0))};

    const void* hash_blob = sqlite3_column_blob(stmts_->select, 1);
    int hash_len = sqlite3_column_bytes(stmts_->select, 1);
    if (hash_blob && hash_len == 20) {
        std::memcpy(entry.pubkey_hash.bytes(), hash_blob, 20);
    }

    entry.height = static_cast<uint64_t>(sqlite3_column_int64(stmts_->select, 2));
    return entry;
}

void UtxoSet::add(const Hash256& txid, uint32_t vout, const UtxoEntry& entry) {
    sqlite3_reset(stmts_->insert);
    sqlite3_bind_blob(stmts_->insert, 1, txid.bytes(), 32, SQLITE_STATIC);
    sqlite3_bind_int(stmts_->insert, 2, static_cast<int>(vout));
    sqlite3_bind_int64(stmts_->insert, 3, entry.amount.value);
    sqlite3_bind_blob(stmts_->insert, 4, entry.pubkey_hash.bytes(), 20, SQLITE_STATIC);
    sqlite3_bind_int64(stmts_->insert, 5, static_cast<int64_t>(entry.height));

    check_sqlite(sqlite3_step(stmts_->insert), db_, "insert utxo");
}

bool UtxoSet::spend(const COutPoint& outpoint) {
    sqlite3_reset(stmts_->remove);
    sqlite3_bind_blob(stmts_->remove, 1, outpoint.txid.bytes(), 32, SQLITE_STATIC);
    sqlite3_bind_int(stmts_->remove, 2, static_cast<int>(outpoint.vout));

    sqlite3_step(stmts_->remove);
    return sqlite3_changes(db_) > 0;
}

Result<Ok> UtxoSet::connect_block(const std::vector<CTransaction>& txs, uint64_t height) {
    sqlite3_exec(db_, "BEGIN;", nullptr, nullptr, nullptr);

    for (const auto& tx : txs) {
        // Spend inputs (skip coinbase)
        if (!tx.is_coinbase()) {
            for (const auto& in : tx.vin) {
                if (!spend(in.prevout)) {
                    sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
                    return Error{"utxo-missing: " + in.prevout.txid.to_hex()};
                }
            }
        }

        // Add outputs
        Hash256 txid = tx.get_hash();
        for (uint32_t i = 0; i < tx.vout.size(); ++i) {
            UtxoEntry entry;
            entry.amount = tx.vout[i].amount;
            entry.pubkey_hash = tx.vout[i].pubkey_hash;
            entry.height = height;
            add(txid, i, entry);
        }
    }

    sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, nullptr);
    return Ok{};
}

void UtxoSet::disconnect_block(const std::vector<CTransaction>& txs,
                                const std::vector<std::optional<UtxoEntry>>& spent_utxos) {
    sqlite3_exec(db_, "BEGIN;", nullptr, nullptr, nullptr);

    // Process transactions in reverse order
    size_t spent_idx = spent_utxos.size();
    for (auto it = txs.rbegin(); it != txs.rend(); ++it) {
        const auto& tx = *it;

        // Remove outputs
        Hash256 txid = tx.get_hash();
        for (uint32_t i = 0; i < tx.vout.size(); ++i) {
            COutPoint op;
            op.txid = txid;
            op.vout = i;
            spend(op);
        }

        // Re-add spent inputs (skip coinbase)
        if (!tx.is_coinbase()) {
            for (auto vin_it = tx.vin.rbegin(); vin_it != tx.vin.rend(); ++vin_it) {
                --spent_idx;
                if (spent_idx < spent_utxos.size() && spent_utxos[spent_idx]) {
                    add(vin_it->prevout.txid, vin_it->prevout.vout,
                        *spent_utxos[spent_idx]);
                }
            }
        }
    }

    sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, nullptr);
}

std::vector<UtxoSet::OwnedUtxo> UtxoSet::find_by_pubkey_hashes(
        const std::vector<Blob<20>>& pubkey_hashes) const {
    std::vector<OwnedUtxo> result;

    // Query all UTXOs and filter by pubkey_hash
    // For large UTXO sets, an index on pubkey_hash would be better.
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_,
        "SELECT txid, vout, amount, pubkey_hash, height FROM utxos;",
        -1, &stmt, nullptr);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Blob<20> pkh;
        const void* ph = sqlite3_column_blob(stmt, 3);
        if (ph && sqlite3_column_bytes(stmt, 3) == 20) {
            std::memcpy(pkh.bytes(), ph, 20);
        }

        // Check if this pubkey_hash is in our set
        bool owned = false;
        for (const auto& target : pubkey_hashes) {
            if (pkh == target) { owned = true; break; }
        }
        if (!owned) continue;

        OwnedUtxo u;
        const void* txid_blob = sqlite3_column_blob(stmt, 0);
        if (txid_blob && sqlite3_column_bytes(stmt, 0) == 32) {
            std::memcpy(u.outpoint.txid.bytes(), txid_blob, 32);
        }
        u.outpoint.vout = static_cast<uint32_t>(sqlite3_column_int(stmt, 1));
        u.entry.amount = Amount{static_cast<int64_t>(sqlite3_column_int64(stmt, 2))};
        u.entry.pubkey_hash = pkh;
        u.entry.height = static_cast<uint64_t>(sqlite3_column_int64(stmt, 4));
        result.push_back(u);
    }

    sqlite3_finalize(stmt);
    return result;
}

size_t UtxoSet::count() const {
    sqlite3_reset(stmts_->count_stmt);
    sqlite3_step(stmts_->count_stmt);
    return static_cast<size_t>(sqlite3_column_int64(stmts_->count_stmt, 0));
}

} // namespace flow

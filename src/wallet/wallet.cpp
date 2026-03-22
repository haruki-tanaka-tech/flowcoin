// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "wallet.h"
#include "crypto/sign.h"
#include "core/hash.h"

#include <sqlite3.h>
#include <algorithm>
#include <stdexcept>

namespace flow {

static void check_sqlite(int rc, sqlite3* db, const char* ctx) {
    if (rc != SQLITE_OK && rc != SQLITE_DONE && rc != SQLITE_ROW) {
        throw std::runtime_error(std::string(ctx) + ": " + sqlite3_errmsg(db));
    }
}

Wallet::Wallet(const std::string& wallet_path, const std::string& seed_hex) {
    // Parse seed
    if (seed_hex.size() < 32 || seed_hex.size() > 128) {
        throw std::runtime_error("wallet: seed must be 16-64 bytes hex");
    }
    std::vector<uint8_t> seed;
    for (size_t i = 0; i + 1 < seed_hex.size(); i += 2) {
        auto hi = seed_hex[i];
        auto lo = seed_hex[i + 1];
        auto hex_val = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        seed.push_back(static_cast<uint8_t>((hex_val(hi) << 4) | hex_val(lo)));
    }

    master_ = crypto::master_key_from_seed(seed.data(), seed.size());

    int rc = sqlite3_open(wallet_path.c_str(), &db_);
    check_sqlite(rc, db_, "open wallet.dat");

    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    create_tables();
    load_keys();
}

Wallet::~Wallet() {
    if (db_) sqlite3_close(db_);
}

void Wallet::create_tables() {
    const char* sql =
        "CREATE TABLE IF NOT EXISTS keys ("
        "  idx INTEGER PRIMARY KEY,"
        "  privkey BLOB,"
        "  pubkey BLOB NOT NULL,"
        "  address TEXT NOT NULL,"
        "  pubkey_hash BLOB NOT NULL,"
        "  used INTEGER NOT NULL DEFAULT 0,"
        "  imported INTEGER NOT NULL DEFAULT 0"
        ");";
    check_sqlite(sqlite3_exec(db_, sql, nullptr, nullptr, nullptr), db_, "create keys table");
}

void Wallet::load_keys() {
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_,
        "SELECT idx, privkey, pubkey, address, pubkey_hash, used, imported FROM keys ORDER BY idx;",
        -1, &stmt, nullptr);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        WalletKey wk;
        wk.index = static_cast<uint32_t>(sqlite3_column_int(stmt, 0));

        bool imported = sqlite3_column_int(stmt, 6) != 0;

        if (imported) {
            // Imported key: read privkey directly from DB
            const void* pk_blob = sqlite3_column_blob(stmt, 1);
            if (pk_blob && sqlite3_column_bytes(stmt, 1) == 32) {
                std::memcpy(wk.keypair.privkey.bytes(), pk_blob, 32);
            }
            wk.keypair.pubkey = crypto::derive_pubkey(wk.keypair.privkey);
        } else {
            // HD-derived: re-derive from master + index
            auto ext = crypto::derive_default(master_, wk.index);
            wk.keypair.privkey = ext.key;
            wk.keypair.pubkey = crypto::derive_pubkey(ext.key);
        }

        wk.address = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));

        const void* ph = sqlite3_column_blob(stmt, 4);
        if (ph && sqlite3_column_bytes(stmt, 4) == 20) {
            std::memcpy(wk.pubkey_hash.bytes(), ph, 20);
        }

        wk.used = sqlite3_column_int(stmt, 5) != 0;
        keys_.push_back(wk);

        if (!imported && wk.index >= next_index_) {
            next_index_ = wk.index + 1;
        }
    }
    sqlite3_finalize(stmt);
}

WalletKey Wallet::derive_key(uint32_t index) {
    auto ext = crypto::derive_default(master_, index);
    WalletKey wk;
    wk.index = index;
    wk.keypair.privkey = ext.key;
    wk.keypair.pubkey = crypto::derive_pubkey(ext.key);
    wk.address = crypto::pubkey_to_address(wk.keypair.pubkey);

    Hash256 full_hash = keccak256d(wk.keypair.pubkey.bytes(), 32);
    std::memcpy(wk.pubkey_hash.bytes(), full_hash.bytes(), 20);

    return wk;
}

void Wallet::store_key(const WalletKey& wk) {
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO keys (idx, privkey, pubkey, address, pubkey_hash, used, imported) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);",
        -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, static_cast<int>(wk.index));
    sqlite3_bind_blob(stmt, 2, wk.keypair.privkey.bytes(), 32, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, wk.keypair.pubkey.bytes(), 32, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, wk.address.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, wk.pubkey_hash.bytes(), 20, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, wk.used ? 1 : 0);
    sqlite3_bind_int(stmt, 7, 0); // not imported (HD-derived)
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::string Wallet::get_new_address() {
    WalletKey wk = derive_key(next_index_);
    store_key(wk);
    keys_.push_back(wk);
    next_index_++;
    return wk.address;
}

std::string Wallet::get_mining_address() {
    // New address for every mined block — never reuse
    WalletKey wk = derive_key(next_index_);
    wk.used = true;
    store_key(wk);
    keys_.push_back(wk);
    next_index_++;
    return wk.address;
}

std::vector<WalletKey> Wallet::get_all_keys() const {
    return keys_;
}

bool Wallet::is_mine(const Blob<20>& pubkey_hash) const {
    for (const auto& wk : keys_) {
        if (wk.pubkey_hash == pubkey_hash) return true;
    }
    return false;
}

const WalletKey* Wallet::find_key(const Blob<20>& pubkey_hash) const {
    for (const auto& wk : keys_) {
        if (wk.pubkey_hash == pubkey_hash) return &wk;
    }
    return nullptr;
}

Result<std::string> Wallet::import_privkey(const PrivKey& privkey) {
    PubKey pubkey = crypto::derive_pubkey(privkey);
    std::string address = crypto::pubkey_to_address(pubkey);

    Hash256 full_hash = keccak256d(pubkey.bytes(), 32);
    Blob<20> pkh;
    std::memcpy(pkh.bytes(), full_hash.bytes(), 20);

    // Check if already imported
    if (is_mine(pkh)) {
        return Error{"key already in wallet"};
    }

    // Store with special index (use high bit to mark imported)
    uint32_t import_idx = 0x80000000u | static_cast<uint32_t>(keys_.size());

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_,
        "INSERT INTO keys (idx, privkey, pubkey, address, pubkey_hash, used, imported) "
        "VALUES (?, ?, ?, ?, ?, 0, 1);",
        -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, static_cast<int>(import_idx));
    sqlite3_bind_blob(stmt, 2, privkey.bytes(), 32, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, pubkey.bytes(), 32, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, address.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, pkh.bytes(), 20, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    WalletKey wk;
    wk.index = import_idx;
    wk.keypair.privkey = privkey;
    wk.keypair.pubkey = pubkey;
    wk.address = address;
    wk.pubkey_hash = pkh;
    keys_.push_back(wk);

    return address;
}

std::vector<std::pair<std::string, std::string>> Wallet::dump_keys() const {
    std::vector<std::pair<std::string, std::string>> result;
    result.reserve(keys_.size());
    for (const auto& wk : keys_) {
        result.emplace_back(wk.keypair.privkey.to_hex(), wk.address);
    }
    return result;
}

Result<CTransaction> Wallet::create_transaction(
        const std::vector<COutPoint>& inputs,
        const std::vector<CTxOut>& outputs) {

    CTransaction tx;
    tx.version = CTransaction::CURRENT_VERSION;
    tx.vout = outputs;

    for (const auto& outpoint : inputs) {
        CTxIn in;
        in.prevout = outpoint;
        tx.vin.push_back(in);
    }

    // First pass: assign pubkeys
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        if (keys_.empty()) {
            return Error{"no keys in wallet"};
        }
        tx.vin[i].pubkey = keys_[0].keypair.pubkey;
    }

    // Compute sighash
    auto sign_data = tx.signing_data();
    Hash256 sighash = keccak256d(sign_data.data(), sign_data.size());

    // Sign each input
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const auto& wk = keys_[0];
        tx.vin[i].pubkey = wk.keypair.pubkey;
        tx.vin[i].sig = crypto::sign(wk.keypair.privkey, wk.keypair.pubkey,
                                      sighash.bytes(), 32);
    }

    return tx;
}

} // namespace flow

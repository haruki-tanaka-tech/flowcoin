// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// HD Wallet: SLIP-0010 Ed25519, backed by SQLite (wallet.dat).
// New address for every coinbase (mining) and change output.
// Supports import/export of private keys.

#pragma once

#include "core/types.h"
#include "crypto/keys.h"
#include "crypto/hd.h"
#include "crypto/address.h"
#include "primitives/transaction.h"

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace flow {

struct WalletKey {
    uint32_t index;
    crypto::KeyPair keypair;
    std::string address;
    Blob<20> pubkey_hash;
    bool used{false};
};

class Wallet {
public:
    // Open or create wallet. File is wallet.dat (SQLite internally).
    // seed_hex: master seed in hex (32-64 bytes).
    Wallet(const std::string& wallet_path, const std::string& seed_hex);
    ~Wallet();

    Wallet(const Wallet&) = delete;
    Wallet& operator=(const Wallet&) = delete;

    // Generate the next unused address.
    // Called automatically for each mined block (new address per coinbase).
    std::string get_new_address();

    // Get a fresh address for mining. Marks it as used immediately.
    std::string get_mining_address();

    // Get all keys (for UTXO scanning).
    std::vector<WalletKey> get_all_keys() const;

    // Check if a pubkey_hash belongs to this wallet.
    bool is_mine(const Blob<20>& pubkey_hash) const;

    // Find the key for a given pubkey_hash.
    const WalletKey* find_key(const Blob<20>& pubkey_hash) const;

    // Build and sign a transaction.
    Result<CTransaction> create_transaction(
        const std::vector<COutPoint>& inputs,
        const std::vector<CTxOut>& outputs);

    // Import a private key (adds to wallet, derives pubkey + address).
    Result<std::string> import_privkey(const PrivKey& privkey);

    // Export all private keys as hex strings (for dumpwallet).
    std::vector<std::pair<std::string, std::string>> dump_keys() const;

    // Number of generated keys.
    uint32_t key_count() const { return next_index_; }

private:
    sqlite3* db_{nullptr};
    crypto::ExtKey master_;
    uint32_t next_index_{0};
    std::vector<WalletKey> keys_;

    void create_tables();
    void load_keys();
    WalletKey derive_key(uint32_t index);
    void store_key(const WalletKey& wk);
};

} // namespace flow

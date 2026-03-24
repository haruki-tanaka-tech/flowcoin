// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Wallet database layer backed by SQLite (wallet.dat).
// Stores master seed, HD chain state, keys, addresses, and transaction history.

#pragma once

#include "util/types.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

struct sqlite3;

namespace flow {

class WalletDB {
public:
    /// Open or create the wallet database at the given path.
    explicit WalletDB(const std::string& path);
    ~WalletDB();

    // Non-copyable
    WalletDB(const WalletDB&) = delete;
    WalletDB& operator=(const WalletDB&) = delete;

    // ---- Master seed management ----

    bool store_master_seed(const std::vector<uint8_t>& encrypted_seed);
    bool load_master_seed(std::vector<uint8_t>& encrypted_seed) const;
    bool has_master_seed() const;

    // ---- HD chain state ----

    bool store_hd_index(uint32_t next_index);
    uint32_t load_hd_index() const;

    // ---- Key storage ----

    struct KeyRecord {
        std::string derivation_path;              // e.g. "m/44'/9555'/0'/0'/0'"
        std::array<uint8_t, 32> pubkey;
        std::vector<uint8_t> encrypted_privkey;   // XOR with keccak256(master_seed + index)
    };

    bool store_key(const KeyRecord& key);
    bool load_key(const std::array<uint8_t, 32>& pubkey, KeyRecord& key) const;
    std::vector<KeyRecord> load_all_keys() const;

    // ---- Address records ----

    struct AddressRecord {
        std::string address;                      // fl1q...
        std::array<uint8_t, 32> pubkey;
        uint32_t hd_index;
        int64_t created_at;
    };

    bool store_address(const AddressRecord& addr);
    std::vector<AddressRecord> load_all_addresses() const;
    bool has_address(const std::string& address) const;

    // ---- Transaction history ----

    struct WalletTx {
        uint256 txid;
        int64_t timestamp;
        int64_t amount;           // positive = received, negative = sent
        uint64_t block_height;    // 0 if unconfirmed
        std::string label;
    };

    bool store_tx(const WalletTx& tx);
    std::vector<WalletTx> load_transactions(int count, int skip) const;

private:
    sqlite3* db_ = nullptr;
    void init_tables();
};

} // namespace flow

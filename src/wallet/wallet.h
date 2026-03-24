// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Main wallet: HD key management, UTXO scanning, transaction creation,
// signing, and address generation.  Each mined block gets a fresh address
// (never reuses coinbase addresses).

#pragma once

#include "wallet/coinselect.h"
#include "wallet/hdchain.h"
#include "wallet/walletdb.h"

#include "chain/utxo.h"
#include "primitives/transaction.h"
#include "util/types.h"

#include <array>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace flow {

class Wallet {
public:
    /// Open or create a wallet backed by the file at wallet_path,
    /// scanning UTXOs from the given (shared, read-only) UTXO set.
    explicit Wallet(const std::string& wallet_path, const UTXOSet& utxo);

    /// Initialize the wallet: generate a new seed if the database is empty,
    /// otherwise load the existing seed and key cache.  Returns false on
    /// unrecoverable error.
    bool init();

    // ---- Address management ----

    /// Generate a fresh HD address (increments the derivation index).
    std::string get_new_address();

    /// Get all addresses that belong to this wallet.
    std::vector<std::string> get_addresses() const;

    /// Check whether an address belongs to this wallet.
    bool is_mine(const std::string& address) const;

    /// Return a fresh address for a mining coinbase output.
    /// Guarantees a unique address per mined block.
    std::string get_coinbase_address();

    // ---- Balance / UTXOs ----

    /// Total confirmed balance (sum of wallet UTXOs in the UTXO set).
    Amount get_balance() const;

    /// List all unspent outputs that belong to this wallet.
    std::vector<CoinToSpend> list_unspent() const;

    // ---- Sending ----

    struct SendResult {
        CTransaction tx;
        std::string error;
        bool success;
    };

    /// Create, sign, and return a transaction paying amount to dest_address.
    /// On failure, success=false and error contains the reason.
    SendResult send_to_address(const std::string& dest_address, Amount amount);

    // ---- Import ----

    /// Import a raw Ed25519 private key (32-byte seed).
    /// Derives the public key and address, stores them in the database.
    bool import_privkey(const std::array<uint8_t, 32>& privkey);

    // ---- Notifications ----

    /// Called when a confirmed transaction is connected to a block.
    /// Records it in the wallet transaction history if relevant.
    void notify_transaction(const CTransaction& tx, uint64_t block_height);

    // ---- History ----

    /// Retrieve recent wallet transactions (newest first).
    std::vector<WalletDB::WalletTx> get_transactions(
        int count = 10, int skip = 0) const;

private:
    WalletDB db_;
    HDChain hd_;
    const UTXOSet& utxo_;

    mutable std::mutex mu_;

    // Fast lookup caches (populated from database on init)
    std::set<std::array<uint8_t, 32>> our_pubkeys_;

    // Map: pubkey_hash (32 bytes, keccak256(pubkey)) -> pubkey
    std::map<std::array<uint8_t, 32>, std::array<uint8_t, 32>> hash_to_pubkey_;

    /// Retrieve the private key for a given public key (decrypts from DB).
    std::array<uint8_t, 32> get_privkey(
        const std::array<uint8_t, 32>& pubkey) const;

    /// Encrypt a private key for storage: XOR with keccak256(seed || index).
    std::vector<uint8_t> encrypt_privkey(
        const std::array<uint8_t, 32>& privkey, uint32_t index) const;

    /// Decrypt a private key from storage.
    std::array<uint8_t, 32> decrypt_privkey(
        const std::vector<uint8_t>& encrypted, uint32_t index) const;

    /// Derive the key-encryption mask: keccak256(seed || index_be4).
    std::array<uint8_t, 32> key_mask(uint32_t index) const;

    /// Rebuild the in-memory pubkey caches from the database.
    void load_keys_cache();
};

} // namespace flow

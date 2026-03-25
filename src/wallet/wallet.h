// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Main wallet: HD key management, UTXO scanning, transaction creation,
// signing, and address generation.  Each mined block gets a fresh address
// (never reuses coinbase addresses).

#pragma once

#include "wallet/coinselect.h"
#include "wallet/encryption.h"
#include "wallet/hdchain.h"
#include "wallet/keypool.h"
#include "wallet/walletdb.h"

#include "chain/utxo.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/types.h"

#include <array>
#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_set>
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

    // ---- Wallet Encryption ----

    /// Encrypt all wallet private keys with AES-256-CBC derived from a passphrase.
    /// Generates a random salt, derives an AES key via Keccak-based KDF,
    /// re-encrypts all stored private keys, and locks the wallet.
    /// Returns false if already encrypted or on error.
    bool encrypt_wallet(const std::string& passphrase);

    /// Unlock the wallet for the given number of seconds.
    /// Derives the AES key from the passphrase, decrypts the master seed,
    /// and caches plaintext keys for `timeout` seconds.
    /// Returns false if passphrase is wrong or wallet is not encrypted.
    bool walletpassphrase(const std::string& passphrase, int timeout_seconds);

    /// Lock the wallet immediately. Clears all cached plaintext keys.
    void walletlock();

    /// Returns true if the wallet is encrypted and currently locked.
    bool is_locked() const;

    /// Returns true if the wallet has been encrypted with a passphrase.
    bool is_encrypted() const;

    // ---- Rescan ----

    /// Rescan the blockchain from the given height to discover wallet transactions.
    /// For each block, checks all transaction outputs against wallet addresses.
    /// Updates wallet balance and transaction history.
    /// @param from_height  Starting block height for the rescan.
    /// @param chain_tip    The current chain tip block index.
    /// @param store        Block store for reading full blocks.
    /// @return             Number of transactions found during rescan.
    int rescan(uint64_t from_height, const class CBlockIndex* chain_tip,
               class BlockStore& store);

    // ---- Label Management ----

    /// Set a label for an address. The label is stored in the wallet database.
    void set_label(const std::string& address, const std::string& label);

    /// Get the label for an address. Returns empty string if no label is set.
    std::string get_label(const std::string& address) const;

    /// Get all addresses that have a given label.
    std::vector<std::string> get_addresses_by_label(const std::string& label) const;

    /// Get all labels and their addresses.
    std::map<std::string, std::vector<std::string>> get_all_labels() const;

    // ---- Sign/Verify messages ----

    /// Sign a message with the private key of a wallet address.
    /// Returns the 64-byte signature concatenated with the 32-byte pubkey (96 bytes).
    std::vector<uint8_t> sign_message(const std::string& address,
                                       const std::string& message);

    // ---- Key pool ----

    /// Access the key pool.
    KeyPool& key_pool() { return keypool_; }

    // ---- Multi-recipient sending ----

    struct Recipient {
        std::string address;
        Amount amount;
        bool subtract_fee = false;
    };

    struct SendManyResult {
        bool success;
        CTransaction tx;
        uint256 txid;
        std::string error;
        Amount total_amount;
        Amount fee;
        int inputs_used;
    };

    SendManyResult send_many(const std::vector<Recipient>& recipients,
                              int target_conf = 6);

    // ---- Create transaction without broadcasting ----

    struct CreateTxResult {
        bool success;
        CTransaction tx;
        std::string error;
        Amount fee;
        Amount change;
        std::vector<CoinToSpend> inputs_used;
    };

    CreateTxResult create_transaction(const std::vector<Recipient>& recipients,
                                       int target_conf = 6);

    // ---- Fee bumping (RBF) ----

    struct BumpFeeResult {
        bool success;
        CTransaction tx;
        std::string error;
        Amount old_fee;
        Amount new_fee;
    };

    BumpFeeResult bump_fee(const uint256& txid, Amount new_fee_rate);

    // ---- Address book ----

    struct AddressBookEntry {
        std::string address;
        std::string label;
        std::string purpose;
        bool is_mine;
        Amount total_received;
        Amount total_sent;
        int tx_count;
        int64_t created_at;
    };

    std::vector<AddressBookEntry> get_address_book() const;
    void set_address_book_entry(const std::string& addr,
                                 const std::string& label,
                                 const std::string& purpose);
    void delete_address_book_entry(const std::string& addr);

    // ---- Wallet notifications ----

    struct WalletNotification {
        enum class Type { TX_ADDED, TX_CONFIRMED, TX_REMOVED, BALANCE_CHANGED };
        Type type;
        uint256 txid;
        Amount amount;
        int confirmations;
        int64_t timestamp;
        std::string address;
    };

    using NotifyCallback = std::function<void(const WalletNotification&)>;

    void subscribe(NotifyCallback callback);
    void unsubscribe_all();
    void emit_notification(const WalletNotification& notif);
    void notify_transaction_event(const CTransaction& tx,
                                   uint64_t block_height,
                                   WalletNotification::Type type);

    // ---- Coin control ----

    void lock_unspent(const uint256& txid, uint32_t vout);
    void unlock_unspent(const uint256& txid, uint32_t vout);
    bool is_locked(const uint256& txid, uint32_t vout) const;
    std::vector<COutPoint> list_locked_unspent() const;
    void unlock_all();

    // ---- Wallet statistics ----

    struct WalletStats {
        Amount balance;
        Amount unconfirmed_balance;
        Amount immature_balance;
        Amount total_received;
        Amount total_sent;
        int tx_count;
        int address_count;
        int keypool_size;
        uint32_t hd_index;
        int utxo_count;
        int64_t oldest_key_time;
        int64_t wallet_created;
        size_t wallet_file_size;
        bool encrypted;
        bool locked;
    };

    WalletStats get_stats() const;

    // ---- Blockchain rescan with progress ----

    struct RescanProgress {
        uint64_t current_height;
        uint64_t target_height;
        double progress;
        int found_txs;
        Amount found_amount;
    };

    using RescanCallback = std::function<void(const RescanProgress&)>;
    bool rescan_blockchain(uint64_t from_height, RescanCallback cb = nullptr);

    // ---- Gap scanning ----

    int scan_gap(int gap_limit = 20);

private:
    WalletDB db_;
    HDChain hd_;
    const UTXOSet& utxo_;
    KeyPool keypool_;

    mutable std::mutex mu_;

    // Fast lookup caches (populated from database on init)
    std::set<std::array<uint8_t, 32>> our_pubkeys_;

    // Map: pubkey_hash (32 bytes, keccak256(pubkey)) -> pubkey
    std::map<std::array<uint8_t, 32>, std::array<uint8_t, 32>> hash_to_pubkey_;

    // Map: address -> pubkey (for address-to-key lookups)
    std::map<std::string, std::array<uint8_t, 32>> addr_to_pubkey_;

    // Map: address -> label
    std::map<std::string, std::string> labels_;

    // Locked outpoints (coin control)
    std::set<COutPoint> locked_outpoints_;

    // Notification callbacks
    mutable std::mutex notify_mu_;
    std::vector<NotifyCallback> notify_callbacks_;

    // Encryption state
    bool encrypted_ = false;
    bool locked_ = true;
    std::array<uint8_t, 16> encryption_salt_{};
    std::array<uint8_t, 32> cached_aes_key_{};
    std::chrono::steady_clock::time_point unlock_expiry_;

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

    /// Check if the unlock timer has expired and re-lock if so.
    void check_lock_timeout();
};

} // namespace flow

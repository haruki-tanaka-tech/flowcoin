// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Wallet database layer backed by SQLite (wallet.dat).
// Stores master seed, HD chain state, keys, addresses, transaction history,
// labels, encrypted seed, and arbitrary metadata key-value pairs.
// Supports batch operations and backup.

#pragma once

#include "util/types.h"
#include "wallet/hdchain.h"

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;

namespace flow {

class WalletDB {
public:
    /// Open or create the wallet database at the given path.
    explicit WalletDB(const std::string& path);
    ~WalletDB();

    // Non-copyable
    WalletDB(const WalletDB&) = delete;
    WalletDB& operator=(const WalletDB&) = delete;

    // -------------------------------------------------------------------
    // Master seed management
    // -------------------------------------------------------------------

    bool store_master_seed(const std::vector<uint8_t>& encrypted_seed);
    bool load_master_seed(std::vector<uint8_t>& encrypted_seed) const;
    bool has_master_seed() const;

    // Encrypted seed with separate salt storage
    bool store_encrypted_seed(const std::vector<uint8_t>& encrypted,
                               const std::array<uint8_t, 16>& salt);
    bool load_encrypted_seed(std::vector<uint8_t>& encrypted,
                              std::array<uint8_t, 16>& salt) const;

    // -------------------------------------------------------------------
    // HD chain state
    // -------------------------------------------------------------------

    bool store_hd_index(uint32_t next_index);
    uint32_t load_hd_index() const;

    bool store_hd_change_index(uint32_t next_change_index);
    uint32_t load_hd_change_index() const;

    bool store_hd_chain(const HDChain& chain);
    bool load_hd_chain(HDChain& chain) const;

    // -------------------------------------------------------------------
    // Key storage
    // -------------------------------------------------------------------

    struct KeyRecord {
        std::string derivation_path;              // e.g. "m/44'/9555'/0'/0'/0'"
        std::array<uint8_t, 32> pubkey;
        std::vector<uint8_t> encrypted_privkey;   // XOR with keccak256(master_seed + index)
        uint32_t hd_index;
        int64_t created_at;
    };

    bool store_key(const KeyRecord& key);
    bool load_key(const std::array<uint8_t, 32>& pubkey, KeyRecord& key) const;
    std::vector<KeyRecord> load_all_keys() const;
    bool has_key(const std::array<uint8_t, 32>& pubkey) const;
    bool delete_key(const std::array<uint8_t, 32>& pubkey);
    size_t key_count() const;

    // -------------------------------------------------------------------
    // Address records
    // -------------------------------------------------------------------

    struct AddressRecord {
        std::string address;                      // fl1q...
        std::array<uint8_t, 32> pubkey;
        uint32_t hd_index;
        int64_t created_at;
        bool is_change;
    };

    bool store_address(const AddressRecord& addr);
    std::vector<AddressRecord> load_all_addresses() const;
    bool has_address(const std::string& address) const;
    bool get_pubkey_for_address(const std::string& address,
                                 std::array<uint8_t, 32>& pubkey) const;
    bool delete_address(const std::string& address);
    size_t address_count() const;

    // -------------------------------------------------------------------
    // Transaction history
    // -------------------------------------------------------------------

    struct WalletTx {
        uint256 txid;
        int64_t timestamp;
        int64_t amount;           // positive = received, negative = sent
        int64_t fee = 0;          // transaction fee paid
        uint64_t block_height;    // 0 if unconfirmed
        int confirmations = 0;   // number of confirmations
        uint256 block_hash;
        std::string from_address;
        std::string to_address;
        std::string address;      // primary address (to_address or from_address)
        std::string label;
        bool is_send = false;     // whether this is a send transaction
        bool is_coinbase = false; // whether this is a coinbase transaction
    };

    bool store_tx(const WalletTx& tx);
    bool update_tx_height(const uint256& txid, uint64_t block_height,
                           const uint256& block_hash);
    std::vector<WalletTx> load_transactions(int count, int skip) const;
    bool get_transaction(const uint256& txid, WalletTx& tx) const;
    bool has_transaction(const uint256& txid) const;
    size_t transaction_count() const;
    std::vector<WalletTx> load_unconfirmed() const;

    // -------------------------------------------------------------------
    // Labels
    // -------------------------------------------------------------------

    bool store_label(const std::string& address, const std::string& label);
    std::string load_label(const std::string& address) const;
    std::vector<std::pair<std::string, std::string>> load_all_labels() const;
    bool delete_label(const std::string& address);

    // -------------------------------------------------------------------
    // Metadata key-value store
    // -------------------------------------------------------------------

    bool store_meta(const std::string& key, const std::string& value);
    bool load_meta(const std::string& key, std::string& value) const;
    bool store_meta_blob(const std::string& key, const std::vector<uint8_t>& value);
    bool load_meta_blob(const std::string& key, std::vector<uint8_t>& value) const;
    bool has_meta(const std::string& key) const;
    bool delete_meta(const std::string& key);

    // -------------------------------------------------------------------
    // Batch operations
    // -------------------------------------------------------------------

    void begin_batch();
    void commit_batch();
    void rollback_batch();
    bool in_batch() const { return in_batch_; }

    // -------------------------------------------------------------------
    // Backup
    // -------------------------------------------------------------------

    bool backup(const std::string& dest_path);

    // -------------------------------------------------------------------
    // Database info
    // -------------------------------------------------------------------

    std::string db_path() const { return db_path_; }
    int64_t db_size_bytes() const;

    // -------------------------------------------------------------------
    // Schema migration
    // -------------------------------------------------------------------

    bool migrate_schema(int from_version, int to_version);
    bool check_and_migrate();

    // -------------------------------------------------------------------
    // Integrity verification
    // -------------------------------------------------------------------

    struct IntegrityResult {
        bool passed;
        int orphan_keys;
        int orphan_addrs;
        int missing_txids;
        int duplicate_entries;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
    };

    IntegrityResult verify_integrity() const;
    int repair();

    // -------------------------------------------------------------------
    // Database statistics
    // -------------------------------------------------------------------

    struct DBStats {
        size_t file_size;
        int key_count;
        int address_count;
        int tx_count;
        int label_count;
        int locked_coin_count;
        int address_book_count;
        int schema_version;
        int page_size;
        int page_count;
        int freelist_count;
        std::string sqlite_version;
        bool wal_mode = false;
    };

    DBStats get_db_stats() const;

    // -------------------------------------------------------------------
    // Secure key erasure
    // -------------------------------------------------------------------

    bool secure_erase_key(uint32_t index);
    bool secure_erase_all_keys();

    // -------------------------------------------------------------------
    // Locked coins
    // -------------------------------------------------------------------

    bool store_locked_coin(const uint256& txid, uint32_t vout,
                            const std::string& reason = "");
    bool remove_locked_coin(const uint256& txid, uint32_t vout);
    std::vector<std::pair<uint256, uint32_t>> load_locked_coins() const;
    bool clear_locked_coins();

    // -------------------------------------------------------------------
    // Address book
    // -------------------------------------------------------------------

    bool store_address_book_entry(const std::string& addr,
                                   const std::string& label,
                                   const std::string& purpose);
    bool delete_address_book_entry(const std::string& addr);
    std::vector<std::tuple<std::string, std::string, std::string>>
        load_address_book() const;

    // -------------------------------------------------------------------
    // Scan progress tracking
    // -------------------------------------------------------------------

    bool store_scan_progress(uint64_t height, uint64_t total, int found);
    bool load_scan_progress(uint64_t& height, uint64_t& total, int& found) const;

private:
    sqlite3* db_ = nullptr;
    std::string db_path_;
    bool in_batch_ = false;

    void init_tables();
    void migrate_tables();

    // Prepared statement cache
    struct StmtCache {
        sqlite3_stmt* store_key = nullptr;
        sqlite3_stmt* load_key = nullptr;
        sqlite3_stmt* store_addr = nullptr;
        sqlite3_stmt* has_addr = nullptr;
        sqlite3_stmt* store_tx = nullptr;
        sqlite3_stmt* load_txs = nullptr;
        sqlite3_stmt* store_label = nullptr;
        sqlite3_stmt* load_label = nullptr;
        sqlite3_stmt* store_meta = nullptr;
        sqlite3_stmt* load_meta = nullptr;
    };
    StmtCache stmts_{};

    void prepare_statements();
    void finalize_statements();
};

} // namespace flow

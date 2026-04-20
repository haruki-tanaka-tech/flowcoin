// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// UTXO set backed by SQLite with WAL mode for concurrent read access.
// Each unspent transaction output is keyed by (txid, vout) and stores
// the value, recipient pubkey hash, creation height, and coinbase flag.

#ifndef FLOWCOIN_CHAIN_UTXO_H
#define FLOWCOIN_CHAIN_UTXO_H

#include "util/types.h"
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <utility>
#include <functional>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;

namespace flow {

// ---- UTXO entry stored in the database --------------------------------------

struct UTXOEntry {
    Amount   value;             // Output value in atomic units
    std::array<uint8_t, 32> pubkey_hash;  // Recipient's pubkey hash (keccak256(pubkey))
    uint64_t height;            // Block height where this UTXO was created
    bool     is_coinbase;       // Coinbase outputs need COINBASE_MATURITY confirmations
};

// ---- UTXO set (SQLite-backed) -----------------------------------------------

class UTXOSet {
public:
    /// Open or create the UTXO database at the given path.
    explicit UTXOSet(const std::string& db_path);
    ~UTXOSet();

    // Non-copyable, non-movable (owns SQLite handle + prepared statements)
    UTXOSet(const UTXOSet&) = delete;
    UTXOSet& operator=(const UTXOSet&) = delete;

    /// Add a UTXO to the set. Returns true on success.
    bool add(const uint256& txid, uint32_t vout, const UTXOEntry& entry);

    /// Remove a UTXO (mark as spent). Returns true if it existed and was removed.
    bool remove(const uint256& txid, uint32_t vout);

    /// Look up a UTXO. Returns true if found, populating entry.
    bool get(const uint256& txid, uint32_t vout, UTXOEntry& entry) const;

    /// Check if a UTXO exists.
    bool exists(const uint256& txid, uint32_t vout) const;

    /// Get total balance for a given pubkey_hash.
    Amount get_balance(const std::array<uint8_t, 32>& pubkey_hash) const;

    /// Get all UTXOs for a given pubkey_hash.
    /// Returns vector of ((txid, vout), UTXOEntry) pairs.
    std::vector<std::pair<std::pair<uint256, uint32_t>, UTXOEntry>>
        get_utxos_for_script(const std::array<uint8_t, 32>& pubkey_hash) const;

    /// Begin a SQLite transaction (for batching block connect/disconnect).
    void begin_transaction();

    /// Commit the current transaction.
    void commit_transaction();

    /// Roll back the current transaction.
    void rollback_transaction();

    // ---- Batch operations and cache ----------------------------------------

    /// Flush all dirty entries from the in-memory write cache to SQLite.
    /// Called periodically during IBD and at chain tip changes.
    void flush_cache();

    /// Get the number of entries in the write cache.
    size_t cache_size() const;

    /// Get the number of dirty entries pending write.
    size_t dirty_count() const;

    /// Clear the entire in-memory cache (does not affect DB).
    void clear_cache();

    /// Enable/disable the write cache. When disabled, all writes go
    /// directly to SQLite. When enabled, writes accumulate in memory
    /// and are flushed in batches for IBD performance.
    void set_cache_enabled(bool enabled);
    bool is_cache_enabled() const { return cache_enabled_; }

    // ---- Statistics --------------------------------------------------------

    /// Total number of UTXOs in the database.
    size_t total_count() const;

    /// Total value of all UTXOs (in atomic units).
    Amount total_value() const;

    /// Number of UTXOs created at a specific block height.
    size_t count_for_height(uint64_t height) const;

    /// Get database size on disk (bytes).
    size_t disk_usage() const;

    // ---- Cursor for full UTXO set iteration --------------------------------

    class UTXOCursor {
    public:
        explicit UTXOCursor(const UTXOSet& owner);
        ~UTXOCursor();

        // Non-copyable
        UTXOCursor(const UTXOCursor&) = delete;
        UTXOCursor& operator=(const UTXOCursor&) = delete;

        /// Advance to the next entry. Returns true if a valid entry was found.
        bool next(uint256& txid, uint32_t& vout, UTXOEntry& entry);

        /// Reset the cursor to the beginning.
        void reset();

    private:
        sqlite3_stmt* stmt_ = nullptr;
        const UTXOSet& owner_;
        bool started_ = false;
    };

    /// Get a cursor for iterating the entire UTXO set.
    /// Useful for computing gettxoutsetinfo hash.
    UTXOCursor get_cursor() const;

    /// Alias for total_count() — convenience for generic code.
    size_t size() const { return total_count(); }

    /// Flush all pending data (alias for flush_cache).
    void flush() { flush_cache(); }

    /// Compact the underlying SQLite database (VACUUM).
    void compact();

    /// Iterate all UTXOs, calling fn(txid, vout, entry) for each.
    void for_each(std::function<void(const uint256&, uint32_t, const UTXOEntry&)> fn) const;

    /// Get all UTXOs as a vector of ((txid, vout), entry) pairs.
    std::vector<std::pair<std::pair<uint256, uint32_t>, UTXOEntry>> get_all() const;

private:
    sqlite3* db_ = nullptr;
    std::string db_path_;

    // Prepared statements for performance
    sqlite3_stmt* stmt_add_ = nullptr;
    sqlite3_stmt* stmt_remove_ = nullptr;
    sqlite3_stmt* stmt_get_ = nullptr;
    sqlite3_stmt* stmt_exists_ = nullptr;
    sqlite3_stmt* stmt_balance_ = nullptr;
    sqlite3_stmt* stmt_by_script_ = nullptr;
    sqlite3_stmt* stmt_count_ = nullptr;
    sqlite3_stmt* stmt_total_value_ = nullptr;
    sqlite3_stmt* stmt_count_height_ = nullptr;

    // In-memory LRU cache
    static constexpr size_t MAX_CACHE_SIZE = 10'000;
    bool cache_enabled_ = false;

    struct CacheKey {
        uint256 txid;
        uint32_t vout;

        bool operator==(const CacheKey& o) const {
            return txid == o.txid && vout == o.vout;
        }
    };

    struct CacheKeyHasher {
        size_t operator()(const CacheKey& k) const {
            uint64_t val;
            std::memcpy(&val, k.txid.data(), sizeof(val));
            return static_cast<size_t>(val) ^ static_cast<size_t>(k.vout * 2654435761u);
        }
    };

    struct CacheEntry {
        UTXOEntry entry;
        bool dirty = false;
        bool removed = false;  // Marked for deletion
    };

    mutable std::unordered_map<CacheKey, CacheEntry, CacheKeyHasher> cache_;

    /// Create tables and indices if they don't exist.
    void init_tables();

    /// Prepare all SQL statements.
    void prepare_statements();

    /// Finalize all prepared statements.
    void finalize_statements();

    /// Write a single cache entry to SQLite.
    bool flush_entry(const CacheKey& key, const CacheEntry& entry);
};

} // namespace flow

#endif // FLOWCOIN_CHAIN_UTXO_H

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// UTXO set backed by SQLite with WAL mode for concurrent read access.
// Each unspent transaction output is keyed by (txid, vout) and stores
// the value, recipient pubkey hash, creation height, and coinbase flag.

#ifndef FLOWCOIN_CHAIN_UTXO_H
#define FLOWCOIN_CHAIN_UTXO_H

#include "util/types.h"
#include <cstdint>
#include <string>
#include <utility>
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

private:
    sqlite3* db_ = nullptr;

    // Prepared statements for performance
    sqlite3_stmt* stmt_add_ = nullptr;
    sqlite3_stmt* stmt_remove_ = nullptr;
    sqlite3_stmt* stmt_get_ = nullptr;
    sqlite3_stmt* stmt_exists_ = nullptr;
    sqlite3_stmt* stmt_balance_ = nullptr;
    sqlite3_stmt* stmt_by_script_ = nullptr;

    /// Create tables and indices if they don't exist.
    void init_tables();

    /// Prepare all SQL statements.
    void prepare_statements();

    /// Finalize all prepared statements.
    void finalize_statements();
};

} // namespace flow

#endif // FLOWCOIN_CHAIN_UTXO_H

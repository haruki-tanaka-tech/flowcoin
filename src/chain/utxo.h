// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// UTXO set backed by SQLite.
// Tracks unspent transaction outputs for validating spends.

#pragma once

#include "core/types.h"
#include "primitives/transaction.h"

#include <memory>
#include <optional>
#include <string>

struct sqlite3;

namespace flow {

struct UtxoEntry {
    Amount   amount;
    Blob<20> pubkey_hash;
    uint64_t height;      // block height where this output was created
    bool     is_coinbase; // true if this output is from a coinbase transaction
};

class UtxoSet {
public:
    // Open or create the UTXO database at the given path.
    explicit UtxoSet(const std::string& db_path);
    ~UtxoSet();

    UtxoSet(const UtxoSet&) = delete;
    UtxoSet& operator=(const UtxoSet&) = delete;

    // Check if an outpoint exists in the UTXO set.
    bool has(const COutPoint& outpoint) const;

    // Get a UTXO entry. Returns nullopt if not found.
    std::optional<UtxoEntry> get(const COutPoint& outpoint) const;

    // Add a new UTXO (from a transaction output).
    void add(const Hash256& txid, uint32_t vout, const UtxoEntry& entry);

    // Remove (spend) a UTXO. Returns false if it doesn't exist.
    bool spend(const COutPoint& outpoint);

    // Apply a full block's transactions to the UTXO set.
    // Adds all outputs, spends all inputs (except coinbase inputs).
    // Returns false if any input references a non-existent UTXO (double-spend).
    Result<Ok> connect_block(const std::vector<CTransaction>& txs, uint64_t height);

    // Undo a block's transactions (for reorgs).
    // Re-adds spent inputs, removes created outputs.
    // Requires the full transactions and the UTXOs that were spent.
    void disconnect_block(const std::vector<CTransaction>& txs,
                          const std::vector<std::optional<UtxoEntry>>& spent_utxos);

    // Find all UTXOs belonging to a set of pubkey hashes.
    // Used by wallet to compute balance and select coins.
    struct OwnedUtxo {
        COutPoint outpoint;
        UtxoEntry entry;
    };
    std::vector<OwnedUtxo> find_by_pubkey_hashes(
        const std::vector<Blob<20>>& pubkey_hashes) const;

    // Get total number of UTXOs (for diagnostics).
    size_t count() const;

private:
    sqlite3* db_{nullptr};

    void create_tables();
    void prepare_statements();

    struct Statements;
    std::unique_ptr<Statements> stmts_;
};

} // namespace flow

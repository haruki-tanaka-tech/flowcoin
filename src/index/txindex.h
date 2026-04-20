// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Transaction index built on the BaseIndex framework.
// Provides O(1) lookup of any confirmed transaction by txid, returning
// the block hash, block height, and position within the block.
//
// SQL schema:
//   CREATE TABLE tx_index (
//       txid BLOB NOT NULL PRIMARY KEY,
//       block_hash BLOB NOT NULL,
//       block_height INTEGER NOT NULL,
//       tx_pos INTEGER NOT NULL,
//       tx_data BLOB
//   );
//   CREATE INDEX idx_tx_height ON tx_index(block_height);

#ifndef FLOWCOIN_INDEX_TXINDEX_H
#define FLOWCOIN_INDEX_TXINDEX_H

#include "index/base.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/types.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

struct sqlite3_stmt;

namespace flow {

class TxIndexImpl : public BaseIndex {
public:
    explicit TxIndexImpl(const std::string& db_path);
    ~TxIndexImpl() override;

    // ---- Lookup ------------------------------------------------------------

    /// Result of a transaction lookup.
    struct TxResult {
        CTransaction tx;
        uint256 block_hash;
        uint64_t block_height = 0;
        uint32_t tx_pos = 0;
        bool found = false;
    };

    /// Find a single transaction by its txid.
    TxResult find_tx(const uint256& txid) const;

    /// Find multiple transactions by their txids.
    /// Returns a result for each input txid (in the same order).
    std::vector<TxResult> find_txs(const std::vector<uint256>& txids) const;

    /// Get the number of confirmations for a transaction.
    /// Returns -1 if the transaction is not found.
    int get_confirmations(const uint256& txid, uint64_t chain_height) const;

    /// Check if a transaction exists in the index.
    bool has_tx(const uint256& txid) const;

    /// Get all transaction IDs at a given block height.
    std::vector<uint256> get_txids_at_height(uint64_t height) const;

    /// Count the total number of indexed transactions.
    uint64_t count() const;

    /// Get the block hash for a transaction.
    bool get_block_hash(const uint256& txid, uint256& block_hash) const;

protected:
    bool write_block(const CBlock& block, uint64_t height) override;
    bool undo_block(const CBlock& block, uint64_t height) override;
    bool init_db() override;

private:
    // Prepared statements
    sqlite3_stmt* stmt_insert_ = nullptr;
    sqlite3_stmt* stmt_find_ = nullptr;
    sqlite3_stmt* stmt_delete_ = nullptr;
    sqlite3_stmt* stmt_has_ = nullptr;
    sqlite3_stmt* stmt_by_height_ = nullptr;
    sqlite3_stmt* stmt_count_ = nullptr;
    sqlite3_stmt* stmt_block_hash_ = nullptr;

    void prepare_statements();
    void finalize_statements();
};

} // namespace flow

#endif // FLOWCOIN_INDEX_TXINDEX_H

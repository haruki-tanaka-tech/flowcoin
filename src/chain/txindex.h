// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Transaction index: optional SQLite-backed index that maps txid -> block
// location, enabling the getTransaction RPC. Without this index, looking
// up a transaction by ID would require scanning every block on disk.
//
// Schema:
//   tx_index(txid BLOB PRIMARY KEY, block_height INTEGER, block_hash BLOB, tx_pos INTEGER)

#ifndef FLOWCOIN_CHAIN_TXINDEX_H
#define FLOWCOIN_CHAIN_TXINDEX_H

#include "chain/blockindex.h"
#include "primitives/block.h"
#include "util/types.h"

#include <cstdint>
#include <string>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;

namespace flow {

class TxIndex {
public:
    explicit TxIndex(const std::string& db_path);
    ~TxIndex();

    // Non-copyable
    TxIndex(const TxIndex&) = delete;
    TxIndex& operator=(const TxIndex&) = delete;

    // Check if the index is open and operational
    bool is_open() const { return db_ != nullptr; }

    // Index a block's transactions
    bool index_block(const CBlock& block, uint64_t height, const uint256& block_hash);

    // Remove index for a block (reorg)
    bool deindex_block(uint64_t height);

    // Look up transaction location
    struct TxLocation {
        uint64_t block_height;
        uint256 block_hash;
        uint32_t tx_index;  // position within block
        bool found;
    };
    TxLocation find(const uint256& txid) const;

    // Get the highest indexed block height
    uint64_t get_best_height() const;

private:
    sqlite3* db_ = nullptr;

    // Prepared statements
    sqlite3_stmt* stmt_insert_ = nullptr;
    sqlite3_stmt* stmt_delete_by_height_ = nullptr;
    sqlite3_stmt* stmt_find_ = nullptr;
    sqlite3_stmt* stmt_best_height_ = nullptr;

    void init_tables();
    void prepare_statements();
    void finalize_statements();
};

} // namespace flow

#endif // FLOWCOIN_CHAIN_TXINDEX_H

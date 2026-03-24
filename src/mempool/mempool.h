// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Transaction mempool: holds unconfirmed transactions awaiting inclusion
// in a block. Provides fee-rate sorting for block assembly, double-spend
// detection within the pool, and full input validation against the UTXO set.

#ifndef FLOWCOIN_MEMPOOL_H
#define FLOWCOIN_MEMPOOL_H

#include "util/types.h"
#include "primitives/transaction.h"
#include "chain/blockindex.h"  // Uint256Hasher

#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace flow {

class UTXOSet;

struct MempoolEntry {
    CTransaction tx;
    uint256 txid;
    Amount fee;           // total input - total output
    size_t tx_size;       // serialized size in bytes
    double fee_rate;      // fee / size (atomic units per byte)
    int64_t time_added;   // unix timestamp when added to mempool
};

class Mempool {
public:
    explicit Mempool(const UTXOSet& utxo);

    // Result of attempting to add a transaction
    struct AddResult {
        bool accepted;
        std::string reject_reason;
    };

    // Add a transaction to the mempool.
    // Validates: not duplicate, not coinbase, size limit, inputs exist
    // (UTXO or other mempool tx), no double-spends within mempool,
    // signatures valid, fee >= minimum.
    AddResult add_transaction(const CTransaction& tx);

    // Remove a transaction by txid (when included in a block)
    void remove(const uint256& txid);

    // Remove transactions that conflict with a confirmed block's transactions.
    // Removes both the block's transactions and any mempool transactions
    // that spend the same inputs.
    void remove_for_block(const std::vector<CTransaction>& block_txs);

    // Check if a transaction is in the mempool
    bool exists(const uint256& txid) const;

    // Get a transaction from the mempool
    bool get(const uint256& txid, CTransaction& tx) const;

    // Get transactions sorted by fee rate (highest first) for block assembly
    std::vector<CTransaction> get_sorted_transactions(size_t max_count = 0) const;

    // Get all transaction IDs
    std::vector<uint256> get_txids() const;

    // Get mempool size (number of transactions)
    size_t size() const;

    // Get total serialized bytes of all transactions in mempool
    size_t total_bytes() const;

    // Clear all transactions
    void clear();

    // Check if an outpoint is spent by any mempool transaction
    bool is_spent_by_mempool(const uint256& txid, uint32_t vout) const;

private:
    const UTXOSet& utxo_;

    mutable std::mutex mutex_;

    // Primary storage: txid -> entry
    std::unordered_map<uint256, MempoolEntry, Uint256Hasher> txs_;

    // Fee-rate index for transaction selection (sorted descending)
    std::multimap<double, uint256, std::greater<double>> by_fee_rate_;

    // Spent outpoints tracker: (prev_txid, prev_vout) -> spending txid
    // Prevents double-spends within mempool
    struct OutpointHasher {
        size_t operator()(const std::pair<uint256, uint32_t>& p) const {
            uint64_t val;
            std::memcpy(&val, p.first.data(), 8);
            return val ^ std::hash<uint32_t>{}(p.second);
        }
    };
    std::unordered_map<std::pair<uint256, uint32_t>, uint256, OutpointHasher> spent_outpoints_;

    size_t total_bytes_ = 0;

    // Minimum fee rate in atomic units per byte
    static constexpr double MIN_FEE_RATE = 1.0;

    // Validate transaction inputs and compute fee.
    // Checks UTXO existence (or parent in mempool), pubkey hash match,
    // and Ed25519 signature verification.
    bool validate_inputs(const CTransaction& tx, Amount& fee_out,
                         std::string& error) const;

    // Remove a single transaction from all internal indexes (no lock)
    void remove_locked(const uint256& txid);
};

} // namespace flow

#endif // FLOWCOIN_MEMPOOL_H

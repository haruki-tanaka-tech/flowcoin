// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Transaction memory pool: pending unconfirmed transactions.
// Ordered by fee rate (amount per byte) for block assembly.

#pragma once

#include "core/types.h"
#include "primitives/transaction.h"

#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace flow {

struct MempoolEntry {
    CTransaction tx;
    Hash256      txid;
    Amount       fee;
    size_t       size;     // serialized size in bytes
    int64_t      time;     // when added to mempool

    // Fee rate: fee per byte (higher = more priority)
    double fee_rate() const {
        return (size > 0) ? static_cast<double>(fee.value) / static_cast<double>(size) : 0.0;
    }
};

class Mempool {
public:
    explicit Mempool(size_t max_size_bytes = 50'000'000); // 50 MB default

    // Add a transaction. Returns error if invalid or duplicate.
    Result<Ok> add(const CTransaction& tx, Amount fee);

    // Remove a transaction by txid.
    bool remove(const Hash256& txid);

    // Remove all transactions that are in the given block.
    void remove_for_block(const std::vector<CTransaction>& txs);

    // Check if a transaction is in the mempool.
    bool has(const Hash256& txid) const;

    // Get a transaction from the mempool.
    std::optional<MempoolEntry> get(const Hash256& txid) const;

    // Get transactions sorted by fee rate (highest first) for block assembly.
    // Returns up to max_count transactions.
    std::vector<CTransaction> get_sorted(size_t max_count) const;

    // Check if an outpoint is spent by any mempool transaction.
    bool is_spent(const COutPoint& outpoint) const;

    size_t size() const;
    size_t size_bytes() const { return current_size_bytes_; }

private:
    size_t max_size_bytes_;
    size_t current_size_bytes_{0};

    // txid hex → entry
    std::unordered_map<std::string, MempoolEntry> entries_;

    // fee_rate → txid hex (for ordering). multimap handles equal fee rates.
    std::multimap<double, std::string, std::greater<double>> by_fee_rate_;

    // Track spent outpoints: outpoint_key → txid hex
    std::unordered_map<std::string, std::string> spent_outpoints_;

    mutable std::mutex mu_;

    static std::string outpoint_key(const COutPoint& op);
    void evict_lowest();
};

} // namespace flow

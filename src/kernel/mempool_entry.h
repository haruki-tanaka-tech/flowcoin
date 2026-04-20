// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// MempoolEntry: metadata for a transaction in the memory pool.
// Each entry wraps a transaction with additional consensus and policy
// information needed for prioritization, fee estimation, and eviction.
//
// The mempool sorts entries by fee rate (atomic units per byte) to
// determine which transactions to include in the next block template.
// During eviction (when the mempool is full), lowest-fee-rate
// transactions are removed first.

#ifndef FLOWCOIN_KERNEL_MEMPOOL_ENTRY_H
#define FLOWCOIN_KERNEL_MEMPOOL_ENTRY_H

#include "primitives/transaction.h"
#include "util/types.h"

#include <chrono>
#include <cstdint>
#include <set>
#include <vector>

namespace flow::kernel {

// ============================================================================
// Fee rate
// ============================================================================

struct FeeRate {
    /// Fee in atomic units per 1000 bytes.
    int64_t sats_per_kb = 0;

    FeeRate() = default;
    explicit FeeRate(int64_t rate) : sats_per_kb(rate) {}

    /// Compute fee for a given size.
    int64_t get_fee(size_t size_bytes) const {
        return (sats_per_kb * static_cast<int64_t>(size_bytes)) / 1000;
    }

    /// Create a FeeRate from a total fee and size.
    static FeeRate from_fee_and_size(int64_t fee, size_t size_bytes) {
        if (size_bytes == 0) return FeeRate(0);
        return FeeRate((fee * 1000) / static_cast<int64_t>(size_bytes));
    }

    bool operator<(const FeeRate& other) const { return sats_per_kb < other.sats_per_kb; }
    bool operator>(const FeeRate& other) const { return sats_per_kb > other.sats_per_kb; }
    bool operator<=(const FeeRate& other) const { return sats_per_kb <= other.sats_per_kb; }
    bool operator>=(const FeeRate& other) const { return sats_per_kb >= other.sats_per_kb; }
    bool operator==(const FeeRate& other) const { return sats_per_kb == other.sats_per_kb; }
    bool operator!=(const FeeRate& other) const { return sats_per_kb != other.sats_per_kb; }
};

// ============================================================================
// MempoolEntry
// ============================================================================

struct MempoolEntry {
    /// The transaction itself.
    CTransaction tx;

    /// Transaction ID (cached for fast lookup).
    uint256 txid;

    /// Total fee paid by this transaction (in atomic units).
    Amount fee = 0;

    /// Serialized size in bytes.
    size_t tx_size = 0;

    /// Fee rate (fee per 1000 bytes).
    FeeRate fee_rate;

    /// Time when this transaction was added to the mempool.
    int64_t entry_time = 0;

    /// Block height when this transaction entered the mempool.
    uint64_t entry_height = 0;

    /// Number of signature operations.
    int sigops = 0;

    /// Modified fee (fee + priority adjustments from `prioritisetransaction`).
    Amount modified_fee = 0;

    /// Priority delta (from RPC prioritisetransaction).
    double priority_delta = 0.0;

    /// Fee delta (from RPC prioritisetransaction).
    Amount fee_delta = 0;

    /// Number of in-mempool ancestors (including self).
    size_t count_with_ancestors = 1;

    /// Total size of all in-mempool ancestors (including self).
    size_t size_with_ancestors = 0;

    /// Total fee of all in-mempool ancestors (including self).
    Amount fee_with_ancestors = 0;

    /// Number of in-mempool descendants (including self).
    size_t count_with_descendants = 1;

    /// Total size of all in-mempool descendants (including self).
    size_t size_with_descendants = 0;

    /// Total fee of all in-mempool descendants (including self).
    Amount fee_with_descendants = 0;

    /// Set of txids that this transaction depends on (in-mempool parents).
    std::set<uint256> parent_txids;

    /// Set of txids that depend on this transaction (in-mempool children).
    std::set<uint256> child_txids;

    /// Whether this transaction can be replaced by fee (BIP 125 style).
    bool is_replaceable = false;

    /// Whether this transaction spends unconfirmed change.
    bool spends_unconfirmed = false;

    // ---- Construction -------------------------------------------------------

    /// Create an entry from a transaction and its validation result.
    static MempoolEntry create(const CTransaction& tx, Amount fee,
                                uint64_t height) {
        MempoolEntry entry;
        entry.tx = tx;
        entry.txid = tx.get_txid();
        entry.fee = fee;
        entry.modified_fee = fee;
        entry.tx_size = tx.serialize().size();
        entry.fee_rate = FeeRate::from_fee_and_size(fee, entry.tx_size);
        entry.entry_height = height;
        entry.size_with_ancestors = entry.tx_size;
        entry.fee_with_ancestors = fee;
        entry.size_with_descendants = entry.tx_size;
        entry.fee_with_descendants = fee;

        auto now = std::chrono::system_clock::now();
        entry.entry_time = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();

        // Check if any input has the sequence number signaling replaceability
        for (const auto& input : tx.vin) {
            if (input.sequence < 0xFFFFFFFE) {
                entry.is_replaceable = true;
                break;
            }
        }

        return entry;
    }

    // ---- Comparison (for sorting) ------------------------------------------

    /// Compare by ancestor fee rate (for mining priority).
    struct CompareAncestorFeeRate {
        bool operator()(const MempoolEntry& a, const MempoolEntry& b) const {
            // Higher fee rate first
            FeeRate a_rate = FeeRate::from_fee_and_size(
                a.fee_with_ancestors, a.size_with_ancestors);
            FeeRate b_rate = FeeRate::from_fee_and_size(
                b.fee_with_ancestors, b.size_with_ancestors);
            if (a_rate != b_rate) return a_rate > b_rate;
            // Tie-break by txid for determinism
            return a.txid < b.txid;
        }
    };

    /// Compare by descendant fee rate (for eviction).
    struct CompareDescendantFeeRate {
        bool operator()(const MempoolEntry& a, const MempoolEntry& b) const {
            // Lower fee rate first (evict cheapest)
            FeeRate a_rate = FeeRate::from_fee_and_size(
                a.fee_with_descendants, a.size_with_descendants);
            FeeRate b_rate = FeeRate::from_fee_and_size(
                b.fee_with_descendants, b.size_with_descendants);
            if (a_rate != b_rate) return a_rate < b_rate;
            return a.txid < b.txid;
        }
    };

    /// Compare by entry time (for expiration).
    struct CompareEntryTime {
        bool operator()(const MempoolEntry& a, const MempoolEntry& b) const {
            if (a.entry_time != b.entry_time) return a.entry_time < b.entry_time;
            return a.txid < b.txid;
        }
    };

    // ---- Helpers -----------------------------------------------------------

    /// Get the effective fee rate considering priority adjustments.
    FeeRate get_modified_fee_rate() const {
        return FeeRate::from_fee_and_size(modified_fee, tx_size);
    }

    /// Get age in seconds since entry.
    int64_t get_age(int64_t now) const {
        return now - entry_time;
    }

    /// Update ancestor/descendant counts after a dependency is confirmed.
    void update_ancestor_state(int64_t mod_size, Amount mod_fee, int64_t mod_count) {
        size_with_ancestors = static_cast<size_t>(
            static_cast<int64_t>(size_with_ancestors) + mod_size);
        fee_with_ancestors += mod_fee;
        count_with_ancestors = static_cast<size_t>(
            static_cast<int64_t>(count_with_ancestors) + mod_count);
    }

    void update_descendant_state(int64_t mod_size, Amount mod_fee, int64_t mod_count) {
        size_with_descendants = static_cast<size_t>(
            static_cast<int64_t>(size_with_descendants) + mod_size);
        fee_with_descendants += mod_fee;
        count_with_descendants = static_cast<size_t>(
            static_cast<int64_t>(count_with_descendants) + mod_count);
    }
};

} // namespace flow::kernel

#endif // FLOWCOIN_KERNEL_MEMPOOL_ENTRY_H

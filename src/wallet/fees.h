// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Fee estimation: records confirmed transaction fee rates and provides
// estimates for future transactions targeting a certain confirmation depth.

#pragma once

#include "util/types.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>

namespace flow {

class FeeEstimator {
public:
    /// Record a transaction that was confirmed at a given block depth.
    /// @param tx_size        Serialized transaction size in bytes.
    /// @param fee            Total fee paid (atomic units).
    /// @param confirm_blocks Number of blocks between broadcast and confirmation.
    void record_confirmation(size_t tx_size, Amount fee, uint64_t confirm_blocks);

    /// Estimate the fee rate (atomic units per byte) needed to confirm within
    /// target_blocks blocks. Falls back to MIN_RELAY_FEE_RATE when there is
    /// insufficient history.
    /// @param target_blocks  Desired confirmation depth (1 = next block).
    /// @return               Estimated fee rate in atomic units per byte.
    Amount estimate_fee_rate(int target_blocks = 6) const;

    /// Minimum relay fee rate: 1 atomic unit per byte.
    static constexpr Amount MIN_RELAY_FEE_RATE = 1;

    /// Calculate the total fee for a transaction of the given size.
    /// @param tx_size        Transaction size in bytes.
    /// @param target_blocks  Desired confirmation depth.
    /// @return               Estimated total fee in atomic units.
    Amount calculate_fee(size_t tx_size, int target_blocks = 6) const;

    /// Return the number of fee records currently stored.
    size_t history_size() const;

    /// Clear all recorded fee history.
    void clear();

private:
    struct FeeRecord {
        double fee_rate;       // atomic units per byte
        int confirm_blocks;    // how many blocks it took to confirm
        int64_t recorded_at;   // monotonic ordering token
    };

    mutable std::mutex mutex_;
    std::deque<FeeRecord> history_;
    static constexpr size_t MAX_HISTORY = 10000;

    // Internal counter for ordering records (no need for real time)
    int64_t next_id_ = 0;

    // Compute the median fee rate for records confirmed within the
    // given target depth. Returns 0 if no qualifying records exist.
    double median_fee_rate_for_target(int target_blocks) const;
};

} // namespace flow

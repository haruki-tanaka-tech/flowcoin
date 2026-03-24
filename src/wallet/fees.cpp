// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "wallet/fees.h"

#include <algorithm>
#include <cmath>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// Record a confirmed transaction's fee information
// ---------------------------------------------------------------------------

void FeeEstimator::record_confirmation(size_t tx_size, Amount fee,
                                        uint64_t confirm_blocks) {
    if (tx_size == 0) return;

    double rate = static_cast<double>(fee) / static_cast<double>(tx_size);
    if (!std::isfinite(rate) || rate < 0.0) return;

    std::lock_guard<std::mutex> lock(mutex_);

    FeeRecord rec;
    rec.fee_rate = rate;
    rec.confirm_blocks = static_cast<int>(
        std::min(confirm_blocks, static_cast<uint64_t>(1000)));
    rec.recorded_at = next_id_++;

    history_.push_back(rec);

    // Evict oldest records when we exceed the cap
    while (history_.size() > MAX_HISTORY) {
        history_.pop_front();
    }
}

// ---------------------------------------------------------------------------
// Estimate fee rate for a given confirmation target
// ---------------------------------------------------------------------------

Amount FeeEstimator::estimate_fee_rate(int target_blocks) const {
    if (target_blocks < 1) target_blocks = 1;

    std::lock_guard<std::mutex> lock(mutex_);

    double median = median_fee_rate_for_target(target_blocks);

    if (median <= 0.0) {
        // Not enough data. Try progressively wider targets.
        for (int t = target_blocks + 1; t <= 144; t *= 2) {
            median = median_fee_rate_for_target(t);
            if (median > 0.0) break;
        }
    }

    if (median <= 0.0) {
        return MIN_RELAY_FEE_RATE;
    }

    // Round up to the nearest integer, ensure at least MIN_RELAY_FEE_RATE
    Amount rate = static_cast<Amount>(std::ceil(median));
    if (rate < MIN_RELAY_FEE_RATE) rate = MIN_RELAY_FEE_RATE;

    return rate;
}

// ---------------------------------------------------------------------------
// Calculate total fee for a transaction of a given size
// ---------------------------------------------------------------------------

Amount FeeEstimator::calculate_fee(size_t tx_size, int target_blocks) const {
    Amount rate = estimate_fee_rate(target_blocks);
    Amount fee = rate * static_cast<Amount>(tx_size);

    // Enforce a minimum fee of 1000 atomic units (prevents trivially small fees)
    if (fee < 1000) fee = 1000;

    return fee;
}

// ---------------------------------------------------------------------------
// History size
// ---------------------------------------------------------------------------

size_t FeeEstimator::history_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return history_.size();
}

// ---------------------------------------------------------------------------
// Clear
// ---------------------------------------------------------------------------

void FeeEstimator::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    history_.clear();
    next_id_ = 0;
}

// ---------------------------------------------------------------------------
// Internal: median fee rate for records confirmed at or below the target
// ---------------------------------------------------------------------------

double FeeEstimator::median_fee_rate_for_target(int target_blocks) const {
    // Caller holds mutex_

    // Collect fee rates from records that confirmed within target_blocks
    std::vector<double> rates;
    rates.reserve(history_.size());

    for (const auto& rec : history_) {
        if (rec.confirm_blocks <= target_blocks) {
            rates.push_back(rec.fee_rate);
        }
    }

    if (rates.empty()) return 0.0;

    // Compute the median
    size_t n = rates.size();
    auto mid = rates.begin() + static_cast<long>(n / 2);
    std::nth_element(rates.begin(), mid, rates.end());

    if (n % 2 == 0) {
        // Even count: average of the two middle elements
        double upper = *mid;
        auto lower_it = std::max_element(rates.begin(), mid);
        double lower = *lower_it;
        return (lower + upper) / 2.0;
    }

    return *mid;
}

} // namespace flow

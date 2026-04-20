// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "policy/fees.h"
#include "hash/keccak.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <set>
#include <fstream>

namespace flow {

// ============================================================================
// Bucket boundaries (sat/kB, logarithmically spaced)
// ============================================================================
// Coverage: 1 sat/kB to ~50M sat/kB (0.5 FLOW/kB)
// Uses a modified Fibonacci-like progression for even log-space coverage.

const Amount CBlockPolicyEstimator::BUCKET_BOUNDS[NUM_BUCKETS + 1] = {
    0,          // lower bound of bucket 0
    1000,       // 1 sat/byte = 1000 sat/kB
    2000,
    3000,
    5000,
    8000,
    10000,
    12000,
    15000,
    20000,
    25000,
    30000,
    40000,
    50000,
    60000,
    80000,
    100000,
    120000,
    150000,
    200000,
    250000,
    300000,
    400000,
    500000,
    600000,
    800000,
    1000000,    // 1000 sat/byte
    1200000,
    1500000,
    2000000,
    2500000,
    3000000,
    4000000,
    5000000,
    6000000,
    8000000,
    10000000,   // 10000 sat/byte
    12000000,
    15000000,
    20000000,
    25000000,
    30000000,
    40000000,
    50000000,
    60000000,
    80000000,
    100000000,  // 100000 sat/byte
    200000000,
    500000000   // upper sentinel
};

Amount CBlockPolicyEstimator::bucket_boundary(int i) {
    if (i < 0) return 0;
    if (i > NUM_BUCKETS) return BUCKET_BOUNDS[NUM_BUCKETS];
    return BUCKET_BOUNDS[i];
}

// ============================================================================
// BucketStats
// ============================================================================

void CBlockPolicyEstimator::BucketStats::decay(double factor) {
    total_confirmed *= factor;
    in_mempool *= factor;
    left_mempool *= factor;
    for (auto& c : confirmed_within) {
        c *= factor;
    }
}

double CBlockPolicyEstimator::BucketStats::success_rate(int target) const {
    if (target <= 0 || target > MAX_TARGET) return 0.0;

    double attempted = total_confirmed + in_mempool + left_mempool;
    if (attempted < 0.5) return 0.0;  // No data

    double confirmed = (target <= static_cast<int>(confirmed_within.size()))
                       ? confirmed_within[target - 1] : 0.0;
    return confirmed / attempted;
}

// ============================================================================
// Construction
// ============================================================================

CBlockPolicyEstimator::CBlockPolicyEstimator()
    : buckets_(NUM_BUCKETS) {
}

// ============================================================================
// Block processing
// ============================================================================

void CBlockPolicyEstimator::process_block(
    uint64_t height, const std::vector<CTransaction>& txs) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Apply decay to all buckets
    decay_all();

    // Build a set of confirmed txids for quick lookup
    std::set<uint256> confirmed_set;
    for (const auto& tx : txs) {
        confirmed_set.insert(tx.get_txid());
    }

    // Update tracked transactions
    std::vector<uint256> to_remove;
    for (auto& [txid, stats] : tracked_txs_) {
        if (confirmed_set.count(txid)) {
            // Transaction confirmed!
            int blocks_to_confirm = static_cast<int>(height - stats.entered_height);
            if (blocks_to_confirm < 1) blocks_to_confirm = 1;

            int bucket = stats.bucket_index;
            if (bucket >= 0 && bucket < NUM_BUCKETS) {
                buckets_[bucket].total_confirmed += 1.0;
                buckets_[bucket].in_mempool -= 1.0;
                if (buckets_[bucket].in_mempool < 0.0) {
                    buckets_[bucket].in_mempool = 0.0;
                }

                // Update confirmed_within for all targets >= blocks_to_confirm
                for (int t = blocks_to_confirm - 1;
                     t < static_cast<int>(buckets_[bucket].confirmed_within.size());
                     ++t) {
                    buckets_[bucket].confirmed_within[t] += 1.0;
                }
            }

            total_observations_++;
            to_remove.push_back(txid);
        }
    }

    for (const auto& txid : to_remove) {
        tracked_txs_.erase(txid);
    }

    last_height_ = height;
}

void CBlockPolicyEstimator::process_transaction(
    const CTransaction& tx, Amount fee, uint64_t height) {
    std::lock_guard<std::mutex> lock(mutex_);

    uint256 txid = tx.get_txid();
    size_t tx_size = tx.get_serialize_size();
    if (tx_size == 0) return;

    // Calculate fee rate in sat/kB
    Amount fee_rate = (fee * 1000) / static_cast<Amount>(tx_size);

    int bucket = find_bucket(fee_rate);
    if (bucket < 0 || bucket >= NUM_BUCKETS) return;

    TxStats stats;
    stats.txid = txid;
    stats.fee_rate = fee_rate;
    stats.entered_height = height;
    stats.tx_size = tx_size;
    stats.bucket_index = bucket;

    tracked_txs_[txid] = stats;
    buckets_[bucket].in_mempool += 1.0;
}

void CBlockPolicyEstimator::remove_transaction(const uint256& txid) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tracked_txs_.find(txid);
    if (it == tracked_txs_.end()) return;

    int bucket = it->second.bucket_index;
    if (bucket >= 0 && bucket < NUM_BUCKETS) {
        buckets_[bucket].in_mempool -= 1.0;
        if (buckets_[bucket].in_mempool < 0.0) {
            buckets_[bucket].in_mempool = 0.0;
        }
        buckets_[bucket].left_mempool += 1.0;
    }

    tracked_txs_.erase(it);
}

// ============================================================================
// Fee estimation
// ============================================================================

CBlockPolicyEstimator::FeeEstimate
CBlockPolicyEstimator::estimate_fee(int target_blocks) const {
    std::lock_guard<std::mutex> lock(mutex_);

    FeeEstimate est;
    est.target_blocks = target_blocks;

    if (target_blocks < 1) target_blocks = 1;
    if (target_blocks > MAX_TARGET) target_blocks = MAX_TARGET;

    est.fee_rate = compute_estimate(target_blocks, ECONOMICAL_THRESHOLD);
    est.confidence = ECONOMICAL_THRESHOLD;
    est.data_points = total_observations_;
    est.sufficient_data = (total_observations_ >= MIN_OBSERVATIONS);

    // Fallback to minimum relay fee if no data
    if (est.fee_rate <= 0) {
        est.fee_rate = 1000;  // 1 sat/byte
        est.sufficient_data = false;
    }

    return est;
}

CBlockPolicyEstimator::FeeEstimate
CBlockPolicyEstimator::estimate_smart_fee(int target_blocks,
                                           bool conservative) const {
    std::lock_guard<std::mutex> lock(mutex_);

    FeeEstimate est;
    est.target_blocks = target_blocks;

    if (target_blocks < 1) target_blocks = 1;
    if (target_blocks > MAX_TARGET) target_blocks = MAX_TARGET;

    double threshold = conservative ? CONSERVATIVE_THRESHOLD
                                     : ECONOMICAL_THRESHOLD;

    // Try the requested target first
    Amount rate = compute_estimate(target_blocks, threshold);

    // If insufficient data, try longer targets
    if (rate <= 0 && total_observations_ >= MIN_OBSERVATIONS) {
        for (int t = target_blocks * 2; t <= MAX_TARGET && rate <= 0; t *= 2) {
            rate = compute_estimate(t, threshold);
            if (rate > 0) {
                est.target_blocks = t;
            }
        }
    }

    // If conservative, also check shorter targets and take the maximum
    if (conservative && rate > 0) {
        for (int t = target_blocks / 2; t >= 1; t /= 2) {
            Amount shorter_rate = compute_estimate(t, threshold);
            if (shorter_rate > rate) {
                rate = shorter_rate;
            }
        }
    }

    est.fee_rate = rate;
    est.confidence = threshold;
    est.data_points = total_observations_;
    est.sufficient_data = (rate > 0 && total_observations_ >= MIN_OBSERVATIONS);

    // Absolute minimum
    if (est.fee_rate <= 0) {
        est.fee_rate = 1000;  // 1 sat/byte
        est.sufficient_data = false;
    }

    return est;
}

// ============================================================================
// Fee rate histogram
// ============================================================================

std::vector<CBlockPolicyEstimator::FeeRateBucket>
CBlockPolicyEstimator::get_fee_rate_buckets() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<FeeRateBucket> result(NUM_BUCKETS);
    size_t cumulative = 0;

    // Build histogram from highest bucket to lowest
    for (int i = NUM_BUCKETS - 1; i >= 0; --i) {
        result[i].min_rate = BUCKET_BOUNDS[i];
        result[i].max_rate = BUCKET_BOUNDS[i + 1];

        // Count tracked txs in this bucket
        size_t count = 0;
        for (const auto& [txid, stats] : tracked_txs_) {
            if (stats.bucket_index == i) {
                count++;
            }
        }

        result[i].count = count;
        cumulative += count;
        result[i].cumulative = cumulative;
    }

    return result;
}

// ============================================================================
// Persistence
// ============================================================================

bool CBlockPolicyEstimator::save(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    // Version
    uint32_t version = 1;
    file.write(reinterpret_cast<const char*>(&version), 4);

    // Last height
    file.write(reinterpret_cast<const char*>(&last_height_), 8);

    // Total observations
    uint64_t obs = total_observations_;
    file.write(reinterpret_cast<const char*>(&obs), 8);

    // Number of buckets
    uint32_t nb = NUM_BUCKETS;
    file.write(reinterpret_cast<const char*>(&nb), 4);

    // Bucket data
    for (int i = 0; i < NUM_BUCKETS; ++i) {
        const auto& b = buckets_[i];
        file.write(reinterpret_cast<const char*>(&b.total_confirmed), 8);
        file.write(reinterpret_cast<const char*>(&b.in_mempool), 8);
        file.write(reinterpret_cast<const char*>(&b.left_mempool), 8);

        // Write confirmed_within array (first MAX_TARGET entries)
        for (int t = 0; t < MAX_TARGET; ++t) {
            double val = b.confirmed_within[t];
            file.write(reinterpret_cast<const char*>(&val), 8);
        }
    }

    return file.good();
}

bool CBlockPolicyEstimator::load(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), 4);
    if (version != 1) return false;

    file.read(reinterpret_cast<char*>(&last_height_), 8);

    uint64_t obs;
    file.read(reinterpret_cast<char*>(&obs), 8);
    total_observations_ = obs;

    uint32_t nb;
    file.read(reinterpret_cast<char*>(&nb), 4);
    if (nb != NUM_BUCKETS) return false;

    buckets_.resize(NUM_BUCKETS);
    for (int i = 0; i < NUM_BUCKETS; ++i) {
        auto& b = buckets_[i];
        file.read(reinterpret_cast<char*>(&b.total_confirmed), 8);
        file.read(reinterpret_cast<char*>(&b.in_mempool), 8);
        file.read(reinterpret_cast<char*>(&b.left_mempool), 8);

        b.confirmed_within.resize(MAX_TARGET);
        for (int t = 0; t < MAX_TARGET; ++t) {
            file.read(reinterpret_cast<char*>(&b.confirmed_within[t]), 8);
        }
    }

    return file.good();
}

// ============================================================================
// Statistics
// ============================================================================

size_t CBlockPolicyEstimator::tracked_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return tracked_txs_.size();
}

size_t CBlockPolicyEstimator::observation_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_observations_;
}

uint64_t CBlockPolicyEstimator::best_height() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_height_;
}

void CBlockPolicyEstimator::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    buckets_.assign(NUM_BUCKETS, BucketStats());
    tracked_txs_.clear();
    last_height_ = 0;
    total_observations_ = 0;
}

// ============================================================================
// Internal helpers
// ============================================================================

int CBlockPolicyEstimator::find_bucket(Amount fee_rate) const {
    // Binary search for the bucket containing fee_rate
    for (int i = 0; i < NUM_BUCKETS; ++i) {
        if (fee_rate < BUCKET_BOUNDS[i + 1]) {
            return i;
        }
    }
    return NUM_BUCKETS - 1;
}

Amount CBlockPolicyEstimator::compute_estimate(
    int target, double success_threshold) const {
    // Walk from the highest bucket down, accumulating statistics
    // Find the lowest fee rate bucket where the success rate exceeds
    // the threshold.

    double total_passed = 0.0;
    double total_attempted = 0.0;
    Amount best_rate = -1;

    // Scan from highest bucket to lowest
    for (int i = NUM_BUCKETS - 1; i >= 0; --i) {
        const auto& b = buckets_[i];

        double attempted = b.total_confirmed + b.in_mempool + b.left_mempool;
        if (attempted < 0.5) continue;

        double confirmed = 0.0;
        if (target > 0 && target <= static_cast<int>(b.confirmed_within.size())) {
            confirmed = b.confirmed_within[target - 1];
        }

        total_passed += confirmed;
        total_attempted += attempted;

        if (total_attempted < MIN_OBSERVATIONS) continue;

        double rate = total_passed / total_attempted;
        if (rate >= success_threshold) {
            best_rate = BUCKET_BOUNDS[i];
            // Don't break -- keep going to find an even lower rate
        } else {
            // Once we drop below threshold, stop
            break;
        }
    }

    return best_rate;
}

void CBlockPolicyEstimator::decay_all() {
    for (auto& b : buckets_) {
        b.decay(DECAY);
    }
}

// ============================================================================
// Fee estimation analysis utilities
// ============================================================================

namespace fee_detail {

/// Compute a weighted median fee rate from bucket data.
/// Uses confirmed transaction counts as weights.
Amount weighted_median_fee_rate(
    const std::vector<CBlockPolicyEstimator::BucketStats>& buckets,
    int target) {
    // Collect weighted fee rates
    struct WeightedRate {
        Amount rate;
        double weight;
    };

    std::vector<WeightedRate> rates;
    for (int i = 0; i < CBlockPolicyEstimator::NUM_BUCKETS; ++i) {
        double confirmed = 0.0;
        if (target > 0 && target <= static_cast<int>(
                buckets[i].confirmed_within.size())) {
            confirmed = buckets[i].confirmed_within[target - 1];
        }
        if (confirmed > 0.5) {
            rates.push_back({CBlockPolicyEstimator::bucket_boundary(i),
                             confirmed});
        }
    }

    if (rates.empty()) return -1;

    // Sort by rate
    std::sort(rates.begin(), rates.end(),
        [](const WeightedRate& a, const WeightedRate& b) {
            return a.rate < b.rate;
        });

    // Find the weighted median
    double total_weight = 0.0;
    for (const auto& r : rates) {
        total_weight += r.weight;
    }

    double half = total_weight / 2.0;
    double cumulative = 0.0;
    for (const auto& r : rates) {
        cumulative += r.weight;
        if (cumulative >= half) {
            return r.rate;
        }
    }

    return rates.back().rate;
}

/// Compute the expected confirmation time for a given fee rate.
/// Returns the estimated number of blocks.
int estimate_confirmation_blocks(
    const std::vector<CBlockPolicyEstimator::BucketStats>& buckets,
    Amount fee_rate,
    double success_threshold) {
    // Find which bucket this fee rate falls into
    int bucket = 0;
    for (int i = 0; i < CBlockPolicyEstimator::NUM_BUCKETS; ++i) {
        if (fee_rate < CBlockPolicyEstimator::bucket_boundary(i + 1)) {
            bucket = i;
            break;
        }
        bucket = i;
    }

    // Find the lowest target where this bucket's success rate
    // exceeds the threshold
    for (int target = 1; target <= CBlockPolicyEstimator::MAX_TARGET; ++target) {
        double rate = buckets[bucket].success_rate(target);
        if (rate >= success_threshold) {
            return target;
        }
    }

    return CBlockPolicyEstimator::MAX_TARGET;
}

/// Detect fee rate spikes by comparing recent rates to historical average.
/// Returns a multiplier: 1.0 = normal, >1.0 = congested, <1.0 = low usage.
double detect_congestion(
    const std::vector<CBlockPolicyEstimator::BucketStats>& buckets) {
    // Sum all current mempool transactions across buckets
    double total_in_mempool = 0.0;
    double total_confirmed = 0.0;

    for (const auto& b : buckets) {
        total_in_mempool += b.in_mempool;
        total_confirmed += b.total_confirmed;
    }

    if (total_confirmed < 1.0) return 1.0;

    // Congestion ratio: how many are waiting relative to throughput
    double ratio = total_in_mempool / total_confirmed;
    return std::max(0.1, std::min(10.0, ratio));
}

/// Compute a confidence interval for a fee rate estimate.
/// Returns (lower_bound, upper_bound) in sat/kB.
std::pair<Amount, Amount> estimate_confidence_interval(
    const std::vector<CBlockPolicyEstimator::BucketStats>& buckets,
    int target,
    double confidence_level) {
    // Find the fee rate range where success_rate >= confidence_level
    Amount lower = -1, upper = -1;

    for (int i = 0; i < CBlockPolicyEstimator::NUM_BUCKETS; ++i) {
        double rate = buckets[i].success_rate(target);
        if (rate >= confidence_level) {
            Amount boundary = CBlockPolicyEstimator::bucket_boundary(i);
            if (lower < 0) lower = boundary;
            upper = CBlockPolicyEstimator::bucket_boundary(i + 1);
        }
    }

    if (lower < 0) lower = 0;
    if (upper < 0) upper = lower;

    return {lower, upper};
}

/// Analyze fee rate trends over recent blocks.
/// Returns the direction: >0 = increasing, <0 = decreasing, 0 = stable.
int fee_rate_trend(
    const std::vector<CBlockPolicyEstimator::BucketStats>& buckets,
    int short_window,
    int long_window) {
    // Compare success rates between short and long targets
    // If short-target success rates are lower, fees are increasing
    double short_avg = 0.0, long_avg = 0.0;
    int count = 0;

    for (int i = 0; i < CBlockPolicyEstimator::NUM_BUCKETS; ++i) {
        double attempted = buckets[i].total_confirmed +
                           buckets[i].in_mempool +
                           buckets[i].left_mempool;
        if (attempted < 1.0) continue;

        double short_rate = buckets[i].success_rate(short_window);
        double long_rate = buckets[i].success_rate(long_window);

        short_avg += short_rate;
        long_avg += long_rate;
        count++;
    }

    if (count == 0) return 0;

    short_avg /= count;
    long_avg /= count;

    double diff = long_avg - short_avg;
    if (diff > 0.1) return 1;   // Fees increasing (harder to confirm quickly)
    if (diff < -0.1) return -1; // Fees decreasing
    return 0;                    // Stable
}

} // namespace fee_detail

} // namespace flow

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Smart fee estimation based on observed confirmation times.
// Uses bucketed exponential moving averages to track how quickly
// transactions at different fee rates confirm. Produces estimates
// of the fee rate needed to confirm within N blocks.
//
// Architecture:
//   - Fee rates are bucketed into 48 logarithmically-spaced buckets
//   - For each bucket, we track: confirmed-within-N, total-attempted
//   - Exponential decay (0.998 per block) weights recent observations
//   - Estimates are computed by finding the lowest bucket where
//     success rate exceeds the target threshold (85% or 95%)

#ifndef FLOWCOIN_POLICY_FEES_H
#define FLOWCOIN_POLICY_FEES_H

#include "primitives/transaction.h"
#include "util/types.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace flow {

class CBlockPolicyEstimator {
public:
    CBlockPolicyEstimator();
    ~CBlockPolicyEstimator() = default;

    // Non-copyable
    CBlockPolicyEstimator(const CBlockPolicyEstimator&) = delete;
    CBlockPolicyEstimator& operator=(const CBlockPolicyEstimator&) = delete;

    // ---- Block processing --------------------------------------------------

    /// Process a confirmed block: update confirmation statistics for
    /// all tracked transactions that were confirmed in this block.
    void process_block(uint64_t height,
                       const std::vector<CTransaction>& txs);

    /// Record a transaction entering the mempool.
    /// The fee and size are used to determine which bucket to track it in.
    void process_transaction(const CTransaction& tx, Amount fee,
                              uint64_t height);

    /// Remove a transaction from tracking (e.g., evicted from mempool).
    void remove_transaction(const uint256& txid);

    // ---- Fee estimation ----------------------------------------------------

    /// Fee estimate result.
    struct FeeEstimate {
        Amount fee_rate = 0;         // satoshis per kB
        int target_blocks = 0;       // requested target
        double confidence = 0.0;     // success probability (0-1)
        size_t data_points = 0;      // observations used
        bool sufficient_data = false; // true if enough data for estimate
    };

    /// Estimate fee rate for confirmation within target_blocks.
    /// Returns the lowest fee rate where at least success_threshold
    /// fraction of transactions confirmed within the target.
    FeeEstimate estimate_fee(int target_blocks) const;

    /// Smart fee estimation with fallback logic.
    /// If conservative=true, uses a higher success threshold (95%),
    /// otherwise uses 85%.
    /// Falls back to longer targets if data is insufficient.
    FeeEstimate estimate_smart_fee(int target_blocks,
                                    bool conservative = true) const;

    // ---- Fee rate histogram -------------------------------------------------

    /// A bucket in the fee rate histogram.
    struct FeeRateBucket {
        Amount min_rate = 0;     // lower bound (sat/kB)
        Amount max_rate = 0;     // upper bound (sat/kB)
        size_t count = 0;        // transactions in this bucket
        size_t cumulative = 0;   // cumulative count from highest bucket down
    };

    /// Get the current fee rate distribution of tracked transactions.
    std::vector<FeeRateBucket> get_fee_rate_buckets() const;

    // ---- Persistence -------------------------------------------------------

    /// Save estimator state to a file.
    bool save(const std::string& path) const;

    /// Load estimator state from a file.
    bool load(const std::string& path);

    // ---- Statistics --------------------------------------------------------

    /// Get the number of transactions currently being tracked.
    size_t tracked_count() const;

    /// Get the number of data points (completed observations).
    size_t observation_count() const;

    /// Get the highest block height that has been processed.
    uint64_t best_height() const;

    /// Clear all tracking data and observations.
    void clear();

    // ---- Constants ---------------------------------------------------------

    /// Number of fee rate buckets (logarithmically spaced).
    static constexpr int NUM_BUCKETS = 48;

    /// Exponential decay factor per block.
    static constexpr double DECAY = 0.998;

    /// Maximum confirmation target (blocks).
    static constexpr int MAX_TARGET = 1008;

    /// Minimum number of observations needed for an estimate.
    static constexpr size_t MIN_OBSERVATIONS = 10;

    /// Success threshold for conservative estimates.
    static constexpr double CONSERVATIVE_THRESHOLD = 0.95;

    /// Success threshold for economical estimates.
    static constexpr double ECONOMICAL_THRESHOLD = 0.85;

    /// Get the bucket boundary for bucket index i.
    static Amount bucket_boundary(int i);

private:
    // ---- Tracking structure ------------------------------------------------

    struct TxStats {
        uint256 txid;
        Amount fee_rate = 0;        // sat/kB
        uint64_t entered_height = 0;
        size_t tx_size = 0;
        int bucket_index = -1;
    };

    // ---- Bucket statistics -------------------------------------------------

    struct BucketStats {
        // Exponentially decayed totals
        double total_confirmed = 0.0;
        double in_mempool = 0.0;
        double left_mempool = 0.0;

        // Confirmed-within-N statistics (index = blocks to confirm - 1)
        // confirmed_within[i] = count of txs confirmed within (i+1) blocks
        std::vector<double> confirmed_within;

        BucketStats() : confirmed_within(MAX_TARGET, 0.0) {}

        /// Apply exponential decay to all counters.
        void decay(double factor);

        /// Get the success rate for confirming within target blocks.
        double success_rate(int target) const;
    };

    // ---- State -------------------------------------------------------------

    std::vector<BucketStats> buckets_;

    // Tracked unconfirmed transactions
    std::map<uint256, TxStats> tracked_txs_;

    uint64_t last_height_ = 0;
    size_t total_observations_ = 0;

    mutable std::mutex mutex_;

    // ---- Internal helpers --------------------------------------------------

    /// Find the bucket index for a given fee rate.
    int find_bucket(Amount fee_rate) const;

    /// Compute an estimate from bucket data.
    Amount compute_estimate(int target, double success_threshold) const;

    /// Apply decay to all buckets (called once per block).
    void decay_all();

    // ---- Bucket boundaries (logarithmic spacing) ---------------------------
    // Boundaries: 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, ...
    // Approximately Fibonacci-like for good coverage of fee rate space.
    static const Amount BUCKET_BOUNDS[NUM_BUCKETS + 1];
};

} // namespace flow

#endif // FLOWCOIN_POLICY_FEES_H

// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Difficulty monitoring and estimation for the mining subsystem.
// Provides difficulty history tracking, estimated time-to-block calculations,
// network hashrate estimation, and difficulty adjustment predictions.

#ifndef FLOWCOIN_MINING_DIFFICULTY_H
#define FLOWCOIN_MINING_DIFFICULTY_H

#include "util/arith_uint256.h"
#include "util/types.h"

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace flow {

class ChainState;
struct CBlockIndex;

// ---------------------------------------------------------------------------
// DifficultyInfo -- snapshot of difficulty state
// ---------------------------------------------------------------------------

struct DifficultyInfo {
    uint64_t height;                    //!< Block height
    uint32_t nbits;                     //!< Compact difficulty target
    double difficulty;                  //!< Human-readable difficulty
    int64_t timestamp;                  //!< Block timestamp
    double block_time;                  //!< Time since previous block (seconds)
    double estimated_hashrate;          //!< Estimated network hashrate at this block

    /// Format difficulty as a human-readable string.
    std::string difficulty_string() const;
};

// ---------------------------------------------------------------------------
// RetargetInfo -- information about an upcoming difficulty adjustment
// ---------------------------------------------------------------------------

struct RetargetInfo {
    uint64_t next_retarget_height;      //!< Height of next retarget
    int blocks_until_retarget;          //!< Blocks remaining until retarget
    int64_t expected_retarget_time;     //!< Estimated Unix timestamp of retarget
    double estimated_change;            //!< Estimated difficulty change factor
    uint32_t estimated_nbits;           //!< Estimated new nbits value
    double current_period_elapsed;      //!< Seconds elapsed in current retarget period
    double current_period_target;       //!< Target seconds for current period
    bool is_at_retarget;                //!< Whether we're at a retarget boundary
};

// ---------------------------------------------------------------------------
// DifficultyMonitor -- tracks and analyzes difficulty
// ---------------------------------------------------------------------------

class DifficultyMonitor {
public:
    explicit DifficultyMonitor(const ChainState& chain);

    /// Update the monitor with the current chain state.
    void update();

    /// Get the current difficulty information.
    DifficultyInfo get_current() const;

    /// Get difficulty history for the last N blocks.
    std::vector<DifficultyInfo> get_history(size_t max_entries = 100) const;

    /// Get information about the next difficulty adjustment.
    RetargetInfo get_retarget_info() const;

    /// Estimate the network hashrate based on recent block times.
    /// @param window  Number of recent blocks to average over.
    double estimate_hashrate(int window = 144) const;

    /// Estimate the time (in seconds) until the next block is found,
    /// given the current difficulty and estimated network hashrate.
    double estimate_time_to_block() const;

    /// Estimate the time until the next block for a miner with the given hashrate.
    double estimate_time_to_block(double miner_hashrate) const;

    /// Compute the probability of finding a block with the given hashrate
    /// within the given time window (in seconds).
    double block_probability(double hashrate, double seconds) const;

    /// Get the difficulty as a floating-point number.
    /// difficulty = target_at_genesis / target_at_current
    static double compute_difficulty(uint32_t nbits);

    /// Get the difficulty ratio between two nbits values.
    static double difficulty_ratio(uint32_t nbits_old, uint32_t nbits_new);

    /// Convert a difficulty value to a human-readable string.
    static std::string format_difficulty(double difficulty);

    /// Estimate network hashrate from difficulty and target block time.
    static double hashrate_from_difficulty(double difficulty,
                                            int64_t target_block_time = 600);

    /// Get the minimum and maximum difficulty from history.
    void get_difficulty_range(double& min_diff, double& max_diff,
                              size_t window = 0) const;

    /// Get average block time over a window.
    double get_average_block_time(size_t window = 144) const;

private:
    const ChainState& chain_;
    mutable std::mutex mutex_;

    // History of difficulty snapshots
    std::deque<DifficultyInfo> history_;
    static constexpr size_t MAX_HISTORY = 10000;

    /// Build a DifficultyInfo from a block index entry.
    DifficultyInfo build_info(const CBlockIndex* pindex, const CBlockIndex* pprev) const;

    /// Decode nbits into a 256-bit target.
    static arith_uint256 decode_target(uint32_t nbits);
};

// ---------------------------------------------------------------------------
// SolveTimeSampler -- tracks solve time distribution
// ---------------------------------------------------------------------------
// Useful for miners to understand their expected earnings.

class SolveTimeSampler {
public:
    /// Record a block solve time (seconds).
    void add_sample(double solve_time_seconds);

    /// Get the mean solve time.
    double mean() const;

    /// Get the median solve time.
    double median() const;

    /// Get the Nth percentile solve time.
    double percentile(double p) const;

    /// Get the standard deviation.
    double stddev() const;

    /// Get the number of samples.
    size_t count() const;

    /// Clear all samples.
    void clear();

    /// Get a human-readable summary.
    std::string summary() const;

private:
    mutable std::mutex mutex_;
    std::deque<double> samples_;
    static constexpr size_t MAX_SAMPLES = 10000;
};

} // namespace flow

#endif // FLOWCOIN_MINING_DIFFICULTY_H

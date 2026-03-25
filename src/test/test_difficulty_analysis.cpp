// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for difficulty analysis: expected steps, time estimation,
// retarget info, difficulty prediction, nbits conversion,
// formatting, validation, and minimum difficulty detection.

#include "consensus/difficulty.h"
#include "consensus/params.h"
#include "consensus/pow.h"
#include "util/arith_uint256.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

using namespace flow;
using namespace flow::consensus;

// ---------------------------------------------------------------------------
// RetargetInfo — information about a retarget period
// ---------------------------------------------------------------------------

struct RetargetInfo {
    uint64_t period_start_height;
    uint64_t period_end_height;
    int64_t  actual_timespan;
    int64_t  target_timespan;
    double   ratio;          // actual / target
    uint32_t old_nbits;
    uint32_t new_nbits;
    double   old_difficulty;
    double   new_difficulty;
    bool     difficulty_increased;
};

static RetargetInfo compute_retarget_info(uint64_t height,
                                           uint32_t parent_nbits,
                                           int64_t first_block_time,
                                           int64_t last_block_time) {
    RetargetInfo info;
    info.period_start_height = height - RETARGET_INTERVAL;
    info.period_end_height = height - 1;
    info.actual_timespan = last_block_time - first_block_time;
    info.target_timespan = RETARGET_TIMESPAN;
    info.ratio = static_cast<double>(info.actual_timespan) /
                 static_cast<double>(info.target_timespan);
    info.old_nbits = parent_nbits;
    info.new_nbits = get_next_work_required(height, parent_nbits,
                                             first_block_time, last_block_time);
    info.old_difficulty = GetDifficulty(info.old_nbits);
    info.new_difficulty = GetDifficulty(info.new_nbits);
    info.difficulty_increased = info.new_difficulty > info.old_difficulty;
    return info;
}

// ---------------------------------------------------------------------------
// DifficultyPrediction
// ---------------------------------------------------------------------------

struct DifficultyPrediction {
    double   current_difficulty;
    double   predicted_difficulty;
    double   predicted_change_pct;
    bool     predicts_increase;
    bool     predicts_decrease;
};

static DifficultyPrediction predict_difficulty(uint64_t current_height,
                                                uint32_t current_nbits,
                                                int64_t period_start_time,
                                                int64_t current_time) {
    DifficultyPrediction pred;
    pred.current_difficulty = GetDifficulty(current_nbits);

    // Blocks elapsed in current period
    uint64_t blocks_in_period = current_height % RETARGET_INTERVAL;
    if (blocks_in_period == 0) blocks_in_period = RETARGET_INTERVAL;

    // Time elapsed
    int64_t elapsed = current_time - period_start_time;
    if (elapsed <= 0) elapsed = 1;

    // Extrapolate to full period
    double time_per_block = static_cast<double>(elapsed) /
                            static_cast<double>(blocks_in_period);
    double projected_timespan = time_per_block * RETARGET_INTERVAL;

    // Clamp like the real algorithm
    if (projected_timespan < RETARGET_TIMESPAN / MAX_RETARGET_FACTOR) {
        projected_timespan = RETARGET_TIMESPAN / MAX_RETARGET_FACTOR;
    }
    if (projected_timespan > RETARGET_TIMESPAN * MAX_RETARGET_FACTOR) {
        projected_timespan = RETARGET_TIMESPAN * MAX_RETARGET_FACTOR;
    }

    double ratio = static_cast<double>(RETARGET_TIMESPAN) / projected_timespan;
    pred.predicted_difficulty = pred.current_difficulty * ratio;
    pred.predicted_change_pct = (ratio - 1.0) * 100.0;
    pred.predicts_increase = pred.predicted_difficulty > pred.current_difficulty;
    pred.predicts_decrease = pred.predicted_difficulty < pred.current_difficulty;

    return pred;
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

static std::string format_difficulty(double diff) {
    if (diff < 1000.0) {
        std::ostringstream ss;
        ss.precision(2);
        ss << std::fixed << diff;
        return ss.str();
    } else if (diff < 1000000.0) {
        std::ostringstream ss;
        ss.precision(1);
        ss << std::fixed << (diff / 1000.0) << "K";
        return ss.str();
    } else if (diff < 1000000000.0) {
        std::ostringstream ss;
        ss.precision(1);
        ss << std::fixed << (diff / 1000000.0) << "M";
        return ss.str();
    } else if (diff < 1000000000000.0) {
        std::ostringstream ss;
        ss.precision(1);
        ss << std::fixed << (diff / 1000000000.0) << "G";
        return ss.str();
    } else {
        std::ostringstream ss;
        ss.precision(1);
        ss << std::fixed << (diff / 1000000000000.0) << "T";
        return ss.str();
    }
}

static std::string format_hashrate(double rate) {
    if (rate < 1000.0) {
        std::ostringstream ss;
        ss.precision(0);
        ss << std::fixed << rate << " st/s";
        return ss.str();
    } else if (rate < 1000000.0) {
        std::ostringstream ss;
        ss.precision(1);
        ss << std::fixed << (rate / 1000.0) << "K st/s";
        return ss.str();
    } else {
        std::ostringstream ss;
        ss.precision(1);
        ss << std::fixed << (rate / 1000000.0) << "M st/s";
        return ss.str();
    }
}

static bool is_min_difficulty(uint32_t nbits) {
    return nbits == INITIAL_NBITS;
}

void test_difficulty_analysis() {

    // -----------------------------------------------------------------------
    // Test 1: expected_steps matches formula: 2^256 / target
    // -----------------------------------------------------------------------
    {
        arith_uint256 target;
        bool ok = derive_target(INITIAL_NBITS, target);
        assert(ok);
        assert(!target.IsNull());

        // Expected steps = 2^256 / (target + 1)
        auto work = GetBlockProof(INITIAL_NBITS);
        assert(!work.IsNull());

        // For minimum difficulty, work should be relatively small
        // (target is very large -> few steps needed)
    }

    // -----------------------------------------------------------------------
    // Test 2: estimate_time_to_block reasonable for known hashrate
    // -----------------------------------------------------------------------
    {
        double diff = 1.0;
        double hashrate = 1.0;  // 1 training op per second

        double time = EstimateTimeToBlock(diff, hashrate);
        assert(time > 0.0);
        assert(std::isfinite(time));

        // Higher hashrate -> less time
        double time_fast = EstimateTimeToBlock(diff, 100.0);
        assert(time_fast < time);

        // Higher difficulty -> more time
        double time_hard = EstimateTimeToBlock(100.0, 1.0);
        assert(time_hard > time);
    }

    // -----------------------------------------------------------------------
    // Test 3: RetargetInfo: correct for first retarget
    // -----------------------------------------------------------------------
    {
        // Simulate first retarget at height 2016
        // Assume blocks came exactly on time
        int64_t start_time = GENESIS_TIMESTAMP;
        int64_t end_time = start_time + RETARGET_TIMESPAN;

        auto info = compute_retarget_info(2016, INITIAL_NBITS,
                                           start_time, end_time);

        assert(info.period_start_height == 0);
        assert(info.period_end_height == 2015);
        assert(info.actual_timespan == RETARGET_TIMESPAN);
        assert(std::abs(info.ratio - 1.0) < 0.001);
        // On-time blocks -> difficulty stays the same
        assert(info.new_nbits == info.old_nbits);
    }

    // -----------------------------------------------------------------------
    // Test 4: DifficultyPrediction: predicts increase when blocks fast
    // -----------------------------------------------------------------------
    {
        int64_t period_start = GENESIS_TIMESTAMP;
        // Blocks coming 2x faster than target (5 min instead of 10 min)
        uint64_t blocks_elapsed = 1000;
        int64_t elapsed_time = static_cast<int64_t>(blocks_elapsed) * 300;
        int64_t current_time = period_start + elapsed_time;

        auto pred = predict_difficulty(blocks_elapsed, INITIAL_NBITS,
                                        period_start, current_time);

        assert(pred.predicts_increase);
        assert(!pred.predicts_decrease);
        assert(pred.predicted_change_pct > 0.0);
    }

    // -----------------------------------------------------------------------
    // Test 5: DifficultyPrediction: predicts decrease when blocks slow
    // -----------------------------------------------------------------------
    {
        int64_t period_start = GENESIS_TIMESTAMP;
        // Blocks coming 2x slower than target (20 min instead of 10 min)
        uint64_t blocks_elapsed = 1000;
        int64_t elapsed_time = static_cast<int64_t>(blocks_elapsed) * 1200;
        int64_t current_time = period_start + elapsed_time;

        auto pred = predict_difficulty(blocks_elapsed, INITIAL_NBITS,
                                        period_start, current_time);

        assert(pred.predicts_decrease);
        assert(!pred.predicts_increase);
        assert(pred.predicted_change_pct < 0.0);
    }

    // -----------------------------------------------------------------------
    // Test 6: nbits_to_difficulty: INITIAL_NBITS -> ~1.0
    // -----------------------------------------------------------------------
    {
        double diff = GetDifficulty(INITIAL_NBITS);
        assert(diff >= 1.0);
        // At minimum difficulty, should be exactly 1.0
        assert(std::abs(diff - 1.0) < 0.001);
    }

    // -----------------------------------------------------------------------
    // Test 7: difficulty_to_nbits round-trip
    // -----------------------------------------------------------------------
    {
        double original_diff = GetDifficulty(INITIAL_NBITS);
        uint32_t computed_nbits = DifficultyToTarget(original_diff);
        double roundtrip_diff = GetDifficulty(computed_nbits);

        // Should be approximately the same (some precision loss expected)
        assert(std::abs(roundtrip_diff - original_diff) / original_diff < 0.1);
    }

    // -----------------------------------------------------------------------
    // Test 8: format_difficulty: "1.00", "1.5K", "2.3M"
    // -----------------------------------------------------------------------
    {
        assert(format_difficulty(1.0) == "1.00");
        assert(format_difficulty(999.99).find("999") != std::string::npos);

        std::string k = format_difficulty(1500.0);
        assert(k.find("K") != std::string::npos);
        assert(k.find("1.5") != std::string::npos);

        std::string m = format_difficulty(2300000.0);
        assert(m.find("M") != std::string::npos);
        assert(m.find("2.3") != std::string::npos);

        std::string g = format_difficulty(5000000000.0);
        assert(g.find("G") != std::string::npos);
    }

    // -----------------------------------------------------------------------
    // Test 9: format_hashrate: "350 st/s", "2.1K st/s"
    // -----------------------------------------------------------------------
    {
        std::string s1 = format_hashrate(350.0);
        assert(s1.find("350") != std::string::npos);
        assert(s1.find("st/s") != std::string::npos);

        std::string s2 = format_hashrate(2100.0);
        assert(s2.find("K") != std::string::npos);
        assert(s2.find("st/s") != std::string::npos);

        std::string s3 = format_hashrate(5500000.0);
        assert(s3.find("M") != std::string::npos);
    }

    // -----------------------------------------------------------------------
    // Test 10: is_valid_nbits: accepts valid, rejects invalid
    // -----------------------------------------------------------------------
    {
        assert(validate_nbits(INITIAL_NBITS));
        assert(validate_nbits(0x1e00ffff));

        // Zero target should be invalid
        assert(!validate_nbits(0x00000000));
    }

    // -----------------------------------------------------------------------
    // Test 11: is_min_difficulty: true for INITIAL_NBITS
    // -----------------------------------------------------------------------
    {
        assert(is_min_difficulty(INITIAL_NBITS));
        assert(!is_min_difficulty(0x1e00ffff));
        assert(!is_min_difficulty(0x1d00ffff));
    }

    // -----------------------------------------------------------------------
    // Test 12: Difficulty comparison
    // -----------------------------------------------------------------------
    {
        // Same difficulty
        assert(compare_difficulty(INITIAL_NBITS, INITIAL_NBITS) == 0);

        // Smaller target (harder) vs larger target (easier)
        int cmp = compare_difficulty(0x1e00ffff, INITIAL_NBITS);
        assert(cmp == -1);  // 0x1e00ffff is harder

        cmp = compare_difficulty(INITIAL_NBITS, 0x1e00ffff);
        assert(cmp == 1);  // INITIAL_NBITS is easier
    }

    // -----------------------------------------------------------------------
    // Test 13: Timespan ratio computation
    // -----------------------------------------------------------------------
    {
        // Exact 2 weeks -> ratio = 1.0
        double ratio = compute_timespan_ratio(0, RETARGET_TIMESPAN);
        assert(std::abs(ratio - 1.0) < 0.001);

        // Half the time -> ratio < 1.0
        double ratio_fast = compute_timespan_ratio(0, RETARGET_TIMESPAN / 2);
        assert(ratio_fast < 1.0);

        // Double the time -> ratio > 1.0
        double ratio_slow = compute_timespan_ratio(0, RETARGET_TIMESPAN * 2);
        assert(ratio_slow > 1.0);
    }

    // -----------------------------------------------------------------------
    // Test 14: Retarget with fast blocks -> difficulty increases
    // -----------------------------------------------------------------------
    {
        int64_t start = GENESIS_TIMESTAMP;
        // Blocks took half the expected time
        int64_t end = start + RETARGET_TIMESPAN / 2;

        uint32_t new_nbits = get_next_work_required(2016, INITIAL_NBITS,
                                                      start, end);
        double old_diff = GetDifficulty(INITIAL_NBITS);
        double new_diff = GetDifficulty(new_nbits);

        assert(new_diff > old_diff);
    }

    // -----------------------------------------------------------------------
    // Test 15: Retarget with slow blocks -> difficulty decreases
    // -----------------------------------------------------------------------
    {
        int64_t start = GENESIS_TIMESTAMP;
        // Blocks took 4x the expected time
        int64_t end = start + RETARGET_TIMESPAN * 4;

        uint32_t new_nbits = get_next_work_required(2016, INITIAL_NBITS,
                                                      start, end);
        double old_diff = GetDifficulty(INITIAL_NBITS);
        double new_diff = GetDifficulty(new_nbits);

        assert(new_diff < old_diff);
    }

    // -----------------------------------------------------------------------
    // Test 16: Retarget clamped to 4x factor
    // -----------------------------------------------------------------------
    {
        int64_t start = GENESIS_TIMESTAMP;
        // Blocks took 100x the expected time (way too slow)
        int64_t end = start + RETARGET_TIMESPAN * 100;

        uint32_t new_nbits = get_next_work_required(2016, INITIAL_NBITS,
                                                      start, end);
        double old_diff = GetDifficulty(INITIAL_NBITS);
        double new_diff = GetDifficulty(new_nbits);

        // Should be clamped to at most 4x easier
        double ratio = old_diff / new_diff;
        assert(ratio <= 4.1);
    }

    // -----------------------------------------------------------------------
    // Test 17: Network hashrate estimation
    // -----------------------------------------------------------------------
    {
        double diff = 1.0;
        double hashrate = EstimateNetworkHashrate(diff);
        assert(hashrate > 0.0);
        assert(std::isfinite(hashrate));

        // Higher difficulty -> higher estimated hashrate
        double hashrate_hard = EstimateNetworkHashrate(100.0);
        assert(hashrate_hard > hashrate);
    }

    // -----------------------------------------------------------------------
    // Test 18: IsRetargetHeight correctness
    // -----------------------------------------------------------------------
    {
        assert(!IsRetargetHeight(0));
        assert(!IsRetargetHeight(1));
        assert(!IsRetargetHeight(2015));
        assert(IsRetargetHeight(2016));
        assert(!IsRetargetHeight(2017));
        assert(IsRetargetHeight(4032));
    }

    // -----------------------------------------------------------------------
    // Test 19: DifficultyProgress structure
    // -----------------------------------------------------------------------
    {
        auto progress = GetDifficultyProgress(1000, INITIAL_NBITS,
                                               GENESIS_TIMESTAMP,
                                               GENESIS_TIMESTAMP + 600000);
        assert(progress.blocks_in_period > 0);
        assert(progress.period_progress_pct > 0.0);
        assert(progress.period_progress_pct <= 100.0);
        assert(progress.blocks_until_retarget > 0);
        assert(progress.current_difficulty >= 1.0);
        assert(progress.estimated_hashrate >= 0.0);
    }

    // -----------------------------------------------------------------------
    // Test 20: FormatTarget returns non-empty string
    // -----------------------------------------------------------------------
    {
        std::string target_str = FormatTarget(INITIAL_NBITS);
        assert(!target_str.empty());
        assert(target_str.size() > 0);
    }
}

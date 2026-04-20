// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "mining/difficulty.h"
#include "chain/chainstate.h"
#include "util/time.h"
#include "chain/blockindex.h"
#include "consensus/params.h"
#include "util/arith_uint256.h"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <sstream>

namespace flow {

// ===========================================================================
// DifficultyInfo
// ===========================================================================

std::string DifficultyInfo::difficulty_string() const {
    return DifficultyMonitor::format_difficulty(difficulty);
}

// ===========================================================================
// DifficultyMonitor
// ===========================================================================

DifficultyMonitor::DifficultyMonitor(const ChainState& chain)
    : chain_(chain) {}

// ---------------------------------------------------------------------------
// decode_target
// ---------------------------------------------------------------------------

arith_uint256 DifficultyMonitor::decode_target(uint32_t nbits) {
    arith_uint256 target;
    target.SetCompact(nbits);
    return target;
}

// ---------------------------------------------------------------------------
// compute_difficulty
// ---------------------------------------------------------------------------

double DifficultyMonitor::compute_difficulty(uint32_t nbits) {
    arith_uint256 target = decode_target(nbits);
    if (target.IsNull()) return 0.0;

    // Genesis difficulty target
    arith_uint256 genesis_target = decode_target(consensus::INITIAL_NBITS);
    if (genesis_target.IsNull()) return 0.0;

    // difficulty = genesis_target / current_target
    // To avoid integer division issues with 256-bit numbers, we use
    // the bit positions for an approximation.
    int target_bits = target.bits();

    if (target_bits <= 0) return std::numeric_limits<double>::infinity();

    // More precise calculation using the top 64 bits
    arith_uint256 ratio = genesis_target / target;
    return static_cast<double>(ratio.GetLow64());
}

// ---------------------------------------------------------------------------
// difficulty_ratio
// ---------------------------------------------------------------------------

double DifficultyMonitor::difficulty_ratio(uint32_t nbits_old, uint32_t nbits_new) {
    double old_diff = compute_difficulty(nbits_old);
    double new_diff = compute_difficulty(nbits_new);
    if (old_diff <= 0.0) return 0.0;
    return new_diff / old_diff;
}

// ---------------------------------------------------------------------------
// format_difficulty
// ---------------------------------------------------------------------------

std::string DifficultyMonitor::format_difficulty(double difficulty) {
    char buf[64];
    if (difficulty >= 1e12) {
        std::snprintf(buf, sizeof(buf), "%.2f T", difficulty / 1e12);
    } else if (difficulty >= 1e9) {
        std::snprintf(buf, sizeof(buf), "%.2f G", difficulty / 1e9);
    } else if (difficulty >= 1e6) {
        std::snprintf(buf, sizeof(buf), "%.2f M", difficulty / 1e6);
    } else if (difficulty >= 1e3) {
        std::snprintf(buf, sizeof(buf), "%.2f K", difficulty / 1e3);
    } else {
        std::snprintf(buf, sizeof(buf), "%.4f", difficulty);
    }
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// hashrate_from_difficulty
// ---------------------------------------------------------------------------

double DifficultyMonitor::hashrate_from_difficulty(double difficulty,
                                                     int64_t target_block_time) {
    if (target_block_time <= 0) return 0.0;
    // hashrate = difficulty * 2^32 / target_block_time
    // This is the standard Bitcoin formula.
    return difficulty * 4294967296.0 / static_cast<double>(target_block_time);
}

// ---------------------------------------------------------------------------
// build_info
// ---------------------------------------------------------------------------

DifficultyInfo DifficultyMonitor::build_info(const CBlockIndex* pindex,
                                              const CBlockIndex* pprev) const {
    DifficultyInfo info;
    info.height = pindex->height;
    info.nbits = pindex->nbits;
    info.difficulty = compute_difficulty(pindex->nbits);
    info.timestamp = pindex->timestamp;

    if (pprev) {
        info.block_time = static_cast<double>(pindex->timestamp - pprev->timestamp);
    } else {
        info.block_time = static_cast<double>(consensus::TARGET_BLOCK_TIME);
    }

    info.estimated_hashrate = hashrate_from_difficulty(info.difficulty);
    return info;
}

// ---------------------------------------------------------------------------
// update
// ---------------------------------------------------------------------------

void DifficultyMonitor::update() {
    std::lock_guard<std::mutex> lock(mutex_);

    CBlockIndex* tip = chain_.tip();
    if (!tip) return;

    // Determine what height we already have
    uint64_t last_height = 0;
    if (!history_.empty()) {
        last_height = history_.back().height;
    }

    // Walk the chain from last_height to tip and add entries
    // We need to collect entries in order, so build a list from tip backwards
    std::vector<const CBlockIndex*> new_blocks;
    const CBlockIndex* pindex = tip;
    while (pindex && pindex->height > last_height) {
        new_blocks.push_back(pindex);
        pindex = pindex->prev;
    }

    // Add in forward order
    for (auto it = new_blocks.rbegin(); it != new_blocks.rend(); ++it) {
        const CBlockIndex* prev = (*it)->prev;
        DifficultyInfo info = build_info(*it, prev);
        history_.push_back(info);

        // Trim history
        while (history_.size() > MAX_HISTORY) {
            history_.pop_front();
        }
    }
}

// ---------------------------------------------------------------------------
// get_current
// ---------------------------------------------------------------------------

DifficultyInfo DifficultyMonitor::get_current() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!history_.empty()) {
        return history_.back();
    }

    // Return a default info
    DifficultyInfo info;
    info.height = 0;
    info.nbits = consensus::INITIAL_NBITS;
    info.difficulty = compute_difficulty(consensus::INITIAL_NBITS);
    info.timestamp = 0;
    info.block_time = static_cast<double>(consensus::TARGET_BLOCK_TIME);
    info.estimated_hashrate = 0.0;
    return info;
}

// ---------------------------------------------------------------------------
// get_history
// ---------------------------------------------------------------------------

std::vector<DifficultyInfo> DifficultyMonitor::get_history(size_t max_entries) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (max_entries == 0 || max_entries >= history_.size()) {
        return std::vector<DifficultyInfo>(history_.begin(), history_.end());
    }

    auto start = history_.end() - static_cast<ptrdiff_t>(max_entries);
    return std::vector<DifficultyInfo>(start, history_.end());
}

// ---------------------------------------------------------------------------
// get_retarget_info
// ---------------------------------------------------------------------------

RetargetInfo DifficultyMonitor::get_retarget_info() const {
    std::lock_guard<std::mutex> lock(mutex_);

    RetargetInfo info;

    CBlockIndex* tip = chain_.tip();
    uint64_t current_height = tip ? tip->height : 0;

    // Next retarget height
    info.next_retarget_height = ((current_height / consensus::RETARGET_INTERVAL) + 1)
                                * consensus::RETARGET_INTERVAL;
    info.blocks_until_retarget = static_cast<int>(info.next_retarget_height - current_height);
    info.is_at_retarget = (current_height % consensus::RETARGET_INTERVAL == 0);

    // Current retarget period start
    uint64_t period_start = (current_height / consensus::RETARGET_INTERVAL)
                            * consensus::RETARGET_INTERVAL;

    // Target time for this period
    info.current_period_target = static_cast<double>(consensus::RETARGET_TIMESPAN);

    // Elapsed time in this period
    if (!history_.empty() && period_start < history_.back().height) {
        // Find the block at period_start
        int64_t start_time = 0;
        for (const auto& entry : history_) {
            if (entry.height == period_start) {
                start_time = entry.timestamp;
                break;
            }
        }
        if (start_time > 0 && tip) {
            info.current_period_elapsed = static_cast<double>(tip->timestamp - start_time);
        } else {
            info.current_period_elapsed = 0.0;
        }
    } else {
        info.current_period_elapsed = 0.0;
    }

    // Estimate the change factor
    if (info.blocks_until_retarget > 0 && info.current_period_elapsed > 0.0) {
        int blocks_in_period = static_cast<int>(current_height - period_start);
        if (blocks_in_period > 0) {
            double avg_time = info.current_period_elapsed / blocks_in_period;
            double projected_total = avg_time * consensus::RETARGET_INTERVAL;
            info.estimated_change = info.current_period_target / projected_total;

            // Clamp to [0.25, 4.0]
            info.estimated_change = std::max(0.25, std::min(4.0, info.estimated_change));
        } else {
            info.estimated_change = 1.0;
        }
    } else {
        info.estimated_change = 1.0;
    }

    // Estimate new nbits
    if (tip) {
        arith_uint256 current_target;
        current_target.SetCompact(tip->nbits);
        // New target = current_target / estimated_change
        // (higher change = higher difficulty = lower target)
        if (info.estimated_change > 0.0) {
            // Approximate by scaling
            arith_uint256 new_target = current_target;
            // Multiply by 1000, divide by (estimated_change * 1000)
            uint32_t factor = static_cast<uint32_t>(info.estimated_change * 1000.0);
            if (factor > 0) {
                new_target *= 1000;
                new_target /= factor;
            }
            info.estimated_nbits = new_target.GetCompact();
        } else {
            info.estimated_nbits = tip->nbits;
        }
    } else {
        info.estimated_nbits = consensus::INITIAL_NBITS;
    }

    // Estimated retarget time
    double avg_block_time = get_average_block_time(144);
    info.expected_retarget_time = GetTime()
        + static_cast<int64_t>(info.blocks_until_retarget * avg_block_time);

    return info;
}

// ---------------------------------------------------------------------------
// estimate_hashrate
// ---------------------------------------------------------------------------

double DifficultyMonitor::estimate_hashrate(int window) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (history_.size() < 2) return 0.0;

    size_t n = std::min(static_cast<size_t>(window), history_.size());
    if (n < 2) return 0.0;

    auto start = history_.end() - static_cast<ptrdiff_t>(n);
    auto end = history_.end() - 1;

    double total_time = static_cast<double>(end->timestamp - start->timestamp);
    if (total_time <= 0.0) return 0.0;

    // Average difficulty over the window
    double total_difficulty = 0.0;
    for (auto it = start; it != history_.end(); ++it) {
        total_difficulty += it->difficulty;
    }
    double avg_difficulty = total_difficulty / n;

    return hashrate_from_difficulty(avg_difficulty);
}

// ---------------------------------------------------------------------------
// estimate_time_to_block
// ---------------------------------------------------------------------------

double DifficultyMonitor::estimate_time_to_block() const {
    double hashrate = estimate_hashrate();
    if (hashrate <= 0.0) return std::numeric_limits<double>::infinity();

    auto current = get_current();
    return hashrate_from_difficulty(current.difficulty) *
           static_cast<double>(consensus::TARGET_BLOCK_TIME) / hashrate;
}

double DifficultyMonitor::estimate_time_to_block(double miner_hashrate) const {
    if (miner_hashrate <= 0.0) return std::numeric_limits<double>::infinity();

    auto current = get_current();
    double network_hashrate = hashrate_from_difficulty(current.difficulty);

    if (network_hashrate <= 0.0) {
        return static_cast<double>(consensus::TARGET_BLOCK_TIME);
    }

    // Expected time = target_time * (network_hashrate / miner_hashrate)
    return static_cast<double>(consensus::TARGET_BLOCK_TIME) *
           (network_hashrate / miner_hashrate);
}

// ---------------------------------------------------------------------------
// block_probability
// ---------------------------------------------------------------------------

double DifficultyMonitor::block_probability(double hashrate, double seconds) const {
    double expected_time = estimate_time_to_block(hashrate);
    if (expected_time <= 0.0) return 0.0;

    // Probability of finding at least one block in time t:
    // P = 1 - e^(-t / expected_time)
    return 1.0 - std::exp(-seconds / expected_time);
}

// ---------------------------------------------------------------------------
// get_difficulty_range
// ---------------------------------------------------------------------------

void DifficultyMonitor::get_difficulty_range(double& min_diff, double& max_diff,
                                              size_t window) const {
    std::lock_guard<std::mutex> lock(mutex_);

    min_diff = std::numeric_limits<double>::max();
    max_diff = 0.0;

    if (history_.empty()) {
        min_diff = 0.0;
        return;
    }

    size_t n = (window > 0) ? std::min(window, history_.size()) : history_.size();
    auto start = history_.end() - static_cast<ptrdiff_t>(n);

    for (auto it = start; it != history_.end(); ++it) {
        if (it->difficulty < min_diff) min_diff = it->difficulty;
        if (it->difficulty > max_diff) max_diff = it->difficulty;
    }
}

// ---------------------------------------------------------------------------
// get_average_block_time
// ---------------------------------------------------------------------------

double DifficultyMonitor::get_average_block_time(size_t window) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (history_.size() < 2) {
        return static_cast<double>(consensus::TARGET_BLOCK_TIME);
    }

    size_t n = std::min(window, history_.size());
    if (n < 2) return static_cast<double>(consensus::TARGET_BLOCK_TIME);

    double total = 0.0;
    size_t count = 0;
    auto start = history_.end() - static_cast<ptrdiff_t>(n);

    for (auto it = start; it != history_.end(); ++it) {
        if (it->block_time > 0.0) {
            total += it->block_time;
            ++count;
        }
    }

    if (count == 0) return static_cast<double>(consensus::TARGET_BLOCK_TIME);
    return total / count;
}

// ===========================================================================
// SolveTimeSampler
// ===========================================================================

void SolveTimeSampler::add_sample(double solve_time_seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    samples_.push_back(solve_time_seconds);
    while (samples_.size() > MAX_SAMPLES) {
        samples_.pop_front();
    }
}

double SolveTimeSampler::mean() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (samples_.empty()) return 0.0;
    double total = std::accumulate(samples_.begin(), samples_.end(), 0.0);
    return total / static_cast<double>(samples_.size());
}

double SolveTimeSampler::median() const {
    return percentile(50.0);
}

double SolveTimeSampler::percentile(double p) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (samples_.empty()) return 0.0;

    std::vector<double> sorted(samples_.begin(), samples_.end());
    std::sort(sorted.begin(), sorted.end());

    double idx = (p / 100.0) * (sorted.size() - 1);
    size_t lo = static_cast<size_t>(idx);
    size_t hi = lo + 1;
    if (hi >= sorted.size()) return sorted.back();

    double frac = idx - static_cast<double>(lo);
    return sorted[lo] + frac * (sorted[hi] - sorted[lo]);
}

double SolveTimeSampler::stddev() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (samples_.size() < 2) return 0.0;

    double m = 0.0;
    for (const auto& s : samples_) m += s;
    m /= static_cast<double>(samples_.size());

    double var = 0.0;
    for (const auto& s : samples_) {
        double d = s - m;
        var += d * d;
    }
    var /= static_cast<double>(samples_.size() - 1);

    return std::sqrt(var);
}

size_t SolveTimeSampler::count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return samples_.size();
}

void SolveTimeSampler::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    samples_.clear();
}

std::string SolveTimeSampler::summary() const {
    std::ostringstream ss;
    ss << "SolveTimeSampler("
       << "n=" << count()
       << " mean=" << mean() << "s"
       << " median=" << median() << "s"
       << " stddev=" << stddev() << "s"
       << " p95=" << percentile(95.0) << "s"
       << ")";
    return ss.str();
}

} // namespace flow

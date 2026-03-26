// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "difficulty.h"
#include "params.h"
#include "../chain/blockindex.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace flow::consensus {

// ---------------------------------------------------------------------------
// powLimit — the maximum allowed target (minimum difficulty = 1)
// ---------------------------------------------------------------------------
// Decoded from INITIAL_NBITS (0x1f00ffff):
//   exponent = 0x1f = 31
//   mantissa = 0x00ffff
//   target   = 0x00ffff << (8 * (31 - 3)) = 0x00ffff << 224
//
// This is computed once and reused for clamping.

static arith_uint256 get_pow_limit() {
    arith_uint256 limit;
    limit.SetCompact(INITIAL_NBITS);
    return limit;
}

// ---------------------------------------------------------------------------
// derive_target
// ---------------------------------------------------------------------------

bool derive_target(uint32_t nbits, arith_uint256& target) {
    bool negative = false;
    bool overflow = false;

    target.SetCompact(nbits, &negative, &overflow);

    // Reject negative targets (sign bit set in mantissa)
    if (negative) {
        return false;
    }

    // Reject overflow (exponent too large for 256 bits)
    if (overflow) {
        return false;
    }

    // Reject zero target (would make mining impossible)
    if (target.IsNull()) {
        return false;
    }

    // Reject targets exceeding powLimit (difficulty below minimum)
    static const arith_uint256 pow_limit = get_pow_limit();
    if (target > pow_limit) {
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// check_proof_of_work
// ---------------------------------------------------------------------------

bool check_proof_of_work(const uint256& block_hash, uint32_t nbits) {
    arith_uint256 target;
    if (!derive_target(nbits, target)) {
        return false;
    }

    // Convert the hash bytes to a 256-bit arithmetic value.
    // The hash is stored in byte order; UintToArith256 interprets byte 0
    // as the least significant byte (little-endian), which is the standard
    // convention for Bitcoin-style proof-of-work comparison.
    arith_uint256 hash_value = UintToArith256(block_hash);

    // The hash must be less than or equal to the target.
    // Lower hash = more "work" (same as Bitcoin PoW).
    return hash_value <= target;
}

// ---------------------------------------------------------------------------
// get_next_work_required
// ---------------------------------------------------------------------------

uint32_t get_next_work_required(uint64_t height, uint32_t parent_nbits,
                                int64_t first_block_time, int64_t last_block_time) {
    // If not at a retarget boundary, keep the same difficulty.
    // Height 0 (genesis) uses INITIAL_NBITS; retarget happens at heights
    // that are multiples of RETARGET_INTERVAL (2016, 4032, ...).
    if (height % RETARGET_INTERVAL != 0) {
        return parent_nbits;
    }

    // Step 1: Compute actual elapsed time for the last 2016 blocks.
    // first_block_time = timestamp of block at (height - RETARGET_INTERVAL)
    // last_block_time  = timestamp of block at (height - 1) = parent
    int64_t actual_timespan = last_block_time - first_block_time;

    // Step 2: Clamp the actual timespan to prevent extreme adjustments.
    //
    // If blocks came too fast (actual < target/4), we only decrease
    // difficulty by 4x. If blocks came too slow (actual > target*4),
    // we only increase difficulty by 4x.
    //
    // RETARGET_TIMESPAN = 2016 * 600 = 1,209,600 seconds (2 weeks)
    // min_timespan = 1,209,600 / 4 = 302,400 seconds (3.5 days)
    // max_timespan = 1,209,600 * 4 = 4,838,400 seconds (8 weeks)
    int64_t min_timespan = RETARGET_TIMESPAN / MAX_RETARGET_FACTOR;
    int64_t max_timespan = RETARGET_TIMESPAN * MAX_RETARGET_FACTOR;

    if (actual_timespan < min_timespan) {
        actual_timespan = min_timespan;
    }
    if (actual_timespan > max_timespan) {
        actual_timespan = max_timespan;
    }

    // Step 3: Calculate new target.
    // new_target = old_target * actual_timespan / RETARGET_TIMESPAN
    //
    // If blocks were faster than expected, actual_timespan < RETARGET_TIMESPAN,
    // so new_target < old_target (harder). If slower, new_target > old_target (easier).
    arith_uint256 new_target;
    new_target.SetCompact(parent_nbits);

    // Multiply by actual timespan (fits in 32 bits after clamping: max ~4.8M)
    new_target *= static_cast<uint32_t>(actual_timespan);

    // Divide by target timespan (1,209,600)
    arith_uint256 divisor(static_cast<uint64_t>(RETARGET_TIMESPAN));
    new_target /= divisor;

    // Step 4: Clamp to powLimit (don't allow target above the minimum difficulty).
    static const arith_uint256 pow_limit = get_pow_limit();
    if (new_target > pow_limit) {
        new_target = pow_limit;
    }

    // Step 5: Return as compact encoding.
    return new_target.GetCompact();
}

// ---------------------------------------------------------------------------
// validate_nbits
// ---------------------------------------------------------------------------

bool validate_nbits(uint32_t nbits) {
    arith_uint256 target;
    return derive_target(nbits, target);
}

// ---------------------------------------------------------------------------
// compare_difficulty
// ---------------------------------------------------------------------------

int compare_difficulty(uint32_t nbits_a, uint32_t nbits_b) {
    arith_uint256 target_a, target_b;

    if (!derive_target(nbits_a, target_a)) return 0;
    if (!derive_target(nbits_b, target_b)) return 0;

    // Smaller target = higher difficulty
    if (target_a < target_b) return -1;  // a is harder
    if (target_a > target_b) return 1;   // b is harder
    return 0;  // equal
}

// ---------------------------------------------------------------------------
// compute_timespan_ratio
// ---------------------------------------------------------------------------

double compute_timespan_ratio(int64_t first_time, int64_t last_time) {
    int64_t actual = last_time - first_time;

    // Clamp to the same bounds as get_next_work_required
    int64_t min_timespan = RETARGET_TIMESPAN / MAX_RETARGET_FACTOR;
    int64_t max_timespan = RETARGET_TIMESPAN * MAX_RETARGET_FACTOR;

    if (actual < min_timespan) actual = min_timespan;
    if (actual > max_timespan) actual = max_timespan;

    return static_cast<double>(actual) / static_cast<double>(RETARGET_TIMESPAN);
}

// ═══════════════════════════════════════════════════════════════════════════
// Difficulty analysis
// ═══════════════════════════════════════════════════════════════════════════

int64_t estimate_time_to_block(uint32_t nbits, double steps_per_second) {
    if (steps_per_second <= 0.0) return INT64_MAX;

    uint64_t exp_steps = expected_steps(nbits);
    if (exp_steps == 0) return 0;

    double time_seconds = static_cast<double>(exp_steps) / steps_per_second;
    return static_cast<int64_t>(time_seconds);
}

uint64_t expected_steps(uint32_t nbits) {
    arith_uint256 target;
    if (!derive_target(nbits, target)) {
        return UINT64_MAX;
    }

    if (target.IsNull()) {
        return UINT64_MAX;
    }

    // Expected number of attempts = 2^256 / (target + 1)
    // For practical purposes, we approximate for targets that fit in 64 bits.
    // The compact representation gives us enough info to estimate.

    // Get the exponent and mantissa from nbits
    uint32_t exponent = nbits >> 24;
    uint32_t mantissa = nbits & 0x007FFFFF;

    if (mantissa == 0) return UINT64_MAX;

    // Target ~= mantissa * 2^(8*(exponent-3))
    // Expected steps ~= 2^256 / target
    // = 2^256 / (mantissa * 2^(8*(exponent-3)))
    // = (2^256 / 2^(8*(exponent-3))) / mantissa
    // = 2^(256 - 8*(exponent-3)) / mantissa

    // For targets near powLimit (exponent=31, 0x1f):
    // bits = 256 - 8*(31-3) = 256 - 224 = 32
    // expected = 2^32 / mantissa

    int shift = 256 - 8 * (static_cast<int>(exponent) - 3);
    if (shift < 0) shift = 0;

    // If shift > 63, the expected steps don't fit in uint64
    if (shift > 63) return UINT64_MAX;

    uint64_t numerator = 1ULL << shift;
    return numerator / static_cast<uint64_t>(mantissa);
}

std::vector<RetargetInfo> get_retarget_history(const flow::CBlockIndex* tip,
                                                 int count) {
    std::vector<RetargetInfo> history;

    if (!tip || count <= 0) return history;

    // Walk back from tip, finding retarget boundaries
    const flow::CBlockIndex* walk = tip;
    int found = 0;

    while (walk && found < count) {
        // Check if this block is at a retarget boundary
        if (walk->height > 0 && walk->height % RETARGET_INTERVAL == 0) {
            RetargetInfo info;
            info.height = walk->height;
            info.new_nbits = walk->nbits;
            info.new_difficulty = nbits_to_difficulty(walk->nbits);

            // Walk back to the previous retarget point to find the old nbits
            const flow::CBlockIndex* prev_retarget = walk->prev;
            if (prev_retarget) {
                info.old_nbits = prev_retarget->nbits;
                info.old_difficulty = nbits_to_difficulty(prev_retarget->nbits);
            } else {
                info.old_nbits = INITIAL_NBITS;
                info.old_difficulty = 1.0;
            }

            // Compute actual timespan for this period
            // Walk back RETARGET_INTERVAL blocks to find the first block's timestamp
            const flow::CBlockIndex* period_start = walk;
            for (int i = 0; i < RETARGET_INTERVAL && period_start && period_start->prev; i++) {
                period_start = period_start->prev;
            }

            if (period_start) {
                info.actual_timespan = walk->timestamp - period_start->timestamp;
            } else {
                info.actual_timespan = RETARGET_TIMESPAN;
            }

            info.target_timespan = RETARGET_TIMESPAN;

            // Compute adjustment factor
            if (info.old_difficulty > 0.0) {
                info.adjustment_factor = info.new_difficulty / info.old_difficulty;
            } else {
                info.adjustment_factor = 1.0;
            }

            // Check if clamped
            int64_t min_timespan = RETARGET_TIMESPAN / MAX_RETARGET_FACTOR;
            int64_t max_timespan = RETARGET_TIMESPAN * MAX_RETARGET_FACTOR;
            info.clamped = (info.actual_timespan <= min_timespan ||
                           info.actual_timespan >= max_timespan);

            history.push_back(info);
            found++;
        }

        walk = walk->prev;
    }

    return history;
}

DifficultyPrediction predict_next_difficulty(const flow::CBlockIndex* tip) {
    DifficultyPrediction pred;
    pred.current_difficulty = 0.0;
    pred.predicted_difficulty = 0.0;
    pred.adjustment_factor = 1.0;
    pred.blocks_until_retarget = 0;
    pred.estimated_time_until_retarget = 0;
    pred.avg_block_time_current_period = TARGET_BLOCK_TIME;

    if (!tip) return pred;

    pred.current_difficulty = nbits_to_difficulty(tip->nbits);

    // How many blocks until the next retarget?
    uint64_t next_retarget = ((tip->height / RETARGET_INTERVAL) + 1) * RETARGET_INTERVAL;
    pred.blocks_until_retarget = static_cast<int64_t>(next_retarget - tip->height);

    // Find the start of the current retarget period
    uint64_t period_start_height = (tip->height / RETARGET_INTERVAL) * RETARGET_INTERVAL;

    const flow::CBlockIndex* period_start = tip;
    while (period_start && period_start->height > period_start_height) {
        period_start = period_start->prev;
    }

    if (!period_start) {
        pred.predicted_difficulty = pred.current_difficulty;
        pred.estimated_time_until_retarget = pred.blocks_until_retarget * TARGET_BLOCK_TIME;
        return pred;
    }

    // Blocks elapsed in this period
    uint64_t blocks_elapsed = tip->height - period_start_height;

    if (blocks_elapsed > 0) {
        int64_t time_elapsed = tip->timestamp - period_start->timestamp;
        pred.avg_block_time_current_period =
            static_cast<double>(time_elapsed) / static_cast<double>(blocks_elapsed);

        // Predict total timespan for the full retarget period
        double predicted_total_timespan =
            pred.avg_block_time_current_period * static_cast<double>(RETARGET_INTERVAL);

        // Clamp the prediction
        double min_ts = static_cast<double>(RETARGET_TIMESPAN) / MAX_RETARGET_FACTOR;
        double max_ts = static_cast<double>(RETARGET_TIMESPAN) * MAX_RETARGET_FACTOR;

        if (predicted_total_timespan < min_ts) predicted_total_timespan = min_ts;
        if (predicted_total_timespan > max_ts) predicted_total_timespan = max_ts;

        // New difficulty ~= current_difficulty * target_timespan / predicted_timespan
        pred.adjustment_factor = static_cast<double>(RETARGET_TIMESPAN) / predicted_total_timespan;
        pred.predicted_difficulty = pred.current_difficulty * pred.adjustment_factor;

        // Estimated time until retarget
        pred.estimated_time_until_retarget = static_cast<int64_t>(
            static_cast<double>(pred.blocks_until_retarget) *
            pred.avg_block_time_current_period);
    } else {
        pred.predicted_difficulty = pred.current_difficulty;
        pred.estimated_time_until_retarget = pred.blocks_until_retarget * TARGET_BLOCK_TIME;
    }

    return pred;
}

// ═══════════════════════════════════════════════════════════════════════════
// Difficulty encoding utilities
// ═══════════════════════════════════════════════════════════════════════════

double nbits_to_difficulty(uint32_t nbits) {
    // difficulty = powLimit_target / current_target
    // For simplicity, use the ratio of compact encodings:
    // difficulty ~= (initial_mantissa * 2^(8*(initial_exp-3))) /
    //               (mantissa * 2^(8*(exp-3)))

    uint32_t init_exp = INITIAL_NBITS >> 24;
    uint32_t init_mantissa = INITIAL_NBITS & 0x007FFFFF;

    uint32_t cur_exp = nbits >> 24;
    uint32_t cur_mantissa = nbits & 0x007FFFFF;

    if (cur_mantissa == 0) return 0.0;

    // Exponent difference in bits
    int exp_diff = (static_cast<int>(init_exp) - static_cast<int>(cur_exp)) * 8;

    double ratio = static_cast<double>(init_mantissa) /
                   static_cast<double>(cur_mantissa);

    if (exp_diff > 0) {
        ratio *= std::pow(2.0, static_cast<double>(exp_diff));
    } else if (exp_diff < 0) {
        ratio /= std::pow(2.0, static_cast<double>(-exp_diff));
    }

    return ratio;
}

uint32_t difficulty_to_nbits(double difficulty) {
    if (difficulty <= 0.0) return INITIAL_NBITS;
    if (difficulty <= 1.0) return INITIAL_NBITS;

    // Reverse of nbits_to_difficulty:
    // target = powLimit_target / difficulty
    arith_uint256 pow_limit;
    pow_limit.SetCompact(INITIAL_NBITS);

    // Approximate by scaling the exponent and mantissa
    uint32_t init_exp = INITIAL_NBITS >> 24;
    uint32_t init_mantissa = INITIAL_NBITS & 0x007FFFFF;

    // New mantissa and exponent
    double target_mantissa = static_cast<double>(init_mantissa) / difficulty;

    // Find the right exponent
    uint32_t new_exp = init_exp;
    while (target_mantissa < static_cast<double>(0x008000) && new_exp > 3) {
        target_mantissa *= 256.0;
        new_exp--;
    }
    while (target_mantissa >= static_cast<double>(0x800000) && new_exp < 32) {
        target_mantissa /= 256.0;
        new_exp++;
    }

    uint32_t new_mantissa = static_cast<uint32_t>(target_mantissa);
    if (new_mantissa > 0x7FFFFF) new_mantissa = 0x7FFFFF;
    if (new_mantissa == 0) new_mantissa = 1;

    return (new_exp << 24) | new_mantissa;
}

std::string format_difficulty(double difficulty) {
    char buf[64];

    if (difficulty < 1000.0) {
        snprintf(buf, sizeof(buf), "%.2f", difficulty);
    } else if (difficulty < 1000000.0) {
        snprintf(buf, sizeof(buf), "%.1fK", difficulty / 1000.0);
    } else if (difficulty < 1000000000.0) {
        snprintf(buf, sizeof(buf), "%.1fM", difficulty / 1000000.0);
    } else if (difficulty < 1000000000000.0) {
        snprintf(buf, sizeof(buf), "%.1fG", difficulty / 1000000000.0);
    } else {
        snprintf(buf, sizeof(buf), "%.1fT", difficulty / 1000000000000.0);
    }

    return std::string(buf);
}

std::string format_target(const arith_uint256& target) {
    // Format as hex string
    uint32_t compact = target.GetCompact();
    char buf[32];
    snprintf(buf, sizeof(buf), "%08x", compact);
    return std::string(buf);
}

std::string format_hashrate(double steps_per_second) {
    char buf[64];

    if (steps_per_second < 1000.0) {
        snprintf(buf, sizeof(buf), "%.1f st/s", steps_per_second);
    } else if (steps_per_second < 1000000.0) {
        snprintf(buf, sizeof(buf), "%.1fK st/s", steps_per_second / 1000.0);
    } else if (steps_per_second < 1000000000.0) {
        snprintf(buf, sizeof(buf), "%.1fM st/s", steps_per_second / 1000000.0);
    } else {
        snprintf(buf, sizeof(buf), "%.1fG st/s", steps_per_second / 1000000000.0);
    }

    return std::string(buf);
}

// ═══════════════════════════════════════════════════════════════════════════
// Difficulty validation helpers
// ═══════════════════════════════════════════════════════════════════════════

bool is_valid_nbits(uint32_t nbits) {
    return validate_nbits(nbits);
}

bool is_min_difficulty(uint32_t nbits) {
    return nbits == INITIAL_NBITS;
}

uint32_t get_min_difficulty_nbits() {
    return INITIAL_NBITS;
}

} // namespace flow::consensus

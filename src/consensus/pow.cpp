// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Keccak-256d Proof-of-Work implementation.

#include "pow.h"
#include "difficulty.h"
#include "params.h"
#include "../util/arith_uint256.h"

#include <cmath>
#include <cstring>
#include <limits>
#include <string>

namespace flow::consensus {

// ===========================================================================
// PoW verification
// ===========================================================================

bool CheckProofOfWork(const CBlockHeader& header) {
    arith_uint256 target;
    if (!derive_target(header.nbits, target)) {
        return false;
    }

    // block_id = keccak256d(header[0..91]) — same hash used for indexing.
    uint256 block_id = header.get_hash();

    // derive_target gives us a little-endian arith_uint256; the hash is raw
    // bytes in the same little-endian layout used for chain arithmetic, so
    // compare via ArithToUint256 with a byte-reverse to big-endian.
    uint256 target_le = ArithToUint256(target);
    uint256 target_be;
    for (int i = 0; i < 32; ++i) {
        target_be[i] = target_le[31 - i];
    }
    return block_id <= target_be;
}

// ===========================================================================
// Difficulty math (target/nbits encoding is independent of the hash
// function used)
// ===========================================================================

arith_uint256 GetPowLimit() {
    arith_uint256 limit;
    limit.SetCompact(INITIAL_NBITS);
    return limit;
}

double GetDifficulty(uint32_t nbits) {
    arith_uint256 target;
    if (!derive_target(nbits, target)) return 0.0;

    int shift = (nbits >> 24) & 0xff;
    double mantissa = static_cast<double>(nbits & 0x00ffffff);
    if (mantissa == 0.0) return 0.0;

    int pow_shift = (INITIAL_NBITS >> 24) & 0xff;
    double pow_mantissa = static_cast<double>(INITIAL_NBITS & 0x00ffffff);

    double difficulty = pow_mantissa / mantissa;
    int exponent_diff = pow_shift - shift;
    if (exponent_diff > 0) {
        difficulty *= std::pow(256.0, static_cast<double>(exponent_diff));
    } else if (exponent_diff < 0) {
        difficulty /= std::pow(256.0, static_cast<double>(-exponent_diff));
    }
    return difficulty;
}

bool AllowMinDifficultyBlocks(bool regtest) { return regtest; }

uint32_t GetNextWorkRequired(uint64_t parent_height, uint32_t parent_nbits,
                              int64_t parent_timestamp, int64_t first_block_time,
                              bool regtest) {
    uint64_t child_height = parent_height + 1;
    if (regtest) return INITIAL_NBITS;
    return get_next_work_required(child_height, parent_nbits,
                                   first_block_time, parent_timestamp);
}

double EstimateNetworkHashrate(double difficulty) {
    if (difficulty <= 0.0) return 0.0;
    constexpr double two_pow_32 = 4294967296.0;
    return difficulty * two_pow_32 / static_cast<double>(TARGET_BLOCK_TIME);
}

arith_uint256 GetBlockProof(uint32_t nbits) {
    arith_uint256 target;
    if (!derive_target(nbits, target)) return arith_uint256(0);

    arith_uint256 one(1);
    arith_uint256 target_plus_one = target;
    target_plus_one += one;
    if (target_plus_one.IsNull()) return arith_uint256(0);

    arith_uint256 not_target = ~target;
    arith_uint256 work = not_target / target_plus_one;
    work += one;
    return work;
}

uint32_t DifficultyToTarget(double difficulty) {
    if (difficulty <= 0.0 || !std::isfinite(difficulty)) return INITIAL_NBITS;

    arith_uint256 pow_limit = GetPowLimit();
    if (difficulty <= 1.0) return pow_limit.GetCompact();

    int pow_shift = (INITIAL_NBITS >> 24) & 0xff;
    double pow_mantissa = static_cast<double>(INITIAL_NBITS & 0x00ffffff);
    double target_mantissa = pow_mantissa / difficulty;

    int shift = pow_shift;
    while (target_mantissa < 0x008000 && shift > 3) {
        target_mantissa *= 256.0;
        shift--;
    }
    while (target_mantissa > 0x7fffff) {
        target_mantissa /= 256.0;
        shift++;
    }

    uint32_t mantissa = static_cast<uint32_t>(target_mantissa) & 0x7fffff;
    return (static_cast<uint32_t>(shift) << 24) | mantissa;
}

std::string FormatTarget(uint32_t nbits) {
    arith_uint256 target;
    if (!derive_target(nbits, target)) return "invalid";

    std::string hex;
    hex.reserve(64);
    static const char hexchars[] = "0123456789abcdef";
    bool leading = true;

    for (int i = arith_uint256::WIDTH - 1; i >= 0; i--) {
        uint32_t limb = target.pn[i];
        for (int j = 28; j >= 0; j -= 4) {
            uint8_t nibble = (limb >> j) & 0xf;
            if (nibble == 0 && leading) continue;
            leading = false;
            hex.push_back(hexchars[nibble]);
        }
    }

    if (hex.empty()) hex = "0";
    return hex;
}

double EstimateTimeToBlock(double difficulty, double local_hashrate) {
    if (local_hashrate <= 0.0 || difficulty <= 0.0) {
        return std::numeric_limits<double>::infinity();
    }
    constexpr double two_pow_32 = 4294967296.0;
    double expected_hashes = difficulty * two_pow_32;
    return expected_hashes / local_hashrate;
}

void GetRetargetPeriod(uint64_t height, uint64_t& period_start,
                        uint64_t& period_end) {
    uint64_t period_index = height / RETARGET_INTERVAL;
    period_start = period_index * RETARGET_INTERVAL;
    period_end = period_start + RETARGET_INTERVAL - 1;
}

DifficultyProgress GetDifficultyProgress(uint64_t current_height,
                                          uint32_t current_nbits,
                                          int64_t period_start_time,
                                          int64_t current_time) {
    DifficultyProgress progress{};

    progress.current_difficulty = GetDifficulty(current_nbits);
    progress.blocks_in_period =
        static_cast<double>(current_height % RETARGET_INTERVAL);
    progress.period_progress_pct =
        (progress.blocks_in_period / static_cast<double>(RETARGET_INTERVAL)) * 100.0;
    progress.blocks_until_retarget = BlocksUntilRetarget(current_height);
    progress.estimated_hashrate = EstimateNetworkHashrate(progress.current_difficulty);

    if (period_start_time > 0 && current_time > period_start_time &&
        progress.blocks_in_period > 0) {
        int64_t elapsed = current_time - period_start_time;
        double blocks_per_second = progress.blocks_in_period /
                                   static_cast<double>(elapsed);
        double expected_timespan = static_cast<double>(RETARGET_TIMESPAN);
        double projected_timespan = static_cast<double>(RETARGET_INTERVAL) /
                                    blocks_per_second;
        progress.estimated_adjustment = expected_timespan / projected_timespan;

        double max_adj = static_cast<double>(MAX_RETARGET_FACTOR);
        if (progress.estimated_adjustment > max_adj) {
            progress.estimated_adjustment = max_adj;
        }
        if (progress.estimated_adjustment < 1.0 / max_adj) {
            progress.estimated_adjustment = 1.0 / max_adj;
        }
    } else {
        progress.estimated_adjustment = 1.0;
    }

    return progress;
}

} // namespace flow::consensus

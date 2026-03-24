// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Proof-of-Training verification implementation.
// All functions in this file are consensus-critical: every full node
// must produce identical results for identical inputs.

#include "pow.h"
#include "difficulty.h"
#include "params.h"
#include "../util/arith_uint256.h"

#include <cmath>
#include <limits>
#include <string>

namespace flow::consensus {

// ---------------------------------------------------------------------------
// GetPowLimit — maximum allowed target (minimum difficulty)
// ---------------------------------------------------------------------------

arith_uint256 GetPowLimit() {
    arith_uint256 limit;
    limit.SetCompact(INITIAL_NBITS);
    return limit;
}

// ---------------------------------------------------------------------------
// CheckProofOfTraining — full PoT verification for a header
// ---------------------------------------------------------------------------

bool CheckProofOfTraining(const CBlockHeader& header) {
    // Step 1: Decode nbits to get the target
    arith_uint256 target;
    if (!derive_target(header.nbits, target)) {
        return false;
    }

    // Step 2: Compute the training hash from the header
    // The training hash is the block hash (keccak256d of unsigned header)
    uint256 training_hash = header.get_training_hash();

    // Step 3: Verify hash <= target
    arith_uint256 hash_value = UintToArith256(training_hash);
    return hash_value <= target;
}

// ---------------------------------------------------------------------------
// GetDifficulty — human-readable difficulty from nbits
// ---------------------------------------------------------------------------

double GetDifficulty(uint32_t nbits) {
    // Decode the target from nbits
    arith_uint256 target;
    if (!derive_target(nbits, target)) {
        return 0.0;
    }

    // Difficulty = powLimit / target
    // We compute this as a double for human consumption.
    //
    // For precision, we work with the mantissa and exponent separately.
    // nbits format: [exponent:8][mantissa:24]
    int shift = (nbits >> 24) & 0xff;
    double mantissa = static_cast<double>(nbits & 0x00ffffff);

    if (mantissa == 0.0) {
        return 0.0;
    }

    // powLimit mantissa and shift from INITIAL_NBITS (0x1f00ffff)
    int pow_shift = (INITIAL_NBITS >> 24) & 0xff;
    double pow_mantissa = static_cast<double>(INITIAL_NBITS & 0x00ffffff);

    // difficulty = (pow_mantissa * 2^(8*(pow_shift-3))) / (mantissa * 2^(8*(shift-3)))
    //            = (pow_mantissa / mantissa) * 2^(8*(pow_shift - shift))
    double difficulty = pow_mantissa / mantissa;
    int exponent_diff = pow_shift - shift;

    if (exponent_diff > 0) {
        difficulty *= std::pow(256.0, static_cast<double>(exponent_diff));
    } else if (exponent_diff < 0) {
        difficulty /= std::pow(256.0, static_cast<double>(-exponent_diff));
    }

    return difficulty;
}

// GetDifficulty(CBlockIndex) moved to chain/ to avoid circular dep

// ---------------------------------------------------------------------------
// AllowMinDifficultyBlocks
// ---------------------------------------------------------------------------

bool AllowMinDifficultyBlocks(bool regtest) {
    return regtest;
}

// ---------------------------------------------------------------------------
// GetNextWorkRequired — wrapper around difficulty retarget
// ---------------------------------------------------------------------------

uint32_t GetNextWorkRequired(uint64_t parent_height, uint32_t parent_nbits,
                              int64_t parent_timestamp, int64_t first_block_time,
                              bool regtest) {
    uint64_t child_height = parent_height + 1;

    // In regtest mode, always allow minimum difficulty
    if (regtest) {
        return INITIAL_NBITS;
    }

    // Delegate to the core retarget algorithm
    return get_next_work_required(child_height, parent_nbits,
                                   first_block_time, parent_timestamp);
}

// ---------------------------------------------------------------------------
// EstimateNetworkHashrate
// ---------------------------------------------------------------------------

double EstimateNetworkHashrate(double difficulty) {
    if (difficulty <= 0.0) {
        return 0.0;
    }

    // Expected hashes to find a block at difficulty d:
    //   expected_hashes = d * 2^32
    // Hashrate = expected_hashes / TARGET_BLOCK_TIME
    //
    // Note: 2^32 = 4,294,967,296
    constexpr double two_pow_32 = 4294967296.0;
    return difficulty * two_pow_32 / static_cast<double>(TARGET_BLOCK_TIME);
}

// ---------------------------------------------------------------------------
// GetBlockProof — work contribution of a single block
// ---------------------------------------------------------------------------

arith_uint256 GetBlockProof(uint32_t nbits) {
    arith_uint256 target;
    if (!derive_target(nbits, target)) {
        return arith_uint256(0);
    }

    // work = 2^256 / (target + 1)
    // To avoid overflow, use: work = (~target / (target + 1)) + 1
    // which is equivalent because ~target = 2^256 - 1 - target
    arith_uint256 one(1);
    arith_uint256 target_plus_one = target;
    target_plus_one += one;

    // If target+1 is zero (overflow), the difficulty is impossibly high
    if (target_plus_one.IsNull()) {
        return arith_uint256(0);
    }

    arith_uint256 not_target = ~target;
    arith_uint256 work = not_target / target_plus_one;
    work += one;

    return work;
}

// ---------------------------------------------------------------------------
// GetChainWork — cumulative work from genesis to tip
// ---------------------------------------------------------------------------

// GetChainWork(CBlockIndex*) moved to chain/ to avoid circular dep

// ---------------------------------------------------------------------------
// DifficultyToTarget — inverse of GetDifficulty
// ---------------------------------------------------------------------------

uint32_t DifficultyToTarget(double difficulty) {
    if (difficulty <= 0.0 || !std::isfinite(difficulty)) {
        return INITIAL_NBITS;
    }

    // target = powLimit / difficulty
    arith_uint256 pow_limit = GetPowLimit();

    // For difficulty 1.0, return powLimit
    if (difficulty <= 1.0) {
        return pow_limit.GetCompact();
    }

    // We need to compute pow_limit / difficulty.
    // Since arith_uint256 doesn't support float division directly,
    // we multiply pow_limit by a precision factor, divide by (difficulty * factor).
    //
    // Simple approach: work with the mantissa/exponent of INITIAL_NBITS.
    int pow_shift = (INITIAL_NBITS >> 24) & 0xff;
    double pow_mantissa = static_cast<double>(INITIAL_NBITS & 0x00ffffff);

    double target_mantissa = pow_mantissa / difficulty;

    // Find the right shift to keep mantissa in 3-byte range
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
    uint32_t nbits = (static_cast<uint32_t>(shift) << 24) | mantissa;

    return nbits;
}

// ---------------------------------------------------------------------------
// FormatTarget — hex string of the full 256-bit target
// ---------------------------------------------------------------------------

std::string FormatTarget(uint32_t nbits) {
    arith_uint256 target;
    if (!derive_target(nbits, target)) {
        return "invalid";
    }

    // Convert to hex string
    std::string hex;
    hex.reserve(64);

    // Walk from most significant limb to least
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

// ---------------------------------------------------------------------------
// EstimateTimeToBlock
// ---------------------------------------------------------------------------

double EstimateTimeToBlock(double difficulty, double local_hashrate) {
    if (local_hashrate <= 0.0 || difficulty <= 0.0) {
        return std::numeric_limits<double>::infinity();
    }

    // Expected hashes = difficulty * 2^32
    constexpr double two_pow_32 = 4294967296.0;
    double expected_hashes = difficulty * two_pow_32;

    return expected_hashes / local_hashrate;
}

// ---------------------------------------------------------------------------
// GetRetargetPeriod
// ---------------------------------------------------------------------------

void GetRetargetPeriod(uint64_t height, uint64_t& period_start,
                        uint64_t& period_end) {
    uint64_t period_index = height / RETARGET_INTERVAL;
    period_start = period_index * RETARGET_INTERVAL;
    period_end = period_start + RETARGET_INTERVAL - 1;
}

// ---------------------------------------------------------------------------
// VerifyFullProofOfTraining
// ---------------------------------------------------------------------------

bool VerifyFullProofOfTraining(const CBlockHeader& header,
                                uint32_t parent_nbits,
                                uint64_t child_height) {
    // Step 1: Verify the basic PoT (hash meets target)
    if (!CheckProofOfTraining(header)) {
        return false;
    }

    // Step 2: Verify the claimed height matches expected
    if (header.height != child_height) {
        return false;
    }

    // Step 3: Verify the nbits is valid
    arith_uint256 target;
    if (!derive_target(header.nbits, target)) {
        return false;
    }

    // Step 4: Verify target does not exceed powLimit
    arith_uint256 pow_limit = GetPowLimit();
    if (target > pow_limit) {
        return false;
    }

    // Step 5: Verify the training hash field is properly bound
    // The training hash must equal the block hash (they are the same in FlowCoin)
    uint256 block_hash = header.get_hash();
    uint256 training_hash = header.get_training_hash();
    if (block_hash != training_hash) {
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// GetDifficultyProgress
// ---------------------------------------------------------------------------

DifficultyProgress GetDifficultyProgress(uint64_t current_height,
                                          uint32_t current_nbits,
                                          int64_t period_start_time,
                                          int64_t current_time) {
    DifficultyProgress progress{};

    progress.current_difficulty = GetDifficulty(current_nbits);

    // Blocks completed in this retarget period
    progress.blocks_in_period = static_cast<double>(
        current_height % RETARGET_INTERVAL);

    // Period progress percentage
    progress.period_progress_pct =
        (progress.blocks_in_period / static_cast<double>(RETARGET_INTERVAL)) * 100.0;

    // Blocks until next retarget
    progress.blocks_until_retarget = BlocksUntilRetarget(current_height);

    // Estimated hashrate
    progress.estimated_hashrate = EstimateNetworkHashrate(progress.current_difficulty);

    // Estimate difficulty adjustment at next retarget
    if (period_start_time > 0 && current_time > period_start_time &&
        progress.blocks_in_period > 0) {

        int64_t elapsed = current_time - period_start_time;
        double blocks_per_second = progress.blocks_in_period /
                                   static_cast<double>(elapsed);
        double expected_timespan = static_cast<double>(RETARGET_TIMESPAN);
        double projected_timespan = static_cast<double>(RETARGET_INTERVAL) /
                                    blocks_per_second;

        // adjustment = expected / projected
        // > 1.0 means blocks are coming too fast (difficulty will increase)
        // < 1.0 means blocks are coming too slow (difficulty will decrease)
        progress.estimated_adjustment = expected_timespan / projected_timespan;

        // Clamp to 4x factor
        if (progress.estimated_adjustment > static_cast<double>(MAX_RETARGET_FACTOR)) {
            progress.estimated_adjustment = static_cast<double>(MAX_RETARGET_FACTOR);
        }
        if (progress.estimated_adjustment <
            1.0 / static_cast<double>(MAX_RETARGET_FACTOR)) {
            progress.estimated_adjustment =
                1.0 / static_cast<double>(MAX_RETARGET_FACTOR);
        }
    } else {
        progress.estimated_adjustment = 1.0;
    }

    return progress;
}

} // namespace flow::consensus

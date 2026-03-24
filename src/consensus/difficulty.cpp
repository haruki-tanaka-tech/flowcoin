// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "difficulty.h"
#include "params.h"

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
// check_proof_of_training
// ---------------------------------------------------------------------------

bool check_proof_of_training(const uint256& training_hash, uint32_t nbits) {
    arith_uint256 target;
    if (!derive_target(nbits, target)) {
        return false;
    }

    // Convert the hash bytes to a 256-bit arithmetic value.
    // The hash is stored in byte order; UintToArith256 interprets byte 0
    // as the least significant byte (little-endian), which is the standard
    // convention for Bitcoin-style proof-of-work comparison.
    arith_uint256 hash_value = UintToArith256(training_hash);

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

} // namespace flow::consensus

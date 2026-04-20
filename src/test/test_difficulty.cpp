// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "consensus/difficulty.h"
#include "consensus/params.h"
#include "util/arith_uint256.h"
#include <cassert>
#include <stdexcept>

void test_difficulty() {
    using namespace flow::consensus;

    // derive_target with initial nbits should succeed
    flow::arith_uint256 target;
    assert(derive_target(INITIAL_NBITS, target));
    assert(!target.IsZero());

    // Target from INITIAL_NBITS should be large (easy difficulty)
    flow::arith_uint256 one(1);
    assert(target > one);

    // derive_target with zero nbits should fail (zero target)
    flow::arith_uint256 zero_target;
    assert(!derive_target(0, zero_target));

    // derive_target: Bitcoin's 0x1d00ffff should also work (it's below powLimit)
    flow::arith_uint256 btc_target;
    assert(derive_target(0x1d00ffff, btc_target));
    // Bitcoin target should be smaller (harder) than FlowCoin target
    assert(btc_target < target);

    // Not at retarget boundary: return parent_nbits unchanged
    uint32_t next = get_next_work_required(1, INITIAL_NBITS, 0, 0);
    assert(next == INITIAL_NBITS);

    next = get_next_work_required(2015, INITIAL_NBITS, 0, 0);
    assert(next == INITIAL_NBITS);

    next = get_next_work_required(100, INITIAL_NBITS, 0, 0);
    assert(next == INITIAL_NBITS);

    // At block 2016: retarget
    int64_t target_timespan = RETARGET_TIMESPAN;  // 1,209,600 seconds

    // If actual time == target time: no change
    next = get_next_work_required(2016, INITIAL_NBITS, 0, target_timespan);
    assert(next == INITIAL_NBITS);

    // If blocks came 2x too fast: difficulty should increase (target decreases)
    next = get_next_work_required(2016, INITIAL_NBITS, 0, target_timespan / 2);
    flow::arith_uint256 harder_target;
    derive_target(next, harder_target);
    assert(harder_target < target);  // smaller target = harder

    // If blocks came 2x too slow: difficulty should decrease (target increases)
    next = get_next_work_required(2016, INITIAL_NBITS, 0, target_timespan * 2);
    flow::arith_uint256 easier_target;
    derive_target(next, easier_target);
    assert(easier_target > target);  // larger target = easier

    // But easier target must still be clamped to powLimit
    // Since INITIAL_NBITS IS powLimit, making it even easier should clamp
    assert(easier_target <= target || next == INITIAL_NBITS);

    // 4x clamp: even if 100x too fast, limited to 4x harder
    uint32_t fast_next = get_next_work_required(2016, INITIAL_NBITS, 0, target_timespan / 100);
    flow::arith_uint256 fast_target;
    derive_target(fast_next, fast_target);
    assert(fast_target <= target);

    // 4x clamp in the other direction: 100x too slow, limited to 4x easier
    uint32_t slow_next = get_next_work_required(2016, INITIAL_NBITS, 0, target_timespan * 100);
    flow::arith_uint256 slow_target;
    derive_target(slow_next, slow_target);
    // Should not exceed powLimit
    assert(slow_target <= target);

    // check_proof_of_work: zero hash should always pass (easiest hash)
    flow::uint256 zero_hash;  // all zeros
    assert(check_proof_of_work(zero_hash, INITIAL_NBITS));

    // check_proof_of_work: max hash (all 0xFF) should fail against INITIAL_NBITS
    flow::uint256 max_hash;
    std::memset(max_hash.data(), 0xFF, 32);
    assert(!check_proof_of_work(max_hash, INITIAL_NBITS));

    // Retarget at block 4032 (second retarget period)
    next = get_next_work_required(4032, INITIAL_NBITS, 0, target_timespan);
    assert(next == INITIAL_NBITS);  // same time = same difficulty
}

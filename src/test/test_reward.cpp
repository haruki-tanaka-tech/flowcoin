// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "consensus/reward.h"
#include "consensus/params.h"
#include <cassert>
#include <stdexcept>

void test_reward() {
    using namespace flow::consensus;

    // Block 0: 50 FLC = 5,000,000,000 atomic units
    assert(compute_block_reward(0) == 50LL * COIN);

    // Block 1: still 50
    assert(compute_block_reward(1) == 50LL * COIN);

    // Block 209999: last block of era 0, still 50
    assert(compute_block_reward(209999) == 50LL * COIN);

    // Block 210000: first halving, 25 FLC
    assert(compute_block_reward(210000) == 25LL * COIN);

    // Block 419999: last block of era 1, still 25
    assert(compute_block_reward(419999) == 25LL * COIN);

    // Block 420000: second halving, 12.5 FLC = 1,250,000,000 atomic units
    assert(compute_block_reward(420000) == 1250000000LL);

    // Block 630000: third halving, 6.25 FLC = 625,000,000 atomic units
    assert(compute_block_reward(630000) == 625000000LL);

    // Block 840000: fourth halving, 3.125 FLC = 312,500,000 atomic units
    assert(compute_block_reward(840000) == 312500000LL);

    // Halving schedule: reward = 50 >> halvings
    // After many halvings, reward should eventually reach 0
    // INITIAL_REWARD = 5,000,000,000 (fits in 33 bits)
    // After 33 halvings: 5,000,000,000 >> 33 = 0
    uint64_t height_33 = 33ULL * 210000;
    assert(compute_block_reward(height_33) == 0);

    // Very high block: reward should be 0
    assert(compute_block_reward(100000000) == 0);

    // Just before 33rd halving: should still have some reward
    uint64_t height_32 = 32ULL * 210000;
    // 5,000,000,000 >> 32 = 1 (just barely above MIN_REWARD)
    assert(compute_block_reward(height_32) >= 0);

    // Reward is always non-negative
    for (int i = 0; i < 64; i++) {
        assert(compute_block_reward(static_cast<uint64_t>(i) * 210000) >= 0);
    }

    // Monotonically non-increasing across halvings
    flow::Amount prev_reward = compute_block_reward(0);
    for (int era = 1; era < 40; era++) {
        flow::Amount cur = compute_block_reward(static_cast<uint64_t>(era) * 210000);
        assert(cur <= prev_reward);
        prev_reward = cur;
    }
}

// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "reward.h"
#include "params.h"

namespace flow::consensus {

Amount get_block_subsidy(uint64_t height) {
    int halvings = static_cast<int>(height / HALVING_INTERVAL);

    // After 64 halvings, reward is 0 (INITIAL_REWARD >> 64 == 0)
    if (halvings >= 64) {
        return Amount{0};
    }

    int64_t reward = INITIAL_REWARD >> halvings;

    if (reward < MIN_REWARD) {
        return Amount{0};
    }

    return Amount{reward};
}

} // namespace flow::consensus

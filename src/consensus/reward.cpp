// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "reward.h"
#include "params.h"

namespace flow::consensus {

Amount compute_block_reward(uint64_t height) {
    // Determine which halving era we are in.
    // Era 0: blocks 0..209999      -> reward = 50 FLOW
    // Era 1: blocks 210000..419999 -> reward = 25 FLOW
    // Era N: reward = INITIAL_REWARD >> N
    //
    // After 64 halvings, the right-shift produces zero for any 64-bit value
    // (INITIAL_REWARD = 5,000,000,000 < 2^33, so >>33 already yields 0).
    // We check for this explicitly to avoid undefined behavior with large shifts.

    uint64_t halvings = height / static_cast<uint64_t>(HALVING_INTERVAL);

    // If halvings >= 64, the shift would be undefined behavior in C++.
    // In practice, INITIAL_REWARD fits in 33 bits, so after 33 halvings
    // the reward is already 0. But we guard against the general case.
    if (halvings >= 64) {
        return 0;
    }

    Amount subsidy = INITIAL_REWARD >> halvings;

    // Once the subsidy drops below the minimum reward (1 atomic unit),
    // return 0 — the coin supply is fully distributed.
    if (subsidy < MIN_REWARD) {
        return 0;
    }

    return subsidy;
}

} // namespace flow::consensus

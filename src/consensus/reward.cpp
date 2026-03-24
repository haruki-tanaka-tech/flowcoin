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

// ---------------------------------------------------------------------------
// get_halving_era
// ---------------------------------------------------------------------------

uint32_t get_halving_era(uint64_t height) {
    return static_cast<uint32_t>(height / static_cast<uint64_t>(HALVING_INTERVAL));
}

// ---------------------------------------------------------------------------
// get_next_halving_height
// ---------------------------------------------------------------------------

uint64_t get_next_halving_height(uint64_t height) {
    uint64_t era = height / static_cast<uint64_t>(HALVING_INTERVAL);
    return (era + 1) * static_cast<uint64_t>(HALVING_INTERVAL);
}

// ---------------------------------------------------------------------------
// blocks_until_halving
// ---------------------------------------------------------------------------

uint64_t blocks_until_halving(uint64_t height) {
    return get_next_halving_height(height) - height;
}

// ---------------------------------------------------------------------------
// compute_total_supply
// ---------------------------------------------------------------------------

Amount compute_total_supply(uint64_t height) {
    // Instead of iterating every block, compute analytically per era.
    // Each era contributes: blocks_in_era * reward_per_block
    //
    // For complete eras: HALVING_INTERVAL * (INITIAL_REWARD >> era)
    // For the partial current era: (height - era_start) * reward

    Amount total = 0;
    uint64_t remaining_height = height + 1;  // +1 because height is inclusive

    for (uint64_t era = 0; remaining_height > 0; era++) {
        if (era >= 64) break;

        Amount era_reward = INITIAL_REWARD >> era;
        if (era_reward < MIN_REWARD) break;

        uint64_t blocks_in_era;
        if (remaining_height >= static_cast<uint64_t>(HALVING_INTERVAL)) {
            blocks_in_era = static_cast<uint64_t>(HALVING_INTERVAL);
        } else {
            blocks_in_era = remaining_height;
        }

        total += static_cast<Amount>(blocks_in_era) * era_reward;
        remaining_height -= blocks_in_era;
    }

    return total;
}

// ---------------------------------------------------------------------------
// compute_remaining_supply
// ---------------------------------------------------------------------------

Amount compute_remaining_supply(uint64_t height) {
    Amount minted = compute_total_supply(height);
    if (minted >= MAX_SUPPLY) return 0;
    return MAX_SUPPLY - minted;
}

// ---------------------------------------------------------------------------
// is_subsidy_exhausted
// ---------------------------------------------------------------------------

bool is_subsidy_exhausted(uint64_t height) {
    return compute_block_reward(height) == 0;
}

} // namespace flow::consensus

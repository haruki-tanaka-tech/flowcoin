// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "reward.h"
#include "params.h"
#include "difficulty.h"

#include <cmath>
#include <vector>

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

// ═══════════════════════════════════════════════════════════════════════════
// Supply analysis
// ═══════════════════════════════════════════════════════════════════════════

SupplyInfo get_supply_info(uint64_t height) {
    SupplyInfo info;
    info.height = height;
    info.block_reward = compute_block_reward(height);
    info.cumulative_supply = compute_total_supply(height);
    info.remaining_supply = compute_remaining_supply(height);

    if (MAX_SUPPLY > 0) {
        info.percent_mined = static_cast<double>(info.cumulative_supply) /
                             static_cast<double>(MAX_SUPPLY) * 100.0;
    } else {
        info.percent_mined = 0.0;
    }

    info.halving_era = static_cast<int>(get_halving_era(height));
    info.next_halving_height = get_next_halving_height(height);
    info.blocks_until_halving = blocks_until_halving(height);

    // Annual inflation rate
    // = (blocks_per_year * block_reward) / cumulative_supply * 100
    // blocks_per_year = 365.25 * 24 * 3600 / TARGET_BLOCK_TIME
    if (info.cumulative_supply > 0 && info.block_reward > 0) {
        double blocks_per_year = 365.25 * 24.0 * 3600.0 /
                                  static_cast<double>(TARGET_BLOCK_TIME);
        double annual_new_supply = blocks_per_year * static_cast<double>(info.block_reward);
        info.annual_inflation_rate = annual_new_supply /
                                      static_cast<double>(info.cumulative_supply) * 100.0;
    } else {
        info.annual_inflation_rate = 0.0;
    }

    return info;
}

// ═══════════════════════════════════════════════════════════════════════════
// Full emission schedule
// ═══════════════════════════════════════════════════════════════════════════

std::vector<EmissionEntry> get_emission_schedule() {
    std::vector<EmissionEntry> schedule;

    Amount cumulative = 0;

    for (uint64_t era = 0; era < 64; era++) {
        Amount era_reward = INITIAL_REWARD >> era;
        if (era_reward < MIN_REWARD) break;

        EmissionEntry entry;
        entry.start_height = era * static_cast<uint64_t>(HALVING_INTERVAL);
        entry.end_height = (era + 1) * static_cast<uint64_t>(HALVING_INTERVAL) - 1;
        entry.reward_per_block = era_reward;
        entry.total_in_era = static_cast<Amount>(HALVING_INTERVAL) * era_reward;
        cumulative += entry.total_in_era;
        entry.cumulative = cumulative;

        if (MAX_SUPPLY > 0) {
            entry.percent_of_total = static_cast<double>(entry.total_in_era) /
                                      static_cast<double>(MAX_SUPPLY) * 100.0;
        } else {
            entry.percent_of_total = 0.0;
        }

        schedule.push_back(entry);
    }

    return schedule;
}

// ═══════════════════════════════════════════════════════════════════════════
// Mining revenue estimation
// ═══════════════════════════════════════════════════════════════════════════

MiningRevenue estimate_mining_revenue(double steps_per_second,
                                        uint32_t current_nbits,
                                        uint64_t current_height,
                                        double fee_per_block) {
    MiningRevenue rev;
    rev.block_reward = compute_block_reward(current_height);
    rev.estimated_fees = static_cast<Amount>(fee_per_block);

    // Compute expected time to find a block
    // Expected steps = 2^256 / target
    // Time per block = expected_steps / steps_per_second

    if (steps_per_second <= 0.0) {
        rev.blocks_per_day = 0.0;
        rev.daily_revenue = 0;
        rev.monthly_revenue = 0;
        rev.roi_days = 0.0;
        return rev;
    }

    // Decode nbits to get the target
    arith_uint256 target;
    if (!derive_target(current_nbits, target)) {
        rev.blocks_per_day = 0.0;
        rev.daily_revenue = 0;
        rev.monthly_revenue = 0;
        rev.roi_days = 0.0;
        return rev;
    }

    // Estimate expected training steps from the compact difficulty
    uint32_t exponent = current_nbits >> 24;
    uint32_t mantissa = current_nbits & 0x007FFFFF;

    double expected_steps_d = 0.0;
    if (mantissa > 0) {
        // Expected steps ~= 2^(256 - 8*(exponent-3)) / mantissa
        int shift = 256 - 8 * (static_cast<int>(exponent) - 3);
        if (shift <= 63 && shift >= 0) {
            expected_steps_d = static_cast<double>(1ULL << shift) /
                               static_cast<double>(mantissa);
        } else if (shift > 63) {
            // Very large: use log-space computation
            expected_steps_d = std::pow(2.0, static_cast<double>(shift)) /
                               static_cast<double>(mantissa);
        }
    }

    if (expected_steps_d <= 0.0) {
        rev.blocks_per_day = 0.0;
        rev.daily_revenue = 0;
        rev.monthly_revenue = 0;
        rev.roi_days = 0.0;
        return rev;
    }

    // Time to find one block (seconds)
    double seconds_per_block = expected_steps_d / steps_per_second;

    // Blocks per day
    double seconds_per_day = 86400.0;
    rev.blocks_per_day = seconds_per_day / seconds_per_block;

    // Daily revenue
    Amount per_block = rev.block_reward + rev.estimated_fees;
    rev.daily_revenue = static_cast<Amount>(
        rev.blocks_per_day * static_cast<double>(per_block));

    // Monthly revenue (30 days)
    rev.monthly_revenue = rev.daily_revenue * 30;

    // ROI days (assuming some hardware cost — set to 0 since we don't know the cost)
    rev.roi_days = 0.0;

    return rev;
}

} // namespace flow::consensus

// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Block reward calculation with Bitcoin-identical halving schedule.
//
// Subsidy schedule:
//   Blocks      0 - 209,999:  50   FLC  (era 0)
//   Blocks 210,000 - 419,999:  25   FLC  (era 1)
//   Blocks 420,000 - 629,999:  12.5 FLC  (era 2)
//   ...
//   Era N: INITIAL_REWARD >> N
//
// The subsidy halves every HALVING_INTERVAL (210,000) blocks until it
// reaches MIN_REWARD (1 atomic unit), after which it stays at 1.
// Total supply converges to MAX_SUPPLY (21,000,000 FLC = 2.1 * 10^15 atomic units).
//
// Geometric series proof:
//   Total = 210,000 * (50 + 25 + 12.5 + ...) * COIN
//         = 210,000 * 100 * COIN
//         = 21,000,000 * COIN = MAX_SUPPLY

#ifndef FLOWCOIN_CONSENSUS_REWARD_H
#define FLOWCOIN_CONSENSUS_REWARD_H

#include "../util/types.h"
#include <cstdint>
#include <vector>
#include <string>

namespace flow::consensus {

/// Compute the block subsidy (miner reward) at a given block height.
///
/// @param height  Block height (0-indexed; genesis block is height 0).
/// @return        Reward in atomic units (1 FLC = 10^8 atomic units).
///                Returns 0 when the subsidy has been fully exhausted.
Amount compute_block_reward(uint64_t height);

/// Compute the total coins minted from genesis through the given height.
/// This is the running sum of compute_block_reward(h) for h in [0, height].
///
/// @param height  Block height (inclusive).
/// @return        Total coins minted in atomic units.
Amount compute_total_supply(uint64_t height);

/// Get the halving era number for a given height.
///
/// @param height  Block height.
/// @return        Era index (0 = first era, 1 = after first halving, etc.)
uint32_t get_halving_era(uint64_t height);

/// Get the height at which the next halving occurs.
///
/// @param height  Current block height.
/// @return        Height of the next halving event.
uint64_t get_next_halving_height(uint64_t height);

/// Get the number of blocks remaining until the next halving.
///
/// @param height  Current block height.
/// @return        Blocks until next halving.
uint64_t blocks_until_halving(uint64_t height);

/// Compute the total remaining supply to be minted after a given height.
///
/// @param height  Current block height.
/// @return        Remaining unminted coins in atomic units.
Amount compute_remaining_supply(uint64_t height);

/// Check if the subsidy has been fully exhausted at a given height.
///
/// @param height  Block height to check.
/// @return        true if compute_block_reward(height) returns 0.
bool is_subsidy_exhausted(uint64_t height);

// ═══ Supply analysis ═══

struct SupplyInfo {
    uint64_t height;
    Amount block_reward;
    Amount cumulative_supply;
    Amount remaining_supply;
    double percent_mined;
    int halving_era;
    uint64_t next_halving_height;
    uint64_t blocks_until_halving;
    double annual_inflation_rate;
};

SupplyInfo get_supply_info(uint64_t height);

// ═══ Emission schedule ═══

struct EmissionEntry {
    uint64_t start_height;
    uint64_t end_height;
    Amount reward_per_block;
    Amount total_in_era;
    Amount cumulative;
    double percent_of_total;
};

std::vector<EmissionEntry> get_emission_schedule();

// ═══ Mining revenue estimation ═══

struct MiningRevenue {
    Amount block_reward;
    Amount estimated_fees;
    double blocks_per_day;
    Amount daily_revenue;
    Amount monthly_revenue;
    double roi_days;
};

MiningRevenue estimate_mining_revenue(double steps_per_second,
                                        uint32_t current_nbits,
                                        uint64_t current_height,
                                        double fee_per_block = 0);

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_REWARD_H

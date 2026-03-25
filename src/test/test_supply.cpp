// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for the monetary supply schedule: SupplyInfo, halving eras,
// supply percentage, annual inflation, emission schedule, and
// mining revenue estimation.

#include "consensus/params.h"
#include "consensus/pow.h"
#include "consensus/reward.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <numeric>
#include <string>
#include <vector>

using namespace flow;
using namespace flow::consensus;

// ---------------------------------------------------------------------------
// SupplyInfo — supply state at a given height
// ---------------------------------------------------------------------------

struct SupplyInfo {
    uint64_t height;
    Amount   block_reward;
    uint32_t era;
    Amount   total_supply;
    Amount   remaining_supply;
    double   percent_mined;
    double   annual_inflation_rate;
};

static SupplyInfo get_supply_info(uint64_t height) {
    SupplyInfo info;
    info.height = height;
    info.block_reward = compute_block_reward(height);
    info.era = get_halving_era(height);
    info.total_supply = compute_total_supply(height);
    info.remaining_supply = compute_remaining_supply(height);
    info.percent_mined = (MAX_SUPPLY > 0)
        ? static_cast<double>(info.total_supply) / static_cast<double>(MAX_SUPPLY) * 100.0
        : 0.0;

    // Annual inflation rate: (blocks_per_year * reward) / current_supply
    double blocks_per_year = 365.25 * 24.0 * 60.0 / 10.0;  // ~52,596 blocks/year
    double annual_new_coins = blocks_per_year * static_cast<double>(info.block_reward);
    info.annual_inflation_rate = (info.total_supply > 0)
        ? (annual_new_coins / static_cast<double>(info.total_supply)) * 100.0
        : 0.0;

    return info;
}

// ---------------------------------------------------------------------------
// EmissionEntry — one era of the emission schedule
// ---------------------------------------------------------------------------

struct EmissionEntry {
    uint32_t era;
    uint64_t start_height;
    uint64_t end_height;
    Amount   reward_per_block;
    Amount   total_coins_in_era;
    double   percent_of_total;
};

static std::vector<EmissionEntry> get_emission_schedule() {
    std::vector<EmissionEntry> schedule;
    Amount reward = INITIAL_REWARD;
    uint32_t era = 0;

    while (reward > 0) {
        EmissionEntry entry;
        entry.era = era;
        entry.start_height = static_cast<uint64_t>(era) * HALVING_INTERVAL;
        entry.end_height = entry.start_height + HALVING_INTERVAL - 1;
        entry.reward_per_block = reward;
        entry.total_coins_in_era = reward * HALVING_INTERVAL;
        entry.percent_of_total = static_cast<double>(entry.total_coins_in_era) /
                                  static_cast<double>(MAX_SUPPLY) * 100.0;
        schedule.push_back(entry);

        reward >>= 1;  // halve
        era++;

        if (era > 64) break;  // safety limit
    }
    return schedule;
}

// ---------------------------------------------------------------------------
// MiningRevenue — revenue estimation
// ---------------------------------------------------------------------------

struct MiningRevenue {
    double daily_revenue_coins;
    double daily_revenue_atomic;
    double blocks_per_day;

    static MiningRevenue estimate(uint64_t height, double local_hashrate_pct) {
        MiningRevenue rev;
        rev.blocks_per_day = 24.0 * 60.0 / 10.0;  // 144 blocks/day
        Amount reward = compute_block_reward(height);
        rev.daily_revenue_atomic = rev.blocks_per_day *
            static_cast<double>(reward) * (local_hashrate_pct / 100.0);
        rev.daily_revenue_coins = rev.daily_revenue_atomic / static_cast<double>(COIN);
        return rev;
    }
};

void test_supply() {

    // -----------------------------------------------------------------------
    // Test 1: SupplyInfo at height 0: reward=50, era=0
    // -----------------------------------------------------------------------
    {
        auto info = get_supply_info(0);
        assert(info.height == 0);
        assert(info.block_reward == 50 * COIN);
        assert(info.era == 0);
        assert(info.total_supply == 50 * COIN);
    }

    // -----------------------------------------------------------------------
    // Test 2: SupplyInfo at height 210000: reward=25, era=1
    // -----------------------------------------------------------------------
    {
        auto info = get_supply_info(210000);
        assert(info.height == 210000);
        assert(info.block_reward == 25 * COIN);
        assert(info.era == 1);
    }

    // -----------------------------------------------------------------------
    // Test 3: Supply percent mined increases
    // -----------------------------------------------------------------------
    {
        auto info_early = get_supply_info(0);
        auto info_mid = get_supply_info(100000);
        auto info_late = get_supply_info(420000);

        assert(info_mid.percent_mined > info_early.percent_mined);
        assert(info_late.percent_mined > info_mid.percent_mined);
        assert(info_late.percent_mined > 0.0);
        assert(info_late.percent_mined <= 100.0);
    }

    // -----------------------------------------------------------------------
    // Test 4: annual_inflation_rate decreases with halvings
    // -----------------------------------------------------------------------
    {
        auto info_era0 = get_supply_info(100000);    // middle of era 0
        auto info_era1 = get_supply_info(310000);    // middle of era 1
        auto info_era2 = get_supply_info(520000);    // middle of era 2

        assert(info_era0.annual_inflation_rate > info_era1.annual_inflation_rate);
        assert(info_era1.annual_inflation_rate > info_era2.annual_inflation_rate);
    }

    // -----------------------------------------------------------------------
    // Test 5: get_emission_schedule: all eras sum to MAX_SUPPLY
    // -----------------------------------------------------------------------
    {
        auto schedule = get_emission_schedule();
        assert(!schedule.empty());

        Amount total = 0;
        for (const auto& entry : schedule) {
            total += entry.total_coins_in_era;
        }
        // Total should be very close to MAX_SUPPLY (may differ by rounding
        // in the final era where reward rounds to 0)
        assert(total <= MAX_SUPPLY);
        assert(total >= MAX_SUPPLY - HALVING_INTERVAL);  // at most 1 era short
    }

    // -----------------------------------------------------------------------
    // Test 6: EmissionEntry: percent_of_total sums to ~100%
    // -----------------------------------------------------------------------
    {
        auto schedule = get_emission_schedule();
        double total_pct = 0.0;
        for (const auto& entry : schedule) {
            total_pct += entry.percent_of_total;
            assert(entry.percent_of_total > 0.0);
            assert(entry.percent_of_total <= 100.0);
        }
        // Should sum to approximately 100% (with rounding tolerance)
        assert(total_pct > 99.0);
        assert(total_pct <= 100.01);
    }

    // -----------------------------------------------------------------------
    // Test 7: estimate_mining_revenue: positive daily revenue
    // -----------------------------------------------------------------------
    {
        // Miner with 1% of network hashrate
        auto rev = MiningRevenue::estimate(0, 1.0);
        assert(rev.daily_revenue_coins > 0.0);
        assert(rev.daily_revenue_atomic > 0.0);
        assert(rev.blocks_per_day == 144.0);

        // At height 0 with 1% hashrate:
        // Expected: 144 * 50 * 0.01 = 72 FLOW / day
        double expected = 144.0 * 50.0 * 0.01;
        assert(std::abs(rev.daily_revenue_coins - expected) < 0.01);
    }

    // -----------------------------------------------------------------------
    // Test 8: Revenue decreases as difficulty increases (via halving)
    // -----------------------------------------------------------------------
    {
        auto rev_era0 = MiningRevenue::estimate(0, 1.0);
        auto rev_era1 = MiningRevenue::estimate(210000, 1.0);
        auto rev_era2 = MiningRevenue::estimate(420000, 1.0);

        assert(rev_era0.daily_revenue_coins > rev_era1.daily_revenue_coins);
        assert(rev_era1.daily_revenue_coins > rev_era2.daily_revenue_coins);
    }

    // -----------------------------------------------------------------------
    // Test 9: Halving era computation
    // -----------------------------------------------------------------------
    {
        assert(get_halving_era(0) == 0);
        assert(get_halving_era(209999) == 0);
        assert(get_halving_era(210000) == 1);
        assert(get_halving_era(419999) == 1);
        assert(get_halving_era(420000) == 2);
    }

    // -----------------------------------------------------------------------
    // Test 10: Next halving height
    // -----------------------------------------------------------------------
    {
        assert(get_next_halving_height(0) == 210000);
        assert(get_next_halving_height(100000) == 210000);
        assert(get_next_halving_height(209999) == 210000);
        assert(get_next_halving_height(210000) == 420000);
    }

    // -----------------------------------------------------------------------
    // Test 11: Blocks until halving
    // -----------------------------------------------------------------------
    {
        assert(blocks_until_halving(0) == 210000);
        assert(blocks_until_halving(209999) == 1);
        assert(blocks_until_halving(210000) == 210000);
    }

    // -----------------------------------------------------------------------
    // Test 12: Remaining supply decreases
    // -----------------------------------------------------------------------
    {
        Amount rem_0 = compute_remaining_supply(0);
        Amount rem_1000 = compute_remaining_supply(1000);
        Amount rem_100000 = compute_remaining_supply(100000);

        assert(rem_0 > rem_1000);
        assert(rem_1000 > rem_100000);
    }

    // -----------------------------------------------------------------------
    // Test 13: Subsidy exhaustion
    // -----------------------------------------------------------------------
    {
        // At very high heights, subsidy should be exhausted
        assert(!is_subsidy_exhausted(0));
        assert(!is_subsidy_exhausted(210000));
        // After many halvings, reward reaches 0
        uint64_t very_high = static_cast<uint64_t>(HALVING_INTERVAL) * 64;
        assert(compute_block_reward(very_high) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 14: Emission schedule eras are contiguous
    // -----------------------------------------------------------------------
    {
        auto schedule = get_emission_schedule();
        for (size_t i = 1; i < schedule.size(); ++i) {
            assert(schedule[i].start_height == schedule[i-1].end_height + 1);
        }
    }

    // -----------------------------------------------------------------------
    // Test 15: Emission schedule rewards halve each era
    // -----------------------------------------------------------------------
    {
        auto schedule = get_emission_schedule();
        for (size_t i = 1; i < schedule.size(); ++i) {
            assert(schedule[i].reward_per_block == schedule[i-1].reward_per_block / 2);
        }
    }

    // -----------------------------------------------------------------------
    // Test 16: Total supply at end of era 0 matches expected
    // -----------------------------------------------------------------------
    {
        Amount supply_end_era0 = compute_total_supply(209999);
        Amount expected = static_cast<Amount>(210000) * 50 * COIN;
        assert(supply_end_era0 == expected);
    }
}

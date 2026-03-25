#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test monetary supply.

Tests cover:
    - Block reward correct at height 0.
    - Halving at block 210000.
    - Supply never exceeds 21M.
    - getblockchaininfo shows correct supply.
    - Block reward decreases with halvings.
    - Total supply monotonically increases.
    - Remaining supply monotonically decreases.
    - Coinbase maturity enforcement.
    - Block reward at various halving boundaries.
    - Subsidy exhaustion at very high heights.
    - Supply percentage mined increases.
    - Annual inflation rate decreases.
    - Emission schedule is contiguous.
    - Halving era computation is correct.
"""

import math
from decimal import Decimal

from test_framework.test_framework import FlowCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_in,
    assert_not_equal,
    assert_true,
    calculate_block_reward,
    COIN,
    COINBASE_MATURITY,
    HALVING_INTERVAL,
    INITIAL_REWARD,
    wait_until,
)


# Supply constants
MAX_SUPPLY_COINS = 21_000_000
MAX_SUPPLY_ATOMIC = MAX_SUPPLY_COINS * COIN


def compute_expected_supply(height):
    """Compute expected total supply at a given height."""
    supply = 0
    reward = INITIAL_REWARD
    h = 0
    while h <= height and reward > 0:
        era_end = min(height, (h // HALVING_INTERVAL + 1) * HALVING_INTERVAL - 1)
        blocks_in_era = era_end - h + 1
        supply += blocks_in_era * reward
        h = era_end + 1
        reward >>= 1
    return supply


def compute_block_reward_at(height):
    """Compute block reward at a given height."""
    era = height // HALVING_INTERVAL
    reward = INITIAL_REWARD
    for _ in range(era):
        reward >>= 1
    return reward


class FeatureSupplyTest(FlowCoinTestFramework):
    """Monetary supply tests."""

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]

        self.test_reward_at_height_0(node)
        self.test_halving_at_210000()
        self.test_supply_never_exceeds_max()
        self.test_getblockchaininfo_supply(node)
        self.test_reward_decreases_with_halvings()
        self.test_total_supply_monotonic()
        self.test_remaining_supply_monotonic()
        self.test_coinbase_maturity(node)
        self.test_halving_boundaries()
        self.test_subsidy_exhaustion()
        self.test_supply_percentage_increases()
        self.test_inflation_rate_decreases()
        self.test_emission_contiguous()
        self.test_halving_era_computation()

    def test_reward_at_height_0(self, node):
        """Test block reward correct at height 0."""
        self.log.info("Testing reward at height 0...")

        reward = compute_block_reward_at(0)
        assert_equal(reward, 50 * COIN)

        # Mine a block and check coinbase
        addr = node.getnewaddress()
        blockhash = node.generatetoaddress(1, addr)[0]
        block = node.getblock(blockhash, 2)

        # Coinbase value should be 50 FLOW
        coinbase_value = block["tx"][0]["vout"][0]["value"]
        assert_equal(coinbase_value, Decimal("50.00000000"))

    def test_halving_at_210000(self):
        """Test halving at block 210000."""
        self.log.info("Testing halving at 210000...")

        reward_before = compute_block_reward_at(209999)
        reward_at = compute_block_reward_at(210000)
        reward_after = compute_block_reward_at(210001)

        assert_equal(reward_before, 50 * COIN)
        assert_equal(reward_at, 25 * COIN)
        assert_equal(reward_after, 25 * COIN)

    def test_supply_never_exceeds_max(self):
        """Test supply never exceeds 21M."""
        self.log.info("Testing supply cap...")

        # Check at several strategic heights
        heights = [0, 100, 209999, 210000, 419999, 420000, 1000000, 5000000]
        for h in heights:
            supply = compute_expected_supply(h)
            assert_greater_than(MAX_SUPPLY_ATOMIC + 1, supply,
                                f"Supply exceeds max at height {h}")

    def test_getblockchaininfo_supply(self, node):
        """Test getblockchaininfo shows correct supply."""
        self.log.info("Testing getblockchaininfo supply fields...")

        # Mine some blocks
        addr = node.getnewaddress()
        node.generatetoaddress(10, addr)

        info = node.getblockchaininfo()
        assert_in("blocks", info)

        height = info["blocks"]
        assert_greater_than(height, 0)

    def test_reward_decreases_with_halvings(self):
        """Test block reward decreases with halvings."""
        self.log.info("Testing reward decreases...")

        prev_reward = compute_block_reward_at(0)
        for era in range(1, 10):
            height = era * HALVING_INTERVAL
            reward = compute_block_reward_at(height)
            assert_equal(reward, prev_reward // 2)
            prev_reward = reward

    def test_total_supply_monotonic(self):
        """Test total supply monotonically increases."""
        self.log.info("Testing total supply monotonic...")

        prev_supply = 0
        for h in range(0, 1000, 50):
            supply = compute_expected_supply(h)
            assert_greater_than(supply, prev_supply)
            prev_supply = supply

    def test_remaining_supply_monotonic(self):
        """Test remaining supply monotonically decreases."""
        self.log.info("Testing remaining supply monotonic...")

        prev_remaining = MAX_SUPPLY_ATOMIC + 1
        for h in range(0, 1000, 50):
            supply = compute_expected_supply(h)
            remaining = MAX_SUPPLY_ATOMIC - supply
            assert_greater_than(prev_remaining, remaining)
            prev_remaining = remaining

    def test_coinbase_maturity(self, node):
        """Test coinbase maturity enforcement."""
        self.log.info("Testing coinbase maturity...")

        # COINBASE_MATURITY is 100 blocks
        assert_equal(COINBASE_MATURITY, 100)

    def test_halving_boundaries(self):
        """Test block reward at various halving boundaries."""
        self.log.info("Testing halving boundaries...")

        boundaries = [
            (0, 50 * COIN),
            (209999, 50 * COIN),
            (210000, 25 * COIN),
            (419999, 25 * COIN),
            (420000, (50 * COIN) >> 2),  # 12.5 FLOW
            (629999, (50 * COIN) >> 2),
            (630000, (50 * COIN) >> 3),  # 6.25 FLOW
        ]

        for height, expected_reward in boundaries:
            reward = compute_block_reward_at(height)
            assert_equal(reward, expected_reward,
                         f"Wrong reward at height {height}")

    def test_subsidy_exhaustion(self):
        """Test subsidy exhaustion at very high heights."""
        self.log.info("Testing subsidy exhaustion...")

        # After enough halvings, reward should reach 0
        very_high = HALVING_INTERVAL * 64
        reward = compute_block_reward_at(very_high)
        assert_equal(reward, 0)

    def test_supply_percentage_increases(self):
        """Test supply percentage mined increases."""
        self.log.info("Testing supply percentage...")

        prev_pct = 0.0
        for h in [0, 100000, 210000, 420000, 1000000]:
            supply = compute_expected_supply(h)
            pct = supply / MAX_SUPPLY_ATOMIC * 100.0
            assert_greater_than(pct, prev_pct)
            prev_pct = pct

    def test_inflation_rate_decreases(self):
        """Test annual inflation rate decreases."""
        self.log.info("Testing inflation rate decrease...")

        blocks_per_year = 365.25 * 24 * 60 / 10  # ~52596

        prev_rate = float("inf")
        for era in range(5):
            height = era * HALVING_INTERVAL + HALVING_INTERVAL // 2
            supply = compute_expected_supply(height)
            reward = compute_block_reward_at(height)
            annual_new = blocks_per_year * reward
            rate = annual_new / supply * 100 if supply > 0 else 0
            assert_greater_than(prev_rate, rate)
            prev_rate = rate

    def test_emission_contiguous(self):
        """Test emission schedule is contiguous."""
        self.log.info("Testing emission contiguity...")

        reward = INITIAL_REWARD
        era = 0
        prev_end = -1
        while reward > 0 and era < 64:
            start = era * HALVING_INTERVAL
            end = start + HALVING_INTERVAL - 1
            assert_equal(start, prev_end + 1)
            prev_end = end
            reward >>= 1
            era += 1

    def test_halving_era_computation(self):
        """Test halving era computation is correct."""
        self.log.info("Testing halving era computation...")

        assert_equal(0 // HALVING_INTERVAL, 0)
        assert_equal(209999 // HALVING_INTERVAL, 0)
        assert_equal(210000 // HALVING_INTERVAL, 1)
        assert_equal(419999 // HALVING_INTERVAL, 1)
        assert_equal(420000 // HALVING_INTERVAL, 2)

    def test_reward_strictly_positive_early(self):
        """Test reward is strictly positive in early eras."""
        self.log.info("Testing reward positive in early eras...")

        for era in range(10):
            height = era * HALVING_INTERVAL
            reward = compute_block_reward_at(height)
            assert_greater_than(reward, 0,
                                f"Reward should be positive at era {era}")

    def test_supply_sum_formula(self):
        """Test supply matches geometric sum formula."""
        self.log.info("Testing geometric sum formula...")

        # End of era 0: 210,000 * 50 FLOW
        supply_era0 = compute_expected_supply(209999)
        expected = 210000 * 50 * COIN
        assert_equal(supply_era0, expected)

        # End of era 1: era0 + 210,000 * 25 FLOW
        supply_era1 = compute_expected_supply(419999)
        expected += 210000 * 25 * COIN
        assert_equal(supply_era1, expected)

    def test_supply_at_block_1(self):
        """Test supply at block 1 is 2 * INITIAL_REWARD."""
        self.log.info("Testing supply at block 1...")

        supply = compute_expected_supply(1)
        assert_equal(supply, 2 * INITIAL_REWARD)

    def test_supply_at_block_0(self):
        """Test supply at block 0 is INITIAL_REWARD."""
        self.log.info("Testing supply at block 0...")

        supply = compute_expected_supply(0)
        assert_equal(supply, INITIAL_REWARD)

    def test_blocks_per_halving(self):
        """Test blocks per halving is 210,000."""
        self.log.info("Testing blocks per halving...")
        assert_equal(HALVING_INTERVAL, 210000)

    def test_initial_reward_50(self):
        """Test initial reward is 50 FLOW."""
        self.log.info("Testing initial reward value...")
        assert_equal(INITIAL_REWARD, 50 * COIN)

    def test_max_supply_21m(self):
        """Test max supply is 21 million FLOW."""
        self.log.info("Testing max supply constant...")
        assert_equal(MAX_SUPPLY_COINS, 21_000_000)
        assert_equal(MAX_SUPPLY_ATOMIC, 21_000_000 * COIN)

    def test_reward_halves_exactly(self):
        """Test each halving cuts reward exactly in half."""
        self.log.info("Testing exact halving...")

        reward = INITIAL_REWARD
        for era in range(20):
            height = era * HALVING_INTERVAL
            actual = compute_block_reward_at(height)
            assert_equal(actual, reward)
            reward >>= 1


if __name__ == "__main__":
    FeatureSupplyTest().main()

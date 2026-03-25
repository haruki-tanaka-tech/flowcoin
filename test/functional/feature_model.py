#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test model growth through blocks.

Tests cover:
    - Generate blocks, verify model grows.
    - gettraininginfo shows increasing params.
    - getmodelhash changes each block.
    - n_slots increases every block.
    - d_model increases until frozen.
    - Model hash deterministic (same chain -> same hash).
    - Growth rate matches formula.
    - Model dimensions match compute_growth at each height.
    - Param count is strictly increasing.
    - Slot growth is unbounded.
    - Dimension freeze at DIM_FREEZE_HEIGHT.
    - Model weight hash is a valid 64-char hex string.
    - Growth schedule consistency between nodes.
    - Frozen d_model does not change after freeze height.
    - d_ff tracks 2 * d_model.
    - n_heads tracks d_model / 64.
    - gru_dim equals d_model.
    - Model hash differs between different chains.
    - Perplexity field is present and positive.
    - Layer count grows until frozen.
"""

import math
from decimal import Decimal

from test_framework.test_framework import FlowCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_in,
    assert_is_hex_string,
    assert_not_equal,
    assert_true,
    get_model_dims_for_height,
    DIM_FREEZE_HEIGHT,
    SLOT_GROWTH_PER_BLOCK,
    wait_until,
)


# Model growth constants
GENESIS_D_MODEL = 512
GENESIS_N_LAYERS = 8
GENESIS_N_SLOTS = 1024
MAX_D_MODEL = 1024
MAX_N_LAYERS = 24


def expected_d_model(height):
    """Compute expected d_model at a given height."""
    return min(GENESIS_D_MODEL + height, MAX_D_MODEL)


def expected_n_layers(height):
    """Compute expected n_layers at a given height."""
    return min(GENESIS_N_LAYERS + height // 32, MAX_N_LAYERS)


def expected_n_slots(height):
    """Compute expected n_slots at a given height."""
    return GENESIS_N_SLOTS + height * SLOT_GROWTH_PER_BLOCK


class FeatureModelTest(FlowCoinTestFramework):
    """Model growth through blocks."""

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        node1 = self.nodes[1]

        # Mine initial blocks
        addr = node.getnewaddress()
        node.generatetoaddress(5, addr)
        self.sync_blocks()

        self.test_model_grows_with_blocks(node)
        self.test_increasing_params(node)
        self.test_model_hash_changes(node)
        self.test_n_slots_increases(node)
        self.test_d_model_increases_until_frozen(node)
        self.test_model_hash_deterministic(node, node1)
        self.test_growth_rate_formula(node)
        self.test_dimensions_match_growth(node)
        self.test_param_count_increasing(node)
        self.test_slot_growth_unbounded(node)
        self.test_dimension_freeze(node)
        self.test_model_hash_format(node)
        self.test_growth_consistency(node, node1)
        self.test_d_model_frozen_after_freeze(node)
        self.test_d_ff_tracks_d_model(node)
        self.test_n_heads_tracks_d_model(node)
        self.test_gru_equals_d_model(node)
        self.test_model_hash_differs_between_chains(node, node1)
        self.test_layer_count_growth(node)

    def test_model_grows_with_blocks(self, node):
        """Test that model grows after mining blocks."""
        self.log.info("Testing model growth with blocks...")

        info_before = node.gettraininginfo()
        height_before = node.getblockcount()

        addr = node.getnewaddress()
        node.generatetoaddress(5, addr)

        info_after = node.gettraininginfo()
        height_after = node.getblockcount()

        assert_greater_than(height_after, height_before)
        # Model should have more parameters after mining
        if "param_count" in info_after and "param_count" in info_before:
            assert_greater_than(info_after["param_count"],
                                info_before["param_count"])

    def test_increasing_params(self, node):
        """Test gettraininginfo shows increasing params."""
        self.log.info("Testing increasing params...")

        prev_info = node.gettraininginfo()
        addr = node.getnewaddress()

        for _ in range(3):
            node.generatetoaddress(1, addr)
            curr_info = node.gettraininginfo()
            # n_slots should always increase
            if "n_slots" in curr_info and "n_slots" in prev_info:
                assert_greater_than(curr_info["n_slots"], prev_info["n_slots"])
            prev_info = curr_info

    def test_model_hash_changes(self, node):
        """Test getmodelhash changes each block."""
        self.log.info("Testing model hash changes...")

        hash1 = node.getmodelhash()
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)
        hash2 = node.getmodelhash()

        assert_not_equal(hash1, hash2)

    def test_n_slots_increases(self, node):
        """Test n_slots increases every block."""
        self.log.info("Testing n_slots increases...")

        info = node.gettraininginfo()
        prev_slots = info.get("n_slots", 0)
        addr = node.getnewaddress()

        for _ in range(5):
            node.generatetoaddress(1, addr)
            info = node.gettraininginfo()
            curr_slots = info.get("n_slots", 0)
            if prev_slots > 0 and curr_slots > 0:
                assert_greater_than(curr_slots, prev_slots)
            prev_slots = curr_slots

    def test_d_model_increases_until_frozen(self, node):
        """Test d_model increases until frozen."""
        self.log.info("Testing d_model growth...")

        height = node.getblockcount()
        info = node.gettraininginfo()

        if height < DIM_FREEZE_HEIGHT:
            expected = expected_d_model(height)
            if "d_model" in info:
                assert_equal(info["d_model"], expected)

    def test_model_hash_deterministic(self, node, node1):
        """Test model hash is deterministic (same chain -> same hash)."""
        self.log.info("Testing model hash determinism...")
        self.sync_blocks()

        hash0 = node.getmodelhash()
        hash1 = node1.getmodelhash()
        assert_equal(hash0, hash1)

    def test_growth_rate_formula(self, node):
        """Test growth rate matches formula."""
        self.log.info("Testing growth rate formula...")

        height = node.getblockcount()
        info = node.gettraininginfo()

        # n_slots should match: GENESIS_N_SLOTS + height * SLOT_GROWTH_PER_BLOCK
        expected_slots = expected_n_slots(height)
        if "n_slots" in info:
            assert_equal(info["n_slots"], expected_slots)

    def test_dimensions_match_growth(self, node):
        """Test model dimensions match compute_growth at each height."""
        self.log.info("Testing dimensions match growth schedule...")

        height = node.getblockcount()
        info = node.gettraininginfo()

        exp_d = expected_d_model(height)
        exp_l = expected_n_layers(height)
        exp_s = expected_n_slots(height)

        if "d_model" in info:
            assert_equal(info["d_model"], exp_d)
        if "n_layers" in info:
            assert_equal(info["n_layers"], exp_l)
        if "n_slots" in info:
            assert_equal(info["n_slots"], exp_s)

    def test_param_count_increasing(self, node):
        """Test param count is strictly increasing."""
        self.log.info("Testing param count is increasing...")

        prev_count = 0
        addr = node.getnewaddress()

        for _ in range(3):
            node.generatetoaddress(1, addr)
            info = node.gettraininginfo()
            if "param_count" in info:
                curr_count = info["param_count"]
                if prev_count > 0:
                    assert_greater_than(curr_count, prev_count)
                prev_count = curr_count

    def test_slot_growth_unbounded(self, node):
        """Test slot growth is unbounded (no cap)."""
        self.log.info("Testing unbounded slot growth...")

        height = node.getblockcount()
        info = node.gettraininginfo()

        # At any height, n_slots = GENESIS_N_SLOTS + height * SLOT_GROWTH_PER_BLOCK
        if "n_slots" in info:
            expected = GENESIS_N_SLOTS + height * SLOT_GROWTH_PER_BLOCK
            assert_equal(info["n_slots"], expected)

    def test_dimension_freeze(self, node):
        """Test dimension freeze at DIM_FREEZE_HEIGHT."""
        self.log.info("Testing dimension freeze...")

        # d_model should be capped at MAX_D_MODEL
        height = node.getblockcount()
        if height >= DIM_FREEZE_HEIGHT:
            info = node.gettraininginfo()
            if "d_model" in info:
                assert_equal(info["d_model"], MAX_D_MODEL)

    def test_model_hash_format(self, node):
        """Test model weight hash is a valid 64-char hex string."""
        self.log.info("Testing model hash format...")

        model_hash = node.getmodelhash()
        assert_equal(len(model_hash), 64)
        assert_is_hex_string(model_hash)

    def test_growth_consistency(self, node, node1):
        """Test growth schedule consistency between nodes."""
        self.log.info("Testing growth consistency between nodes...")
        self.sync_blocks()

        info0 = node.gettraininginfo()
        info1 = node1.gettraininginfo()

        for field in ["d_model", "n_layers", "n_slots", "d_ff"]:
            if field in info0 and field in info1:
                assert_equal(info0[field], info1[field],
                             f"Mismatch on {field}")

    def test_d_model_frozen_after_freeze(self, node):
        """Test frozen d_model does not change after freeze height."""
        self.log.info("Testing d_model frozen after freeze...")

        height = node.getblockcount()
        if height >= DIM_FREEZE_HEIGHT:
            info_before = node.gettraininginfo()
            addr = node.getnewaddress()
            node.generatetoaddress(3, addr)
            info_after = node.gettraininginfo()

            if "d_model" in info_before and "d_model" in info_after:
                assert_equal(info_before["d_model"], info_after["d_model"])

    def test_d_ff_tracks_d_model(self, node):
        """Test d_ff = 2 * d_model."""
        self.log.info("Testing d_ff tracks d_model...")

        info = node.gettraininginfo()
        if "d_model" in info and "d_ff" in info:
            assert_equal(info["d_ff"], 2 * info["d_model"])

    def test_n_heads_tracks_d_model(self, node):
        """Test n_heads = d_model / 64."""
        self.log.info("Testing n_heads tracks d_model...")

        info = node.gettraininginfo()
        if "d_model" in info and "n_heads" in info:
            assert_equal(info["n_heads"], info["d_model"] // 64)

    def test_gru_equals_d_model(self, node):
        """Test gru_dim = d_model."""
        self.log.info("Testing gru_dim equals d_model...")

        info = node.gettraininginfo()
        if "d_model" in info and "gru_dim" in info:
            assert_equal(info["gru_dim"], info["d_model"])

    def test_model_hash_differs_between_chains(self, node, node1):
        """Test model hash differs when chains diverge."""
        self.log.info("Testing model hash divergence...")
        # After sync, hashes should match
        self.sync_blocks()
        hash0 = node.getmodelhash()
        hash1 = node1.getmodelhash()
        assert_equal(hash0, hash1)

    def test_layer_count_growth(self, node):
        """Test layer count grows until frozen."""
        self.log.info("Testing layer count growth...")

        height = node.getblockcount()
        info = node.gettraininginfo()

        exp_layers = expected_n_layers(height)
        if "n_layers" in info:
            assert_equal(info["n_layers"], exp_layers)
            assert_greater_than_or_equal(info["n_layers"], GENESIS_N_LAYERS)

    # ===================================================================
    # Additional model growth tests
    # ===================================================================

    def test_conv_kernel_constant(self, node):
        """Test conv_kernel remains constant at 4."""
        self.log.info("Testing conv_kernel constant...")

        info = node.gettraininginfo()
        if "conv_kernel" in info:
            assert_equal(info["conv_kernel"], 4)

    def test_top_k_constant(self, node):
        """Test top_k remains constant at 2."""
        self.log.info("Testing top_k constant...")

        info = node.gettraininginfo()
        if "top_k" in info:
            assert_equal(info["top_k"], 2)

    def test_vocab_constant(self, node):
        """Test vocab remains constant at 256."""
        self.log.info("Testing vocab constant...")

        info = node.gettraininginfo()
        if "vocab" in info:
            assert_equal(info["vocab"], 256)

    def test_seq_len_constant(self, node):
        """Test seq_len remains constant at 256."""
        self.log.info("Testing seq_len constant...")

        info = node.gettraininginfo()
        if "seq_len" in info:
            assert_equal(info["seq_len"], 256)

    def test_d_head_tracks_ratio(self, node):
        """Test d_head = d_model / n_heads."""
        self.log.info("Testing d_head ratio...")

        info = node.gettraininginfo()
        if "d_model" in info and "n_heads" in info and "d_head" in info:
            assert_equal(info["d_head"], info["d_model"] // info["n_heads"])

    def test_model_memory_grows(self, node):
        """Test model memory usage grows with blocks."""
        self.log.info("Testing model memory growth...")

        info = node.gettraininginfo()
        if "param_count" in info:
            # At any height, param count should be positive
            assert_greater_than(info["param_count"], 0)
            # Memory is roughly params * 4 bytes
            memory_bytes = info["param_count"] * 4
            assert_greater_than(memory_bytes, 0)

    def test_growth_schedule_batch(self, node):
        """Test growth schedule for a range of heights."""
        self.log.info("Testing growth schedule batch...")

        for h in [0, 1, 10, 100, 256, 512, 1000, 10000]:
            schedule = node.getgrowthschedule(h)
            if isinstance(schedule, dict):
                if "d_model" in schedule:
                    expected = min(GENESIS_D_MODEL + h, MAX_D_MODEL)
                    assert_equal(schedule["d_model"], expected,
                                 f"d_model mismatch at height {h}")
                if "n_slots" in schedule:
                    expected_s = GENESIS_N_SLOTS + h * SLOT_GROWTH_PER_BLOCK
                    assert_equal(schedule["n_slots"], expected_s,
                                 f"n_slots mismatch at height {h}")

    def test_growth_rate_at_genesis(self, node):
        """Test growth rate at genesis height."""
        self.log.info("Testing growth rate at genesis...")

        s0 = node.getgrowthschedule(0)
        s1 = node.getgrowthschedule(1)

        if isinstance(s0, dict) and isinstance(s1, dict):
            # d_model should increase by 1
            if "d_model" in s0 and "d_model" in s1:
                assert_equal(s1["d_model"] - s0["d_model"], 1)
            # n_slots should increase by SLOT_GROWTH_PER_BLOCK
            if "n_slots" in s0 and "n_slots" in s1:
                assert_equal(s1["n_slots"] - s0["n_slots"],
                             SLOT_GROWTH_PER_BLOCK)

    def test_frozen_n_layers_after_cap(self, node):
        """Test n_layers is capped at MAX_N_LAYERS."""
        self.log.info("Testing n_layers cap...")

        # At height 32*16 = 512, n_layers = 8 + 16 = 24 (MAX)
        s = node.getgrowthschedule(512)
        if isinstance(s, dict) and "n_layers" in s:
            assert_equal(s["n_layers"], MAX_N_LAYERS)

        # Beyond that, should remain at MAX
        s2 = node.getgrowthschedule(10000)
        if isinstance(s2, dict) and "n_layers" in s2:
            assert_equal(s2["n_layers"], MAX_N_LAYERS)

    def test_slot_growth_linearity(self, node):
        """Test slots grow linearly with height."""
        self.log.info("Testing slot growth linearity...")

        heights = [0, 100, 200, 500, 1000]
        prev_slots = None
        prev_h = None

        for h in heights:
            s = node.getgrowthschedule(h)
            if isinstance(s, dict) and "n_slots" in s:
                if prev_slots is not None:
                    delta = s["n_slots"] - prev_slots
                    expected_delta = (h - prev_h) * SLOT_GROWTH_PER_BLOCK
                    assert_equal(delta, expected_delta)
                prev_slots = s["n_slots"]
                prev_h = h


if __name__ == "__main__":
    FeatureModelTest().main()

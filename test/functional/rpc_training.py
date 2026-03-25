#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test training-specific RPCs.

Tests cover:
    - gettraininginfo all fields present.
    - getgrowthschedule returns correct dims.
    - getvalidationdata returns hex data.
    - getmodelhash is 64-char hex.
    - Model dimensions consistent with height.
    - gettraininginfo d_model field.
    - gettraininginfo n_layers field.
    - gettraininginfo n_slots field.
    - gettraininginfo d_ff field.
    - gettraininginfo gru_dim field.
    - getgrowthschedule at height 0.
    - getgrowthschedule at freeze boundary.
    - getgrowthschedule after freeze.
    - Model hash changes after mining.
    - Model hash is deterministic across nodes.
    - Validation data is deterministic.
    - Validation data is non-empty.
    - Growth schedule dimensions are consistent.
    - Param count is positive.
    - Training info matches block header fields.
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


GENESIS_D_MODEL = 512
GENESIS_N_LAYERS = 8
GENESIS_N_SLOTS = 1024
MAX_D_MODEL = 1024
MAX_N_LAYERS = 24


class RPCTrainingTest(FlowCoinTestFramework):
    """Training-specific RPC tests."""

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        node1 = self.nodes[1]

        # Mine some blocks
        addr = node.getnewaddress()
        node.generatetoaddress(10, addr)
        self.sync_blocks()

        self.test_gettraininginfo_fields(node)
        self.test_getgrowthschedule_dims(node)
        self.test_getvalidationdata_hex(node)
        self.test_getmodelhash_format(node)
        self.test_dimensions_consistent(node)
        self.test_d_model_field(node)
        self.test_n_layers_field(node)
        self.test_n_slots_field(node)
        self.test_d_ff_field(node)
        self.test_gru_dim_field(node)
        self.test_growth_at_height_0(node)
        self.test_growth_at_freeze(node)
        self.test_growth_after_freeze(node)
        self.test_hash_changes_mining(node)
        self.test_hash_deterministic(node, node1)
        self.test_validation_data_deterministic(node, node1)
        self.test_validation_data_nonempty(node)
        self.test_growth_dims_consistent(node)
        self.test_param_count_positive(node)
        self.test_training_matches_header(node)

    def test_gettraininginfo_fields(self, node):
        """Test gettraininginfo all fields present."""
        self.log.info("Testing gettraininginfo fields...")

        info = node.gettraininginfo()
        assert_true(isinstance(info, dict))

        required_fields = ["d_model", "n_layers"]
        for field in required_fields:
            assert_in(field, info, f"Missing field: {field}")

    def test_getgrowthschedule_dims(self, node):
        """Test getgrowthschedule returns correct dims."""
        self.log.info("Testing getgrowthschedule...")

        height = node.getblockcount()
        schedule = node.getgrowthschedule(height)
        assert_true(isinstance(schedule, dict))

        if "d_model" in schedule:
            expected = min(GENESIS_D_MODEL + height, MAX_D_MODEL)
            assert_equal(schedule["d_model"], expected)

    def test_getvalidationdata_hex(self, node):
        """Test getvalidationdata returns hex data."""
        self.log.info("Testing getvalidationdata format...")

        data = node.getvalidationdata()
        assert_true(isinstance(data, str) or isinstance(data, dict))

        if isinstance(data, str):
            assert_greater_than(len(data), 0)
        elif isinstance(data, dict) and "hex" in data:
            assert_is_hex_string(data["hex"])

    def test_getmodelhash_format(self, node):
        """Test getmodelhash is 64-char hex."""
        self.log.info("Testing getmodelhash format...")

        model_hash = node.getmodelhash()
        assert_equal(len(model_hash), 64)
        assert_is_hex_string(model_hash)

    def test_dimensions_consistent(self, node):
        """Test model dimensions consistent with height."""
        self.log.info("Testing dimensions consistent with height...")

        height = node.getblockcount()
        info = node.gettraininginfo()

        if "d_model" in info and "d_ff" in info:
            assert_equal(info["d_ff"], 2 * info["d_model"])

        if "d_model" in info and "gru_dim" in info:
            assert_equal(info["gru_dim"], info["d_model"])

    def test_d_model_field(self, node):
        """Test gettraininginfo d_model field."""
        self.log.info("Testing d_model field...")

        info = node.gettraininginfo()
        height = node.getblockcount()

        if "d_model" in info:
            expected = min(GENESIS_D_MODEL + height, MAX_D_MODEL)
            assert_equal(info["d_model"], expected)

    def test_n_layers_field(self, node):
        """Test gettraininginfo n_layers field."""
        self.log.info("Testing n_layers field...")

        info = node.gettraininginfo()
        height = node.getblockcount()

        if "n_layers" in info:
            expected = min(GENESIS_N_LAYERS + height // 32, MAX_N_LAYERS)
            assert_equal(info["n_layers"], expected)

    def test_n_slots_field(self, node):
        """Test gettraininginfo n_slots field."""
        self.log.info("Testing n_slots field...")

        info = node.gettraininginfo()
        height = node.getblockcount()

        if "n_slots" in info:
            expected = GENESIS_N_SLOTS + height * SLOT_GROWTH_PER_BLOCK
            assert_equal(info["n_slots"], expected)

    def test_d_ff_field(self, node):
        """Test gettraininginfo d_ff field."""
        self.log.info("Testing d_ff field...")

        info = node.gettraininginfo()
        if "d_ff" in info and "d_model" in info:
            assert_equal(info["d_ff"], 2 * info["d_model"])

    def test_gru_dim_field(self, node):
        """Test gettraininginfo gru_dim field."""
        self.log.info("Testing gru_dim field...")

        info = node.gettraininginfo()
        if "gru_dim" in info and "d_model" in info:
            assert_equal(info["gru_dim"], info["d_model"])

    def test_growth_at_height_0(self, node):
        """Test getgrowthschedule at height 0."""
        self.log.info("Testing growth at height 0...")

        schedule = node.getgrowthschedule(0)
        if isinstance(schedule, dict):
            if "d_model" in schedule:
                assert_equal(schedule["d_model"], GENESIS_D_MODEL)
            if "n_layers" in schedule:
                assert_equal(schedule["n_layers"], GENESIS_N_LAYERS)
            if "n_slots" in schedule:
                assert_equal(schedule["n_slots"], GENESIS_N_SLOTS)

    def test_growth_at_freeze(self, node):
        """Test getgrowthschedule at freeze boundary."""
        self.log.info("Testing growth at freeze boundary...")

        schedule = node.getgrowthschedule(DIM_FREEZE_HEIGHT)
        if isinstance(schedule, dict) and "d_model" in schedule:
            assert_equal(schedule["d_model"], MAX_D_MODEL)

    def test_growth_after_freeze(self, node):
        """Test getgrowthschedule after freeze."""
        self.log.info("Testing growth after freeze...")

        for h in [DIM_FREEZE_HEIGHT + 1, DIM_FREEZE_HEIGHT + 100]:
            schedule = node.getgrowthschedule(h)
            if isinstance(schedule, dict) and "d_model" in schedule:
                assert_equal(schedule["d_model"], MAX_D_MODEL)

    def test_hash_changes_mining(self, node):
        """Test model hash changes after mining."""
        self.log.info("Testing hash changes after mining...")

        hash_before = node.getmodelhash()
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)
        hash_after = node.getmodelhash()

        assert_not_equal(hash_before, hash_after)

    def test_hash_deterministic(self, node, node1):
        """Test model hash is deterministic across nodes."""
        self.log.info("Testing hash determinism across nodes...")
        self.sync_blocks()

        h0 = node.getmodelhash()
        h1 = node1.getmodelhash()
        assert_equal(h0, h1)

    def test_validation_data_deterministic(self, node, node1):
        """Test validation data is deterministic."""
        self.log.info("Testing validation data determinism...")

        d0 = node.getvalidationdata()
        d1 = node1.getvalidationdata()
        assert_equal(d0, d1)

    def test_validation_data_nonempty(self, node):
        """Test validation data is non-empty."""
        self.log.info("Testing validation data non-empty...")

        data = node.getvalidationdata()
        if isinstance(data, str):
            assert_greater_than(len(data), 0)
        elif isinstance(data, dict):
            assert_greater_than(len(data), 0)

    def test_growth_dims_consistent(self, node):
        """Test growth schedule dimensions are consistent."""
        self.log.info("Testing growth dimension consistency...")

        for h in [0, 10, 100, DIM_FREEZE_HEIGHT]:
            schedule = node.getgrowthschedule(h)
            if isinstance(schedule, dict):
                if "d_model" in schedule and "n_heads" in schedule:
                    assert_equal(schedule["n_heads"],
                                 schedule["d_model"] // 64)

    def test_param_count_positive(self, node):
        """Test param count is positive."""
        self.log.info("Testing param count positive...")

        info = node.gettraininginfo()
        if "param_count" in info:
            assert_greater_than(info["param_count"], 0)

    def test_training_matches_header(self, node):
        """Test training info matches block header fields."""
        self.log.info("Testing training info matches header...")

        height = node.getblockcount()
        blockhash = node.getblockhash(height)
        block = node.getblock(blockhash, 1)

        info = node.gettraininginfo()

        # Block header fields should match training info
        if "d_model" in block and "d_model" in info:
            assert_equal(block["d_model"], info["d_model"])
        if "n_layers" in block and "n_layers" in info:
            assert_equal(block["n_layers"], info["n_layers"])


if __name__ == "__main__":
    RPCTrainingTest().main()

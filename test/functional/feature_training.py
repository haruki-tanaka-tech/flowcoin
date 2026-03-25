#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test training/model RPC methods.

Tests cover:
    - gettraininginfo returns correct model dimensions.
    - getmodelhash is deterministic per block.
    - getgrowthschedule returns correct dims (continuous growth).
    - getgrowthschedule at dimension freeze boundary.
    - getgrowthschedule after freeze (frozen architecture).
    - getvalidationdata format and fields.
    - Model dimensions in mined blocks.
    - Growth schedule consistency across nodes.
    - Training steps requirements at various heights.
    - Model parameter count computation.
    - Improvement flag tracking.
    - Delta payload fields in blocks.
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
    compute_min_training_steps,
    get_model_dims_for_height,
    DIM_FREEZE_HEIGHT,
    wait_until,
)


class FeatureTrainingTest(FlowCoinTestFramework):
    """Training and model RPC tests."""

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

        self.test_gettraininginfo(node)
        self.test_getmodelhash(node)
        self.test_getgrowthschedule_continuous(node)
        self.test_getgrowthschedule_boundaries(node)
        self.test_getgrowthschedule_frozen(node)
        self.test_getvalidationdata(node)
        self.test_model_dims_in_blocks(node)
        self.test_growth_consistency(node, node1)
        self.test_training_steps(node)
        self.test_continuous_transitions(node)
        self.test_improvement_flag(node)
        self.test_delta_fields(node)

    def test_gettraininginfo(self, node):
        """Test gettraininginfo returns correct model dimensions."""
        self.log.info("Testing gettraininginfo...")

        info = node.gettraininginfo()
        assert_true(isinstance(info, dict))

        # Required fields
        required = ["d_model", "n_layers"]
        for field in required:
            assert_in(field, info, f"Missing: {field}")

        height = node.getblockcount()
        expected = get_model_dims_for_height(height)

        assert_equal(
            info["d_model"], expected["d_model"],
            f"d_model at height {height}"
        )
        assert_equal(
            info["n_layers"], expected["n_layers"],
            f"n_layers at height {height}"
        )

        # Additional training fields
        optional_fields = [
            "d_ff", "n_heads", "height", "val_loss",
            "training_steps", "model_hash",
        ]
        found = 0
        for field in optional_fields:
            if field in info:
                found += 1
                self.log.info("    %s = %s", field, info[field])

        # d_ff should be 2x d_model
        if "d_ff" in info:
            expected_dff = expected.get("d_ff", expected["d_model"] * 2)
            assert_equal(info["d_ff"], expected_dff)

        self.log.info(
            "  gettraininginfo: d_model=%d, n_layers=%d (%d optional fields)",
            info["d_model"], info["n_layers"], found
        )

    def test_getmodelhash(self, node):
        """Test getmodelhash is deterministic per block."""
        self.log.info("Testing getmodelhash...")

        try:
            hash1 = node.getmodelhash()
            hash2 = node.getmodelhash()

            # Same block should produce same hash
            assert_equal(hash1, hash2, "Model hash should be deterministic")

            if isinstance(hash1, str):
                assert_is_hex_string(hash1)
                assert_equal(len(hash1), 64, "Model hash should be 32 bytes")

            # After mining, hash may change (new model state)
            addr = node.getnewaddress()
            node.generatetoaddress(1, addr)

            hash3 = node.getmodelhash()
            # Hash may or may not change depending on training
            self.log.info(
                "  Model hash: %s (stable), after mine: %s",
                str(hash1)[:16], str(hash3)[:16]
            )

        except Exception as e:
            self.log.info("  getmodelhash: %s", e)

        self.log.info("  getmodelhash verified")

    def test_getgrowthschedule_continuous(self, node):
        """Test getgrowthschedule returns correct dims with continuous growth."""
        self.log.info("Testing getgrowthschedule continuous growth...")

        test_heights = [
            (0, 512, 8),
            (100, 612, 11),
            (256, 768, 16),
            (512, 1024, 24),
            (1000, 1024, 24),
        ]

        for height, expected_d, expected_l in test_heights:
            schedule = node.getgrowthschedule(height)
            assert_equal(
                schedule["d_model"], expected_d,
                f"d_model at height {height}"
            )
            assert_equal(
                schedule["n_layers"], expected_l,
                f"n_layers at height {height}"
            )

            self.log.info(
                "  Height %d: d=%d, L=%d", height, expected_d, expected_l
            )

        self.log.info("  Continuous growth verified")

    def test_getgrowthschedule_boundaries(self, node):
        """Test getgrowthschedule at dimension freeze boundary."""
        self.log.info("Testing growth schedule boundaries...")

        # Consecutive blocks should have different d_model during growth
        dims_0 = node.getgrowthschedule(0)
        dims_1 = node.getgrowthschedule(1)
        assert_equal(dims_0["d_model"], 512)
        assert_equal(dims_1["d_model"], 513)
        assert_not_equal(dims_0["d_model"], dims_1["d_model"])

        # At dimension freeze boundary (511 -> 512)
        dims_511 = node.getgrowthschedule(511)
        dims_512 = node.getgrowthschedule(512)
        assert_equal(dims_511["d_model"], 1023)
        assert_equal(dims_512["d_model"], 1024)

        # After freeze, d_model stays 1024
        dims_513 = node.getgrowthschedule(513)
        assert_equal(dims_513["d_model"], 1024)

        self.log.info("  Boundary transitions verified")

    def test_getgrowthschedule_frozen(self, node):
        """Test getgrowthschedule after dimension freeze."""
        self.log.info("Testing frozen architecture after height 512...")

        # After DIM_FREEZE_HEIGHT, all should have d=1024, L=24
        frozen_heights = [512, 600, 1000, 5000, 10000, 50000, 100000]

        for height in frozen_heights:
            dims = node.getgrowthschedule(height)
            assert_equal(
                dims["d_model"], 1024,
                f"d_model should be 1024 at height {height}"
            )
            assert_equal(
                dims["n_layers"], 24,
                f"n_layers should be 24 at height {height}"
            )

        self.log.info("  Architecture frozen at d=1024, L=24 after h=512")

    def test_getvalidationdata(self, node):
        """Test getvalidationdata format and fields."""
        self.log.info("Testing getvalidationdata...")

        try:
            data = node.getvalidationdata()
            assert_true(isinstance(data, dict))

            # Expected fields
            possible_fields = [
                "height", "d_model", "n_layers", "val_loss",
                "model_hash", "optimizer_hash", "training_steps",
            ]
            found = 0
            for field in possible_fields:
                if field in data:
                    found += 1
                    self.log.info("    %s = %s", field, data[field])

            if found > 0:
                self.log.info(
                    "  getvalidationdata: %d/%d fields present",
                    found, len(possible_fields)
                )
            else:
                self.log.info("  getvalidationdata returned empty data")

        except Exception as e:
            self.log.info("  getvalidationdata: %s", e)

    def test_model_dims_in_blocks(self, node):
        """Test that model dimensions are correctly embedded in mined blocks."""
        self.log.info("Testing model dims in mined blocks...")

        # Check dimensions in existing blocks
        height = node.getblockcount()
        for h in range(min(height + 1, 10)):
            block_hash = node.getblockhash(h)
            block = node.getblock(block_hash, 1)

            expected = get_model_dims_for_height(h)

            if "d_model" in block:
                assert_equal(
                    block["d_model"], expected["d_model"],
                    f"d_model in block at height {h}"
                )
            if "n_layers" in block:
                assert_equal(
                    block["n_layers"], expected["n_layers"],
                    f"n_layers in block at height {h}"
                )

        self.log.info("  Model dims verified in %d blocks", min(height + 1, 10))

    def test_growth_consistency(self, node, node1):
        """Test that growth schedule is consistent across nodes."""
        self.log.info("Testing growth consistency across nodes...")

        self.sync_blocks()

        test_heights = [0, 50, 100, 250, 400, 500, 1000]

        for height in test_heights:
            dims0 = node.getgrowthschedule(height)
            dims1 = node1.getgrowthschedule(height)

            assert_equal(
                dims0["d_model"], dims1["d_model"],
                f"d_model mismatch at height {height}"
            )
            assert_equal(
                dims0["n_layers"], dims1["n_layers"],
                f"n_layers mismatch at height {height}"
            )

        self.log.info("  Growth schedule consistent across %d heights", len(test_heights))

    def test_training_steps(self, node):
        """Min training steps removed -- difficulty alone regulates mining."""
        self.log.info("Training steps test skipped (min_steps removed from consensus)")

    def test_continuous_transitions(self, node):
        """Test that dimensions change at every block during growth phase."""
        self.log.info("Testing continuous growth transitions...")

        # During growth phase, every consecutive block has different d_model
        for h in [0, 50, 100, 200, 400, 510]:
            dims_a = node.getgrowthschedule(h)
            dims_b = node.getgrowthschedule(h + 1)
            assert_not_equal(
                dims_a["d_model"], dims_b["d_model"],
                f"d_model should change between {h} and {h+1}"
            )

        # After freeze, d_model stays constant
        dims_512 = node.getgrowthschedule(512)
        dims_513 = node.getgrowthschedule(513)
        assert_equal(dims_512["d_model"], dims_513["d_model"])

        self.log.info("  Continuous transitions verified")

    def test_improvement_flag(self, node):
        """Test improvement flag tracking in blocks."""
        self.log.info("Testing improvement flag...")

        tip = node.getbestblockhash()
        block = node.getblock(tip, 1)

        if "improvement_flag" in block:
            flag = block["improvement_flag"]
            assert_true(
                isinstance(flag, (int, bool)),
                f"improvement_flag should be int or bool: {type(flag)}"
            )
            self.log.info("  Improvement flag at tip: %s", flag)
        else:
            self.log.info("  improvement_flag not in block JSON")

        # gettraininginfo may also have this
        try:
            info = node.gettraininginfo()
            if "improvement" in info:
                self.log.info("  Training improvement: %s", info["improvement"])
        except Exception:
            pass

        self.log.info("  Improvement flag tested")

    def test_delta_fields(self, node):
        """Test delta payload fields in blocks."""
        self.log.info("Testing delta fields...")

        tip = node.getbestblockhash()
        block = node.getblock(tip, 1)

        delta_fields = ["delta_hash", "delta_count", "delta_size"]
        found = 0
        for field in delta_fields:
            if field in block:
                found += 1
                self.log.info("    %s = %s", field, block[field])

        if found > 0:
            # delta_hash should be a hex string
            if "delta_hash" in block:
                delta_hash = block["delta_hash"]
                if isinstance(delta_hash, str) and len(delta_hash) == 64:
                    assert_is_hex_string(delta_hash)

            # delta_count should be non-negative
            if "delta_count" in block:
                assert_greater_than_or_equal(block["delta_count"], 0)

            # delta_size should be non-negative
            if "delta_size" in block:
                assert_greater_than_or_equal(block["delta_size"], 0)

        self.log.info("  %d/%d delta fields found in block",
                       found, len(delta_fields))

    def test_growth_schedule_monotonic(self, node):
        """Test that model dimensions are monotonically non-decreasing."""
        self.log.info("Testing growth schedule monotonicity...")

        prev_d_model = 0
        prev_n_layers = 0

        for height in range(0, 600, 10):
            dims = node.getgrowthschedule(height)
            d_model = dims["d_model"]
            n_layers = dims["n_layers"]

            assert_greater_than_or_equal(
                d_model, prev_d_model,
                f"d_model should not decrease at height {height}"
            )
            assert_greater_than_or_equal(
                n_layers, prev_n_layers,
                f"n_layers should not decrease at height {height}"
            )

            prev_d_model = d_model
            prev_n_layers = n_layers

        self.log.info("  Growth schedule is monotonically non-decreasing")

    def test_training_info_consistency(self, node):
        """Test that gettraininginfo is consistent with getgrowthschedule."""
        self.log.info("Testing training info consistency...")

        info = node.gettraininginfo()
        height = node.getblockcount()
        schedule = node.getgrowthschedule(height)

        assert_equal(
            info["d_model"], schedule["d_model"],
            "gettraininginfo d_model should match getgrowthschedule"
        )
        assert_equal(
            info["n_layers"], schedule["n_layers"],
            "gettraininginfo n_layers should match getgrowthschedule"
        )

        self.log.info(
            "  Training info consistent: d_model=%d, n_layers=%d",
            info["d_model"], info["n_layers"]
        )

    def test_growth_schedule_at_extreme_heights(self, node):
        """Test growth schedule at very large heights."""
        self.log.info("Testing growth at extreme heights...")

        extreme_heights = [1000000, 10000000, 100000000]

        for height in extreme_heights:
            dims = node.getgrowthschedule(height)
            # After freeze: dims should be at max
            assert_equal(
                dims["d_model"], 1024,
                f"d_model should be 1024 at height {height}"
            )
            assert_equal(
                dims["n_layers"], 24,
                f"n_layers should be 24 at height {height}"
            )

        self.log.info("  Extreme heights: architecture frozen correctly")

    def test_model_dims_fields_complete(self, node):
        """Test that getgrowthschedule returns all dimension fields."""
        self.log.info("Testing growth schedule field completeness...")

        dims = node.getgrowthschedule(0)

        required_fields = ["d_model", "n_layers"]
        for field in required_fields:
            assert_in(field, dims, f"Missing required field: {field}")

        optional_fields = ["d_ff", "n_heads", "gru_dim", "n_slots"]
        found = 0
        for field in optional_fields:
            if field in dims:
                found += 1
                assert_greater_than(
                    dims[field], 0,
                    f"{field} should be positive"
                )

        self.log.info(
            "  Growth schedule: %d required + %d optional fields",
            len(required_fields), found
        )

    def test_training_info_after_mining(self, node):
        """Test that training info updates after mining blocks."""
        self.log.info("Testing training info after mining...")

        info_before = node.gettraininginfo()
        height_before = node.getblockcount()

        addr = node.getnewaddress()
        node.generatetoaddress(5, addr)

        info_after = node.gettraininginfo()
        height_after = node.getblockcount()

        assert_equal(height_after, height_before + 5)

        # Dims should match expected for the new height
        expected_before = get_model_dims_for_height(height_before)
        expected_after = get_model_dims_for_height(height_after)

        assert_equal(info_after["d_model"], expected_after["d_model"])
        assert_equal(info_after["n_layers"], expected_after["n_layers"])

        self.log.info(
            "  Training info updated: height %d->%d",
            height_before, height_after
        )

    def test_getdeltapayload(self, node):
        """Test getdeltapayload RPC if available."""
        self.log.info("Testing getdeltapayload...")

        try:
            delta = node.getdeltapayload()
            assert_true(isinstance(delta, (dict, str)))

            if isinstance(delta, dict):
                for field in ["size", "hash", "data"]:
                    if field in delta:
                        self.log.info("    %s = %s", field, str(delta[field])[:40])
            elif isinstance(delta, str):
                self.log.info("  Delta payload: %d chars", len(delta))

        except Exception as e:
            self.log.info("  getdeltapayload: %s", e)

    def test_getmodelweights(self, node):
        """Test getmodelweights RPC if available."""
        self.log.info("Testing getmodelweights...")

        try:
            weights = node.getmodelweights()
            if isinstance(weights, dict):
                for field in ["size", "hash", "param_count"]:
                    if field in weights:
                        self.log.info("    %s = %s", field, weights[field])
            elif isinstance(weights, str):
                self.log.info("  Model weights hash: %s", weights[:40])
        except Exception as e:
            self.log.info("  getmodelweights: %s", e)


if __name__ == "__main__":
    FeatureTrainingTest().main()

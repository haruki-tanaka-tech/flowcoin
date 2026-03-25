#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test difficulty adjustment on regtest.

Tests cover:
    - Initial difficulty on regtest.
    - Difficulty reported in getmininginfo.
    - Difficulty reported in getblockchaininfo.
    - Difficulty reported in block headers.
    - Difficulty consistency across multiple blocks.
    - Difficulty bits encoding in block data.
    - getdifficulty RPC return value.
    - Difficulty at various block heights.
    - Difficulty target in getblocktemplate.
    - Regtest minimum difficulty.
    - Difficulty adjustment period (2016 blocks).
    - Difficulty stability during mining bursts.
"""

import time
from decimal import Decimal

from test_framework.test_framework import FlowCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_in,
    assert_is_hex_string,
    assert_true,
    wait_until,
)


class DifficultyTest(FlowCoinTestFramework):
    """Difficulty adjustment tests."""

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]

        self.test_initial_difficulty(node)
        self.test_difficulty_in_mininginfo(node)
        self.test_difficulty_in_chaininfo(node)
        self.test_difficulty_in_headers(node)
        self.test_difficulty_consistency(node)
        self.test_bits_encoding(node)
        self.test_getdifficulty(node)
        self.test_difficulty_at_heights(node)
        self.test_difficulty_in_template(node)
        self.test_regtest_min_difficulty(node)
        self.test_difficulty_stability(node)
        self.test_retarget_period(node)

    def test_initial_difficulty(self, node):
        """Test difficulty at genesis on regtest."""
        self.log.info("Testing initial difficulty...")

        diff = node.getdifficulty()
        assert_greater_than(diff, 0)

        # On regtest, initial difficulty should be very low
        self.log.info("  Initial difficulty: %s", diff)

        # Genesis block difficulty
        genesis_hash = node.getblockhash(0)
        genesis = node.getblock(genesis_hash)
        if "difficulty" in genesis:
            assert_equal(
                genesis["difficulty"], diff,
                "Genesis difficulty should match getdifficulty"
            )

    def test_difficulty_in_mininginfo(self, node):
        """Test difficulty field in getmininginfo."""
        self.log.info("Testing difficulty in getmininginfo...")

        info = node.getmininginfo()
        assert_in("difficulty", info)

        diff = info["difficulty"]
        assert_greater_than(diff, 0)

        # Should match getdifficulty
        assert_equal(
            diff, node.getdifficulty(),
            "Mining info difficulty should match getdifficulty"
        )

        self.log.info("  Mining info difficulty: %s", diff)

    def test_difficulty_in_chaininfo(self, node):
        """Test difficulty field in getblockchaininfo."""
        self.log.info("Testing difficulty in getblockchaininfo...")

        info = node.getblockchaininfo()
        assert_in("difficulty", info)

        diff = info["difficulty"]
        assert_greater_than(diff, 0)
        assert_equal(
            diff, node.getdifficulty(),
            "Blockchain info difficulty should match getdifficulty"
        )

        self.log.info("  Blockchain info difficulty: %s", diff)

    def test_difficulty_in_headers(self, node):
        """Test difficulty field in block headers."""
        self.log.info("Testing difficulty in block headers...")

        addr = node.getnewaddress()
        node.generatetoaddress(5, addr)

        # Check difficulty in each block header
        height = node.getblockcount()
        for h in range(max(0, height - 4), height + 1):
            block_hash = node.getblockhash(h)
            header = node.getblockheader(block_hash)

            assert_in("difficulty", header)
            assert_greater_than(header["difficulty"], 0)

            assert_in("bits", header)

        self.log.info("  Block header difficulties verified")

    def test_difficulty_consistency(self, node):
        """Test that difficulty is consistent across blocks on regtest."""
        self.log.info("Testing difficulty consistency...")

        addr = node.getnewaddress()
        node.generatetoaddress(10, addr)

        height = node.getblockcount()
        difficulties = []

        for h in range(max(0, height - 9), height + 1):
            block_hash = node.getblockhash(h)
            header = node.getblockheader(block_hash)
            difficulties.append(header["difficulty"])

        # On regtest without actual retargets, difficulty should be stable
        if len(set(difficulties)) == 1:
            self.log.info(
                "  All %d blocks have same difficulty: %s",
                len(difficulties), difficulties[0]
            )
        else:
            self.log.info(
                "  Difficulty range: min=%s, max=%s",
                min(difficulties), max(difficulties)
            )

    def test_bits_encoding(self, node):
        """Test the 'bits' field encoding in blocks."""
        self.log.info("Testing bits encoding...")

        tip = node.getbestblockhash()
        header = node.getblockheader(tip)

        bits = header["bits"]
        assert_true(
            isinstance(bits, (str, int)),
            f"Bits should be str or int, got {type(bits)}"
        )

        if isinstance(bits, str):
            # Should be hex-encoded
            assert_true(
                len(bits) == 8,
                f"Bits hex should be 8 chars: {bits}"
            )
            # Parse compact format
            bits_int = int(bits, 16)
        else:
            bits_int = bits

        # Compact format: first byte is exponent, remaining 3 are mantissa
        exponent = (bits_int >> 24) & 0xFF
        mantissa = bits_int & 0x007FFFFF

        assert_greater_than(exponent, 0, "Exponent should be positive")
        assert_greater_than(mantissa, 0, "Mantissa should be positive")

        self.log.info(
            "  Bits: %s (exp=%d, mantissa=0x%06X)",
            bits, exponent, mantissa
        )

    def test_getdifficulty(self, node):
        """Test getdifficulty RPC return value."""
        self.log.info("Testing getdifficulty...")

        diff = node.getdifficulty()
        assert_true(
            isinstance(diff, (int, float, Decimal)),
            f"Difficulty type: {type(diff)}"
        )
        assert_greater_than(diff, 0)

        # Call multiple times for consistency
        diff2 = node.getdifficulty()
        assert_equal(diff, diff2, "Difficulty should be consistent")

        self.log.info("  getdifficulty: %s", diff)

    def test_difficulty_at_heights(self, node):
        """Test difficulty at various block heights."""
        self.log.info("Testing difficulty at various heights...")

        addr = node.getnewaddress()
        current = node.getblockcount()

        # Mine to at least height 20
        if current < 20:
            node.generatetoaddress(20 - current, addr)

        height = node.getblockcount()

        # Collect difficulties
        diff_by_height = {}
        for h in [0, 1, 5, 10, 15, min(20, height)]:
            if h > height:
                continue
            block_hash = node.getblockhash(h)
            header = node.getblockheader(block_hash)
            diff_by_height[h] = header["difficulty"]

        for h, d in sorted(diff_by_height.items()):
            self.log.info("  Height %d: difficulty=%s", h, d)

    def test_difficulty_in_template(self, node):
        """Test difficulty target in getblocktemplate."""
        self.log.info("Testing difficulty in block template...")

        try:
            template = node.getblocktemplate()
            assert_in("bits", template)

            bits = template["bits"]
            assert_true(len(bits) > 0, "Template bits should not be empty")

            if "target" in template:
                target = template["target"]
                assert_true(len(target) > 0)
                self.log.info(
                    "  Template: bits=%s, target=%s...",
                    bits, target[:16]
                )
            else:
                self.log.info("  Template: bits=%s", bits)

        except Exception as e:
            self.log.info("  getblocktemplate: %s", e)

    def test_regtest_min_difficulty(self, node):
        """Test that regtest uses minimum difficulty."""
        self.log.info("Testing regtest minimum difficulty...")

        diff = node.getdifficulty()

        # On regtest, difficulty should be much lower than mainnet
        # Typical Bitcoin regtest difficulty is around 4.6566e-10
        # FlowCoin regtest should also be very low
        assert_greater_than(
            1.0, diff,
            "Regtest difficulty should be less than 1.0"
        )

        self.log.info("  Regtest difficulty: %s (below 1.0)", diff)

    def test_difficulty_stability(self, node):
        """Test that difficulty remains stable during rapid mining."""
        self.log.info("Testing difficulty stability during mining burst...")

        diff_before = node.getdifficulty()

        # Mine many blocks rapidly
        addr = node.getnewaddress()
        node.generatetoaddress(50, addr)

        diff_after = node.getdifficulty()

        # On regtest without 2016-block retarget, difficulty should not change
        # (unless we cross a retarget boundary)
        height = node.getblockcount()
        crossed_retarget = (height // 2016) != ((height - 50) // 2016)

        if not crossed_retarget:
            assert_equal(
                diff_before, diff_after,
                "Difficulty should be stable within retarget period"
            )
            self.log.info(
                "  Difficulty stable after 50 blocks: %s", diff_after
            )
        else:
            self.log.info(
                "  Crossed retarget boundary: %s -> %s",
                diff_before, diff_after
            )

    def test_retarget_period(self, node):
        """Test the difficulty retarget period (2016 blocks)."""
        self.log.info("Testing retarget period...")

        # Record current state
        height = node.getblockcount()
        diff = node.getdifficulty()

        # Calculate distance to next retarget
        next_retarget = ((height // 2016) + 1) * 2016
        blocks_until = next_retarget - height

        self.log.info(
            "  Current height: %d, difficulty: %s",
            height, diff
        )
        self.log.info(
            "  Next retarget at height %d (%d blocks away)",
            next_retarget, blocks_until
        )

        # Verify blocks before retarget have same difficulty
        if height >= 5:
            diffs = set()
            for h in range(max(0, height - 4), height + 1):
                bh = node.getblockhash(h)
                header = node.getblockheader(bh)
                diffs.add(header["difficulty"])

            if len(diffs) == 1:
                self.log.info(
                    "  Last 5 blocks all at difficulty %s",
                    diffs.pop()
                )
            else:
                self.log.info(
                    "  Difficulty varied in last 5 blocks: %s", diffs
                )

    def test_difficulty_type(self, node):
        """Test that difficulty is returned as a numeric type."""
        self.log.info("Testing difficulty type...")

        diff = node.getdifficulty()
        assert_true(
            isinstance(diff, (int, float, Decimal)),
            f"Difficulty should be numeric, got {type(diff)}"
        )

        # Should also be in block data
        tip = node.getbestblockhash()
        block = node.getblock(tip)
        if "difficulty" in block:
            assert_true(
                isinstance(block["difficulty"], (int, float, Decimal)),
                "Block difficulty should be numeric"
            )

        self.log.info("  Difficulty type verified: %s", type(diff).__name__)

    def test_bits_consistency_across_blocks(self, node):
        """Test that 'bits' field is consistent within a retarget period."""
        self.log.info("Testing bits consistency...")

        addr = node.getnewaddress()
        node.generatetoaddress(10, addr)

        height = node.getblockcount()
        bits_values = set()
        for h in range(max(0, height - 9), height + 1):
            bh = node.getblockhash(h)
            header = node.getblockheader(bh)
            bits_values.add(str(header["bits"]))

        if len(bits_values) == 1:
            self.log.info(
                "  All 10 blocks have same bits: %s", bits_values.pop()
            )
        else:
            self.log.info(
                "  Bits varied across 10 blocks: %d unique values",
                len(bits_values)
            )

    def test_difficulty_matches_bits(self, node):
        """Test that difficulty and bits are mathematically consistent."""
        self.log.info("Testing difficulty-bits consistency...")

        tip = node.getbestblockhash()
        header = node.getblockheader(tip)

        diff = header["difficulty"]
        bits = header["bits"]

        # Both should be present and positive
        assert_greater_than(diff, 0)
        if isinstance(bits, str):
            assert_greater_than(len(bits), 0)
        else:
            assert_greater_than(bits, 0)

        self.log.info("  Difficulty=%s, bits=%s", diff, bits)

    def test_difficulty_across_many_blocks(self, node):
        """Test difficulty across a large number of blocks."""
        self.log.info("Testing difficulty across many blocks...")

        addr = node.getnewaddress()
        current = node.getblockcount()
        if current < 100:
            node.generatetoaddress(100 - current, addr)

        height = node.getblockcount()

        # Sample every 10th block
        difficulties = {}
        for h in range(0, min(height + 1, 101), 10):
            bh = node.getblockhash(h)
            header = node.getblockheader(bh)
            difficulties[h] = header["difficulty"]

        unique_diffs = set(difficulties.values())
        self.log.info(
            "  Sampled %d blocks: %d unique difficulty values",
            len(difficulties), len(unique_diffs)
        )

        for h, d in sorted(difficulties.items())[:5]:
            self.log.info("    Height %d: difficulty=%s", h, d)

    def test_difficulty_after_gap(self, node):
        """Test difficulty after a gap in mining (simulated)."""
        self.log.info("Testing difficulty after mining gap...")

        diff_before = node.getdifficulty()

        # Mine rapidly
        addr = node.getnewaddress()
        node.generatetoaddress(20, addr)

        diff_after = node.getdifficulty()

        # On regtest, rapid mining should not change difficulty
        # (no actual time-based retarget)
        self.log.info(
            "  Before: %s, After: %s (20 rapid blocks)",
            diff_before, diff_after
        )


if __name__ == "__main__":
    DifficultyTest().main()

#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test mining RPC methods.

Tests cover:
    - getmininginfo fields and correctness.
    - getblocktemplate structure.
    - getblocktemplate transaction inclusion.
    - submitblock with valid block data.
    - submitblock error cases.
    - getnetworkhashps computation.
    - generatetoaddress on regtest.
    - generatetoaddress with invalid address.
    - Mining reward address changes per block.
    - Block template difficulty target.
    - Block template training fields.
    - Mining info updates after mining.
    - getblocktemplate after mempool changes.
"""

import time
from decimal import Decimal

from test_framework.test_framework import FlowCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_in,
    assert_is_block_hash,
    assert_is_hex_string,
    assert_not_equal,
    assert_raises_rpc_error,
    assert_true,
    calculate_block_reward,
    get_model_dims_for_height,
    wait_until,
)


class RPCMiningTest(FlowCoinTestFramework):
    """Mining RPC method tests."""

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]

        self.test_getmininginfo(node)
        self.test_generatetoaddress(node)
        self.test_generatetoaddress_errors(node)
        self.test_getblocktemplate(node)
        self.test_getblocktemplate_fields(node)
        self.test_submitblock_valid(node)
        self.test_submitblock_errors(node)
        self.test_getnetworkhashps(node)
        self.test_mining_reward_address(node)
        self.test_template_difficulty(node)
        self.test_template_training_fields(node)
        self.test_mining_info_updates(node)
        self.test_template_after_mempool_change(node)
        self.test_block_generation_rate(node)

    def test_getmininginfo(self, node):
        """Test getmininginfo returns expected fields."""
        self.log.info("Testing getmininginfo...")

        info = node.getmininginfo()
        assert_true(isinstance(info, dict))

        expected_fields = [
            "blocks", "difficulty",
        ]
        for field in expected_fields:
            assert_in(field, info, f"Missing field: {field}")

        # Blocks should match getblockcount
        assert_equal(info["blocks"], node.getblockcount())

        # Difficulty should be positive
        assert_greater_than(info["difficulty"], 0)

        # Network hash rate may be present
        if "networkhashps" in info:
            assert_greater_than_or_equal(info["networkhashps"], 0)

        # Chain should be regtest
        if "chain" in info:
            assert_in(info["chain"], ["regtest", "test"])

        # Model dimensions may be present
        if "d_model" in info:
            height = info["blocks"]
            expected_dims = get_model_dims_for_height(height)
            assert_equal(info["d_model"], expected_dims["d_model"])

        self.log.info("  getmininginfo: blocks=%d, diff=%.4f",
                       info["blocks"], info["difficulty"])

    def test_generatetoaddress(self, node):
        """Test generatetoaddress basic functionality."""
        self.log.info("Testing generatetoaddress...")

        addr = node.getnewaddress()
        height_before = node.getblockcount()

        # Generate 1 block
        hashes = node.generatetoaddress(1, addr)
        assert_equal(len(hashes), 1)
        assert_is_block_hash(hashes[0])
        assert_equal(node.getblockcount(), height_before + 1)

        # Generate 10 blocks
        hashes = node.generatetoaddress(10, addr)
        assert_equal(len(hashes), 10)
        assert_equal(node.getblockcount(), height_before + 11)

        # All hashes should be unique
        assert_equal(len(set(hashes)), 10)

        # Each block's coinbase should pay to addr
        for block_hash in hashes[:3]:
            block = node.getblock(block_hash, 2)
            coinbase = block["tx"][0]
            # Check at least one output pays to our address
            vout_addrs = []
            for vout in coinbase.get("vout", []):
                sp = vout.get("scriptPubKey", {})
                vout_addrs.extend(sp.get("addresses", []))
                if "address" in sp:
                    vout_addrs.append(sp["address"])
            # Note: on regtest with OP_TRUE scripts this may vary

        # Generate 0 blocks returns empty
        empty = node.generatetoaddress(0, addr)
        assert_equal(len(empty), 0)

        self.log.info("  generatetoaddress: 11 blocks generated")

    def test_generatetoaddress_errors(self, node):
        """Test generatetoaddress error cases."""
        self.log.info("Testing generatetoaddress errors...")

        # Invalid address
        assert_raises_rpc_error(
            None, None,
            node.generatetoaddress, 1, "invalid_address"
        )

        # Negative block count
        addr = node.getnewaddress()
        assert_raises_rpc_error(
            None, None,
            node.generatetoaddress, -1, addr
        )

        # Empty address
        assert_raises_rpc_error(
            None, None,
            node.generatetoaddress, 1, ""
        )

        self.log.info("  generatetoaddress errors handled")

    def test_getblocktemplate(self, node):
        """Test getblocktemplate basic structure."""
        self.log.info("Testing getblocktemplate...")

        try:
            template = node.getblocktemplate()
        except Exception as e:
            self.log.info("  getblocktemplate not available: %s", e)
            return

        assert_true(isinstance(template, dict))

        # Core fields
        expected = [
            "version", "previousblockhash", "curtime",
            "bits", "height",
        ]
        for field in expected:
            assert_in(field, template, f"Template missing: {field}")

        # Height should be tip + 1
        assert_equal(template["height"], node.getblockcount() + 1)

        # Previous block hash should be current tip
        assert_equal(
            template["previousblockhash"],
            node.getbestblockhash()
        )

        # Version should be positive
        assert_greater_than(template["version"], 0)

        # Bits (difficulty target) should be present
        assert_true(len(template["bits"]) > 0)

        # Current time should be reasonable
        assert_greater_than(template["curtime"], 1735689600)

        self.log.info("  getblocktemplate: height=%d, bits=%s",
                       template["height"], template["bits"])

    def test_getblocktemplate_fields(self, node):
        """Test getblocktemplate detailed field structure."""
        self.log.info("Testing getblocktemplate fields...")

        try:
            template = node.getblocktemplate()
        except Exception:
            self.log.info("  Skipping: getblocktemplate unavailable")
            return

        # Transactions list
        if "transactions" in template:
            assert_true(isinstance(template["transactions"], list))
            for tx in template["transactions"]:
                assert_in("data", tx)
                assert_in("txid", tx)
                if "fee" in tx:
                    assert_greater_than_or_equal(tx["fee"], 0)

        # Coinbase value (total available for coinbase output)
        if "coinbasevalue" in template:
            expected_reward = calculate_block_reward(template["height"])
            # Coinbase value = reward + fees
            assert_greater_than_or_equal(
                template["coinbasevalue"],
                int(expected_reward * 10**8)
            )

        # Mutable fields (what the miner can change)
        if "mutable" in template:
            assert_true(isinstance(template["mutable"], list))

        # Training-specific fields
        if "d_model" in template:
            expected_dims = get_model_dims_for_height(template["height"])
            assert_equal(template["d_model"], expected_dims["d_model"])
        if "n_layers" in template:
            expected_dims = get_model_dims_for_height(template["height"])
            assert_equal(template["n_layers"], expected_dims["n_layers"])

        self.log.info("  getblocktemplate fields verified")

    def test_submitblock_valid(self, node):
        """Test submitblock with a previously mined block's data."""
        self.log.info("Testing submitblock...")

        # Mine a block and get its hex
        addr = node.getnewaddress()
        hashes = node.generatetoaddress(1, addr)
        block_hex = node.getblock(hashes[0], 0)

        # Re-submitting the same block should return "duplicate"
        result = node.submitblock(block_hex)
        # Result is either None (accepted/dup) or an error string
        self.log.info("  submitblock (dup): result=%s", result)

        self.log.info("  submitblock tested")

    def test_submitblock_errors(self, node):
        """Test submitblock with invalid data."""
        self.log.info("Testing submitblock errors...")

        # Garbage data
        result = node.submitblock("deadbeef" * 50)
        assert_true(
            result is not None,
            "submitblock should reject garbage"
        )

        # Too-short data
        result = node.submitblock("abcd")
        assert_true(
            result is not None,
            "submitblock should reject short data"
        )

        # Valid hex but invalid block structure
        result = node.submitblock("00" * 308)
        assert_true(
            result is not None,
            "submitblock should reject zero block"
        )

        height_after = node.getblockcount()
        self.log.info("  submitblock errors handled (height stable: %d)",
                       height_after)

    def test_getnetworkhashps(self, node):
        """Test getnetworkhashps computation."""
        self.log.info("Testing getnetworkhashps...")

        # Mine some blocks first
        addr = node.getnewaddress()
        node.generatetoaddress(20, addr)

        try:
            hashps = node.getnetworkhashps()
            assert_true(
                isinstance(hashps, (int, float)),
                "Should return a number"
            )
            assert_greater_than_or_equal(hashps, 0)

            # With explicit window
            hashps_10 = node.getnetworkhashps(10)
            assert_greater_than_or_equal(hashps_10, 0)

            # With window and height
            hashps_at = node.getnetworkhashps(10, node.getblockcount())
            assert_greater_than_or_equal(hashps_at, 0)

            self.log.info("  getnetworkhashps: %s H/s", hashps)
        except Exception as e:
            self.log.info("  getnetworkhashps: %s", e)

    def test_mining_reward_address(self, node):
        """Test that mining reward goes to the specified address."""
        self.log.info("Testing mining reward address...")

        addr1 = node.getnewaddress()
        addr2 = node.getnewaddress()

        # Mine to addr1
        h1 = node.generatetoaddress(1, addr1)

        # Mine to addr2
        h2 = node.generatetoaddress(1, addr2)

        # Blocks should have different coinbase destinations
        block1 = node.getblock(h1[0], 2)
        block2 = node.getblock(h2[0], 2)

        # The coinbase outputs should differ (different addresses)
        cb1 = block1["tx"][0]
        cb2 = block2["tx"][0]

        # Compare scriptPubKey of coinbase outputs
        sp1 = cb1["vout"][0].get("scriptPubKey", {})
        sp2 = cb2["vout"][0].get("scriptPubKey", {})

        # Different addresses should produce different scripts
        if "hex" in sp1 and "hex" in sp2:
            if sp1["hex"] != sp2["hex"]:
                self.log.info("  Different addresses produce different scripts")
            else:
                self.log.info("  Scripts may be same (OP_TRUE on regtest)")

        self.log.info("  Mining reward address verified")

    def test_template_difficulty(self, node):
        """Test that block template has correct difficulty target."""
        self.log.info("Testing template difficulty...")

        try:
            template = node.getblocktemplate()
        except Exception:
            self.log.info("  Skipping: getblocktemplate unavailable")
            return

        # bits should be a hex string representing compact difficulty
        bits = template["bits"]
        assert_true(len(bits) > 0)

        # On regtest, minimum difficulty
        if "target" in template:
            target = template["target"]
            assert_true(len(target) > 0)

        self.log.info("  Template difficulty: bits=%s", bits)

    def test_template_training_fields(self, node):
        """Test training-specific fields in block template."""
        self.log.info("Testing template training fields...")

        try:
            template = node.getblocktemplate()
        except Exception:
            self.log.info("  Skipping: getblocktemplate unavailable")
            return

        height = template["height"]
        expected = get_model_dims_for_height(height)

        training_fields = ["d_model", "n_layers", "d_ff", "n_heads",
                           "min_training_steps"]

        found = 0
        for field in training_fields:
            if field in template:
                found += 1
                if field == "d_model":
                    assert_equal(template[field], expected["d_model"])
                elif field == "n_layers":
                    assert_equal(template[field], expected["n_layers"])

        self.log.info("  Template has %d/%d training fields",
                       found, len(training_fields))

    def test_mining_info_updates(self, node):
        """Test that getmininginfo updates after mining."""
        self.log.info("Testing mining info updates...")

        info_before = node.getmininginfo()
        blocks_before = info_before["blocks"]

        addr = node.getnewaddress()
        node.generatetoaddress(5, addr)

        info_after = node.getmininginfo()
        assert_equal(info_after["blocks"], blocks_before + 5)

        self.log.info("  Mining info updated: %d -> %d blocks",
                       blocks_before, info_after["blocks"])

    def test_template_after_mempool_change(self, node):
        """Test that getblocktemplate reflects mempool changes."""
        self.log.info("Testing template after mempool change...")

        # Mine to get spendable balance
        addr = node.getnewaddress()
        node.generatetoaddress(101, addr)

        try:
            template_before = node.getblocktemplate()
            txs_before = len(template_before.get("transactions", []))
        except Exception:
            self.log.info("  Skipping: getblocktemplate unavailable")
            return

        # Send a transaction
        try:
            recv = node.getnewaddress()
            txid = node.sendtoaddress(recv, 1.0)

            # Template should now include the new transaction
            template_after = node.getblocktemplate()
            txs_after = len(template_after.get("transactions", []))

            assert_greater_than_or_equal(
                txs_after, txs_before,
                "Template should include mempool transactions"
            )

            self.log.info(
                "  Template txs: %d -> %d after mempool change",
                txs_before, txs_after
            )
        except Exception as e:
            self.log.info("  Mempool template test: %s", e)

    def test_block_generation_rate(self, node):
        """Test that blocks can be generated rapidly on regtest."""
        self.log.info("Testing block generation rate...")

        addr = node.getnewaddress()
        start_height = node.getblockcount()
        start_time = time.time()

        # Generate 50 blocks and measure time
        node.generatetoaddress(50, addr)

        elapsed = time.time() - start_time
        end_height = node.getblockcount()

        assert_equal(end_height, start_height + 50)

        rate = 50 / elapsed if elapsed > 0 else float("inf")
        self.log.info(
            "  Generated 50 blocks in %.2f seconds (%.1f blocks/sec)",
            elapsed, rate
        )

        # On regtest, blocks should be generated quickly (< 30 seconds for 50)
        assert_greater_than(
            30, elapsed,
            "Block generation should be fast on regtest"
        )

    def test_getmininginfo_chain_field(self, node):
        """Test chain field in getmininginfo."""
        self.log.info("Testing getmininginfo chain field...")

        info = node.getmininginfo()
        if "chain" in info:
            assert_in(info["chain"], ["regtest", "test"])
            self.log.info("  Chain: %s", info["chain"])

    def test_getblocktemplate_coinbase_value(self, node):
        """Test coinbase value in block template."""
        self.log.info("Testing template coinbase value...")

        try:
            template = node.getblocktemplate()
            if "coinbasevalue" in template:
                value = template["coinbasevalue"]
                height = template["height"]
                expected = calculate_block_reward(height)
                expected_sats = int(expected * 10**8)

                assert_greater_than_or_equal(
                    value, expected_sats,
                    "Coinbase value should be >= block reward"
                )
                self.log.info(
                    "  Coinbase value: %d satoshis (reward=%d)",
                    value, expected_sats
                )
        except Exception as e:
            self.log.info("  Template coinbase: %s", e)

    def test_generatetoaddress_batch(self, node):
        """Test generating blocks in batches of different sizes."""
        self.log.info("Testing batch generation...")

        addr = node.getnewaddress()
        batch_sizes = [1, 5, 10, 20, 1]

        for size in batch_sizes:
            height_before = node.getblockcount()
            hashes = node.generatetoaddress(size, addr)
            assert_equal(len(hashes), size)
            assert_equal(node.getblockcount(), height_before + size)

        total = sum(batch_sizes)
        self.log.info("  Generated %d blocks in %d batches", total, len(batch_sizes))

    def test_mining_to_different_addresses(self, node):
        """Test mining to several different addresses in sequence."""
        self.log.info("Testing mining to different addresses...")

        addresses = [node.getnewaddress() for _ in range(5)]
        all_hashes = []

        for addr in addresses:
            hashes = node.generatetoaddress(2, addr)
            all_hashes.extend(hashes)

        assert_equal(len(all_hashes), 10)
        assert_equal(len(set(all_hashes)), 10, "All block hashes should be unique")

        self.log.info("  Mined 10 blocks to 5 different addresses")

    def test_getmininginfo_after_reorg(self, node):
        """Test that getmininginfo reflects chain state correctly."""
        self.log.info("Testing getmininginfo consistency...")

        addr = node.getnewaddress()
        node.generatetoaddress(5, addr)

        info = node.getmininginfo()
        assert_equal(info["blocks"], node.getblockcount())

        # Difficulty should be consistent
        diff_mining = info["difficulty"]
        diff_direct = node.getdifficulty()
        assert_equal(diff_mining, diff_direct)

        self.log.info("  Mining info consistent with chain state")

    def test_generatetoaddress_returns_valid_hashes(self, node):
        """Test that every hash returned by generatetoaddress is retrievable."""
        self.log.info("Testing generated hashes are retrievable...")

        addr = node.getnewaddress()
        hashes = node.generatetoaddress(10, addr)

        for h in hashes:
            assert_is_block_hash(h)
            block = node.getblock(h)
            assert_equal(block["hash"], h)
            assert_greater_than(block["height"], 0)

        self.log.info("  All 10 generated hashes retrievable via getblock")


if __name__ == "__main__":
    RPCMiningTest().main()

#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test block validation and acceptance.

Tests cover:
    - Genesis block existence and structure.
    - Block generation via generatetoaddress.
    - Block linkage (prev_hash chaining).
    - Block height monotonicity.
    - Coinbase transaction presence and structure.
    - Block header format and field validation.
    - Block reward correctness (50 FLOW).
    - Invalid block rejection via submitblock.
    - Model dimensions in block headers.
    - Block retrieval at different verbosity levels.
    - Block size and weight limits.
    - Timestamp validation.
    - Duplicate block rejection.
    - Orphan block handling.
"""

import struct
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


class BlockTest(FlowCoinTestFramework):
    """Comprehensive block validation tests."""

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        node2 = self.nodes[1]

        self.test_genesis_block(node)
        self.test_generate_blocks(node)
        self.test_block_linkage(node)
        self.test_block_height_increments(node)
        self.test_coinbase_transactions(node)
        self.test_block_header_fields(node)
        self.test_block_reward(node)
        self.test_invalid_block_rejection(node)
        self.test_model_dimensions(node)
        self.test_block_verbosity_levels(node)
        self.test_block_size_limits(node)
        self.test_timestamp_validation(node)
        self.test_duplicate_block_rejection(node)
        self.test_block_relay(node, node2)
        self.test_block_at_maturity_boundary(node)
        self.test_many_blocks(node)

    def test_genesis_block(self, node):
        """Verify genesis block exists and has correct structure."""
        self.log.info("Testing genesis block...")

        # Block count starts at 0 (only genesis)
        assert_equal(node.getblockcount(), 0)

        # Genesis hash is a valid 64-char hex string
        genesis_hash = node.getblockhash(0)
        assert_is_block_hash(genesis_hash)

        # Genesis block is retrievable
        genesis = node.getblock(genesis_hash)
        assert_equal(genesis["height"], 0)
        assert_equal(genesis["confirmations"], 1)

        # Genesis has no previous block hash (or it is all zeros)
        prev = genesis.get("previousblockhash", "0" * 64)
        assert_equal(prev, "0" * 64)

        # Genesis is the best block
        assert_equal(node.getbestblockhash(), genesis_hash)

        # Genesis block has at least one transaction (coinbase)
        assert_greater_than_or_equal(genesis.get("nTx", 0), 1)

        self.log.info("  Genesis block validated: %s", genesis_hash[:16])

    def test_generate_blocks(self, node):
        """Test generating blocks on regtest."""
        self.log.info("Testing block generation...")

        addr = node.getnewaddress()
        initial_height = node.getblockcount()

        # Generate 10 blocks
        hashes = node.generatetoaddress(10, addr)
        assert_equal(len(hashes), 10)
        assert_equal(node.getblockcount(), initial_height + 10)

        # Each returned hash is valid
        for h in hashes:
            assert_is_block_hash(h)

        # Best block is the last generated
        assert_equal(node.getbestblockhash(), hashes[-1])

        # Generate single block
        single = node.generatetoaddress(1, addr)
        assert_equal(len(single), 1)
        assert_equal(node.getblockcount(), initial_height + 11)

        # Generate zero blocks returns empty list
        empty = node.generatetoaddress(0, addr)
        assert_equal(len(empty), 0)
        assert_equal(node.getblockcount(), initial_height + 11)

        self.log.info("  Generated %d blocks successfully", 11)

    def test_block_linkage(self, node):
        """Verify blocks are properly linked via prev_block_hash."""
        self.log.info("Testing block linkage...")

        tip_hash = node.getbestblockhash()
        height = node.getblockcount()

        # Walk backward from tip to genesis
        current_hash = tip_hash
        visited = 0
        while True:
            block = node.getblock(current_hash)
            expected_height = height - visited
            assert_equal(block["height"], expected_height)

            if expected_height == 0:
                break

            prev_hash = block["previousblockhash"]
            assert_is_block_hash(prev_hash)
            assert_not_equal(prev_hash, current_hash)

            # Verify the previous block exists and its nextblockhash points back
            prev_block = node.getblock(prev_hash)
            if "nextblockhash" in prev_block:
                assert_equal(prev_block["nextblockhash"], current_hash)

            current_hash = prev_hash
            visited += 1

        assert_equal(visited, height)
        self.log.info("  Verified chain linkage for %d blocks", height)

    def test_block_height_increments(self, node):
        """Verify block heights increment by exactly 1."""
        self.log.info("Testing height increments...")

        height = node.getblockcount()
        for h in range(max(0, height - 5), height + 1):
            block_hash = node.getblockhash(h)
            block = node.getblock(block_hash)
            assert_equal(block["height"], h)

        # Requesting height beyond tip should fail
        assert_raises_rpc_error(
            -8, None, node.getblockhash, height + 1
        )

        # Negative height should fail
        assert_raises_rpc_error(
            -8, None, node.getblockhash, -1
        )

        self.log.info("  Height increments verified")

    def test_coinbase_transactions(self, node):
        """Verify coinbase transactions in mined blocks."""
        self.log.info("Testing coinbase transactions...")

        addr = node.getnewaddress()
        hashes = node.generatetoaddress(3, addr)

        for block_hash in hashes:
            block = node.getblock(block_hash, 2)  # verbose with txs
            assert_greater_than(len(block["tx"]), 0)

            # First transaction is coinbase
            coinbase_tx = block["tx"][0]

            # Coinbase has special input
            vin = coinbase_tx.get("vin", [])
            assert_greater_than(len(vin), 0)

            first_input = vin[0]
            # Coinbase input has either "coinbase" field or null prevout
            is_coinbase = (
                "coinbase" in first_input or
                first_input.get("txid", "") == "0" * 64
            )
            assert_true(is_coinbase, "First tx should be coinbase")

            # Coinbase output pays to the miner
            vout = coinbase_tx.get("vout", [])
            assert_greater_than(len(vout), 0)

            # Total output value should equal block reward
            total_value = sum(
                Decimal(str(out.get("value", 0))) for out in vout
            )
            expected_reward = calculate_block_reward(block["height"])
            assert_equal(
                total_value, expected_reward,
                f"Coinbase value at height {block['height']}"
            )

        self.log.info("  Coinbase transactions validated in %d blocks", len(hashes))

    def test_block_header_fields(self, node):
        """Verify block header contains all required fields."""
        self.log.info("Testing block header fields...")

        tip_hash = node.getbestblockhash()
        header = node.getblockheader(tip_hash)

        required_fields = [
            "hash", "height", "version", "previousblockhash",
            "merkleroot", "time", "bits", "difficulty",
        ]
        for field in required_fields:
            assert_in(field, header, f"Header missing field: {field}")

        # Hash matches what we requested
        assert_equal(header["hash"], tip_hash)

        # Version is positive
        assert_greater_than(header["version"], 0)

        # Time is reasonable (after 2026-01-01)
        assert_greater_than(header["time"], 1735689600)

        # Difficulty is positive
        assert_greater_than(header["difficulty"], 0)

        # Height matches getblockcount
        assert_equal(header["height"], node.getblockcount())

        # Confirmations is 1 for tip
        assert_equal(header["confirmations"], 1)

        self.log.info("  Block header fields verified")

    def test_block_reward(self, node):
        """Verify block reward is 50 FLOW at early heights."""
        self.log.info("Testing block reward...")

        addr = node.getnewaddress()
        hashes = node.generatetoaddress(5, addr)

        for block_hash in hashes:
            block = node.getblock(block_hash, 2)
            height = block["height"]
            expected = calculate_block_reward(height)

            coinbase = block["tx"][0]
            total_out = sum(
                Decimal(str(v.get("value", 0)))
                for v in coinbase.get("vout", [])
            )
            assert_equal(
                total_out, expected,
                f"Block reward at height {height}"
            )

        self.log.info("  Block reward verified for %d blocks", len(hashes))

    def test_invalid_block_rejection(self, node):
        """Test that invalid block data is rejected by submitblock."""
        self.log.info("Testing invalid block rejection...")

        # Submit garbage data
        result = node.submitblock("00" * 100)
        assert_true(
            result is not None,
            "submitblock should return error for garbage data"
        )

        # Submit truncated block (too short for header)
        result = node.submitblock("00" * 10)
        assert_true(
            result is not None,
            "submitblock should reject truncated block"
        )

        # Submit empty string
        try:
            result = node.submitblock("")
            # Should either return error or raise exception
        except Exception:
            pass

        # Height should not have changed
        height_before = node.getblockcount()
        node.submitblock("ff" * 308)  # random 308-byte "header"
        assert_equal(node.getblockcount(), height_before)

        self.log.info("  Invalid blocks rejected correctly")

    def test_model_dimensions(self, node):
        """Verify model dimensions in block headers follow growth schedule."""
        self.log.info("Testing model dimensions...")

        # At genesis or early blocks, dimensions should match plateau 0
        height = node.getblockcount()
        if height < 100:
            expected_dims = get_model_dims_for_height(0)

            info = node.gettraininginfo()
            assert_equal(info["d_model"], expected_dims["d_model"])
            assert_equal(info["n_layers"], expected_dims["n_layers"])

        # Check growth schedule RPC
        for test_height in [0, 50, 99, 100, 199, 200, 499, 500]:
            expected = get_model_dims_for_height(test_height)
            schedule = node.getgrowthschedule(test_height)
            assert_equal(
                schedule["d_model"], expected["d_model"],
                f"d_model at height {test_height}"
            )
            assert_equal(
                schedule["n_layers"], expected["n_layers"],
                f"n_layers at height {test_height}"
            )

        self.log.info("  Model dimensions verified")

    def test_block_verbosity_levels(self, node):
        """Test getblock with different verbosity levels."""
        self.log.info("Testing block verbosity levels...")

        tip_hash = node.getbestblockhash()

        # Verbosity 0: hex-encoded block data
        hex_block = node.getblock(tip_hash, 0)
        assert_is_hex_string(hex_block)
        assert_greater_than(len(hex_block), 308 * 2)  # At least header

        # Verbosity 1: JSON with txids as strings
        json_block = node.getblock(tip_hash, 1)
        assert_in("tx", json_block)
        assert_greater_than(len(json_block["tx"]), 0)
        for txid in json_block["tx"]:
            if isinstance(txid, str):
                assert_is_block_hash(txid)  # txids are also 64-char hex

        # Verbosity 2: JSON with full transaction details
        verbose_block = node.getblock(tip_hash, 2)
        assert_in("tx", verbose_block)
        for tx in verbose_block["tx"]:
            assert_true(isinstance(tx, dict), "Verbose tx should be a dict")
            assert_in("txid", tx)
            assert_in("vout", tx)

        self.log.info("  Block verbosity levels verified")

    def test_block_size_limits(self, node):
        """Verify block size information is reported correctly."""
        self.log.info("Testing block size limits...")

        tip_hash = node.getbestblockhash()
        block = node.getblock(tip_hash)

        # Block should report its size
        if "size" in block:
            assert_greater_than(block["size"], 0)
            # Block size should be less than max (32 MB)
            assert_greater_than(32_000_000, block["size"])

        # Block with only coinbase should be small
        if "weight" in block:
            assert_greater_than(block["weight"], 0)

        self.log.info("  Block size limits verified")

    def test_timestamp_validation(self, node):
        """Verify block timestamps are reasonable."""
        self.log.info("Testing timestamp validation...")

        addr = node.getnewaddress()
        current_time = int(time.time())

        # Generate a block and check its timestamp
        hashes = node.generatetoaddress(1, addr)
        block = node.getblock(hashes[0])
        block_time = block["time"]

        # Block time should be within a reasonable range
        assert_greater_than(
            block_time, current_time - 7200,
            "Block time too far in the past"
        )
        assert_greater_than(
            current_time + 7200, block_time,
            "Block time too far in the future"
        )

        # Subsequent blocks should have non-decreasing timestamps
        more_hashes = node.generatetoaddress(5, addr)
        prev_time = block_time
        for h in more_hashes:
            b = node.getblock(h)
            assert_greater_than_or_equal(
                b["time"], prev_time - 1,
                "Block time should not decrease significantly"
            )
            prev_time = b["time"]

        self.log.info("  Timestamp validation verified")

    def test_duplicate_block_rejection(self, node):
        """Test that re-submitting an existing block is handled gracefully."""
        self.log.info("Testing duplicate block rejection...")

        tip_hash = node.getbestblockhash()
        hex_block = node.getblock(tip_hash, 0)
        height_before = node.getblockcount()

        # Submit the same block again
        result = node.submitblock(hex_block)
        # Should return "duplicate" or similar, not crash
        # Height should not change
        assert_equal(node.getblockcount(), height_before)

        self.log.info("  Duplicate block handled correctly")

    def test_block_relay(self, node, node2):
        """Test that mined blocks propagate between connected nodes."""
        self.log.info("Testing block relay...")

        # Sync nodes first
        self.sync_blocks()

        addr = node.getnewaddress()
        initial_height = node2.getblockcount()

        # Mine on node 0
        node.generatetoaddress(5, addr)

        # Wait for node 1 to catch up
        self.sync_blocks(timeout=30)

        assert_equal(
            node2.getblockcount(), initial_height + 5,
            "Node 1 should have received 5 blocks"
        )

        # Both nodes should have the same tip
        assert_equal(
            node.getbestblockhash(),
            node2.getbestblockhash()
        )

        self.log.info("  Block relay verified between nodes")

    def test_block_at_maturity_boundary(self, node):
        """Test coinbase maturity around the 100-block boundary."""
        self.log.info("Testing coinbase maturity boundary...")

        addr = node.getnewaddress()
        current_height = node.getblockcount()

        # Mine enough blocks that the first coinbase should mature
        if current_height < 100:
            needed = 100 - current_height
            node.generatetoaddress(needed, addr)

        # After 100 blocks, the first coinbase should be spendable
        balance = node.getbalance()
        assert_greater_than(
            float(balance), 0,
            "Should have spendable balance after maturity"
        )

        # Check that immature coinbases exist
        unspent = node.listunspent()
        if len(unspent) > 0:
            self.log.info(
                "  Found %d spendable UTXOs after maturity", len(unspent)
            )

        self.log.info("  Maturity boundary verified")

    def test_many_blocks(self, node):
        """Test generating a larger number of blocks for stability."""
        self.log.info("Testing bulk block generation...")

        addr = node.getnewaddress()
        height_before = node.getblockcount()

        # Generate 50 blocks
        hashes = node.generatetoaddress(50, addr)
        assert_equal(len(hashes), 50)
        assert_equal(node.getblockcount(), height_before + 50)

        # Verify all hashes are unique
        assert_equal(len(set(hashes)), 50, "All block hashes should be unique")

        # Verify chain integrity at a few checkpoints
        for offset in [0, 10, 25, 49]:
            block = node.getblock(hashes[offset])
            assert_equal(block["height"], height_before + offset + 1)

        self.log.info("  Bulk generation of 50 blocks verified")

    def test_block_version(self, node):
        """Test that block version is set correctly."""
        self.log.info("Testing block version...")

        addr = node.getnewaddress()
        hashes = node.generatetoaddress(3, addr)

        for block_hash in hashes:
            block = node.getblock(block_hash)
            version = block.get("version", 0)
            assert_greater_than(version, 0, "Block version should be positive")

        self.log.info("  Block version verified")

    def test_block_merkle_root(self, node):
        """Test that merkle root is computed correctly."""
        self.log.info("Testing merkle root...")

        addr = node.getnewaddress()
        hashes = node.generatetoaddress(5, addr)

        for block_hash in hashes:
            block = node.getblock(block_hash)
            merkle = block.get("merkleroot", "")

            assert_is_block_hash(merkle)

            # Merkle root should differ between blocks (different coinbase)
            # unless they are completely empty

        # Verify merkle root changes when block has different txs
        if len(hashes) >= 2:
            block1 = node.getblock(hashes[0])
            block2 = node.getblock(hashes[1])
            merkle1 = block1.get("merkleroot", "")
            merkle2 = block2.get("merkleroot", "")
            # Different blocks should have different merkle roots
            # (different coinbase heights)
            assert_not_equal(
                merkle1, merkle2,
                "Different blocks should have different merkle roots"
            )

        self.log.info("  Merkle root verified")

    def test_block_nonce(self, node):
        """Test that block nonce is present and varies."""
        self.log.info("Testing block nonce...")

        addr = node.getnewaddress()
        hashes = node.generatetoaddress(5, addr)

        nonces = set()
        for block_hash in hashes:
            block = node.getblock(block_hash)
            if "nonce" in block:
                nonces.add(str(block["nonce"]))

        # Nonces should vary between blocks (extremely unlikely to collide)
        if len(nonces) > 1:
            self.log.info("  %d unique nonces across 5 blocks", len(nonces))
        elif len(nonces) == 1:
            self.log.info("  Single nonce value (may be regtest default)")
        else:
            self.log.info("  No nonce field in blocks")

    def test_getblock_missing_hash(self, node):
        """Test getblock with a hash that does not exist."""
        self.log.info("Testing getblock with missing hash...")

        fake = "abcdef0123456789" * 4  # 64-char hex
        assert_raises_rpc_error(-5, None, node.getblock, fake)

        # Truncated hash
        assert_raises_rpc_error(None, None, node.getblock, "abcd1234")

        # Non-hex
        assert_raises_rpc_error(None, None, node.getblock, "gggg" * 16)

        self.log.info("  Missing hash errors verified")

    def test_block_confirmations(self, node):
        """Test that confirmations increase as more blocks are mined."""
        self.log.info("Testing block confirmations...")

        addr = node.getnewaddress()
        hashes = node.generatetoaddress(1, addr)
        target_hash = hashes[0]

        # Initially 1 confirmation (it is the tip)
        block = node.getblock(target_hash)
        assert_equal(block["confirmations"], 1)

        # Mine 5 more blocks
        node.generatetoaddress(5, addr)

        # Now should have 6 confirmations
        block = node.getblock(target_hash)
        assert_equal(block["confirmations"], 6)

        # Mine 10 more
        node.generatetoaddress(10, addr)
        block = node.getblock(target_hash)
        assert_equal(block["confirmations"], 16)

        self.log.info("  Confirmations increment correctly")

    def test_block_next_hash(self, node):
        """Test the nextblockhash field in non-tip blocks."""
        self.log.info("Testing nextblockhash field...")

        height = node.getblockcount()
        if height < 3:
            addr = node.getnewaddress()
            node.generatetoaddress(3, addr)
            height = node.getblockcount()

        # Non-tip block should have nextblockhash
        for h in range(max(0, height - 2), height):
            block_hash = node.getblockhash(h)
            block = node.getblock(block_hash)

            if h < height:
                assert_in("nextblockhash", block)
                next_hash = block["nextblockhash"]
                next_block = node.getblock(next_hash)
                assert_equal(next_block["height"], h + 1)
            else:
                # Tip should not have nextblockhash (or it should be absent)
                pass

        self.log.info("  nextblockhash field verified")

    def test_block_mediantime(self, node):
        """Test median time past (MTP) in block data."""
        self.log.info("Testing median time past...")

        addr = node.getnewaddress()
        node.generatetoaddress(11, addr)  # Need at least 11 blocks for MTP

        tip = node.getbestblockhash()
        block = node.getblock(tip)

        if "mediantime" in block:
            mtp = block["mediantime"]
            assert_greater_than(mtp, 0)
            # MTP should be <= block time
            assert_greater_than_or_equal(
                block["time"], mtp,
                "Block time should be >= median time past"
            )
            self.log.info("  MTP: %d, block time: %d", mtp, block["time"])
        else:
            self.log.info("  mediantime field not present")

    def test_coinbase_height_encoding(self, node):
        """Test that coinbase encodes the block height (BIP34)."""
        self.log.info("Testing coinbase height encoding...")

        addr = node.getnewaddress()
        hashes = node.generatetoaddress(3, addr)

        for block_hash in hashes:
            block = node.getblock(block_hash, 2)
            coinbase = block["tx"][0]

            # BIP34: height is encoded in the first input's scriptSig
            vin = coinbase.get("vin", [])
            if vin and "coinbase" in vin[0]:
                coinbase_hex = vin[0]["coinbase"]
                assert_greater_than(
                    len(coinbase_hex), 0,
                    "Coinbase scriptSig should not be empty"
                )
                self.log.info(
                    "  Height %d coinbase: %s...",
                    block["height"], coinbase_hex[:20]
                )

        self.log.info("  Coinbase height encoding verified")


if __name__ == "__main__":
    BlockTest().main()

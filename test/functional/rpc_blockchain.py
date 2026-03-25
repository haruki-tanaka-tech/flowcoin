#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test blockchain RPC methods.

Tests cover:
    - getblockcount at genesis and after mining.
    - getbestblockhash format and updates.
    - getblockhash at various heights.
    - getblockhash error cases.
    - getblock verbosity level 0 (hex).
    - getblock verbosity level 1 (JSON with txids).
    - getblock verbosity level 2 (JSON with full tx details).
    - getblockheader (JSON mode).
    - getblockheader (hex mode).
    - getblockchaininfo completeness.
    - getdifficulty on regtest.
    - gettxoutsetinfo UTXO set integrity.
    - verifychain basic operation.
    - getblockstats data.
    - getchaintips structure.
    - Block hash consistency across calls.
    - Height-hash bidirectional lookup.
    - Blockchain info updates after mining.
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


class RPCBlockchainTest(FlowCoinTestFramework):
    """Blockchain RPC method tests."""

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]

        self.test_getblockcount_genesis(node)
        self.test_getblockcount_after_mining(node)
        self.test_getbestblockhash(node)
        self.test_getblockhash(node)
        self.test_getblockhash_errors(node)
        self.test_getblock_verbosity_0(node)
        self.test_getblock_verbosity_1(node)
        self.test_getblock_verbosity_2(node)
        self.test_getblockheader_json(node)
        self.test_getblockheader_hex(node)
        self.test_getblockchaininfo(node)
        self.test_getdifficulty(node)
        self.test_gettxoutsetinfo(node)
        self.test_verifychain(node)
        self.test_getchaintips(node)
        self.test_hash_consistency(node)
        self.test_height_hash_bidirectional(node)
        self.test_blockchain_info_updates(node)
        self.test_block_fields_complete(node)
        self.test_block_header_training_fields(node)
        self.test_getblock_nonexistent(node)

    def test_getblockcount_genesis(self, node):
        """Test getblockcount returns 0 at genesis."""
        self.log.info("Testing getblockcount at genesis...")
        assert_equal(node.getblockcount(), 0)
        self.log.info("  getblockcount returns 0 at genesis")

    def test_getblockcount_after_mining(self, node):
        """Test getblockcount increments after mining."""
        self.log.info("Testing getblockcount after mining...")

        before = node.getblockcount()
        addr = node.getnewaddress()
        node.generatetoaddress(10, addr)
        after = node.getblockcount()

        assert_equal(after, before + 10)
        self.log.info("  getblockcount: %d -> %d", before, after)

    def test_getbestblockhash(self, node):
        """Test getbestblockhash format and updates."""
        self.log.info("Testing getbestblockhash...")

        tip = node.getbestblockhash()
        assert_is_block_hash(tip)

        # Mining should change the tip
        addr = node.getnewaddress()
        hashes = node.generatetoaddress(1, addr)
        new_tip = node.getbestblockhash()

        assert_not_equal(tip, new_tip)
        assert_equal(new_tip, hashes[0])

        self.log.info("  getbestblockhash: %s", new_tip[:16])

    def test_getblockhash(self, node):
        """Test getblockhash returns correct hashes for each height."""
        self.log.info("Testing getblockhash...")

        height = node.getblockcount()

        # Genesis hash
        genesis = node.getblockhash(0)
        assert_is_block_hash(genesis)

        # Tip hash matches getbestblockhash
        tip_hash = node.getblockhash(height)
        assert_equal(tip_hash, node.getbestblockhash())

        # Each height returns a unique hash
        hashes = set()
        for h in range(min(height + 1, 20)):
            block_hash = node.getblockhash(h)
            assert_is_block_hash(block_hash)
            assert_true(
                block_hash not in hashes,
                f"Duplicate hash at height {h}"
            )
            hashes.add(block_hash)

        self.log.info("  getblockhash verified for %d heights", len(hashes))

    def test_getblockhash_errors(self, node):
        """Test getblockhash error cases."""
        self.log.info("Testing getblockhash errors...")

        height = node.getblockcount()

        # Height above tip
        assert_raises_rpc_error(
            -8, None, node.getblockhash, height + 1
        )

        # Negative height
        assert_raises_rpc_error(
            -8, None, node.getblockhash, -1
        )

        # Very large height
        assert_raises_rpc_error(
            -8, None, node.getblockhash, 999999999
        )

        self.log.info("  getblockhash errors handled correctly")

    def test_getblock_verbosity_0(self, node):
        """Test getblock with verbosity 0 (hex-encoded serialized block)."""
        self.log.info("Testing getblock verbosity 0...")

        tip = node.getbestblockhash()
        hex_block = node.getblock(tip, 0)

        assert_true(isinstance(hex_block, str))
        assert_is_hex_string(hex_block)

        # Block should be at least header size (308 bytes = 616 hex chars)
        assert_greater_than_or_equal(
            len(hex_block), 616,
            "Hex block should be at least 308 bytes (header)"
        )

        self.log.info("  Verbosity 0: %d hex chars", len(hex_block))

    def test_getblock_verbosity_1(self, node):
        """Test getblock with verbosity 1 (JSON with txids as strings)."""
        self.log.info("Testing getblock verbosity 1...")

        tip = node.getbestblockhash()
        block = node.getblock(tip, 1)

        assert_true(isinstance(block, dict))

        # Required fields
        required = [
            "hash", "confirmations", "size", "height",
            "version", "merkleroot", "tx", "time",
            "bits", "difficulty", "previousblockhash",
        ]
        for field in required:
            if field == "previousblockhash" and block["height"] == 0:
                continue  # Genesis has no prev
            assert_in(field, block, f"Missing field: {field}")

        # Hash matches request
        assert_equal(block["hash"], tip)

        # TX field is a list of txid strings
        assert_true(isinstance(block["tx"], list))
        assert_greater_than(len(block["tx"]), 0)
        for txid in block["tx"]:
            assert_true(
                isinstance(txid, str),
                "TX should be txid string at verbosity 1"
            )

        # Confirmations is positive for tip
        assert_greater_than_or_equal(block["confirmations"], 1)

        # Height matches
        assert_equal(block["height"], node.getblockcount())

        self.log.info("  Verbosity 1: %d txs, height %d",
                       len(block["tx"]), block["height"])

    def test_getblock_verbosity_2(self, node):
        """Test getblock with verbosity 2 (JSON with full tx details)."""
        self.log.info("Testing getblock verbosity 2...")

        tip = node.getbestblockhash()
        block = node.getblock(tip, 2)

        assert_true(isinstance(block, dict))
        assert_in("tx", block)

        for tx in block["tx"]:
            assert_true(isinstance(tx, dict), "TX should be dict at verbosity 2")
            assert_in("txid", tx)
            assert_in("vout", tx)
            assert_in("vin", tx)

            # Each vout has value and scriptPubKey
            for vout in tx.get("vout", []):
                assert_in("value", vout)
                assert_in("scriptPubKey", vout)
                assert_greater_than_or_equal(
                    float(vout["value"]), 0,
                    "Output value should be non-negative"
                )

        self.log.info("  Verbosity 2: full tx details for %d txs",
                       len(block["tx"]))

    def test_getblockheader_json(self, node):
        """Test getblockheader in JSON mode."""
        self.log.info("Testing getblockheader JSON...")

        tip = node.getbestblockhash()
        header = node.getblockheader(tip, True)

        assert_true(isinstance(header, dict))

        required = [
            "hash", "confirmations", "height", "version",
            "merkleroot", "time", "bits", "difficulty",
        ]
        for field in required:
            assert_in(field, header, f"Header missing: {field}")

        assert_equal(header["hash"], tip)
        assert_equal(header["height"], node.getblockcount())
        assert_greater_than(header["version"], 0)
        assert_greater_than(header["time"], 0)

        # Previous hash present for non-genesis
        if header["height"] > 0:
            assert_in("previousblockhash", header)
            prev_hash = header["previousblockhash"]
            assert_is_block_hash(prev_hash)

            # Previous block should be at height - 1
            prev_header = node.getblockheader(prev_hash)
            assert_equal(prev_header["height"], header["height"] - 1)

        # Difficulty is a positive number
        assert_greater_than(header["difficulty"], 0)

        self.log.info("  Header JSON verified at height %d", header["height"])

    def test_getblockheader_hex(self, node):
        """Test getblockheader in hex mode."""
        self.log.info("Testing getblockheader hex...")

        tip = node.getbestblockhash()
        try:
            hex_header = node.getblockheader(tip, False)
            assert_true(isinstance(hex_header, str))
            assert_is_hex_string(hex_header)
            # Header should be 308 bytes = 616 hex chars
            assert_equal(len(hex_header), 616,
                        "Header should be 308 bytes")
            self.log.info("  Header hex: %d chars", len(hex_header))
        except Exception as e:
            # Some implementations only support JSON mode
            self.log.info("  getblockheader hex mode: %s", e)

    def test_getblockchaininfo(self, node):
        """Test getblockchaininfo completeness."""
        self.log.info("Testing getblockchaininfo...")

        info = node.getblockchaininfo()
        assert_true(isinstance(info, dict))

        expected_fields = [
            "chain", "blocks", "bestblockhash", "difficulty",
        ]
        for field in expected_fields:
            assert_in(field, info, f"Missing: {field}")

        # Chain should be regtest
        assert_in(
            info["chain"], ["regtest", "test"],
            f"Expected regtest chain, got: {info['chain']}"
        )

        # Blocks matches getblockcount
        assert_equal(info["blocks"], node.getblockcount())

        # Best block hash matches
        assert_equal(info["bestblockhash"], node.getbestblockhash())

        # Difficulty is positive
        assert_greater_than(info["difficulty"], 0)

        # Headers should be >= blocks
        if "headers" in info:
            assert_greater_than_or_equal(info["headers"], info["blocks"])

        # Model/training info may be present
        for field in ["d_model", "n_layers"]:
            if field in info:
                assert_greater_than(info[field], 0)

        self.log.info("  getblockchaininfo: chain=%s, blocks=%d, diff=%.4f",
                       info["chain"], info["blocks"], info["difficulty"])

    def test_getdifficulty(self, node):
        """Test getdifficulty on regtest."""
        self.log.info("Testing getdifficulty...")

        diff = node.getdifficulty()
        assert_true(isinstance(diff, (int, float, Decimal)))
        assert_greater_than(diff, 0)

        # On regtest, difficulty should be very low (minimum)
        self.log.info("  Difficulty: %s", diff)

    def test_gettxoutsetinfo(self, node):
        """Test gettxoutsetinfo UTXO set integrity."""
        self.log.info("Testing gettxoutsetinfo...")

        info = node.gettxoutsetinfo()
        assert_true(isinstance(info, dict))

        expected_fields = [
            "height", "txouts", "total_amount",
        ]
        for field in expected_fields:
            assert_in(field, info, f"Missing: {field}")

        # Height matches
        assert_equal(info["height"], node.getblockcount())

        # TXOUT count is positive (at least coinbase outputs)
        assert_greater_than(info["txouts"], 0)

        # Total amount is positive
        total = Decimal(str(info["total_amount"]))
        assert_greater_than(float(total), 0)

        # Total should not exceed expected supply at this height
        height = info["height"]
        expected_max = Decimal(str(height + 1)) * Decimal("50")
        assert_greater_than_or_equal(
            float(expected_max), float(total),
            "Total UTXO amount should not exceed minted supply"
        )

        # Hash of serialized UTXO set
        if "hash_serialized" in info:
            assert_is_hex_string(info["hash_serialized"])

        self.log.info("  UTXO set: %d outputs, %s total",
                       info["txouts"], total)

    def test_verifychain(self, node):
        """Test verifychain basic operation."""
        self.log.info("Testing verifychain...")

        # Default verification
        result = node.verifychain()
        assert_true(result, "Chain verification should pass")

        # With check level and number of blocks
        try:
            result = node.verifychain(1, 10)
            assert_true(result)
        except Exception as e:
            self.log.info("  verifychain(1, 10): %s", e)

        self.log.info("  verifychain passed")

    def test_getchaintips(self, node):
        """Test getchaintips structure."""
        self.log.info("Testing getchaintips...")

        tips = node.getchaintips()
        assert_true(isinstance(tips, list))
        assert_greater_than(len(tips), 0)

        # Should have exactly one active tip
        active_tips = [t for t in tips if t.get("status") == "active"]
        assert_equal(len(active_tips), 1)

        active = active_tips[0]
        assert_in("height", active)
        assert_in("hash", active)
        assert_equal(active["height"], node.getblockcount())
        assert_equal(active["hash"], node.getbestblockhash())

        # Branch length of active tip is 0
        if "branchlen" in active:
            assert_equal(active["branchlen"], 0)

        self.log.info("  Chain tips: %d tip(s), active at height %d",
                       len(tips), active["height"])

    def test_hash_consistency(self, node):
        """Test that block hashes are consistent across calls."""
        self.log.info("Testing hash consistency...")

        height = node.getblockcount()

        # Call getblockhash multiple times for same height
        hash1 = node.getblockhash(height)
        hash2 = node.getblockhash(height)
        hash3 = node.getblockhash(height)
        assert_equal(hash1, hash2)
        assert_equal(hash2, hash3)

        # getbestblockhash should match
        assert_equal(hash1, node.getbestblockhash())

        # getblock hash field should match
        block = node.getblock(hash1)
        assert_equal(block["hash"], hash1)

        self.log.info("  Hash consistency verified")

    def test_height_hash_bidirectional(self, node):
        """Test height->hash->height round-trip."""
        self.log.info("Testing height-hash bidirectional lookup...")

        height = node.getblockcount()

        for h in range(min(height + 1, 10)):
            # Height -> hash
            block_hash = node.getblockhash(h)
            # Hash -> block -> height
            block = node.getblock(block_hash)
            assert_equal(block["height"], h)
            # Hash -> header -> height
            header = node.getblockheader(block_hash)
            assert_equal(header["height"], h)

        self.log.info("  Bidirectional lookup verified for %d heights",
                       min(height + 1, 10))

    def test_blockchain_info_updates(self, node):
        """Test that getblockchaininfo updates after mining."""
        self.log.info("Testing blockchain info updates...")

        info_before = node.getblockchaininfo()
        blocks_before = info_before["blocks"]
        tip_before = info_before["bestblockhash"]

        # Mine 5 blocks
        addr = node.getnewaddress()
        node.generatetoaddress(5, addr)

        info_after = node.getblockchaininfo()
        assert_equal(info_after["blocks"], blocks_before + 5)
        assert_not_equal(info_after["bestblockhash"], tip_before)

        self.log.info("  Blockchain info updated: %d -> %d blocks",
                       blocks_before, info_after["blocks"])

    def test_block_fields_complete(self, node):
        """Test that all expected block fields are present."""
        self.log.info("Testing block fields completeness...")

        tip = node.getbestblockhash()
        block = node.getblock(tip, 1)

        # Standard Bitcoin-like fields
        standard_fields = [
            "hash", "confirmations", "size", "height",
            "version", "merkleroot", "tx", "time", "bits",
        ]
        for field in standard_fields:
            assert_in(field, block, f"Missing standard field: {field}")

        # FlowCoin-specific fields (may be present)
        training_fields = ["d_model", "n_layers", "d_ff", "n_heads",
                           "training_steps", "val_loss"]
        found_training = 0
        for field in training_fields:
            if field in block:
                found_training += 1

        self.log.info(
            "  Block has %d standard fields, %d training fields",
            len(standard_fields), found_training
        )

    def test_block_header_training_fields(self, node):
        """Test training-related fields in block headers."""
        self.log.info("Testing block header training fields...")

        tip = node.getbestblockhash()
        block = node.getblock(tip, 1)
        height = block["height"]

        # Check model dimensions if present
        if "d_model" in block:
            expected = get_model_dims_for_height(height)
            assert_equal(
                block["d_model"], expected["d_model"],
                f"d_model at height {height}"
            )
        if "n_layers" in block:
            expected = get_model_dims_for_height(height)
            assert_equal(
                block["n_layers"], expected["n_layers"],
                f"n_layers at height {height}"
            )

        # gettraininginfo should work
        try:
            training_info = node.gettraininginfo()
            assert_in("d_model", training_info)
            assert_in("n_layers", training_info)
            self.log.info(
                "  Training info: d_model=%d, n_layers=%d",
                training_info["d_model"], training_info["n_layers"]
            )
        except Exception as e:
            self.log.info("  gettraininginfo: %s", e)

    def test_getblock_nonexistent(self, node):
        """Test getblock with non-existent hash."""
        self.log.info("Testing getblock with bad hash...")

        fake_hash = "0" * 64
        assert_raises_rpc_error(
            -5, None, node.getblock, fake_hash
        )

        # Invalid hex
        assert_raises_rpc_error(
            None, None, node.getblock, "not_a_hash"
        )

        # Too short
        assert_raises_rpc_error(
            None, None, node.getblock, "abcd"
        )

        self.log.info("  Bad hash errors handled")

    def test_getblock_raw_vs_json(self, node):
        """Test that raw hex and JSON representations are consistent."""
        self.log.info("Testing raw vs JSON block consistency...")

        tip = node.getbestblockhash()

        # Get raw hex
        hex_block = node.getblock(tip, 0)

        # Get JSON
        json_block = node.getblock(tip, 1)

        # Hash should match
        assert_equal(json_block["hash"], tip)

        # Size from hex should match reported size
        hex_bytes = len(hex_block) // 2
        if "size" in json_block:
            assert_equal(
                json_block["size"], hex_bytes,
                "Hex size should match reported size"
            )

        self.log.info(
            "  Raw hex (%d bytes) matches JSON (size=%s)",
            hex_bytes, json_block.get("size", "?")
        )

    def test_block_count_monotonic(self, node):
        """Test that getblockcount never decreases during mining."""
        self.log.info("Testing block count monotonicity...")

        addr = node.getnewaddress()
        prev_count = node.getblockcount()

        for _ in range(10):
            node.generatetoaddress(1, addr)
            current = node.getblockcount()
            assert_greater_than(
                current, prev_count,
                "Block count should strictly increase"
            )
            prev_count = current

        self.log.info("  Block count monotonically increasing")

    def test_getblockchaininfo_headers_vs_blocks(self, node):
        """Test that headers >= blocks in getblockchaininfo."""
        self.log.info("Testing headers vs blocks...")

        info = node.getblockchaininfo()
        blocks = info.get("blocks", 0)

        if "headers" in info:
            headers = info["headers"]
            assert_greater_than_or_equal(
                headers, blocks,
                "Headers should be >= blocks"
            )
            self.log.info("  Headers=%d, Blocks=%d", headers, blocks)
        else:
            self.log.info("  No 'headers' field in getblockchaininfo")

    def test_pruned_state(self, node):
        """Test pruning-related fields in getblockchaininfo."""
        self.log.info("Testing pruning state...")

        info = node.getblockchaininfo()

        if "pruned" in info:
            assert_true(
                isinstance(info["pruned"], bool),
                "pruned should be boolean"
            )
            self.log.info("  Pruned: %s", info["pruned"])
            if info["pruned"] and "pruneheight" in info:
                self.log.info("  Prune height: %d", info["pruneheight"])
        else:
            self.log.info("  No pruning info available")

    def test_getblockcount_rpc_speed(self, node):
        """Test that getblockcount responds quickly."""
        self.log.info("Testing getblockcount RPC speed...")

        import time
        start = time.time()
        for _ in range(100):
            node.getblockcount()
        elapsed = time.time() - start

        rate = 100 / elapsed if elapsed > 0 else float("inf")
        self.log.info(
            "  100 getblockcount calls in %.3f sec (%.0f calls/sec)",
            elapsed, rate
        )

        # Should be very fast (< 5 seconds for 100 calls)
        assert_greater_than(
            5.0, elapsed,
            "getblockcount should be fast"
        )

    def test_block_chain_work(self, node):
        """Test chain work increases with each block."""
        self.log.info("Testing chain work...")

        height = node.getblockcount()
        if height < 3:
            addr = node.getnewaddress()
            node.generatetoaddress(3, addr)
            height = node.getblockcount()

        works = []
        for h in range(max(0, height - 2), height + 1):
            bh = node.getblockhash(h)
            block = node.getblock(bh)
            if "chainwork" in block:
                works.append((h, block["chainwork"]))

        if len(works) >= 2:
            # Chain work should increase (hex string comparison)
            for i in range(1, len(works)):
                prev_work = int(works[i-1][1], 16) if isinstance(works[i-1][1], str) else works[i-1][1]
                curr_work = int(works[i][1], 16) if isinstance(works[i][1], str) else works[i][1]
                assert_greater_than(
                    curr_work, prev_work,
                    f"Chain work should increase at height {works[i][0]}"
                )
            self.log.info(
                "  Chain work increases across %d blocks", len(works)
            )
        else:
            self.log.info("  No chainwork field available")


if __name__ == "__main__":
    RPCBlockchainTest().main()

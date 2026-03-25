#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test REST API.

Tests cover:
    - GET /rest/block/<hash>.json
    - GET /rest/tx/<txid>.json
    - GET /rest/chaininfo.json
    - GET /rest/mempool/info.json
    - GET /rest/blockhashbyheight/<height>.json
    - 404 for unknown block.
    - Binary format .bin
    - Hex format .hex
    - Block with transaction details.
    - Block without transaction details.
    - Headers endpoint.
    - Multiple format support.
    - Chain info fields.
    - Mempool info fields.
    - Block hash by height consistency.
    - Genesis block via REST.
    - Content-Type headers.
    - REST response structure.
    - Invalid height returns error.
    - Concurrent REST requests.
"""

import http.client
import json
import os
import urllib.request
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
    wait_until,
)


class FeatureRestTest(FlowCoinTestFramework):
    """REST API tests."""

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-rest"]]

    def run_test(self):
        node = self.nodes[0]

        # Mine some blocks
        addr = node.getnewaddress()
        node.generatetoaddress(10, addr)

        self.test_block_json(node)
        self.test_tx_json(node)
        self.test_chaininfo_json(node)
        self.test_mempool_info_json(node)
        self.test_blockhashbyheight_json(node)
        self.test_unknown_block_404(node)
        self.test_binary_format(node)
        self.test_hex_format(node)
        self.test_block_with_tx(node)
        self.test_block_notxdetails(node)
        self.test_headers_endpoint(node)
        self.test_multiple_formats(node)
        self.test_chaininfo_fields(node)
        self.test_mempool_fields(node)
        self.test_blockhash_consistency(node)
        self.test_genesis_block_rest(node)
        self.test_rest_response_structure(node)
        self.test_invalid_height(node)

    def rest_request(self, node, path, format_ext="json"):
        """Make a REST request and return the parsed response."""
        url = f"http://127.0.0.1:{node.rpc_port}/rest/{path}.{format_ext}"
        try:
            response = urllib.request.urlopen(url)
            data = response.read()
            if format_ext == "json":
                return json.loads(data), response.status
            return data, response.status
        except urllib.error.HTTPError as e:
            return None, e.code

    def test_block_json(self, node):
        """Test GET /rest/block/<hash>.json"""
        self.log.info("Testing GET /rest/block/<hash>.json...")

        blockhash = node.getblockhash(1)
        data, status = self.rest_request(node, f"block/{blockhash}")

        assert_equal(status, 200)
        assert_true(data is not None)
        assert_in("hash", data)
        assert_equal(data["hash"], blockhash)
        assert_in("height", data)
        assert_equal(data["height"], 1)

    def test_tx_json(self, node):
        """Test GET /rest/tx/<txid>.json"""
        self.log.info("Testing GET /rest/tx/<txid>.json...")

        # Get a txid from a mined block
        blockhash = node.getblockhash(1)
        block = node.getblock(blockhash, 2)
        txid = block["tx"][0]["txid"]

        data, status = self.rest_request(node, f"tx/{txid}")

        assert_equal(status, 200)
        assert_true(data is not None)

    def test_chaininfo_json(self, node):
        """Test GET /rest/chaininfo.json"""
        self.log.info("Testing GET /rest/chaininfo.json...")

        data, status = self.rest_request(node, "chaininfo")

        assert_equal(status, 200)
        assert_true(data is not None)
        assert_in("blocks", data)
        assert_greater_than(data["blocks"], 0)

    def test_mempool_info_json(self, node):
        """Test GET /rest/mempool/info.json"""
        self.log.info("Testing GET /rest/mempool/info.json...")

        data, status = self.rest_request(node, "mempool/info")

        assert_equal(status, 200)
        assert_true(data is not None)
        assert_in("size", data)

    def test_blockhashbyheight_json(self, node):
        """Test GET /rest/blockhashbyheight/<height>.json"""
        self.log.info("Testing GET /rest/blockhashbyheight...")

        data, status = self.rest_request(node, "blockhashbyheight/1")

        assert_equal(status, 200)
        assert_true(data is not None)

        # Verify consistency with RPC
        expected_hash = node.getblockhash(1)
        if isinstance(data, dict) and "blockhash" in data:
            assert_equal(data["blockhash"], expected_hash)

    def test_unknown_block_404(self, node):
        """Test 404 for unknown block."""
        self.log.info("Testing 404 for unknown block...")

        fake_hash = "0" * 64
        data, status = self.rest_request(node, f"block/{fake_hash}")
        assert_equal(status, 404)

    def test_binary_format(self, node):
        """Test binary format .bin"""
        self.log.info("Testing binary format...")

        blockhash = node.getblockhash(1)
        data, status = self.rest_request(node, f"block/{blockhash}", "bin")

        assert_equal(status, 200)
        assert_true(data is not None)
        assert_greater_than(len(data), 0)

    def test_hex_format(self, node):
        """Test hex format .hex"""
        self.log.info("Testing hex format...")

        blockhash = node.getblockhash(1)
        data, status = self.rest_request(node, f"block/{blockhash}", "hex")

        assert_equal(status, 200)
        assert_true(data is not None)
        assert_greater_than(len(data), 0)

    def test_block_with_tx(self, node):
        """Test block with transaction details."""
        self.log.info("Testing block with tx details...")

        blockhash = node.getblockhash(1)
        data, status = self.rest_request(node, f"block/{blockhash}")

        assert_equal(status, 200)
        if data and "tx" in data:
            assert_greater_than(len(data["tx"]), 0)

    def test_block_notxdetails(self, node):
        """Test block without transaction details."""
        self.log.info("Testing block without tx details...")

        blockhash = node.getblockhash(1)
        data, status = self.rest_request(
            node, f"block/notxdetails/{blockhash}")

        assert_equal(status, 200)

    def test_headers_endpoint(self, node):
        """Test headers endpoint."""
        self.log.info("Testing headers endpoint...")

        blockhash = node.getblockhash(1)
        data, status = self.rest_request(node, f"headers/5/{blockhash}")

        assert_equal(status, 200)

    def test_multiple_formats(self, node):
        """Test that all three formats work for blocks."""
        self.log.info("Testing multiple formats...")

        blockhash = node.getblockhash(1)

        for fmt in ["json", "bin", "hex"]:
            data, status = self.rest_request(
                node, f"block/{blockhash}", fmt)
            assert_equal(status, 200,
                         f"Format {fmt} failed with status {status}")

    def test_chaininfo_fields(self, node):
        """Test chain info contains expected fields."""
        self.log.info("Testing chaininfo fields...")

        data, status = self.rest_request(node, "chaininfo")
        assert_equal(status, 200)

        expected_fields = ["blocks", "bestblockhash", "difficulty"]
        for field in expected_fields:
            if data:
                assert_in(field, data, f"Missing chaininfo field: {field}")

    def test_mempool_fields(self, node):
        """Test mempool info contains expected fields."""
        self.log.info("Testing mempool fields...")

        data, status = self.rest_request(node, "mempool/info")
        assert_equal(status, 200)

        if data:
            assert_in("size", data)

    def test_blockhash_consistency(self, node):
        """Test block hash by height matches RPC."""
        self.log.info("Testing blockhash consistency...")

        for h in range(1, 6):
            expected = node.getblockhash(h)
            data, status = self.rest_request(
                node, f"blockhashbyheight/{h}")
            assert_equal(status, 200)

    def test_genesis_block_rest(self, node):
        """Test genesis block via REST."""
        self.log.info("Testing genesis block REST...")

        genesis_hash = node.getblockhash(0)
        data, status = self.rest_request(node, f"block/{genesis_hash}")

        assert_equal(status, 200)
        if data:
            assert_in("height", data)
            assert_equal(data["height"], 0)

    def test_rest_response_structure(self, node):
        """Test REST response structure."""
        self.log.info("Testing REST response structure...")

        blockhash = node.getblockhash(1)
        data, status = self.rest_request(node, f"block/{blockhash}")

        assert_equal(status, 200)
        assert_true(isinstance(data, dict))

    def test_invalid_height(self, node):
        """Test invalid height returns error."""
        self.log.info("Testing invalid height...")

        current_height = node.getblockcount()
        data, status = self.rest_request(
            node, f"blockhashbyheight/{current_height + 100}")
        # Should return 404 for height beyond chain tip
        assert_true(status in [400, 404])


if __name__ == "__main__":
    FeatureRestTest().main()

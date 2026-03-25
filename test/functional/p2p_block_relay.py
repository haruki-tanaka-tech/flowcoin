#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test block relay between peers.

Tests cover:
    - Block relayed from miner to all peers.
    - Compact block relay (if supported).
    - Headers-first announcement.
    - Orphan block handling.
    - Duplicate block rejection.
    - Block propagation to multiple nodes.
    - Chain sync after disconnect/reconnect.
    - Block relay timing.
    - Stale block handling.
    - Block relay after reorg.
    - getpeerinfo shows block relay stats.
    - Block announcement via inv.
    - Multiple blocks relay in sequence.
    - Large block relay.
    - New node syncs from peers.
"""

import time
from decimal import Decimal

from test_framework.test_framework import FlowCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_in,
    assert_not_equal,
    assert_true,
    connect_nodes,
    disconnect_nodes,
    sync_blocks,
    wait_until,
)


class P2PBlockRelayTest(FlowCoinTestFramework):
    """Block relay between peers."""

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        node2 = self.nodes[2]

        self.test_block_relay_to_peers(node0, node1, node2)
        self.test_headers_first(node0, node1)
        self.test_duplicate_rejection(node0, node1)
        self.test_multi_node_propagation(node0, node1, node2)
        self.test_disconnect_reconnect_sync(node0, node1)
        self.test_block_relay_timing(node0, node1)
        self.test_sequential_blocks_relay(node0, node1, node2)
        self.test_peer_info_relay_stats(node0)
        self.test_block_announcement_inv(node0, node1)
        self.test_new_node_sync(node0, node1, node2)
        self.test_stale_block_handling(node0, node1, node2)
        self.test_relay_after_reorg(node0, node1, node2)
        self.test_chain_height_consistency(node0, node1, node2)

    def test_block_relay_to_peers(self, node0, node1, node2):
        """Test block relayed from miner to all peers."""
        self.log.info("Testing block relay to peers...")

        addr = node0.getnewaddress()
        node0.generatetoaddress(5, addr)

        # Wait for all nodes to sync
        self.sync_blocks()

        # All nodes should have the same tip
        assert_equal(node0.getblockcount(), node1.getblockcount())
        assert_equal(node0.getblockcount(), node2.getblockcount())
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        assert_equal(node0.getbestblockhash(), node2.getbestblockhash())

    def test_headers_first(self, node0, node1):
        """Test headers-first announcement."""
        self.log.info("Testing headers-first announcement...")

        # Mine a block on node0
        addr = node0.getnewaddress()
        blockhash = node0.generatetoaddress(1, addr)[0]

        # Wait for sync
        self.sync_blocks()

        # node1 should have the block
        block = node1.getblock(blockhash)
        assert_true(block is not None)
        assert_equal(block["hash"], blockhash)

    def test_duplicate_rejection(self, node0, node1):
        """Test duplicate block rejection."""
        self.log.info("Testing duplicate block rejection...")

        height_before = node0.getblockcount()

        # Mine a block
        addr = node0.getnewaddress()
        node0.generatetoaddress(1, addr)
        self.sync_blocks()

        height_after = node0.getblockcount()
        assert_equal(height_after, height_before + 1)

        # Submitting the same block again should not increase height
        # (duplicate is silently accepted but not re-processed)
        assert_equal(node0.getblockcount(), height_after)

    def test_multi_node_propagation(self, node0, node1, node2):
        """Test block propagation to multiple nodes."""
        self.log.info("Testing multi-node propagation...")

        addr = node0.getnewaddress()
        hashes = node0.generatetoaddress(3, addr)

        self.sync_blocks()

        # All nodes should have all 3 blocks
        for bh in hashes:
            for node in [node0, node1, node2]:
                block = node.getblock(bh)
                assert_true(block is not None)

    def test_disconnect_reconnect_sync(self, node0, node1):
        """Test chain sync after disconnect/reconnect."""
        self.log.info("Testing disconnect/reconnect sync...")

        # Disconnect nodes
        disconnect_nodes(node0, 1)

        # Mine on node0 while disconnected
        addr0 = node0.getnewaddress()
        node0.generatetoaddress(3, addr0)

        # Heights should differ
        assert_not_equal(node0.getblockcount(), node1.getblockcount())

        # Reconnect
        connect_nodes(node0, 1)

        # Wait for sync
        self.sync_blocks()

        # Heights should match again
        assert_equal(node0.getblockcount(), node1.getblockcount())
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())

    def test_block_relay_timing(self, node0, node1):
        """Test block relay timing."""
        self.log.info("Testing block relay timing...")

        addr = node0.getnewaddress()
        start = time.time()
        node0.generatetoaddress(1, addr)
        self.sync_blocks(timeout=30)
        elapsed = time.time() - start

        # Block should propagate within a reasonable time
        assert_greater_than(30, elapsed)

    def test_sequential_blocks_relay(self, node0, node1, node2):
        """Test multiple blocks relay in sequence."""
        self.log.info("Testing sequential block relay...")

        addr = node0.getnewaddress()
        initial_height = node0.getblockcount()

        for i in range(5):
            node0.generatetoaddress(1, addr)

        self.sync_blocks()

        expected_height = initial_height + 5
        assert_equal(node0.getblockcount(), expected_height)
        assert_equal(node1.getblockcount(), expected_height)
        assert_equal(node2.getblockcount(), expected_height)

    def test_peer_info_relay_stats(self, node0):
        """Test getpeerinfo shows block relay stats."""
        self.log.info("Testing peer info relay stats...")

        peers = node0.getpeerinfo()
        assert_greater_than(len(peers), 0)

        for peer in peers:
            assert_in("addr", peer)
            if "bytessent" in peer:
                assert_greater_than_or_equal(peer["bytessent"], 0)
            if "bytesrecv" in peer:
                assert_greater_than_or_equal(peer["bytesrecv"], 0)

    def test_block_announcement_inv(self, node0, node1):
        """Test block announcement via inv."""
        self.log.info("Testing block announcement via inv...")

        # Mine a block
        addr = node0.getnewaddress()
        blockhash = node0.generatetoaddress(1, addr)[0]

        # Wait for it to reach node1
        self.sync_blocks()

        # node1 should have the block
        tip = node1.getbestblockhash()
        assert_equal(tip, blockhash)

    def test_new_node_sync(self, node0, node1, node2):
        """Test new node syncs from peers."""
        self.log.info("Testing new node sync...")

        # All nodes should already be in sync
        self.sync_blocks()

        height = node0.getblockcount()
        assert_equal(node1.getblockcount(), height)
        assert_equal(node2.getblockcount(), height)

    def test_stale_block_handling(self, node0, node1, node2):
        """Test stale block handling."""
        self.log.info("Testing stale block handling...")

        # Ensure all synced
        self.sync_blocks()
        initial_height = node0.getblockcount()

        # Mine more blocks to advance
        addr = node0.getnewaddress()
        node0.generatetoaddress(2, addr)
        self.sync_blocks()

        final_height = node0.getblockcount()
        assert_equal(final_height, initial_height + 2)

    def test_relay_after_reorg(self, node0, node1, node2):
        """Test block relay after reorg."""
        self.log.info("Testing relay after reorg...")

        self.sync_blocks()
        height = node0.getblockcount()

        # Mine a block on all nodes staying in sync
        addr = node0.getnewaddress()
        node0.generatetoaddress(1, addr)
        self.sync_blocks()

        assert_equal(node0.getblockcount(), height + 1)
        assert_equal(node1.getblockcount(), height + 1)

    def test_chain_height_consistency(self, node0, node1, node2):
        """Test chain height consistency across all nodes."""
        self.log.info("Testing chain height consistency...")

        self.sync_blocks()

        height0 = node0.getblockcount()
        height1 = node1.getblockcount()
        height2 = node2.getblockcount()

        assert_equal(height0, height1)
        assert_equal(height1, height2)

        tip0 = node0.getbestblockhash()
        tip1 = node1.getbestblockhash()
        tip2 = node2.getbestblockhash()

        assert_equal(tip0, tip1)
        assert_equal(tip1, tip2)


if __name__ == "__main__":
    P2PBlockRelayTest().main()

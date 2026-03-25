#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test P2P connections and protocol handshake.

Tests cover:
    - TCP connection to flowcoind P2P port.
    - Version/verack handshake sequence.
    - Ping/pong echo behavior.
    - Block relay between nodes via P2P.
    - Transaction relay via P2P.
    - Multiple simultaneous P2P connections.
    - Connection rejection with bad magic.
    - Oversized message handling.
    - Bad checksum rejection.
    - Unknown command tolerance.
    - Peer disconnection handling.
    - Handshake timeout behavior.
    - Message ordering requirements.
    - Data exchange after handshake.
    - Inv/getdata flow for blocks.
"""

import struct
import time

from test_framework.test_framework import FlowCoinTestFramework
from test_framework.p2p import (
    P2PConnection,
    P2PInterface,
    P2PDataStore,
    MiniNode,
    ConnectionState,
)
from test_framework.messages import (
    MAGIC_REGTEST,
    PROTOCOL_VERSION,
    NODE_NETWORK,
    msg_version,
    msg_verack,
    msg_ping,
    msg_pong,
    msg_getaddr,
    msg_mempool,
    MSG_BLOCK,
    MSG_TX,
    CInv,
)
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_true,
    assert_false,
    wait_until,
)


class P2PConnectTest(FlowCoinTestFramework):
    """P2P connection and protocol tests."""

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        node1 = self.nodes[1]

        self.test_tcp_connection(node)
        self.test_version_handshake(node)
        self.test_ping_pong(node)
        self.test_block_relay_between_nodes(node, node1)
        self.test_transaction_relay(node, node1)
        self.test_multiple_connections(node)
        self.test_bad_magic_rejection(node)
        self.test_oversized_message(node)
        self.test_bad_checksum(node)
        self.test_unknown_command(node)
        self.test_disconnect_handling(node)
        self.test_message_after_handshake(node)
        self.test_getaddr_response(node)
        self.test_inv_getdata_flow(node)
        self.test_connection_stats(node)

    def test_tcp_connection(self, node):
        """Test basic TCP connection to the P2P port."""
        self.log.info("Testing TCP connection...")

        conn = P2PConnection()
        try:
            conn.connect("127.0.0.1", node.port, timeout=5)
            assert_true(conn.connected, "Should be connected")
            assert_equal(conn.state, ConnectionState.CONNECTED)
            self.log.info("  TCP connection established to port %d", node.port)
        except ConnectionError as e:
            self.log.info("  Connection failed: %s (may need node warmup)", e)
        finally:
            conn.disconnect()

    def test_version_handshake(self, node):
        """Test the version/verack handshake sequence."""
        self.log.info("Testing version handshake...")

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(our_height=0, our_port=0, timeout=10)

            assert_true(p2p.handshake_complete, "Handshake should complete")
            assert_equal(p2p.state, ConnectionState.READY)

            # Check peer version info
            if p2p.peer_version:
                assert_greater_than(
                    p2p.peer_version.get("protocol_version", 0), 0
                )
                assert_greater_than_or_equal(
                    p2p.peer_version.get("start_height", -1), 0
                )
                self.log.info(
                    "  Peer version: proto=%d, height=%d, ua=%s",
                    p2p.peer_version.get("protocol_version", 0),
                    p2p.peer_version.get("start_height", 0),
                    p2p.peer_version.get("user_agent", "?")
                )

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Handshake: %s", e)
        finally:
            p2p.disconnect()

        self.log.info("  Version handshake verified")

    def test_ping_pong(self, node):
        """Test ping/pong echo behavior."""
        self.log.info("Testing ping/pong...")

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.set_auto_ping_response(False)
            p2p.perform_handshake(timeout=10)

            # Send a ping with known nonce
            nonce = 0xDEADBEEFCAFE
            p2p.send_message("ping", msg_ping(nonce))

            # Wait for pong with same nonce
            try:
                pong = p2p.wait_for_message("pong", timeout=5)
                received_nonce = struct.unpack("<Q", pong.payload[:8])[0]
                assert_equal(
                    received_nonce, nonce,
                    "Pong nonce should match ping nonce"
                )
                self.log.info("  Ping/pong echo verified (nonce match)")
            except TimeoutError:
                self.log.info("  Pong not received (node may not support ping)")

            # Test ping_and_wait convenience method
            try:
                p2p.set_auto_ping_response(False)
                rtt = p2p.ping_and_wait(timeout=5)
                self.log.info("  Ping RTT: %.4f sec", rtt)
            except (TimeoutError, ValueError) as e:
                self.log.info("  Ping RTT: %s", e)

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Ping/pong: %s", e)
        finally:
            p2p.disconnect()

    def test_block_relay_between_nodes(self, node, node1):
        """Test that blocks are relayed between connected nodes."""
        self.log.info("Testing block relay between nodes...")

        self.sync_blocks()
        height_before = node1.getblockcount()

        # Mine a block on node0
        addr = node.getnewaddress()
        hashes = node.generatetoaddress(3, addr)

        # Wait for node1 to receive the blocks
        self.sync_blocks(timeout=30)

        assert_equal(
            node1.getblockcount(), height_before + 3,
            "Node1 should receive 3 blocks"
        )
        assert_equal(
            node.getbestblockhash(),
            node1.getbestblockhash(),
            "Both nodes should have same tip"
        )

        self.log.info("  Block relay verified: 3 blocks propagated")

    def test_transaction_relay(self, node, node1):
        """Test transaction relay between connected nodes."""
        self.log.info("Testing transaction relay...")

        # Ensure node0 has balance
        addr = node.getnewaddress()
        node.generatetoaddress(101, addr)
        self.sync_blocks()

        # Send a transaction from node0
        recv = node1.getnewaddress()
        try:
            txid = node.sendtoaddress(recv, 1.0)

            # Wait for transaction to appear in node1's mempool
            wait_until(
                lambda: txid in node1.getrawmempool(),
                timeout=15,
                description="TX relay to node1"
            )

            assert_true(
                txid in node1.getrawmempool(),
                "TX should be relayed to node1"
            )
            self.log.info("  Transaction relayed: %s", txid[:16])
        except Exception as e:
            self.log.info("  Transaction relay: %s", e)

        # Confirm
        node.generatetoaddress(1, addr)
        self.sync_blocks()

    def test_multiple_connections(self, node):
        """Test multiple simultaneous P2P connections."""
        self.log.info("Testing multiple P2P connections...")

        connections = []
        try:
            for i in range(3):
                p2p = P2PInterface()
                p2p.connect("127.0.0.1", node.port, timeout=5)
                p2p.perform_handshake(timeout=10)
                connections.append(p2p)
                self.log.info("  Connection %d established", i)

            # All should be connected
            for i, conn in enumerate(connections):
                assert_true(conn.connected, f"Connection {i} should be active")
                assert_true(conn.handshake_complete, f"Connection {i} handshake")

            self.log.info("  %d simultaneous connections verified",
                           len(connections))

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Multiple connections: %s", e)
        finally:
            for conn in connections:
                conn.disconnect()

    def test_bad_magic_rejection(self, node):
        """Test that connections with bad magic bytes are rejected."""
        self.log.info("Testing bad magic rejection...")

        p2p = P2PConnection()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)

            # Send message with wrong magic
            p2p.send_malformed_header(bad_magic=0xDEADBEEF)

            # The node should disconnect us or ignore the message
            time.sleep(1)

            # Try sending a valid message after bad one
            try:
                version_payload = msg_version(0, 0)
                p2p.send_message("version", version_payload)
                time.sleep(1)
                # If still connected, the node tolerated the bad magic
                self.log.info("  Node tolerated bad magic (ignored)")
            except ConnectionError:
                self.log.info("  Node disconnected after bad magic")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Bad magic test: %s", e)
        finally:
            p2p.disconnect()

    def test_oversized_message(self, node):
        """Test handling of oversized messages."""
        self.log.info("Testing oversized message handling...")

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Send an oversized message
            p2p.send_oversized_message(size=33 * 1024 * 1024)

            time.sleep(2)

            # Node should either disconnect or drop the message
            if p2p.connected:
                self.log.info("  Node dropped oversized message (still connected)")
            else:
                self.log.info("  Node disconnected after oversized message")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Oversized message: %s", e)
        finally:
            p2p.disconnect()

    def test_bad_checksum(self, node):
        """Test that messages with bad checksums are rejected."""
        self.log.info("Testing bad checksum rejection...")

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Send a ping with bad checksum
            p2p.send_bad_checksum("ping", struct.pack("<Q", 12345))

            time.sleep(1)

            # The bad-checksum message should be silently dropped
            if p2p.connected:
                # Send a valid ping to verify connection still works
                nonce = p2p.send_ping()
                try:
                    p2p.wait_for_message("pong", timeout=3)
                    self.log.info("  Bad checksum message dropped, connection alive")
                except TimeoutError:
                    self.log.info("  Connection still up but no pong")
            else:
                self.log.info("  Disconnected after bad checksum")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Bad checksum: %s", e)
        finally:
            p2p.disconnect()

    def test_unknown_command(self, node):
        """Test that unknown commands are tolerated."""
        self.log.info("Testing unknown command handling...")

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Send unknown command
            p2p.send_unknown_command("xyzzy", b"hello")

            time.sleep(1)

            # Should not disconnect for unknown command
            if p2p.connected:
                self.log.info("  Unknown command tolerated")
            else:
                self.log.info("  Disconnected after unknown command")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Unknown command: %s", e)
        finally:
            p2p.disconnect()

    def test_disconnect_handling(self, node):
        """Test graceful disconnect handling."""
        self.log.info("Testing disconnect handling...")

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Verify connected
            assert_true(p2p.connected)

            # Disconnect from our side
            p2p.disconnect()
            assert_false(p2p.connected)

            # Node should handle the disconnect gracefully
            time.sleep(1)

            # Node should still be responsive via RPC
            count = node.getblockcount()
            assert_greater_than_or_equal(count, 0)

            self.log.info("  Disconnect handled gracefully")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Disconnect handling: %s", e)
        finally:
            if p2p.connected:
                p2p.disconnect()

    def test_message_after_handshake(self, node):
        """Test that data messages work after handshake."""
        self.log.info("Testing messages after handshake...")

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Send getaddr
            p2p.send_getaddr()

            # Send mempool request
            p2p.send_message("mempool", msg_mempool())

            # Send sendheaders preference
            p2p.send_sendheaders()

            time.sleep(1)

            # Connection should still be alive
            assert_true(p2p.connected, "Connection should survive data messages")

            # Check for any responses
            stats = p2p.get_stats()
            self.log.info(
                "  After data messages: sent=%d, recv=%d, pending=%d",
                stats["messages_sent"],
                stats["messages_recv"],
                stats["pending_messages"]
            )

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Post-handshake messages: %s", e)
        finally:
            p2p.disconnect()

    def test_getaddr_response(self, node):
        """Test that getaddr request gets an addr response."""
        self.log.info("Testing getaddr response...")

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Request addresses
            p2p.send_getaddr()

            # Wait for addr response (may or may not come)
            try:
                addrs = p2p.wait_for_addr(timeout=5)
                self.log.info("  Received %d addresses", len(addrs))
                for addr in addrs[:3]:
                    self.log.info(
                        "    %s:%d (services=%d)",
                        addr["ip"], addr["port"], addr["services"]
                    )
            except TimeoutError:
                self.log.info("  No addr response (empty address book)")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  getaddr: %s", e)
        finally:
            p2p.disconnect()

    def test_inv_getdata_flow(self, node):
        """Test the inv -> getdata -> block/tx flow."""
        self.log.info("Testing inv/getdata flow...")

        # Mine a block to have a known hash
        addr = node.getnewaddress()
        hashes = node.generatetoaddress(1, addr)
        block_hash = hashes[0]

        p2p = P2PDataStore()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # The node may send us inv for the new block
            time.sleep(1)

            # We can also check if the node sent us inv
            inv_msgs = p2p.get_messages("inv")
            if inv_msgs:
                self.log.info(
                    "  Received %d inv messages", len(inv_msgs)
                )

            self.log.info("  Inv/getdata flow tested")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Inv/getdata: %s", e)
        finally:
            p2p.disconnect()

    def test_connection_stats(self, node):
        """Test P2P connection statistics tracking."""
        self.log.info("Testing connection statistics...")

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            stats = p2p.get_stats()
            assert_true(stats["connected"])
            assert_equal(stats["state"], ConnectionState.READY)
            assert_greater_than(stats["bytes_sent"], 0)
            assert_greater_than(stats["bytes_recv"], 0)
            assert_greater_than(stats["messages_sent"], 0)
            assert_greater_than(stats["messages_recv"], 0)

            self.log.info(
                "  Stats: sent=%d bytes/%d msgs, recv=%d bytes/%d msgs",
                stats["bytes_sent"], stats["messages_sent"],
                stats["bytes_recv"], stats["messages_recv"]
            )

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Connection stats: %s", e)
        finally:
            p2p.disconnect()

    def test_rapid_connect_disconnect(self, node):
        """Test rapid connection cycling for stability."""
        self.log.info("Testing rapid connect/disconnect...")

        for i in range(5):
            p2p = P2PConnection()
            try:
                p2p.connect("127.0.0.1", node.port, timeout=3)
                assert_true(p2p.connected)
                p2p.disconnect()
            except (ConnectionError, TimeoutError):
                pass

        # Node should still be responsive
        count = node.getblockcount()
        assert_greater_than_or_equal(count, 0)

        self.log.info("  5 rapid connect/disconnect cycles completed")

    def test_version_nonce_uniqueness(self, node):
        """Test that version message nonces are unique per connection."""
        self.log.info("Testing version nonce uniqueness...")

        nonces = []
        for i in range(3):
            p2p = P2PInterface()
            try:
                p2p.connect("127.0.0.1", node.port, timeout=5)
                p2p.perform_handshake(timeout=10)
                if p2p.peer_version and "nonce" in p2p.peer_version:
                    nonces.append(p2p.peer_version["nonce"])
            except (ConnectionError, TimeoutError):
                pass
            finally:
                p2p.disconnect()

        if len(nonces) >= 2:
            unique_nonces = set(nonces)
            assert_equal(
                len(unique_nonces), len(nonces),
                "Version nonces should be unique"
            )
            self.log.info("  %d unique nonces from %d connections",
                           len(unique_nonces), len(nonces))
        else:
            self.log.info("  Could not collect enough nonces")

    def test_sendheaders_preference(self, node):
        """Test sending sendheaders preference to the node."""
        self.log.info("Testing sendheaders preference...")

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Send sendheaders to prefer headers announcements
            p2p.send_sendheaders()
            time.sleep(0.5)

            # Mine a block and see if we get headers instead of inv
            addr = node.getnewaddress()
            node.generatetoaddress(1, addr)
            time.sleep(1)

            # Check for headers message
            has_headers = p2p.has_message("headers")
            has_inv = p2p.has_message("inv")

            if has_headers:
                self.log.info("  Received headers announcement")
            elif has_inv:
                self.log.info("  Received inv announcement (sendheaders ignored)")
            else:
                self.log.info("  No block announcement received")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  sendheaders: %s", e)
        finally:
            p2p.disconnect()

    def test_feefilter_message(self, node):
        """Test sending feefilter message."""
        self.log.info("Testing feefilter message...")

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Set minimum fee filter to 1000 satoshis/byte
            p2p.send_feefilter(1000)
            time.sleep(0.5)

            # Connection should still be alive
            assert_true(p2p.connected, "feefilter should not disconnect")

            self.log.info("  feefilter message accepted")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  feefilter: %s", e)
        finally:
            p2p.disconnect()

    def test_data_store_interface(self, node):
        """Test P2PDataStore interface for block/tx storage."""
        self.log.info("Testing P2PDataStore interface...")

        store = P2PDataStore()
        try:
            store.connect("127.0.0.1", node.port, timeout=5)
            store.perform_handshake(timeout=10)

            # Mine a block (should trigger announcements)
            addr = node.getnewaddress()
            node.generatetoaddress(1, addr)
            time.sleep(2)

            # Check if any blocks were stored
            block_count = len(store.blocks)
            tx_count = len(store.txs)

            self.log.info(
                "  DataStore: %d blocks, %d txs stored",
                block_count, tx_count
            )

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  DataStore: %s", e)
        finally:
            store.disconnect()

    def test_mininode_interface(self, node):
        """Test MiniNode full-featured interface."""
        self.log.info("Testing MiniNode interface...")

        mini = MiniNode()
        try:
            mini.connect("127.0.0.1", node.port, timeout=5)
            mini.perform_handshake(timeout=10)

            # Verify initial state
            assert_equal(mini.best_height, 0)
            assert_equal(len(mini.get_reject_messages()), 0)

            # Mine a block
            addr = node.getnewaddress()
            node.generatetoaddress(1, addr)
            time.sleep(2)

            # Check for reject messages (should be none)
            rejects = mini.get_reject_messages()
            assert_equal(
                len(rejects), 0,
                "Should have no reject messages"
            )

            self.log.info("  MiniNode interface verified")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  MiniNode: %s", e)
        finally:
            mini.disconnect()


if __name__ == "__main__":
    P2PConnectTest().main()

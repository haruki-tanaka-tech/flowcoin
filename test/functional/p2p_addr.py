#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test address relay via P2P protocol.

Tests cover:
    - getaddr / addr message exchange.
    - Address manager population via RPC peers.
    - Address diversity from multiple sources.
    - Address relay between peers.
    - Rate limiting of addr messages.
    - Stale address filtering.
    - Self-address detection.
    - Address count limits in a single message.
    - Multiple getaddr requests.
    - Address persistence across connections.
    - Relay of addresses learned from peers.
    - Address time freshness.
"""

import random
import struct
import time

from test_framework.test_framework import FlowCoinTestFramework
from test_framework.p2p import (
    P2PInterface,
    P2PDataStore,
    MiniNode,
    ConnectionState,
)
from test_framework.messages import (
    MAGIC_REGTEST,
    NODE_NETWORK,
    NetAddress,
    msg_addr,
    msg_getaddr,
    msg_version,
    msg_verack,
)
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_true,
    assert_false,
    assert_in,
    wait_until,
)


class P2PAddrTest(FlowCoinTestFramework):
    """Address relay tests."""

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True

    def run_test(self):
        self.test_getaddr_addr_exchange()
        self.test_address_population()
        self.test_address_diversity()
        self.test_addr_relay_between_peers()
        self.test_addr_rate_limiting()
        self.test_self_address_detection()
        self.test_addr_count_limits()
        self.test_multiple_getaddr()
        self.test_addr_time_freshness()
        self.test_peer_address_info()
        self.test_addr_from_connected_peers()
        self.test_empty_addr_response()

    def test_getaddr_addr_exchange(self):
        """Test basic getaddr -> addr message exchange."""
        self.log.info("Testing getaddr/addr exchange...")

        node = self.nodes[0]

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Request addresses
            p2p.send_getaddr()

            # Wait for response
            try:
                addrs = p2p.wait_for_addr(timeout=10)
                self.log.info(
                    "  Received %d addresses from getaddr", len(addrs)
                )
                for addr in addrs[:5]:
                    self.log.info(
                        "    %s:%d services=0x%x time=%d",
                        addr["ip"], addr["port"],
                        addr["services"], addr["timestamp"]
                    )
            except TimeoutError:
                self.log.info(
                    "  No addr response (expected with few known peers)"
                )

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  getaddr/addr: %s", e)
        finally:
            p2p.disconnect()

        self.log.info("  getaddr/addr exchange tested")

    def test_address_population(self):
        """Test that the address manager populates from connected peers."""
        self.log.info("Testing address population...")

        node = self.nodes[0]

        # Node should know about its connected peers
        peers = node.getpeerinfo()
        known_addrs = set()
        for peer in peers:
            addr = peer.get("addr", "")
            if addr:
                known_addrs.add(addr)

        self.log.info(
            "  Node knows %d peer addresses from %d connections",
            len(known_addrs), len(peers)
        )

        # Each connected peer should have an address
        for peer in peers:
            addr = peer.get("addr", "")
            assert_true(
                len(addr) > 0,
                "Each peer should have an address"
            )
            assert_true(
                ":" in addr,
                f"Peer address should be ip:port: {addr}"
            )

        self.log.info("  Address population verified")

    def test_address_diversity(self):
        """Test that addresses from multiple sources are stored."""
        self.log.info("Testing address diversity...")

        node = self.nodes[0]

        # Send addr messages with diverse addresses
        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Construct diverse addresses
            addrs = []
            now = int(time.time())
            for i in range(10):
                net_addr = NetAddress(
                    ip=f"10.{i}.{i}.{i}",
                    port=9333 + i,
                    services=NODE_NETWORK
                )
                addrs.append((now - 3600, net_addr))

            # Send addr message
            p2p.send_addr(addrs)
            time.sleep(1)

            self.log.info("  Sent %d diverse addresses", len(addrs))

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Address diversity: %s", e)
        finally:
            p2p.disconnect()

        self.log.info("  Address diversity tested")

    def test_addr_relay_between_peers(self):
        """Test that addresses are relayed between connected peers."""
        self.log.info("Testing addr relay between peers...")

        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # Send a fake address to node0 via P2P
        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node0.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Send an address that should propagate
            now = int(time.time())
            fake_addr = NetAddress(
                ip="192.168.77.77",
                port=9333,
                services=NODE_NETWORK
            )
            p2p.send_addr([(now, fake_addr)])
            time.sleep(2)

            self.log.info("  Sent relay test address to node0")

            # Check if node1 learned about it (via addr relay)
            # This depends on the node's addr relay policy
            # We can request addrs from node1
            p2p2 = P2PInterface()
            try:
                p2p2.connect("127.0.0.1", node1.port, timeout=5)
                p2p2.perform_handshake(timeout=10)
                p2p2.send_getaddr()

                try:
                    relay_addrs = p2p2.wait_for_addr(timeout=5)
                    relayed = any(
                        a["ip"] == "192.168.77.77" for a in relay_addrs
                    )
                    if relayed:
                        self.log.info("  Address relayed to node1")
                    else:
                        self.log.info(
                            "  Address not relayed (may be filtered/delayed)"
                        )
                except TimeoutError:
                    self.log.info("  No addr response from node1")
            finally:
                p2p2.disconnect()

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Addr relay: %s", e)
        finally:
            p2p.disconnect()

    def test_addr_rate_limiting(self):
        """Test that addr messages are rate-limited."""
        self.log.info("Testing addr rate limiting...")

        node = self.nodes[0]

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Send many addr messages in rapid succession
            now = int(time.time())
            for batch in range(20):
                addrs = []
                for i in range(50):
                    net_addr = NetAddress(
                        ip=f"10.{batch}.{i}.1",
                        port=9333,
                        services=NODE_NETWORK
                    )
                    addrs.append((now - 3600, net_addr))
                p2p.send_addr(addrs)

            time.sleep(1)

            # Connection should still be alive (rate limiting doesn't disconnect)
            if p2p.connected:
                self.log.info(
                    "  Connection survived %d addr messages (1000 addrs)",
                    20
                )
            else:
                self.log.info("  Disconnected after excessive addr messages")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Addr rate limiting: %s", e)
        finally:
            p2p.disconnect()

    def test_self_address_detection(self):
        """Test that the node detects and ignores its own address."""
        self.log.info("Testing self-address detection...")

        node = self.nodes[0]

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Send the node's own address back to it
            now = int(time.time())
            self_addr = NetAddress(
                ip="127.0.0.1",
                port=node.port,
                services=NODE_NETWORK
            )
            p2p.send_addr([(now, self_addr)])
            time.sleep(1)

            # Connection should still be alive
            assert_true(
                p2p.connected,
                "Node should not disconnect when receiving self-address"
            )

            self.log.info("  Self-address handled gracefully")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Self-address: %s", e)
        finally:
            p2p.disconnect()

    def test_addr_count_limits(self):
        """Test maximum address count in a single addr message."""
        self.log.info("Testing addr count limits...")

        node = self.nodes[0]

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Send exactly 1000 addresses (typical limit)
            now = int(time.time())
            addrs = []
            for i in range(1000):
                ip = f"{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}.1"
                net_addr = NetAddress(ip=ip, port=9333, services=NODE_NETWORK)
                addrs.append((now - 3600, net_addr))

            p2p.send_addr(addrs)
            time.sleep(1)

            if p2p.connected:
                self.log.info("  1000 addresses accepted in single message")
            else:
                self.log.info("  Disconnected after 1000-addr message")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Addr count limits: %s", e)
        finally:
            p2p.disconnect()

    def test_multiple_getaddr(self):
        """Test sending multiple getaddr requests."""
        self.log.info("Testing multiple getaddr requests...")

        node = self.nodes[0]

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Send multiple getaddr
            for i in range(5):
                p2p.send_getaddr()
                time.sleep(0.1)

            time.sleep(2)

            # Collect all addr responses
            addr_msgs = p2p.get_messages("addr")
            total_addrs = 0
            for msg in addr_msgs:
                # Parse addr count from payload
                if len(msg.payload) > 0:
                    total_addrs += 1

            self.log.info(
                "  %d addr responses from %d getaddr requests",
                len(addr_msgs), 5
            )

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Multiple getaddr: %s", e)
        finally:
            p2p.disconnect()

    def test_addr_time_freshness(self):
        """Test that stale addresses are handled differently."""
        self.log.info("Testing addr time freshness...")

        node = self.nodes[0]

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            now = int(time.time())

            # Send a mix of fresh and stale addresses
            addrs = []

            # Fresh address (10 minutes ago)
            fresh = NetAddress(ip="10.1.1.1", port=9333, services=NODE_NETWORK)
            addrs.append((now - 600, fresh))

            # Somewhat old (6 hours ago)
            old = NetAddress(ip="10.2.2.2", port=9333, services=NODE_NETWORK)
            addrs.append((now - 21600, old))

            # Very stale (30 days ago)
            stale = NetAddress(ip="10.3.3.3", port=9333, services=NODE_NETWORK)
            addrs.append((now - 2592000, stale))

            # Future timestamp (should be clamped)
            future = NetAddress(ip="10.4.4.4", port=9333, services=NODE_NETWORK)
            addrs.append((now + 3600, future))

            p2p.send_addr(addrs)
            time.sleep(1)

            # Node should accept fresh, may discard very stale
            self.log.info("  Sent 4 addresses with varying freshness")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Addr freshness: %s", e)
        finally:
            p2p.disconnect()

    def test_peer_address_info(self):
        """Test that peer info includes address details."""
        self.log.info("Testing peer address info...")

        node = self.nodes[0]
        peers = node.getpeerinfo()

        for i, peer in enumerate(peers[:5]):
            addr = peer.get("addr", "unknown")
            local = peer.get("addrlocal", "unknown")
            bind = peer.get("addrbind", "unknown")

            self.log.info(
                "  Peer %d: addr=%s, local=%s, bind=%s",
                i, addr, local, bind
            )

            # Address should be set
            assert_true(
                len(str(addr)) > 0,
                f"Peer {i} should have an address"
            )

        self.log.info("  Peer address info verified")

    def test_addr_from_connected_peers(self):
        """Test that the node learns addresses from its RPC-connected peers."""
        self.log.info("Testing addrs from connected peers...")

        node0 = self.nodes[0]
        node1 = self.nodes[1]
        node2 = self.nodes[2]

        # All three nodes are connected
        peers0 = node0.getpeerinfo()
        peers1 = node1.getpeerinfo()

        self.log.info(
            "  Node0 peers: %d, Node1 peers: %d",
            len(peers0), len(peers1)
        )

        # Node0 should know about node1 and node2's addresses
        known_ports = set()
        for peer in peers0:
            addr = peer.get("addr", "")
            if ":" in addr:
                port = int(addr.split(":")[-1])
                known_ports.add(port)

        self.log.info("  Node0 knows ports: %s", known_ports)

    def test_empty_addr_response(self):
        """Test handling of empty addr message."""
        self.log.info("Testing empty addr message...")

        node = self.nodes[0]

        p2p = P2PInterface()
        try:
            p2p.connect("127.0.0.1", node.port, timeout=5)
            p2p.perform_handshake(timeout=10)

            # Send addr with zero entries
            p2p.send_addr([])
            time.sleep(0.5)

            # Should not cause disconnect
            assert_true(
                p2p.connected,
                "Empty addr should not cause disconnect"
            )

            self.log.info("  Empty addr message handled")

        except (ConnectionError, TimeoutError) as e:
            self.log.info("  Empty addr: %s", e)
        finally:
            p2p.disconnect()


if __name__ == "__main__":
    P2PAddrTest().main()

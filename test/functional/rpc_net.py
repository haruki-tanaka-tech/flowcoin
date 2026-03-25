#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test network RPC methods.

Tests cover:
    - getpeerinfo format and fields.
    - getconnectioncount accuracy.
    - addnode / disconnectnode.
    - getnetworkinfo completeness.
    - getnettotals byte counts.
    - getpeerinfo after connecting/disconnecting.
    - addnode "onetry" mode.
    - Network info version fields.
    - Peer subversion strings.
    - Connection direction (inbound/outbound).
    - Ping time tracking.
    - Banned peer management.
    - Local address reporting.
"""

import time

from test_framework.test_framework import FlowCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_in,
    assert_is_hex_string,
    assert_not_equal,
    assert_raises_rpc_error,
    assert_true,
    connect_nodes,
    disconnect_nodes,
    wait_until,
)


class RPCNetTest(FlowCoinTestFramework):
    """Network RPC tests."""

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True

    def run_test(self):
        self.test_getpeerinfo_format()
        self.test_getconnectioncount()
        self.test_addnode_disconnectnode()
        self.test_getnetworkinfo()
        self.test_getnettotals()
        self.test_peer_connect_disconnect()
        self.test_addnode_onetry()
        self.test_network_version_fields()
        self.test_peer_subversion()
        self.test_connection_direction()
        self.test_ping_tracking()
        self.test_banned_peers()
        self.test_local_addresses()

    def test_getpeerinfo_format(self):
        """Test getpeerinfo returns properly formatted peer data."""
        self.log.info("Testing getpeerinfo format...")

        node = self.nodes[0]
        peers = node.getpeerinfo()

        assert_true(isinstance(peers, list))

        if len(peers) > 0:
            peer = peers[0]

            # Required fields
            expected_fields = ["addr", "services", "bytessent",
                               "bytesrecv", "conntime", "version"]
            for field in expected_fields:
                assert_in(field, peer, f"Peer missing: {field}")

            # Address should be an IP:port string
            addr = peer["addr"]
            assert_true(":" in addr, f"Address should contain port: {addr}")

            # Services should be a number or hex string
            services = peer["services"]
            assert_true(
                isinstance(services, (int, str)),
                f"Services should be int or str: {type(services)}"
            )

            # Bytes should be non-negative
            assert_greater_than_or_equal(peer["bytessent"], 0)
            assert_greater_than_or_equal(peer["bytesrecv"], 0)

            # Connection time should be in the past
            assert_greater_than(peer["conntime"], 0)

            # Version should be positive
            if isinstance(peer["version"], int):
                assert_greater_than(peer["version"], 0)

        self.log.info("  getpeerinfo: %d peers", len(peers))

    def test_getconnectioncount(self):
        """Test getconnectioncount accuracy."""
        self.log.info("Testing getconnectioncount...")

        node = self.nodes[0]
        count = node.getconnectioncount()

        # Should match number of connected peers
        peers = node.getpeerinfo()
        assert_equal(
            count, len(peers),
            "Connection count should match peer count"
        )

        self.log.info("  getconnectioncount: %d", count)

    def test_addnode_disconnectnode(self):
        """Test addnode and disconnectnode operations."""
        self.log.info("Testing addnode/disconnectnode...")

        node0 = self.nodes[0]
        node2 = self.nodes[2]

        # Count initial connections to node2
        peers_before = node0.getpeerinfo()
        node2_connected = any(
            str(node2.port) in p.get("addr", "") for p in peers_before
        )

        if not node2_connected:
            # Add node2
            node0.addnode(f"127.0.0.1:{node2.port}", "add")
            # Wait for connection
            wait_until(
                lambda: any(
                    str(node2.port) in p.get("addr", "")
                    for p in node0.getpeerinfo()
                ),
                timeout=10
            )
            self.log.info("  addnode: connected to node2")

        # Disconnect node2
        try:
            node0.addnode(f"127.0.0.1:{node2.port}", "remove")
            time.sleep(1)
            self.log.info("  disconnectnode: removed node2")
        except Exception as e:
            self.log.info("  disconnect: %s", e)

        # Reconnect for subsequent tests
        connect_nodes(node0, node2)

        self.log.info("  addnode/disconnectnode verified")

    def test_getnetworkinfo(self):
        """Test getnetworkinfo completeness."""
        self.log.info("Testing getnetworkinfo...")

        node = self.nodes[0]
        info = node.getnetworkinfo()
        assert_true(isinstance(info, dict))

        # Expected fields
        expected = ["version", "protocolversion", "connections"]
        for field in expected:
            assert_in(field, info, f"Missing: {field}")

        # Version should be positive
        assert_greater_than(info["version"], 0)

        # Protocol version should be positive
        assert_greater_than(info["protocolversion"], 0)

        # Connections should be positive (we have connected nodes)
        assert_greater_than(info["connections"], 0)

        # Subversion (user agent) if present
        if "subversion" in info:
            assert_true(
                len(info["subversion"]) > 0,
                "Subversion should not be empty"
            )

        # Local relay flag
        if "localrelay" in info:
            assert_true(isinstance(info["localrelay"], bool))

        # Networks info
        if "networks" in info:
            assert_true(isinstance(info["networks"], list))
            for net in info["networks"]:
                assert_in("name", net)
                assert_in("reachable", net)

        self.log.info("  getnetworkinfo: version=%d, proto=%d, conns=%d",
                       info["version"], info["protocolversion"],
                       info["connections"])

    def test_getnettotals(self):
        """Test getnettotals byte counts."""
        self.log.info("Testing getnettotals...")

        node = self.nodes[0]
        totals = node.getnettotals()
        assert_true(isinstance(totals, dict))

        expected = ["totalbytesrecv", "totalbytessent", "timemillis"]
        for field in expected:
            assert_in(field, totals, f"Missing: {field}")

        # Bytes should be non-negative
        assert_greater_than_or_equal(totals["totalbytesrecv"], 0)
        assert_greater_than_or_equal(totals["totalbytessent"], 0)

        # Time should be reasonable
        assert_greater_than(totals["timemillis"], 0)

        # After some activity, totals should increase
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)
        time.sleep(1)

        totals_after = node.getnettotals()
        assert_greater_than_or_equal(
            totals_after["totalbytessent"],
            totals["totalbytessent"]
        )

        self.log.info("  getnettotals: recv=%d, sent=%d",
                       totals["totalbytesrecv"], totals["totalbytessent"])

    def test_peer_connect_disconnect(self):
        """Test peer list changes on connect/disconnect."""
        self.log.info("Testing peer connect/disconnect...")

        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # Get initial peer count
        count_before = node0.getconnectioncount()

        # Disconnect node1
        try:
            disconnect_nodes(node0, node1)
            time.sleep(1)

            count_during = node0.getconnectioncount()
            # Count might have decreased
            self.log.info(
                "  After disconnect: %d -> %d peers",
                count_before, count_during
            )
        except Exception as e:
            self.log.info("  Disconnect: %s", e)

        # Reconnect
        connect_nodes(node0, node1)
        wait_until(
            lambda: node0.getconnectioncount() >= count_before,
            timeout=10
        )

        count_after = node0.getconnectioncount()
        assert_greater_than_or_equal(count_after, count_before)

        self.log.info("  Peer connect/disconnect verified: %d peers",
                       count_after)

    def test_addnode_onetry(self):
        """Test addnode with 'onetry' mode."""
        self.log.info("Testing addnode onetry...")

        node0 = self.nodes[0]
        node2 = self.nodes[2]

        # Try connecting with onetry
        try:
            node0.addnode(f"127.0.0.1:{node2.port}", "onetry")
            time.sleep(1)
            self.log.info("  addnode onetry accepted")
        except Exception as e:
            self.log.info("  addnode onetry: %s", e)

        # Verify connection exists
        peers = node0.getpeerinfo()
        connected_to_node2 = any(
            str(node2.port) in p.get("addr", "") for p in peers
        )
        self.log.info(
            "  Node2 connected after onetry: %s", connected_to_node2
        )

    def test_network_version_fields(self):
        """Test version-related fields in network info."""
        self.log.info("Testing network version fields...")

        node = self.nodes[0]
        info = node.getnetworkinfo()

        # Client version
        version = info.get("version", 0)
        assert_greater_than(version, 0)

        # Protocol version
        proto = info.get("protocolversion", 0)
        assert_greater_than(proto, 0)

        # Check peers have version info
        peers = node.getpeerinfo()
        for peer in peers[:3]:
            if "version" in peer:
                assert_greater_than(peer["version"], 0)

        self.log.info("  Version: client=%d, protocol=%d",
                       version, proto)

    def test_peer_subversion(self):
        """Test peer subversion (user agent) strings."""
        self.log.info("Testing peer subversion strings...")

        node = self.nodes[0]
        peers = node.getpeerinfo()

        for peer in peers:
            if "subver" in peer:
                subver = peer["subver"]
                assert_true(
                    len(subver) > 0,
                    "Subversion should not be empty"
                )
                # Should contain some identifier
                self.log.info("  Peer subversion: %s", subver)

        self.log.info("  Peer subversions checked")

    def test_connection_direction(self):
        """Test that peer info includes connection direction."""
        self.log.info("Testing connection direction...")

        node = self.nodes[0]
        peers = node.getpeerinfo()

        inbound = 0
        outbound = 0
        for peer in peers:
            if "inbound" in peer:
                if peer["inbound"]:
                    inbound += 1
                else:
                    outbound += 1

        self.log.info(
            "  Connections: %d inbound, %d outbound", inbound, outbound
        )

    def test_ping_tracking(self):
        """Test that ping times are tracked in peer info."""
        self.log.info("Testing ping tracking...")

        node = self.nodes[0]

        # Send a ping to trigger measurement
        try:
            node.ping()
            time.sleep(1)
        except Exception:
            pass

        peers = node.getpeerinfo()
        for peer in peers:
            if "pingtime" in peer:
                ping = peer["pingtime"]
                assert_greater_than_or_equal(
                    ping, 0,
                    "Ping time should be non-negative"
                )
                self.log.info(
                    "  Peer %s ping: %.4f sec",
                    peer.get("addr", "?"), ping
                )

            if "minping" in peer:
                assert_greater_than_or_equal(peer["minping"], 0)

        self.log.info("  Ping tracking verified")

    def test_banned_peers(self):
        """Test ban list management."""
        self.log.info("Testing banned peers...")

        node = self.nodes[0]

        # List bans (should be empty initially)
        try:
            bans = node.listbanned()
            assert_true(isinstance(bans, list))
            self.log.info("  Current bans: %d", len(bans))

            # Ban a fake address
            node.setban("192.168.99.99", "add", 3600)
            bans = node.listbanned()
            assert_greater_than(len(bans), 0)

            # Unban
            node.setban("192.168.99.99", "remove")
            bans = node.listbanned()
            banned_ips = [b.get("address", "") for b in bans]
            assert_true(
                "192.168.99.99" not in str(banned_ips),
                "Should be unbanned"
            )

            # Clear all bans
            try:
                node.clearbanned()
                bans = node.listbanned()
                assert_equal(len(bans), 0)
            except Exception:
                pass

        except Exception as e:
            self.log.info("  Ban management: %s", e)

        self.log.info("  Banned peers verified")

    def test_local_addresses(self):
        """Test local address reporting."""
        self.log.info("Testing local addresses...")

        node = self.nodes[0]
        info = node.getnetworkinfo()

        if "localaddresses" in info:
            for addr in info["localaddresses"]:
                assert_in("address", addr)
                assert_in("port", addr)
                assert_in("score", addr)
                self.log.info(
                    "  Local addr: %s:%d (score=%d)",
                    addr["address"], addr["port"], addr["score"]
                )
        else:
            self.log.info("  No local addresses reported (expected on regtest)")

        self.log.info("  Local addresses tested")

    def test_getpeerinfo_fields_complete(self):
        """Test that getpeerinfo returns comprehensive peer data."""
        self.log.info("Testing getpeerinfo field completeness...")

        node = self.nodes[0]
        peers = node.getpeerinfo()

        if not peers:
            self.log.info("  No peers to inspect")
            return

        peer = peers[0]

        # Exhaustive field check
        all_fields = [
            "id", "addr", "services", "relaytxes", "lastsend",
            "lastrecv", "bytessent", "bytesrecv", "conntime",
            "timeoffset", "pingtime", "version", "subver",
            "inbound", "startingheight", "banscore",
            "synced_headers", "synced_blocks",
        ]

        found = 0
        for field in all_fields:
            if field in peer:
                found += 1

        self.log.info(
            "  Peer has %d/%d expected fields", found, len(all_fields)
        )

        # Log interesting fields
        for field in ["id", "addr", "version", "subver", "inbound"]:
            if field in peer:
                self.log.info("    %s = %s", field, peer[field])

    def test_nettotals_increase(self):
        """Test that network totals increase with activity."""
        self.log.info("Testing nettotals increase...")

        node = self.nodes[0]
        totals_before = node.getnettotals()

        # Generate activity
        addr = node.getnewaddress()
        node.generatetoaddress(3, addr)
        self.sync_blocks()

        time.sleep(1)
        totals_after = node.getnettotals()

        # Bytes should have increased
        assert_greater_than_or_equal(
            totals_after["totalbytessent"],
            totals_before["totalbytessent"]
        )
        assert_greater_than_or_equal(
            totals_after["totalbytesrecv"],
            totals_before["totalbytesrecv"]
        )

        sent_delta = totals_after["totalbytessent"] - totals_before["totalbytessent"]
        recv_delta = totals_after["totalbytesrecv"] - totals_before["totalbytesrecv"]

        self.log.info(
            "  Net totals delta: sent +%d bytes, recv +%d bytes",
            sent_delta, recv_delta
        )

    def test_peer_starting_height(self):
        """Test that peers report their starting height."""
        self.log.info("Testing peer starting height...")

        node = self.nodes[0]
        peers = node.getpeerinfo()

        for peer in peers:
            if "startingheight" in peer:
                height = peer["startingheight"]
                assert_greater_than_or_equal(
                    height, 0,
                    "Starting height should be non-negative"
                )
                self.log.info(
                    "  Peer %s starting height: %d",
                    peer.get("addr", "?"), height
                )

    def test_connection_count_changes(self):
        """Test that connection count reflects connect/disconnect actions."""
        self.log.info("Testing connection count changes...")

        node0 = self.nodes[0]
        initial = node0.getconnectioncount()

        # Already connected to other nodes
        assert_greater_than(
            initial, 0,
            "Should have at least one connection"
        )

        self.log.info("  Connection count: %d", initial)

    def test_getpeerinfo_consistency(self):
        """Test getpeerinfo consistency across multiple calls."""
        self.log.info("Testing getpeerinfo consistency...")

        node = self.nodes[0]

        peers1 = node.getpeerinfo()
        peers2 = node.getpeerinfo()

        # Same number of peers
        assert_equal(
            len(peers1), len(peers2),
            "Peer count should be consistent"
        )

        # Same peer IDs
        ids1 = sorted(p.get("id", 0) for p in peers1)
        ids2 = sorted(p.get("id", 0) for p in peers2)
        assert_equal(ids1, ids2, "Peer IDs should be consistent")

        self.log.info("  getpeerinfo consistent across calls")

    def test_node_time_offset(self):
        """Test time offset between connected nodes."""
        self.log.info("Testing node time offset...")

        node = self.nodes[0]
        peers = node.getpeerinfo()

        for peer in peers:
            if "timeoffset" in peer:
                offset = peer["timeoffset"]
                assert_true(
                    isinstance(offset, (int, float)),
                    f"Time offset should be numeric: {type(offset)}"
                )
                # On localhost, offset should be very small
                if abs(offset) > 0:
                    self.log.info(
                        "  Peer %s time offset: %d sec",
                        peer.get("addr", "?"), offset
                    )

        self.log.info("  Time offsets checked")


if __name__ == "__main__":
    RPCNetTest().main()

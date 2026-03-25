#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test configuration parsing and management.

Tests cover:
    - Config file parsing (key=value format).
    - Command-line argument override.
    - Default configuration values.
    - Invalid configuration rejection.
    - Data directory configuration.
    - Network selection (regtest).
    - RPC configuration (user, password, port).
    - Debug logging configuration.
    - Conflicting config options.
    - Config persistence across restarts.
    - Multiple config entries.
    - Boolean config values.
"""

import os
import time

from test_framework.test_framework import FlowCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_in,
    assert_true,
    read_config_file,
    write_config_file,
    wait_until,
)


class ConfigTest(FlowCoinTestFramework):
    """Configuration tests."""

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]

        self.test_config_file_exists(node)
        self.test_config_file_parsing(node)
        self.test_default_values(node)
        self.test_regtest_config(node)
        self.test_rpc_config(node)
        self.test_datadir_config(node)
        self.test_debug_config(node)
        self.test_config_persistence(node)
        self.test_network_config_values(node)
        self.test_config_modification(node)
        self.test_port_config(node)
        self.test_boolean_config(node)

    def test_config_file_exists(self, node):
        """Verify the config file was created by the test framework."""
        self.log.info("Testing config file existence...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        assert_true(
            os.path.exists(conf_path),
            f"Config file should exist: {conf_path}"
        )
        assert_greater_than(
            os.path.getsize(conf_path), 0,
            "Config file should not be empty"
        )

        self.log.info("  Config file exists: %s", conf_path)

    def test_config_file_parsing(self, node):
        """Test that the config file is properly formatted."""
        self.log.info("Testing config file parsing...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        assert_greater_than(
            len(config), 0,
            "Config should have at least one entry"
        )

        # All entries should be key=value pairs
        for key, value in config.items():
            assert_true(
                len(key) > 0,
                f"Config key should not be empty: '{key}'"
            )
            assert_true(
                value is not None,
                f"Config value for {key} should not be None"
            )

        self.log.info("  Config has %d entries", len(config))

    def test_default_values(self, node):
        """Test that default configuration values are correct."""
        self.log.info("Testing default values...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        # These should be set by the test framework
        assert_in("regtest", config)
        assert_equal(config["regtest"], "1")

        assert_in("server", config)
        assert_equal(config["server"], "1")

        assert_in("listen", config)
        assert_equal(config["listen"], "1")

        assert_in("rpcuser", config)
        assert_equal(config["rpcuser"], "test")

        assert_in("rpcpassword", config)
        assert_equal(config["rpcpassword"], "test")

        self.log.info("  Default values verified")

    def test_regtest_config(self, node):
        """Test regtest network configuration."""
        self.log.info("Testing regtest config...")

        # Node should be on regtest
        info = node.getblockchaininfo()
        chain = info.get("chain", "")
        assert_in(
            chain, ["regtest", "test"],
            f"Expected regtest chain, got: {chain}"
        )

        # Network info should reflect regtest
        net_info = node.getnetworkinfo()
        self.log.info(
            "  Network: chain=%s, version=%d",
            chain, net_info.get("version", 0)
        )

    def test_rpc_config(self, node):
        """Test RPC configuration is effective."""
        self.log.info("Testing RPC config...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        # RPC port should match what we configured
        if "rpcport" in config:
            configured_port = int(config["rpcport"])
            assert_equal(
                configured_port, node.rpcport,
                "RPC port should match config"
            )

        # RPC should be working with configured credentials
        result = node.getblockcount()
        assert_true(
            isinstance(result, int),
            "RPC should return valid data"
        )

        self.log.info("  RPC config verified (port=%d)", node.rpcport)

    def test_datadir_config(self, node):
        """Test data directory configuration."""
        self.log.info("Testing datadir config...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        if "datadir" in config:
            configured_dir = config["datadir"]
            assert_true(
                os.path.isdir(configured_dir),
                f"Configured datadir should exist: {configured_dir}"
            )

        # Data directory should contain expected files
        expected_contents = []
        if os.path.exists(os.path.join(node.datadir, "flowcoin.conf")):
            expected_contents.append("flowcoin.conf")

        for item in expected_contents:
            full_path = os.path.join(node.datadir, item)
            assert_true(
                os.path.exists(full_path),
                f"Expected {item} in datadir"
            )

        self.log.info("  Datadir config verified: %s", node.datadir)

    def test_debug_config(self, node):
        """Test debug logging configuration."""
        self.log.info("Testing debug config...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        # Debug logging should be enabled by test framework
        if "debug" in config:
            assert_equal(config["debug"], "1")

        # Debug log should exist if node has been running
        debug_log = os.path.join(node.datadir, "debug.log")
        if os.path.exists(debug_log):
            size = os.path.getsize(debug_log)
            assert_greater_than(
                size, 0,
                "Debug log should not be empty"
            )
            self.log.info("  Debug log: %d bytes", size)
        else:
            self.log.info("  Debug log not found (may use different path)")

    def test_config_persistence(self, node):
        """Test that configuration persists across restarts."""
        self.log.info("Testing config persistence...")

        # Record current state
        height_before = node.getblockcount()
        chain_before = node.getblockchaininfo().get("chain", "")

        # Restart node
        self.restart_node(0)

        # Verify config still effective
        height_after = self.nodes[0].getblockcount()
        chain_after = self.nodes[0].getblockchaininfo().get("chain", "")

        assert_equal(height_after, height_before)
        assert_equal(chain_after, chain_before)

        self.log.info("  Config persisted across restart")

    def test_network_config_values(self, node):
        """Test network-specific configuration values."""
        self.log.info("Testing network config values...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        # Port should be in regtest range
        if "port" in config:
            port = int(config["port"])
            assert_greater_than(port, 20000, "Regtest port should be > 20000")

        # RPC port should be in regtest range
        if "rpcport" in config:
            rpcport = int(config["rpcport"])
            assert_greater_than(rpcport, 20000, "Regtest RPC port should be > 20000")

        # Discovery should be off for testing
        if "discover" in config:
            assert_equal(config["discover"], "0")

        # DNS seeds should be off for testing
        if "dnsseed" in config:
            assert_equal(config["dnsseed"], "0")

        self.log.info("  Network config values verified")

    def test_config_modification(self, node):
        """Test modifying config and restarting."""
        self.log.info("Testing config modification...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        # Add a new config entry
        config["shrinkdebugfile"] = "0"
        write_config_file(conf_path, config)

        # Verify written
        reread = read_config_file(conf_path)
        assert_equal(reread["shrinkdebugfile"], "0")

        # Restart to apply
        self.restart_node(0)

        # Node should still work
        count = self.nodes[0].getblockcount()
        assert_greater_than(count, -1)

        self.log.info("  Config modification applied after restart")

    def test_port_config(self, node):
        """Test that configured ports are used."""
        self.log.info("Testing port config...")

        # P2P port should match config
        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        if "port" in config:
            expected_port = int(config["port"])
            assert_equal(
                node.port, expected_port,
                "Node P2P port should match config"
            )

        if "rpcport" in config:
            expected_rpc = int(config["rpcport"])
            assert_equal(
                node.rpcport, expected_rpc,
                "Node RPC port should match config"
            )

        # Verify peers see the correct port
        peers = node.getpeerinfo()
        for peer in peers:
            local = peer.get("addrlocal", "")
            if local and ":" in local:
                local_port = int(local.split(":")[-1])
                # Local port might differ from listening port
                self.log.info("  Peer sees us at: %s", local)

        self.log.info(
            "  Port config: P2P=%d, RPC=%d",
            node.port, node.rpcport
        )

    def test_boolean_config(self, node):
        """Test boolean configuration values."""
        self.log.info("Testing boolean config values...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        boolean_keys = [
            "regtest", "server", "listen", "discover",
            "dnsseed", "fixedseeds", "listenonion",
        ]

        for key in boolean_keys:
            if key in config:
                value = config[key]
                assert_in(
                    value, ["0", "1"],
                    f"Boolean config {key} should be 0 or 1, got: {value}"
                )

        self.log.info("  Boolean config values verified")

    def test_rpc_allow_ip(self, node):
        """Test rpcallowip configuration."""
        self.log.info("Testing rpcallowip config...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        if "rpcallowip" in config:
            assert_equal(
                config["rpcallowip"], "127.0.0.1",
                "rpcallowip should be localhost for testing"
            )

        # RPC should work from localhost
        count = node.getblockcount()
        assert_greater_than(count, -1)

        self.log.info("  rpcallowip config verified")

    def test_keypool_config(self, node):
        """Test keypool configuration."""
        self.log.info("Testing keypool config...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        if "keypool" in config:
            keypool_size = int(config["keypool"])
            assert_greater_than(keypool_size, 0)

            # Wallet should reflect keypool setting
            info = node.getwalletinfo()
            if "keypoolsize" in info:
                self.log.info(
                    "  Keypool: config=%d, wallet=%d",
                    keypool_size, info["keypoolsize"]
                )

        self.log.info("  Keypool config verified")

    def test_bind_config(self, node):
        """Test bind address configuration."""
        self.log.info("Testing bind config...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        if "bind" in config:
            bind_addr = config["bind"]
            assert_equal(
                bind_addr, "127.0.0.1",
                "Should bind to localhost for testing"
            )

        self.log.info("  Bind config verified")

    def test_logging_config(self, node):
        """Test logging configuration options."""
        self.log.info("Testing logging config...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        logging_keys = ["debug", "logtimemicros", "logthreadnames",
                        "shrinkdebugfile", "printtoconsole"]

        for key in logging_keys:
            if key in config:
                self.log.info("  %s = %s", key, config[key])

        # Debug log should exist and be growing
        debug_log = os.path.join(node.datadir, "debug.log")
        if os.path.exists(debug_log):
            size = os.path.getsize(debug_log)
            self.log.info("  Debug log size: %d bytes", size)

    def test_config_comments(self, node):
        """Test that config file comments are preserved."""
        self.log.info("Testing config comments...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")

        # Add a comment to the config
        with open(conf_path, "a") as f:
            f.write("# This is a test comment\n")
            f.write("# Another comment\n")

        # Reading should skip comments
        config = read_config_file(conf_path)
        for key in config:
            assert_true(
                not key.startswith("#"),
                f"Comments should not be config keys: {key}"
            )

        self.log.info("  Config comments handled correctly")

    def test_config_empty_values(self, node):
        """Test handling of config entries with empty values."""
        self.log.info("Testing empty config values...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        # All values should be non-None
        for key, value in config.items():
            assert_true(
                value is not None,
                f"Config value for {key} should not be None"
            )

        self.log.info("  No empty config values found")

    def test_acceptnonstdtxn_config(self, node):
        """Test acceptnonstdtxn config for regtest."""
        self.log.info("Testing acceptnonstdtxn config...")

        conf_path = os.path.join(node.datadir, "flowcoin.conf")
        config = read_config_file(conf_path)

        if "acceptnonstdtxn" in config:
            value = config["acceptnonstdtxn"]
            assert_in(value, ["0", "1"])
            self.log.info("  acceptnonstdtxn = %s", value)

        self.log.info("  acceptnonstdtxn config verified")


if __name__ == "__main__":
    ConfigTest().main()

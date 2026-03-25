#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""FlowCoin functional test framework.

Provides the base class for all functional tests. Each test subclasses
FlowCoinTestFramework, sets up nodes, and implements run_test(). The
framework manages temporary directories, node lifecycle, RPC connections,
and inter-node connectivity on the regtest network.

Architecture mirrors Bitcoin Core's test/functional/test_framework but
is tailored for FlowCoin's Proof-of-Useful-Training consensus.
"""

import argparse
import collections
import configparser
import copy
import enum
import hashlib
import http.client
import json
import logging
import os
import platform
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from test_framework.test_node import TestNode, JSONRPCError
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
    connect_nodes,
    disconnect_nodes,
    get_datadir_path,
    p2p_port,
    rpc_port,
    satoshi_round,
    sync_blocks,
    sync_mempools,
    wait_until,
)

# Default ports for regtest
REGTEST_BASE_P2P_PORT = 29333
REGTEST_BASE_RPC_PORT = 29334

# Port spacing between test nodes
PORT_SPACING = 2

# Maximum number of nodes in a single test
MAX_NODES = 16

# Default timeout for RPC and sync operations
DEFAULT_TIMEOUT = 60

# Environment variable to override binary path
BINARY_ENV_VAR = "FLOWCOIND"
CLI_ENV_VAR = "FLOWCOINCLI"


class TestStatus(enum.Enum):
    """Outcome of a test execution."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class SkipTest(Exception):
    """Raised when a test should be skipped."""
    pass


class PortAllocator:
    """Allocates non-conflicting ports for test nodes.

    Each test run gets a unique base port derived from a combination of
    the PID and a counter, ensuring parallel test runs do not collide.
    """

    _instance = None
    _counter = 0

    def __init__(self):
        self._base = 29400 + (os.getpid() % 1000) * MAX_NODES * PORT_SPACING
        self._used = set()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def allocate(self, node_index: int) -> Tuple[int, int]:
        """Return (p2p_port, rpc_port) for the given node index."""
        offset = node_index * PORT_SPACING
        p2p = self._base + offset
        rpc = self._base + offset + 1

        # Verify ports are available
        for port in (p2p, rpc):
            if port in self._used:
                raise RuntimeError(f"Port {port} already allocated")
            if not self._is_port_available(port):
                # Shift base and try again
                self._base += MAX_NODES * PORT_SPACING
                return self.allocate(node_index)
            self._used.add(port)

        return p2p, rpc

    def release(self, p2p: int, rpc: int):
        """Release previously allocated ports."""
        self._used.discard(p2p)
        self._used.discard(rpc)

    @staticmethod
    def _is_port_available(port: int) -> bool:
        """Check if a TCP port is available for binding."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", port))
                return True
        except OSError:
            return False


class FlowCoinTestMetaClass(type):
    """Metaclass that registers test methods for introspection."""

    def __new__(mcs, name, bases, namespace):
        cls = super().__new__(mcs, name, bases, namespace)
        if hasattr(cls, "run_test") and name != "FlowCoinTestFramework":
            cls._test_name = name
        return cls


class FlowCoinTestFramework(metaclass=FlowCoinTestMetaClass):
    """Base class for FlowCoin functional tests.

    Subclasses must implement:
        - set_test_params():  Set self.num_nodes and other parameters.
        - run_test():         The actual test logic.

    Optional overrides:
        - setup_chain():     Customize chain initialization.
        - setup_network():   Customize node topology.
        - skip_test_if_missing_module(): Skip conditions.
        - add_options():     Add custom argparse options.
    """

    def __init__(self):
        self.nodes: List[TestNode] = []
        self.tmpdir: Optional[str] = None
        self.network = "regtest"
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = True
        self.bind_to_localhost_only = True
        self.rpc_timeout = DEFAULT_TIMEOUT
        self.options = None
        self.log = logging.getLogger(self.__class__.__name__)
        self._test_name = self.__class__.__name__
        self._port_allocator = PortAllocator.get_instance()
        self._allocated_ports: List[Tuple[int, int]] = []
        self._extra_args: List[List[str]] = []
        self._binary_paths: Dict[str, str] = {}
        self._node_configs: List[Dict[str, Any]] = []
        self._running = False
        self._cleanup_on_exit = True
        self._start_time = 0.0
        self._test_status = TestStatus.PASSED
        self._failure_reason = ""
        self._wallet_names: List[str] = []
        self._chain_height_cache: Dict[int, int] = {}

    # ------------------------------------------------------------------
    # Public API: Override in subclasses
    # ------------------------------------------------------------------

    def set_test_params(self):
        """Set test parameters. Must set self.num_nodes at minimum.

        Called before setup_chain(). Subclasses should override this to
        configure:
            - self.num_nodes: Number of nodes to start (default 1).
            - self.setup_clean_chain: If True, start with empty chain.
            - self._extra_args: Per-node extra CLI arguments.
            - self.rpc_timeout: RPC timeout in seconds.

        Example::

            def set_test_params(self):
                self.num_nodes = 3
                self._extra_args = [[], ["-maxconnections=4"], []]
        """
        raise NotImplementedError(
            "Subclasses must implement set_test_params()"
        )

    def setup_chain(self):
        """Initialize the chain data directories.

        Called after set_test_params() and before setup_network().
        Override to pre-populate chain data, import blocks, or
        set up wallet files.

        The default implementation creates empty data directories
        for each node. If self.setup_clean_chain is False, it copies
        a cached chain into the data directories.
        """
        if self.setup_clean_chain:
            for i in range(self.num_nodes):
                datadir = self._get_datadir(i)
                os.makedirs(datadir, exist_ok=True)
                self._write_config(i)
        else:
            self._initialize_chain_from_cache()

    def setup_network(self):
        """Start nodes and create the network topology.

        Default behavior:
            1. Start all nodes.
            2. Connect every node to node 0.
            3. Wait for all connections to establish.
            4. Sync all nodes.

        Override for custom topologies (ring, disconnected, etc.).
        """
        self.setup_nodes()
        if self.num_nodes > 1:
            self._connect_default_topology()
            self.sync_all()

    def run_test(self):
        """Main test logic. Must be overridden by subclasses."""
        raise NotImplementedError("Subclasses must implement run_test()")

    def skip_test_if_missing_module(self):
        """Override to skip test if a required module is missing.

        Raise SkipTest with a message if the test cannot run.
        """
        pass

    def add_options(self, parser: argparse.ArgumentParser):
        """Add custom command-line options for this test.

        Called during argument parsing. Override to add test-specific flags.
        """
        pass

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def main(self) -> int:
        """Entry point for test execution.

        Sets up logging, parses arguments, creates temporary directories,
        runs the test, and cleans up. Returns 0 on success, 1 on failure.
        """
        self._start_time = time.time()
        self._parse_args()
        self._setup_logging()
        self._create_tmpdir()

        try:
            self.skip_test_if_missing_module()
            self.set_test_params()
            self._validate_test_params()
            self._allocate_ports()
            self.setup_chain()
            self.setup_network()
            self._running = True
            self.run_test()
            self._test_status = TestStatus.PASSED
            elapsed = time.time() - self._start_time
            self.log.info(
                "Test %s passed in %.1f seconds", self._test_name, elapsed
            )
            return 0

        except SkipTest as e:
            self._test_status = TestStatus.SKIPPED
            self.log.info("Test skipped: %s", e)
            return 0

        except AssertionError as e:
            self._test_status = TestStatus.FAILED
            self._failure_reason = str(e)
            self.log.error("Test FAILED: %s", e)
            self._dump_debug_info()
            return 1

        except KeyboardInterrupt:
            self._test_status = TestStatus.ERROR
            self._failure_reason = "Interrupted by user"
            self.log.error("Test interrupted by user")
            return 1

        except Exception as e:
            self._test_status = TestStatus.ERROR
            self._failure_reason = str(e)
            self.log.error("Test ERROR: %s", e)
            traceback.print_exc()
            self._dump_debug_info()
            return 1

        finally:
            self._running = False
            self.cleanup()

    # ------------------------------------------------------------------
    # Node management
    # ------------------------------------------------------------------

    def setup_nodes(self):
        """Start all configured nodes.

        Creates data directories, writes config files, starts flowcoind
        processes, and waits for RPC to become available. Populates
        self.nodes with TestNode instances.
        """
        self.log.info("Starting %d node(s)...", self.num_nodes)
        for i in range(self.num_nodes):
            node = self._start_node(i)
            self.nodes.append(node)
            self.log.info(
                "Node %d started (P2P=%d, RPC=%d, PID=%d)",
                i, node.port, node.rpcport, node.process.pid
            )

    def _start_node(self, index: int) -> TestNode:
        """Start a single node and return its TestNode wrapper.

        Creates the data directory, writes the configuration file, launches
        the flowcoind process, and waits for the RPC interface to become
        responsive. Returns a fully initialized TestNode.
        """
        datadir = self._get_datadir(index)
        os.makedirs(datadir, exist_ok=True)

        p2p, rpc = self._allocated_ports[index]

        # Prepare configuration
        conf = self._build_node_config(index, p2p, rpc, datadir)
        self._node_configs.append(conf)

        # Write config file
        conf_path = os.path.join(datadir, "flowcoin.conf")
        self._write_config_file(conf_path, conf)

        # Build command line
        extra_args = []
        if index < len(self._extra_args):
            extra_args = self._extra_args[index]

        binary = self._find_binary("flowcoind")
        cmd = [
            binary,
            f"-datadir={datadir}",
            f"-conf={conf_path}",
        ] + extra_args

        self.log.debug("Starting node %d: %s", index, " ".join(cmd))

        # Launch process
        stdout_file = open(os.path.join(datadir, "stdout.log"), "w")
        stderr_file = open(os.path.join(datadir, "stderr.log"), "w")

        proc = subprocess.Popen(
            cmd,
            stdout=stdout_file,
            stderr=stderr_file,
            cwd=datadir,
        )

        node = TestNode(
            index=index,
            datadir=datadir,
            port=p2p,
            rpcport=rpc,
            process=proc,
            rpc_timeout=self.rpc_timeout,
            binary=binary,
            stderr=stderr_file,
            stdout=stdout_file,
            conf_path=conf_path,
        )

        # Wait for RPC to come up
        node.wait_for_rpc_connection(timeout=self.rpc_timeout)
        return node

    def start_node(self, index: int, extra_args: Optional[List[str]] = None):
        """Start (or restart) a specific node.

        If the node was previously stopped, this re-launches the process
        with the existing data directory.
        """
        if index >= len(self.nodes):
            raise ValueError(f"Node {index} not configured (have {len(self.nodes)} nodes)")

        node = self.nodes[index]
        if node.running:
            raise RuntimeError(f"Node {index} is already running")

        p2p, rpc = self._allocated_ports[index]
        datadir = self._get_datadir(index)

        cmd_extra = extra_args or []
        if index < len(self._extra_args) and not extra_args:
            cmd_extra = self._extra_args[index]

        binary = self._find_binary("flowcoind")
        conf_path = os.path.join(datadir, "flowcoin.conf")
        cmd = [
            binary,
            f"-datadir={datadir}",
            f"-conf={conf_path}",
        ] + cmd_extra

        stdout_file = open(os.path.join(datadir, "stdout.log"), "a")
        stderr_file = open(os.path.join(datadir, "stderr.log"), "a")

        proc = subprocess.Popen(
            cmd,
            stdout=stdout_file,
            stderr=stderr_file,
            cwd=datadir,
        )

        node.process = proc
        node.stderr = stderr_file
        node.stdout = stdout_file
        node.running = True
        node.wait_for_rpc_connection(timeout=self.rpc_timeout)
        self.log.info("Node %d restarted (PID=%d)", index, proc.pid)

    def stop_node(self, index: int, expected_stderr: str = "",
                  wait: int = DEFAULT_TIMEOUT):
        """Stop a specific node gracefully via RPC stop command.

        Waits up to `wait` seconds for the process to terminate.
        If `expected_stderr` is set, verifies that stderr contains it.
        """
        node = self.nodes[index]
        if not node.running:
            self.log.warning("Node %d already stopped", index)
            return

        self.log.info("Stopping node %d...", index)
        node.stop(wait=wait)

        if expected_stderr:
            stderr_path = os.path.join(node.datadir, "stderr.log")
            if os.path.exists(stderr_path):
                with open(stderr_path, "r") as f:
                    stderr_content = f.read()
                if expected_stderr not in stderr_content:
                    raise AssertionError(
                        f"Expected stderr to contain '{expected_stderr}', "
                        f"got: {stderr_content[:500]}"
                    )

    def stop_nodes(self):
        """Stop all running nodes."""
        for i, node in enumerate(self.nodes):
            if node.running:
                self.stop_node(i)

    def restart_node(self, index: int, extra_args: Optional[List[str]] = None):
        """Stop and restart a node, preserving its data directory.

        Useful for testing configuration changes, crash recovery,
        or wallet reload behavior.
        """
        self.stop_node(index)
        self.start_node(index, extra_args=extra_args)

    # ------------------------------------------------------------------
    # Network topology
    # ------------------------------------------------------------------

    def _connect_default_topology(self):
        """Connect all nodes in a star topology around node 0.

        Each node i (for i > 0) connects to node 0. This is the simplest
        topology that ensures full connectivity.
        """
        for i in range(1, self.num_nodes):
            connect_nodes(self.nodes[0], self.nodes[i])
            self._wait_for_peer_connection(self.nodes[0], self.nodes[i])

    def connect_nodes(self, a: int, b: int):
        """Connect node a to node b by index."""
        connect_nodes(self.nodes[a], self.nodes[b])
        self._wait_for_peer_connection(self.nodes[a], self.nodes[b])

    def disconnect_nodes(self, a: int, b: int):
        """Disconnect node a from node b."""
        disconnect_nodes(self.nodes[a], self.nodes[b])

    def isolate_node(self, index: int):
        """Disconnect a node from all peers.

        Useful for testing partition scenarios and reorg behavior.
        """
        node = self.nodes[index]
        peers = node.getpeerinfo()
        for peer in peers:
            addr = peer.get("addr", "")
            if addr:
                try:
                    node.disconnectnode(addr)
                except JSONRPCError:
                    pass

    def reconnect_isolated_node(self, index: int, target: int = 0):
        """Reconnect an isolated node to the target node."""
        connect_nodes(self.nodes[target], self.nodes[index])
        self._wait_for_peer_connection(self.nodes[target], self.nodes[index])

    def _wait_for_peer_connection(self, node_a: TestNode, node_b: TestNode,
                                  timeout: int = 30):
        """Wait until node_a has node_b as a peer.

        Polls getpeerinfo on both nodes until they see each other.
        """
        def connected():
            peers_a = node_a.getpeerinfo()
            peers_b = node_b.getpeerinfo()
            a_sees_b = any(
                str(node_b.port) in p.get("addr", "")
                or str(node_b.port) in p.get("addrlocal", "")
                for p in peers_a
            )
            b_sees_a = any(
                str(node_a.port) in p.get("addr", "")
                or str(node_a.port) in p.get("addrlocal", "")
                for p in peers_b
            )
            return a_sees_b or b_sees_a

        wait_until(connected, timeout=timeout, interval=0.25)

    # ------------------------------------------------------------------
    # Mining / block generation
    # ------------------------------------------------------------------

    def generate(self, node: TestNode, num_blocks: int,
                 address: Optional[str] = None) -> List[str]:
        """Generate blocks on regtest and return the block hashes.

        If no address is given, generates a fresh address from the node's
        wallet. Each call to generatetoaddress produces blocks sequentially
        with instant finality on regtest.
        """
        if address is None:
            address = node.getnewaddress()
        hashes = node.generatetoaddress(num_blocks, address)
        self.log.debug(
            "Generated %d block(s) on node %d (tip: %s)",
            num_blocks, node.index, hashes[-1][:16] if hashes else "none"
        )
        return hashes

    def generate_and_sync(self, node_index: int, num_blocks: int,
                          address: Optional[str] = None) -> List[str]:
        """Generate blocks on a node and sync all nodes."""
        hashes = self.generate(self.nodes[node_index], num_blocks, address)
        self.sync_all()
        return hashes

    def mine_to_height(self, node: TestNode, target_height: int,
                       address: Optional[str] = None) -> List[str]:
        """Mine blocks until the node reaches the target height.

        Returns the list of all block hashes generated.
        """
        current = node.getblockcount()
        if current >= target_height:
            return []
        needed = target_height - current
        return self.generate(node, needed, address)

    # ------------------------------------------------------------------
    # Synchronization
    # ------------------------------------------------------------------

    def sync_all(self, timeout: int = DEFAULT_TIMEOUT):
        """Sync blocks and mempools across all nodes."""
        self.sync_blocks(timeout=timeout)
        self.sync_mempools(timeout=timeout)

    def sync_blocks(self, nodes: Optional[List[TestNode]] = None,
                    timeout: int = DEFAULT_TIMEOUT):
        """Wait for all nodes to converge on the same chain tip.

        Polls getbestblockhash on each node until they all agree or
        the timeout expires.
        """
        if nodes is None:
            nodes = self.nodes
        sync_blocks(nodes, timeout=timeout)

    def sync_mempools(self, nodes: Optional[List[TestNode]] = None,
                      timeout: int = DEFAULT_TIMEOUT):
        """Wait for all nodes to have identical mempools.

        Polls getrawmempool on each node until they all report the same
        set of transaction IDs.
        """
        if nodes is None:
            nodes = self.nodes
        sync_mempools(nodes, timeout=timeout)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _build_node_config(self, index: int, p2p: int, rpc: int,
                           datadir: str) -> Dict[str, Any]:
        """Build the configuration dictionary for a node.

        Returns a dict of key-value pairs to write to flowcoin.conf.
        """
        conf = collections.OrderedDict()
        conf["regtest"] = 1
        conf["server"] = 1
        conf["listen"] = 1
        conf["port"] = p2p
        conf["rpcport"] = rpc
        conf["rpcuser"] = "test"
        conf["rpcpassword"] = "test"
        conf["rpcallowip"] = "127.0.0.1"
        conf["datadir"] = datadir
        conf["printtoconsole"] = 0
        conf["debug"] = 1
        conf["logtimemicros"] = 1
        conf["logthreadnames"] = 1
        conf["shrinkdebugfile"] = 0
        conf["keypool"] = 1
        conf["discover"] = 0
        conf["dnsseed"] = 0
        conf["fixedseeds"] = 0
        conf["listenonion"] = 0

        if self.bind_to_localhost_only:
            conf["bind"] = "127.0.0.1"

        # Allow immediate spending of coinbase on regtest for fast tests
        conf["acceptnonstdtxn"] = 1

        return conf

    def _write_config(self, index: int):
        """Write the flowcoin.conf for a node (pre-start setup)."""
        datadir = self._get_datadir(index)
        os.makedirs(datadir, exist_ok=True)
        p2p, rpc = self._allocated_ports[index]
        conf = self._build_node_config(index, p2p, rpc, datadir)
        conf_path = os.path.join(datadir, "flowcoin.conf")
        self._write_config_file(conf_path, conf)

    @staticmethod
    def _write_config_file(path: str, conf: Dict[str, Any]):
        """Write a config dictionary to a file in key=value format."""
        with open(path, "w") as f:
            for key, value in conf.items():
                f.write(f"{key}={value}\n")

    def _validate_test_params(self):
        """Validate test parameters after set_test_params()."""
        if self.num_nodes < 1:
            raise ValueError("num_nodes must be >= 1")
        if self.num_nodes > MAX_NODES:
            raise ValueError(f"num_nodes must be <= {MAX_NODES}")

        # Pad extra_args to match num_nodes
        while len(self._extra_args) < self.num_nodes:
            self._extra_args.append([])

    # ------------------------------------------------------------------
    # Port allocation
    # ------------------------------------------------------------------

    def _allocate_ports(self):
        """Allocate P2P and RPC ports for all nodes."""
        self._allocated_ports = []
        for i in range(self.num_nodes):
            ports = self._port_allocator.allocate(i)
            self._allocated_ports.append(ports)

    def _release_ports(self):
        """Release all allocated ports."""
        for p2p, rpc in self._allocated_ports:
            self._port_allocator.release(p2p, rpc)
        self._allocated_ports = []

    # ------------------------------------------------------------------
    # Binary discovery
    # ------------------------------------------------------------------

    def _find_binary(self, name: str) -> str:
        """Find the flowcoind or flowcoin-cli binary.

        Search order:
        1. Environment variable FLOWCOIND / FLOWCOINCLI.
        2. ../build/ relative to test directory.
        3. ../../build/ relative to test directory.
        4. Project root /build/.
        5. src/ directory.
        6. System PATH.
        """
        if name in self._binary_paths:
            return self._binary_paths[name]

        env_var = BINARY_ENV_VAR if name == "flowcoind" else CLI_ENV_VAR
        env_path = os.environ.get(env_var)
        if env_path and os.path.isfile(env_path):
            self._binary_paths[name] = env_path
            return env_path

        # Relative search paths from this file
        test_dir = Path(__file__).resolve().parent.parent.parent
        search_dirs = [
            test_dir / "build",
            test_dir / "build" / "src",
            test_dir.parent / "build",
            test_dir.parent / "build" / "src",
            test_dir / "src",
            test_dir,
        ]

        for d in search_dirs:
            candidate = d / name
            if candidate.is_file() and os.access(str(candidate), os.X_OK):
                path = str(candidate)
                self._binary_paths[name] = path
                return path

        # Fall back to PATH
        which = shutil.which(name)
        if which:
            self._binary_paths[name] = which
            return which

        raise FileNotFoundError(
            f"Cannot find {name} binary. Set {env_var} environment variable "
            f"or place the binary in a build/ directory."
        )

    # ------------------------------------------------------------------
    # Temporary directory management
    # ------------------------------------------------------------------

    def _create_tmpdir(self):
        """Create the temporary directory for this test run."""
        self.tmpdir = tempfile.mkdtemp(prefix="flowcoin_test_")
        self.log.info("Using tmpdir: %s", self.tmpdir)

    def _get_datadir(self, index: int) -> str:
        """Get the data directory path for a node."""
        return os.path.join(self.tmpdir, f"node{index}")

    # ------------------------------------------------------------------
    # Cached chain
    # ------------------------------------------------------------------

    def _initialize_chain_from_cache(self):
        """Copy a pre-mined chain from cache into node data directories.

        The cache contains a chain with 200 blocks mined to provide a
        starting balance for tests that need funded wallets.
        """
        cache_dir = self._get_cache_dir()
        if not os.path.isdir(cache_dir):
            self._create_chain_cache(cache_dir)

        for i in range(self.num_nodes):
            datadir = self._get_datadir(i)
            if os.path.exists(datadir):
                shutil.rmtree(datadir)
            shutil.copytree(
                os.path.join(cache_dir, "node0"),
                datadir,
            )
            # Rewrite config with correct ports
            self._write_config(i)

    def _get_cache_dir(self) -> str:
        """Get the path to the chain cache directory."""
        return os.path.join(
            tempfile.gettempdir(), "flowcoin_test_cache"
        )

    def _create_chain_cache(self, cache_dir: str):
        """Create the chain cache by mining 200 blocks.

        Starts a temporary node, mines blocks, and copies the resulting
        data directory to the cache location.
        """
        os.makedirs(cache_dir, exist_ok=True)
        node_dir = os.path.join(cache_dir, "node0")
        os.makedirs(node_dir, exist_ok=True)

        # Build minimal config
        p2p = 29900
        rpc = 29901
        conf = self._build_node_config(0, p2p, rpc, node_dir)
        conf_path = os.path.join(node_dir, "flowcoin.conf")
        self._write_config_file(conf_path, conf)

        binary = self._find_binary("flowcoind")
        proc = subprocess.Popen(
            [binary, f"-datadir={node_dir}", f"-conf={conf_path}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

        node = TestNode(
            index=0, datadir=node_dir, port=p2p, rpcport=rpc,
            process=proc, rpc_timeout=self.rpc_timeout, binary=binary,
        )
        try:
            node.wait_for_rpc_connection()
            addr = node.getnewaddress()
            node.generatetoaddress(200, addr)
        finally:
            node.stop()

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _parse_args(self):
        """Parse command-line arguments."""
        parser = argparse.ArgumentParser(
            description=f"FlowCoin functional test: {self._test_name}"
        )
        parser.add_argument(
            "--nocleanup", action="store_true",
            help="Do not remove tmpdir on exit"
        )
        parser.add_argument(
            "--loglevel", default="INFO",
            choices=["DEBUG", "INFO", "WARNING", "ERROR"],
            help="Log level"
        )
        parser.add_argument(
            "--timeout-factor", type=float, default=1.0,
            help="Multiply all timeouts by this factor"
        )
        parser.add_argument(
            "--tracerpc", action="store_true",
            help="Log all RPC calls"
        )
        parser.add_argument(
            "--randomseed", type=int, default=None,
            help="Random seed for reproducible tests"
        )
        self.add_options(parser)
        self.options = parser.parse_args()

        if self.options.nocleanup:
            self._cleanup_on_exit = False

        if self.options.timeout_factor != 1.0:
            self.rpc_timeout = int(self.rpc_timeout * self.options.timeout_factor)

        if self.options.randomseed is not None:
            random.seed(self.options.randomseed)

    def _setup_logging(self):
        """Configure logging for the test."""
        level = getattr(logging, self.options.loglevel if self.options else "INFO")
        formatter = logging.Formatter(
            "%(asctime)s.%(msecs)03d %(name)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        root_logger.addHandler(console_handler)

        # File handler (if tmpdir exists)
        if self.tmpdir:
            log_path = os.path.join(self.tmpdir, "test_framework.log")
            file_handler = logging.FileHandler(log_path)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)

    # ------------------------------------------------------------------
    # Debug output
    # ------------------------------------------------------------------

    def _dump_debug_info(self):
        """Dump debug information after a test failure.

        Collects node logs, mempool contents, and chain state for
        post-mortem analysis.
        """
        self.log.info("=== Debug dump for failed test %s ===", self._test_name)

        for i, node in enumerate(self.nodes):
            self.log.info("--- Node %d ---", i)

            # Log RPC state if node is still running
            if node.running:
                try:
                    info = node.getblockchaininfo()
                    self.log.info(
                        "  Height: %d, Best hash: %s",
                        info.get("blocks", -1),
                        info.get("bestblockhash", "unknown")[:16]
                    )
                except Exception as e:
                    self.log.info("  Could not get blockchain info: %s", e)

                try:
                    mempool = node.getrawmempool()
                    self.log.info("  Mempool size: %d", len(mempool))
                except Exception:
                    pass

                try:
                    peers = node.getpeerinfo()
                    self.log.info("  Peer count: %d", len(peers))
                except Exception:
                    pass

            # Dump last 50 lines of debug.log
            debug_log = os.path.join(node.datadir, "debug.log")
            if os.path.exists(debug_log):
                try:
                    with open(debug_log, "r") as f:
                        lines = f.readlines()
                        tail = lines[-50:] if len(lines) > 50 else lines
                        self.log.info(
                            "  Last %d lines of debug.log:", len(tail)
                        )
                        for line in tail:
                            self.log.info("    %s", line.rstrip())
                except Exception as e:
                    self.log.info("  Could not read debug.log: %s", e)

            # Dump stderr
            stderr_path = os.path.join(node.datadir, "stderr.log")
            if os.path.exists(stderr_path):
                try:
                    with open(stderr_path, "r") as f:
                        content = f.read().strip()
                        if content:
                            self.log.info("  stderr: %s", content[:1000])
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup(self):
        """Stop all nodes and clean up temporary files.

        Called in the finally block of main(). Stops all running nodes,
        releases ports, and removes the temporary directory unless
        --nocleanup was specified.
        """
        self.log.info("Cleaning up...")

        # Stop all nodes
        for i, node in enumerate(self.nodes):
            if node.running:
                try:
                    node.stop(wait=10)
                except Exception as e:
                    self.log.warning(
                        "Error stopping node %d: %s", i, e
                    )
                    # Force kill
                    try:
                        node.process.kill()
                        node.process.wait(timeout=5)
                    except Exception:
                        pass

        # Close file handles
        for node in self.nodes:
            for fh in (node.stdout, node.stderr):
                if fh and not fh.closed:
                    try:
                        fh.close()
                    except Exception:
                        pass

        # Release ports
        self._release_ports()

        # Remove tmpdir
        if self.tmpdir and self._cleanup_on_exit:
            try:
                shutil.rmtree(self.tmpdir, ignore_errors=True)
                self.log.debug("Removed tmpdir: %s", self.tmpdir)
            except Exception as e:
                self.log.warning("Could not remove tmpdir: %s", e)

    # ------------------------------------------------------------------
    # Utility methods available to tests
    # ------------------------------------------------------------------

    def wait_for_block_height(self, node: TestNode, height: int,
                              timeout: int = DEFAULT_TIMEOUT):
        """Wait until a node reaches the specified block height."""
        def check():
            return node.getblockcount() >= height
        wait_until(check, timeout=timeout, interval=0.25)

    def wait_for_mempool_count(self, node: TestNode, count: int,
                               timeout: int = DEFAULT_TIMEOUT):
        """Wait until a node's mempool has the specified number of txs."""
        def check():
            return len(node.getrawmempool()) >= count
        wait_until(check, timeout=timeout, interval=0.25)

    def wait_for_transaction(self, node: TestNode, txid: str,
                             timeout: int = DEFAULT_TIMEOUT):
        """Wait until a transaction appears in the node's mempool or chain."""
        def check():
            try:
                node.gettransaction(txid)
                return True
            except JSONRPCError:
                pass
            try:
                mempool = node.getrawmempool()
                return txid in mempool
            except JSONRPCError:
                return False
        wait_until(check, timeout=timeout, interval=0.25)

    def create_wallet(self, node: TestNode, name: str = "default",
                      disable_private_keys: bool = False,
                      blank: bool = False) -> dict:
        """Create a new wallet on the node.

        Returns the RPC response from createwallet.
        """
        result = node.createwallet(
            wallet_name=name,
            disable_private_keys=disable_private_keys,
            blank=blank,
        )
        self._wallet_names.append(name)
        return result

    def get_utxo(self, node: TestNode, txid: str,
                 vout: int) -> Optional[dict]:
        """Get a specific UTXO from the node."""
        utxos = node.listunspent()
        for utxo in utxos:
            if utxo["txid"] == txid and utxo["vout"] == vout:
                return utxo
        return None

    def send_and_confirm(self, from_node: TestNode, to_address: str,
                         amount: float, confirm_blocks: int = 1) -> str:
        """Send coins and mine blocks to confirm the transaction.

        Returns the transaction ID.
        """
        txid = from_node.sendtoaddress(to_address, amount)
        if confirm_blocks > 0:
            self.generate(from_node, confirm_blocks)
        return txid

    def get_chain_tips(self, node: TestNode) -> list:
        """Get all chain tips from the node."""
        return node.getchaintips()

    def assert_chain_tip(self, node: TestNode, expected_hash: str):
        """Assert that the node's best block hash matches expected."""
        actual = node.getbestblockhash()
        assert_equal(actual, expected_hash)

    def log_node_info(self, node: TestNode):
        """Log the current state of a node for debugging."""
        info = node.getblockchaininfo()
        self.log.info(
            "Node %d: height=%d, best=%s, difficulty=%.4f",
            node.index,
            info.get("blocks", -1),
            info.get("bestblockhash", "?")[:16],
            info.get("difficulty", 0),
        )

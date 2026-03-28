#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""TestNode: wrapper around a running flowcoind instance.

Provides transparent JSON-RPC proxying through __getattr__, process
lifecycle management, log inspection, and restart capabilities. Each
TestNode represents one flowcoind daemon in the test harness.
"""

import base64
import hashlib
import http.client
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


log = logging.getLogger("TestNode")


class JSONRPCError(Exception):
    """Exception raised when a JSON-RPC call returns an error.

    Attributes:
        error: The error dict from the JSON-RPC response, containing
               'code' (int) and 'message' (str).
    """

    def __init__(self, error: dict):
        self.error = error
        self.code = error.get("code", -1)
        self.message = error.get("message", "Unknown RPC error")
        super().__init__(f"RPC error {self.code}: {self.message}")


class RPCConnection:
    """Low-level JSON-RPC connection to a flowcoind instance.

    Handles HTTP connection pooling, authentication, request formatting,
    and response parsing. All RPC methods are accessible through the
    call() method.
    """

    def __init__(self, url: str, rpc_user: str = "test",
                 rpc_password: str = "test", timeout: int = 60):
        self.url = url
        self.timeout = timeout
        self._auth_header = self._make_auth_header(rpc_user, rpc_password)
        self._id_counter = 0
        self._connection: Optional[http.client.HTTPConnection] = None
        parsed = urllib.parse.urlparse(url)
        self._host = parsed.hostname or "127.0.0.1"
        self._port = parsed.port or 29334
        self._path = parsed.path or "/"

    @staticmethod
    def _make_auth_header(user: str, password: str) -> str:
        """Create HTTP Basic Auth header value."""
        credentials = f"{user}:{password}".encode("utf-8")
        encoded = base64.b64encode(credentials).decode("ascii")
        return f"Basic {encoded}"

    def _get_connection(self) -> http.client.HTTPConnection:
        """Get or create an HTTP connection."""
        if self._connection is None:
            self._connection = http.client.HTTPConnection(
                self._host, self._port, timeout=self.timeout
            )
        return self._connection

    def _reset_connection(self):
        """Close and reset the HTTP connection."""
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None

    def call(self, method: str, params: list = None) -> Any:
        """Make a JSON-RPC call and return the result.

        Args:
            method: The RPC method name (e.g., "getblockcount").
            params: Positional parameters for the method.

        Returns:
            The 'result' field from the JSON-RPC response.

        Raises:
            JSONRPCError: If the response contains an error.
            ConnectionError: If the connection fails.
        """
        if params is None:
            params = []

        self._id_counter += 1
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self._id_counter,
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Authorization": self._auth_header,
            "Connection": "keep-alive",
        }

        for attempt in range(3):
            try:
                conn = self._get_connection()
                conn.request("POST", self._path, payload, headers)
                response = conn.getresponse()
                body = response.read()

                if response.status == 401:
                    raise ConnectionError("RPC authentication failed")
                if response.status == 403:
                    raise ConnectionError("RPC access forbidden")
                if response.status == 500:
                    # Parse error response
                    try:
                        result = json.loads(body.decode("utf-8"))
                        if result.get("error"):
                            raise JSONRPCError(result["error"])
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass
                    raise ConnectionError(
                        f"RPC returned HTTP 500: {body[:200]}"
                    )

                result = json.loads(body.decode("utf-8"))
                if result.get("error"):
                    raise JSONRPCError(result["error"])
                return result.get("result")

            except (ConnectionError, http.client.HTTPException,
                    socket.error, OSError) as e:
                self._reset_connection()
                if attempt == 2:
                    raise ConnectionError(
                        f"RPC connection failed after 3 attempts: {e}"
                    ) from e
                time.sleep(0.1 * (attempt + 1))

    def close(self):
        """Close the connection."""
        self._reset_connection()


class RPCOverloadError(Exception):
    """Raised when the RPC server is overloaded."""
    pass


class TestNode:
    """Wrapper around a running flowcoind instance.

    Provides:
        - Transparent RPC method proxying via __getattr__.
        - Process lifecycle management (start, stop, restart).
        - Log file inspection and pattern matching.
        - State assertions for testing.

    Usage::

        node = TestNode(index=0, datadir="/tmp/node0", port=29333,
                        rpcport=29334, process=proc)
        node.wait_for_rpc_connection()
        count = node.getblockcount()
        node.stop()
    """

    # RPC error codes (mirror consensus/rpc_errors.h)
    RPC_INVALID_REQUEST = -32600
    RPC_METHOD_NOT_FOUND = -32601
    RPC_INVALID_PARAMS = -32602
    RPC_INTERNAL_ERROR = -32603
    RPC_PARSE_ERROR = -32700
    RPC_MISC_ERROR = -1
    RPC_TYPE_ERROR = -3
    RPC_INVALID_ADDRESS_OR_KEY = -5
    RPC_OUT_OF_MEMORY = -7
    RPC_INVALID_PARAMETER = -8
    RPC_DATABASE_ERROR = -20
    RPC_DESERIALIZATION_ERROR = -22
    RPC_VERIFY_ERROR = -25
    RPC_VERIFY_REJECTED = -26
    RPC_VERIFY_ALREADY_IN_CHAIN = -27
    RPC_IN_WARMUP = -28
    RPC_WALLET_ERROR = -4
    RPC_WALLET_INSUFFICIENT_FUNDS = -6
    RPC_WALLET_INVALID_LABEL_NAME = -11
    RPC_WALLET_KEYPOOL_RAN_OUT = -12
    RPC_WALLET_UNLOCK_NEEDED = -13
    RPC_WALLET_PASSPHRASE_INCORRECT = -14
    RPC_WALLET_WRONG_ENC_STATE = -15
    RPC_WALLET_ENCRYPTION_FAILED = -16
    RPC_WALLET_ALREADY_UNLOCKED = -17
    RPC_WALLET_NOT_FOUND = -18
    RPC_WALLET_NOT_SPECIFIED = -19

    def __init__(self, index: int, datadir: str, port: int, rpcport: int,
                 process: subprocess.Popen, rpc_timeout: int = 60,
                 binary: str = "", stderr=None, stdout=None,
                 conf_path: str = ""):
        self.index = index
        self.datadir = datadir
        self.port = port
        self.rpcport = rpcport
        self.process = process
        self.rpc_timeout = rpc_timeout
        self.binary = binary
        self.stderr = stderr
        self.stdout = stdout
        self.conf_path = conf_path

        self.rpc_url = f"http://127.0.0.1:{rpcport}"
        self.rpc: Optional[RPCConnection] = None
        self.running = True
        self._log = logging.getLogger(f"TestNode[{index}]")
        self._genesis_hash: Optional[str] = None

    def __repr__(self) -> str:
        state = "running" if self.running else "stopped"
        return (
            f"<TestNode {self.index} {state} "
            f"P2P={self.port} RPC={self.rpcport}>"
        )

    def __getattr__(self, name: str) -> Callable:
        """Proxy attribute access to JSON-RPC calls.

        Any method not defined on TestNode is forwarded as an RPC call
        to the running flowcoind instance. For example, calling
        node.getblockcount() sends a "getblockcount" RPC request.

        This allows test code to call RPC methods naturally without
        explicitly constructing JSON-RPC requests.
        """
        if name.startswith("_"):
            raise AttributeError(
                f"'{type(self).__name__}' has no attribute '{name}'"
            )

        def rpc_method(*args, **kwargs):
            if not self.running:
                raise ConnectionError(
                    f"Node {self.index} is not running"
                )
            if self.rpc is None:
                raise ConnectionError(
                    f"Node {self.index} has no RPC connection"
                )
            # Convert kwargs to positional args for JSON-RPC
            params = list(args)
            if kwargs:
                # Named parameters: wrap in a dict as the last argument
                if not params:
                    params = [kwargs]
                else:
                    params.append(kwargs)
            return self.rpc.call(name, params)

        rpc_method.__name__ = name
        rpc_method.__qualname__ = f"TestNode.{name}"
        return rpc_method

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def wait_for_rpc_connection(self, timeout: int = 60):
        """Wait for the node to accept RPC connections.

        Polls the RPC interface with getblockcount() until it responds
        successfully or the timeout expires. Initializes self.rpc on
        success.

        Args:
            timeout: Maximum seconds to wait.

        Raises:
            TimeoutError: If the node does not respond within timeout.
            RuntimeError: If the process exits before RPC is ready.
        """
        self._log.debug("Waiting for RPC connection on port %d...", self.rpcport)
        start = time.time()
        rpc = RPCConnection(
            self.rpc_url, timeout=min(timeout, 30)
        )

        while time.time() - start < timeout:
            # Check if process is still alive
            if self.process.poll() is not None:
                exit_code = self.process.returncode
                stderr_content = self._read_stderr()
                raise RuntimeError(
                    f"Node {self.index} exited with code {exit_code} "
                    f"before RPC became available. stderr: {stderr_content}"
                )

            try:
                result = rpc.call("getblockcount")
                self.rpc = rpc
                self._log.debug(
                    "RPC connection established (height=%s)", result
                )
                return
            except JSONRPCError as e:
                if e.code == self.RPC_IN_WARMUP:
                    # Node is starting up, keep waiting
                    time.sleep(0.25)
                    continue
                # Other RPC errors mean RPC is working
                self.rpc = rpc
                return
            except (ConnectionError, ConnectionRefusedError,
                    http.client.HTTPException, socket.error, OSError):
                time.sleep(0.1)

        raise TimeoutError(
            f"Node {self.index} did not start RPC on port {self.rpcport} "
            f"within {timeout} seconds"
        )

    def wait_for_cookie_credentials(self, timeout: int = 30):
        """Wait for the .cookie auth file to appear.

        Some configurations use cookie-based auth instead of
        user/password. This waits for the cookie file to be written.
        """
        cookie_path = os.path.join(self.datadir, ".cookie")
        start = time.time()
        while time.time() - start < timeout:
            if os.path.exists(cookie_path):
                with open(cookie_path, "r") as f:
                    cookie = f.read().strip()
                if ":" in cookie:
                    user, password = cookie.split(":", 1)
                    self.rpc = RPCConnection(
                        self.rpc_url, rpc_user=user, rpc_password=password,
                        timeout=self.rpc_timeout
                    )
                    return
            time.sleep(0.1)
        raise TimeoutError("Cookie file not found")

    # ------------------------------------------------------------------
    # Process lifecycle
    # ------------------------------------------------------------------

    def stop(self, wait: int = 60):
        """Stop the node gracefully via RPC.

        Sends the "stop" RPC command and waits for the process to exit.
        If the process does not exit within `wait` seconds, it is killed.

        Args:
            wait: Maximum seconds to wait for process exit.
        """
        if not self.running:
            return

        self._log.debug("Stopping node %d...", self.index)

        # Try RPC stop first
        try:
            if self.rpc:
                self.rpc.call("stop")
        except (ConnectionError, JSONRPCError, Exception) as e:
            self._log.debug("RPC stop failed (may be expected): %s", e)

        # Wait for process to exit
        try:
            self.process.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            self._log.warning(
                "Node %d did not stop within %d seconds, killing",
                self.index, wait
            )
            self.process.kill()
            self.process.wait(timeout=5)

        self.running = False

        # Close RPC connection
        if self.rpc:
            self.rpc.close()
            self.rpc = None

        # Close file handles
        for fh in (self.stdout, self.stderr):
            if fh and hasattr(fh, "closed") and not fh.closed:
                try:
                    fh.close()
                except Exception:
                    pass

        self._log.debug(
            "Node %d stopped (exit code: %s)",
            self.index, self.process.returncode
        )

    def kill(self):
        """Forcefully kill the node process.

        Does not attempt a graceful shutdown. Use only when testing
        crash recovery scenarios.
        """
        if not self.running:
            return
        self._log.debug("Killing node %d", self.index)
        self.process.kill()
        self.process.wait(timeout=5)
        self.running = False
        if self.rpc:
            self.rpc.close()
            self.rpc = None

    def is_alive(self) -> bool:
        """Check if the node process is still running."""
        if not self.running:
            return False
        return self.process.poll() is None

    def wait_for_exit(self, timeout: int = 30) -> int:
        """Wait for the node to exit and return the exit code."""
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise TimeoutError(
                f"Node {self.index} did not exit within {timeout}s"
            )
        self.running = False
        return self.process.returncode

    # ------------------------------------------------------------------
    # Log inspection
    # ------------------------------------------------------------------

    def _read_stderr(self) -> str:
        """Read the stderr log file content."""
        stderr_path = os.path.join(self.datadir, "stderr.log")
        if os.path.exists(stderr_path):
            try:
                with open(stderr_path, "r") as f:
                    return f.read()
            except Exception:
                pass
        return ""

    def read_debug_log(self) -> str:
        """Read the node's debug.log file."""
        log_path = os.path.join(self.datadir, "debug.log")
        if os.path.exists(log_path):
            with open(log_path, "r") as f:
                return f.read()
        return ""

    def debug_log_contains(self, pattern: str) -> bool:
        """Check if the debug log contains a string or regex pattern."""
        content = self.read_debug_log()
        if re.search(pattern, content):
            return True
        return False

    def wait_for_log(self, pattern: str, timeout: int = 30):
        """Wait for a pattern to appear in the debug log.

        Args:
            pattern: String or regex pattern to search for.
            timeout: Maximum seconds to wait.

        Raises:
            TimeoutError: If the pattern does not appear.
        """
        start = time.time()
        while time.time() - start < timeout:
            if self.debug_log_contains(pattern):
                return
            time.sleep(0.25)
        raise TimeoutError(
            f"Pattern '{pattern}' not found in node {self.index} "
            f"debug.log within {timeout}s"
        )

    def assert_debug_log(self, expected_msgs: List[str],
                         unexpected_msgs: Optional[List[str]] = None,
                         timeout: int = 10):
        """Assert that debug log contains expected messages and none
        of the unexpected messages.

        Args:
            expected_msgs: List of strings that must appear in the log.
            unexpected_msgs: List of strings that must not appear.
            timeout: Seconds to wait for expected messages.
        """
        content = self.read_debug_log()

        for msg in expected_msgs:
            if msg not in content:
                # Wait a bit and try again
                time.sleep(min(timeout, 2))
                content = self.read_debug_log()
                if msg not in content:
                    raise AssertionError(
                        f"Expected message not found in node {self.index} "
                        f"debug.log: '{msg}'"
                    )

        if unexpected_msgs:
            for msg in unexpected_msgs:
                if msg in content:
                    raise AssertionError(
                        f"Unexpected message found in node {self.index} "
                        f"debug.log: '{msg}'"
                    )

    def get_debug_log_size(self) -> int:
        """Get the current size of the debug log in bytes."""
        log_path = os.path.join(self.datadir, "debug.log")
        if os.path.exists(log_path):
            return os.path.getsize(log_path)
        return 0

    # ------------------------------------------------------------------
    # State queries (convenience wrappers)
    # ------------------------------------------------------------------

    def get_genesis_hash(self) -> str:
        """Get the genesis block hash, caching the result."""
        if self._genesis_hash is None:
            self._genesis_hash = self.getblockhash(0)
        return self._genesis_hash

    def get_best_block_hash(self) -> str:
        """Get the current best (tip) block hash."""
        return self.getbestblockhash()

    def get_block_count(self) -> int:
        """Get the current block height."""
        return self.getblockcount()

    def get_balance(self) -> Decimal:
        """Get the wallet balance as a Decimal."""
        return Decimal(str(self.getbalance()))

    def get_mempool_size(self) -> int:
        """Get the number of transactions in the mempool."""
        return len(self.getrawmempool())

    def get_peer_count(self) -> int:
        """Get the number of connected peers."""
        return len(self.getpeerinfo())

    # ------------------------------------------------------------------
    # Transaction helpers
    # ------------------------------------------------------------------

    def send_to_address(self, address: str, amount: float,
                        comment: str = "", comment_to: str = "",
                        subtract_fee: bool = False) -> str:
        """Send coins to an address and return the txid.

        Wrapper around sendtoaddress with default parameters.
        """
        return self.sendtoaddress(
            address, amount, comment, comment_to, subtract_fee
        )

    def get_new_address(self, label: str = "") -> str:
        """Generate a new receiving address."""
        if label:
            return self.getnewaddress(label)
        return self.getnewaddress()

    def generate_to_address(self, nblocks: int, address: str) -> List[str]:
        """Generate blocks to the specified address.

        Returns list of block hashes.
        """
        return self.generatetoaddress(nblocks, address)

    # ------------------------------------------------------------------
    # Error testing helpers
    # ------------------------------------------------------------------

    def assert_start_raises_init_error(
        self, extra_args: Optional[List[str]] = None,
        expected_msg: str = "", match: str = ""
    ):
        """Assert that starting with the given args causes an init error.

        Starts the node with extra_args and verifies it exits with a
        non-zero exit code. If expected_msg is set, verifies it appears
        in stderr.

        Args:
            extra_args: Additional command-line arguments.
            expected_msg: String to check in stderr output.
            match: Regex pattern to match in stderr output.
        """
        if extra_args is None:
            extra_args = []

        binary = self.binary or "flowcoind"
        conf_path = os.path.join(self.datadir, "flowcoin.conf")
        cmd = [
            binary,
            f"-datadir={self.datadir}",
            f"-conf={conf_path}",
        ] + extra_args

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        stdout_data, stderr_data = proc.communicate(timeout=30)
        stderr_text = stderr_data.decode("utf-8", errors="replace")

        if proc.returncode == 0:
            raise AssertionError(
                f"Node started successfully when it should have failed. "
                f"Extra args: {extra_args}"
            )

        if expected_msg and expected_msg not in stderr_text:
            raise AssertionError(
                f"Expected init error message '{expected_msg}' not found "
                f"in stderr: {stderr_text[:500]}"
            )

        if match and not re.search(match, stderr_text):
            raise AssertionError(
                f"Init error stderr does not match pattern '{match}': "
                f"{stderr_text[:500]}"
            )

    def assert_rpc_error(self, code: int, message: str,
                         method: str, *args):
        """Assert that calling an RPC method raises a specific error.

        Args:
            code: Expected JSON-RPC error code.
            message: Expected substring in error message.
            method: RPC method name.
            *args: Arguments to pass to the method.
        """
        try:
            rpc_method = getattr(self, method)
            rpc_method(*args)
        except JSONRPCError as e:
            if code is not None and e.code != code:
                raise AssertionError(
                    f"Expected RPC error code {code}, got {e.code}: "
                    f"{e.message}"
                )
            if message and message not in e.message:
                raise AssertionError(
                    f"Expected error message to contain '{message}', "
                    f"got: {e.message}"
                )
            return
        raise AssertionError(
            f"Expected RPC error calling {method}({args}), but it succeeded"
        )

    # ------------------------------------------------------------------
    # Wallet file helpers
    # ------------------------------------------------------------------

    def get_wallet_path(self) -> str:
        """Get the path to the wallet.dat file."""
        return os.path.join(self.datadir, "wallets", "wallet.dat")

    def wallet_exists(self) -> bool:
        """Check if the wallet file exists."""
        return os.path.exists(self.get_wallet_path())

    def backup_wallet(self, dest: str):
        """Backup the wallet to a file."""
        self.backupwallet(dest)

    # ------------------------------------------------------------------
    # P2P helpers
    # ------------------------------------------------------------------

    def add_p2p_connection(self, p2p_conn, send_version: bool = True):
        """Connect a P2P test connection to this node.

        Args:
            p2p_conn: A P2PConnection or P2PInterface instance.
            send_version: If True, perform version handshake.
        """
        p2p_conn.connect("127.0.0.1", self.port)
        if send_version:
            p2p_conn.perform_handshake()
        return p2p_conn

    def disconnect_p2p(self, p2p_conn):
        """Disconnect a P2P test connection."""
        p2p_conn.disconnect()

    # ------------------------------------------------------------------
    # Data directory access
    # ------------------------------------------------------------------

    def get_datadir_path(self, *subpaths) -> str:
        """Get a path within the node's data directory."""
        return os.path.join(self.datadir, *subpaths)

    def list_datadir_files(self) -> List[str]:
        """List all files in the node's data directory."""
        files = []
        for root, dirs, filenames in os.walk(self.datadir):
            for fname in filenames:
                rel = os.path.relpath(
                    os.path.join(root, fname), self.datadir
                )
                files.append(rel)
        return sorted(files)

    def get_datadir_size(self) -> int:
        """Get total size of the data directory in bytes."""
        total = 0
        for root, dirs, filenames in os.walk(self.datadir):
            for fname in filenames:
                fpath = os.path.join(root, fname)
                try:
                    total += os.path.getsize(fpath)
                except OSError:
                    pass
        return total

    # ------------------------------------------------------------------
    # Chain state helpers
    # ------------------------------------------------------------------

    def get_chain_height(self) -> int:
        """Get the current chain height via RPC."""
        return self.getblockcount()

    def get_tip_hash(self) -> str:
        """Get the current best block hash."""
        return self.getbestblockhash()

    def get_block_at_height(self, height: int) -> dict:
        """Get the full block data at a specific height."""
        block_hash = self.getblockhash(height)
        return self.getblock(block_hash)

    def get_block_header_at_height(self, height: int) -> dict:
        """Get the block header at a specific height."""
        block_hash = self.getblockhash(height)
        return self.getblockheader(block_hash)

    def mine_blocks(self, count: int,
                    address: Optional[str] = None) -> List[str]:
        """Mine blocks and return the hashes.

        If no address is provided, generates a new one.
        """
        if address is None:
            address = self.getnewaddress()
        return self.generatetoaddress(count, address)

    def mine_to_height(self, target_height: int,
                       address: Optional[str] = None) -> List[str]:
        """Mine blocks until reaching the target height."""
        current = self.getblockcount()
        if current >= target_height:
            return []
        needed = target_height - current
        return self.mine_blocks(needed, address)

    # ------------------------------------------------------------------
    # Mempool helpers
    # ------------------------------------------------------------------

    def get_mempool_txids(self) -> list:
        """Get all transaction IDs in the mempool."""
        return self.getrawmempool()

    def is_tx_in_mempool(self, txid: str) -> bool:
        """Check if a transaction is in the mempool."""
        return txid in self.getrawmempool()

    def wait_for_mempool_tx(self, txid: str, timeout: int = 30):
        """Wait for a transaction to appear in the mempool."""
        start = time.time()
        while time.time() - start < timeout:
            if self.is_tx_in_mempool(txid):
                return
            time.sleep(0.1)
        raise TimeoutError(
            f"TX {txid[:16]} not in node {self.index} mempool "
            f"after {timeout}s"
        )

    def get_mempool_count(self) -> int:
        """Get the number of transactions in the mempool."""
        return len(self.getrawmempool())

    def assert_mempool_empty(self):
        """Assert that the mempool is empty."""
        count = self.get_mempool_count()
        if count != 0:
            raise AssertionError(
                f"Expected empty mempool on node {self.index}, "
                f"found {count} transactions"
            )

    # ------------------------------------------------------------------
    # UTXO helpers
    # ------------------------------------------------------------------

    def get_utxos(self, min_conf: int = 1,
                  max_conf: int = 9999999) -> list:
        """Get all UTXOs matching the confirmation criteria."""
        return self.listunspent(min_conf, max_conf)

    def get_utxo_count(self) -> int:
        """Get the number of spendable UTXOs."""
        return len(self.listunspent())

    def get_largest_utxo(self) -> Optional[dict]:
        """Get the UTXO with the largest value."""
        utxos = self.listunspent()
        if not utxos:
            return None
        return max(utxos, key=lambda u: float(u["amount"]))

    # ------------------------------------------------------------------
    # Wallet convenience methods
    # ------------------------------------------------------------------

    def get_wallet_balance(self) -> Decimal:
        """Get the wallet balance as a Decimal."""
        return Decimal(str(self.getbalance()))

    def assert_balance(self, expected: Decimal, message: str = ""):
        """Assert the wallet balance matches expected."""
        actual = self.get_wallet_balance()
        if abs(actual - expected) > Decimal("0.00000001"):
            raise AssertionError(
                f"Node {self.index} balance {actual} != expected "
                f"{expected}. {message}"
            )

    def fund_address(self, address: str, amount: float) -> str:
        """Send funds to an address and return the txid."""
        return self.sendtoaddress(address, amount)

    def create_funded_utxo(self, amount: float,
                           address: Optional[str] = None) -> dict:
        """Create a UTXO with the specified amount.

        Sends `amount` to an address, mines a block to confirm,
        and returns the resulting UTXO.
        """
        if address is None:
            address = self.getnewaddress()
        txid = self.sendtoaddress(address, amount)
        self.mine_blocks(1)

        # Find the UTXO
        utxos = self.listunspent()
        for utxo in utxos:
            if utxo["txid"] == txid:
                return utxo

        raise RuntimeError(f"Could not find UTXO for tx {txid[:16]}")

    # ------------------------------------------------------------------
    # Network helpers
    # ------------------------------------------------------------------

    def get_connection_count(self) -> int:
        """Get the number of peer connections."""
        return self.getconnectioncount()

    def get_peer_addresses(self) -> List[str]:
        """Get a list of connected peer addresses."""
        peers = self.getpeerinfo()
        return [p.get("addr", "") for p in peers]

    def is_connected_to(self, port: int) -> bool:
        """Check if this node is connected to a peer on the given port."""
        for addr in self.get_peer_addresses():
            if str(port) in addr:
                return True
        return False

    def wait_for_peer(self, port: int, timeout: int = 30):
        """Wait until connected to a peer on the given port."""
        start = time.time()
        while time.time() - start < timeout:
            if self.is_connected_to(port):
                return
            time.sleep(0.25)
        raise TimeoutError(
            f"Node {self.index} not connected to port {port} "
            f"after {timeout}s"
        )

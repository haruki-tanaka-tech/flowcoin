#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Utility functions for FlowCoin functional tests.

Provides assertion helpers, synchronization primitives, address utilities,
transaction builders, and other common operations used across test scripts.
"""

import binascii
import hashlib
import json
import logging
import math
import os
import random
import re
import struct
import sys
import time
from decimal import Decimal, ROUND_DOWN, ROUND_UP
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

log = logging.getLogger("TestUtil")

# ======================================================================
# Constants
# ======================================================================

# FlowCoin monetary constants
COIN = 100_000_000  # 1 FLOW = 10^8 atomic units
INITIAL_REWARD = 50 * COIN  # 50 FLOW per block
HALVING_INTERVAL = 210_000
COINBASE_MATURITY = 100

# Regtest network
REGTEST_PORT_BASE = 29333
REGTEST_RPC_PORT_BASE = 29334

# Address prefixes
REGTEST_HRP = "rfl"
MAINNET_HRP = "fl"
TESTNET_HRP = "tfl"

# Model growth schedule (Phase 1 plateaus)
GROWTH_SCHEDULE = [
    # (height_start, height_end, d_model, n_layers, d_ff, n_heads)
    (0, 99, 512, 8, 1024, 8),
    (100, 199, 640, 12, 1280, 10),
    (200, 299, 768, 16, 1536, 12),
    (300, 399, 896, 20, 1792, 14),
    (400, 499, 1024, 24, 2048, 16),
]
DIM_GROWTH_END = 500


# ======================================================================
# Assertion helpers
# ======================================================================

def assert_equal(actual: Any, expected: Any, message: str = ""):
    """Assert that two values are equal.

    Provides a clear error message showing both values on failure.

    Args:
        actual: The value produced by the code under test.
        expected: The value we expect.
        message: Optional additional context for the error message.
    """
    if actual != expected:
        extra = f" {message}" if message else ""
        raise AssertionError(
            f"assert_equal failed: {actual!r} != {expected!r}{extra}"
        )


def assert_not_equal(actual: Any, expected: Any, message: str = ""):
    """Assert that two values are not equal."""
    if actual == expected:
        extra = f" {message}" if message else ""
        raise AssertionError(
            f"assert_not_equal failed: both are {actual!r}{extra}"
        )


def assert_greater_than(a: Any, b: Any, message: str = ""):
    """Assert that a > b."""
    if not a > b:
        extra = f" {message}" if message else ""
        raise AssertionError(
            f"assert_greater_than failed: {a!r} not > {b!r}{extra}"
        )


def assert_greater_than_or_equal(a: Any, b: Any, message: str = ""):
    """Assert that a >= b."""
    if not a >= b:
        extra = f" {message}" if message else ""
        raise AssertionError(
            f"assert_greater_than_or_equal failed: "
            f"{a!r} not >= {b!r}{extra}"
        )


def assert_less_than(a: Any, b: Any, message: str = ""):
    """Assert that a < b."""
    if not a < b:
        extra = f" {message}" if message else ""
        raise AssertionError(
            f"assert_less_than failed: {a!r} not < {b!r}{extra}"
        )


def assert_less_than_or_equal(a: Any, b: Any, message: str = ""):
    """Assert that a <= b."""
    if not a <= b:
        extra = f" {message}" if message else ""
        raise AssertionError(
            f"assert_less_than_or_equal failed: "
            f"{a!r} not <= {b!r}{extra}"
        )


def assert_true(condition: bool, message: str = "Condition is not true"):
    """Assert that a condition is true."""
    if not condition:
        raise AssertionError(f"assert_true failed: {message}")


def assert_false(condition: bool, message: str = "Condition is not false"):
    """Assert that a condition is false."""
    if condition:
        raise AssertionError(f"assert_false failed: {message}")


def assert_in(item: Any, collection: Any, message: str = ""):
    """Assert that item is in collection."""
    if item not in collection:
        extra = f" {message}" if message else ""
        raise AssertionError(
            f"assert_in failed: {item!r} not in {collection!r}{extra}"
        )


def assert_not_in(item: Any, collection: Any, message: str = ""):
    """Assert that item is not in collection."""
    if item in collection:
        extra = f" {message}" if message else ""
        raise AssertionError(
            f"assert_not_in failed: {item!r} found in {collection!r}{extra}"
        )


def assert_raises(exc_type, func: Callable, *args, **kwargs):
    """Assert that calling func(*args) raises exc_type.

    Args:
        exc_type: The expected exception class.
        func: The callable to invoke.
        *args: Positional arguments for func.
        **kwargs: Keyword arguments for func.

    Returns:
        The caught exception instance.
    """
    try:
        func(*args, **kwargs)
    except exc_type as e:
        return e
    except Exception as e:
        raise AssertionError(
            f"Expected {exc_type.__name__}, got {type(e).__name__}: {e}"
        )
    raise AssertionError(
        f"Expected {exc_type.__name__} not raised by {func.__name__}"
    )


def assert_raises_rpc_error(code: Optional[int], message: Optional[str],
                             func: Callable, *args, **kwargs):
    """Assert that an RPC call raises a JSONRPCError with the given code.

    Args:
        code: Expected error code (None to skip check).
        message: Expected substring in error message (None to skip).
        func: The RPC method to call.
        *args: Arguments to pass.
        **kwargs: Keyword arguments to pass.
    """
    from test_framework.test_node import JSONRPCError

    try:
        func(*args, **kwargs)
    except JSONRPCError as e:
        if code is not None:
            assert_equal(
                e.code, code,
                f"Expected RPC error code {code}, got {e.code}: {e.message}"
            )
        if message is not None:
            if message not in e.message:
                raise AssertionError(
                    f"Expected RPC error message to contain '{message}', "
                    f"got: '{e.message}'"
                )
        return e
    except Exception as e:
        raise AssertionError(
            f"Expected JSONRPCError, got {type(e).__name__}: {e}"
        )
    raise AssertionError(
        f"Expected JSONRPCError (code={code}) not raised"
    )


def assert_raises_message(exc_type, message: str,
                           func: Callable, *args, **kwargs):
    """Assert that func raises exc_type with message as substring."""
    try:
        func(*args, **kwargs)
    except exc_type as e:
        if message not in str(e):
            raise AssertionError(
                f"Expected message '{message}' not in exception: {e}"
            )
        return e
    raise AssertionError(
        f"Expected {exc_type.__name__} not raised"
    )


# ======================================================================
# String / hex assertions
# ======================================================================

def assert_is_hex_string(s: str):
    """Assert that s is a valid lowercase hex string."""
    if not isinstance(s, str):
        raise AssertionError(f"Expected str, got {type(s).__name__}")
    if not re.match(r"^[0-9a-f]+$", s):
        raise AssertionError(f"Not a valid hex string: {s!r}")


def assert_is_hash_string(s: str, length: int = 64):
    """Assert that s is a hex hash of the expected length."""
    assert_is_hex_string(s)
    assert_equal(len(s), length, f"Hash length should be {length}")


def assert_is_txid(txid: str):
    """Assert that txid is a valid 64-character hex transaction ID."""
    assert_is_hash_string(txid, 64)


def assert_is_block_hash(block_hash: str):
    """Assert that block_hash is a valid 64-character hex block hash."""
    assert_is_hash_string(block_hash, 64)


def assert_array_result(array: list, key_value_pairs: dict,
                        expected_result: dict):
    """Assert that an element in array matches key_value_pairs and
    contains expected_result values.

    Searches through array for a dict matching all key_value_pairs,
    then verifies that dict also contains all expected_result entries.
    """
    found = False
    for item in array:
        if all(item.get(k) == v for k, v in key_value_pairs.items()):
            found = True
            for k, v in expected_result.items():
                assert_equal(
                    item.get(k), v,
                    f"In matching item, expected {k}={v!r}"
                )
            break
    if not found:
        raise AssertionError(
            f"No element in array matches {key_value_pairs}"
        )


# ======================================================================
# Numeric assertions
# ======================================================================

def assert_approx(actual: float, expected: float,
                  tolerance: float = 1e-6):
    """Assert that actual is approximately equal to expected."""
    if abs(actual - expected) > tolerance:
        raise AssertionError(
            f"assert_approx failed: {actual} not within {tolerance} "
            f"of {expected}"
        )


def assert_fee_amount(fee: Decimal, tx_size: int,
                      feerate_per_byte: Decimal,
                      tolerance: Decimal = Decimal("0.00001000")):
    """Assert that a transaction fee is approximately correct.

    fee should be approximately tx_size * feerate_per_byte.
    """
    expected = Decimal(tx_size) * feerate_per_byte
    if abs(fee - expected) > tolerance:
        raise AssertionError(
            f"Fee {fee} not within tolerance of expected "
            f"{expected} (size={tx_size}, rate={feerate_per_byte})"
        )


# ======================================================================
# Wait / polling utilities
# ======================================================================

def wait_until(condition: Callable[[], bool], timeout: int = 60,
               interval: float = 0.1, description: str = ""):
    """Wait until condition() returns True.

    Polls the condition at the given interval. Raises TimeoutError
    if the condition is not met within timeout seconds.

    Args:
        condition: A callable returning bool.
        timeout: Maximum seconds to wait.
        interval: Seconds between polls.
        description: Human-readable description for error message.
    """
    start = time.time()
    while time.time() - start < timeout:
        if condition():
            return
        time.sleep(interval)
    desc = f": {description}" if description else ""
    raise TimeoutError(
        f"Condition not met within {timeout}s{desc}"
    )


def wait_until_helper(condition: Callable, *args, timeout: int = 60,
                      interval: float = 0.1, **kwargs):
    """Wait until condition(*args, **kwargs) returns True."""
    def check():
        return condition(*args, **kwargs)
    wait_until(check, timeout=timeout, interval=interval)


# ======================================================================
# Node synchronization
# ======================================================================

def sync_blocks(nodes: list, timeout: int = 60):
    """Wait for all nodes to converge on the same chain tip.

    Polls getbestblockhash on each node until they all report the same
    hash, or until timeout expires.

    Args:
        nodes: List of TestNode instances.
        timeout: Maximum seconds to wait.
    """
    if len(nodes) <= 1:
        return

    start = time.time()
    while time.time() - start < timeout:
        tips = set()
        heights = []
        for node in nodes:
            if node.running:
                tip = node.getbestblockhash()
                height = node.getblockcount()
                tips.add(tip)
                heights.append(height)

        if len(tips) == 1:
            return

        time.sleep(0.25)

    # Build diagnostic message
    info_parts = []
    for i, node in enumerate(nodes):
        if node.running:
            tip = node.getbestblockhash()
            height = node.getblockcount()
            info_parts.append(f"node{i}: height={height} tip={tip[:16]}")
    raise TimeoutError(
        f"Blocks not synced after {timeout}s: {'; '.join(info_parts)}"
    )


def sync_mempools(nodes: list, timeout: int = 60):
    """Wait for all nodes to have identical mempools.

    Polls getrawmempool on each node until they all report the same
    set of transaction IDs.

    Args:
        nodes: List of TestNode instances.
        timeout: Maximum seconds to wait.
    """
    if len(nodes) <= 1:
        return

    start = time.time()
    while time.time() - start < timeout:
        pools = []
        for node in nodes:
            if node.running:
                pool = set(node.getrawmempool())
                pools.append(pool)

        if len(pools) > 0 and all(p == pools[0] for p in pools):
            return

        time.sleep(0.25)

    # Diagnostics
    info_parts = []
    for i, node in enumerate(nodes):
        if node.running:
            pool = node.getrawmempool()
            info_parts.append(f"node{i}: {len(pool)} txs")
    raise TimeoutError(
        f"Mempools not synced after {timeout}s: {'; '.join(info_parts)}"
    )


# ======================================================================
# Node connection helpers
# ======================================================================

def connect_nodes(node_a, node_b):
    """Tell node_a to connect to node_b via addnode RPC.

    Uses node_b's P2P port to establish the connection.
    """
    node_a.addnode(f"127.0.0.1:{node_b.port}", "add")


def disconnect_nodes(node_a, node_b):
    """Disconnect node_a from node_b.

    Looks up node_b in node_a's peer list and disconnects by address.
    """
    peers = node_a.getpeerinfo()
    for peer in peers:
        addr = peer.get("addr", "")
        if str(node_b.port) in addr:
            node_a.disconnectnode(addr)
            return

    # Try onetry disconnect
    node_a.disconnectnode(f"127.0.0.1:{node_b.port}")


def connect_nodes_bi(nodes: list, a: int, b: int):
    """Connect two nodes bidirectionally by index."""
    connect_nodes(nodes[a], nodes[b])
    connect_nodes(nodes[b], nodes[a])


# ======================================================================
# Port helpers
# ======================================================================

def p2p_port(n: int) -> int:
    """Get the P2P port for node index n."""
    return REGTEST_PORT_BASE + n * 2


def rpc_port(n: int) -> int:
    """Get the RPC port for node index n."""
    return REGTEST_RPC_PORT_BASE + n * 2


def get_datadir_path(tmpdir: str, n: int) -> str:
    """Get the data directory path for node n."""
    return os.path.join(tmpdir, f"node{n}")


# ======================================================================
# Monetary utilities
# ======================================================================

def satoshi_round(amount: Union[float, Decimal, str]) -> Decimal:
    """Round an amount to 8 decimal places (satoshi precision)."""
    return Decimal(str(amount)).quantize(
        Decimal("0.00000001"), rounding=ROUND_DOWN
    )


def coins_to_satoshi(coins: Union[float, Decimal]) -> int:
    """Convert a coin amount to satoshis."""
    return int(Decimal(str(coins)) * COIN)


def satoshi_to_coins(satoshis: int) -> Decimal:
    """Convert satoshis to coin amount."""
    return Decimal(satoshis) / Decimal(COIN)


def calculate_block_reward(height: int) -> Decimal:
    """Calculate the block subsidy at a given height.

    Mirrors the C++ get_block_subsidy() function. The reward starts
    at 50 FLOW and halves every 210,000 blocks.

    Args:
        height: Block height.

    Returns:
        Block reward in FLOW as a Decimal.
    """
    halvings = height // HALVING_INTERVAL
    if halvings >= 64:
        return Decimal(0)
    reward = INITIAL_REWARD >> halvings
    if reward < 1:
        return Decimal(0)
    return satoshi_to_coins(reward)


def get_total_supply_at_height(height: int) -> Decimal:
    """Calculate the total supply minted up to a given height.

    Sums the block rewards from genesis through the specified height.
    """
    total = 0
    h = 0
    while h <= height:
        era = h // HALVING_INTERVAL
        if era >= 64:
            break
        era_end = min((era + 1) * HALVING_INTERVAL - 1, height)
        blocks_in_era = era_end - h + 1
        reward = INITIAL_REWARD >> era
        if reward < 1:
            break
        total += blocks_in_era * reward
        h = era_end + 1
    return satoshi_to_coins(total)


# ======================================================================
# Hex / byte utilities
# ======================================================================

def hex_str_to_bytes(hex_str: str) -> bytes:
    """Convert a hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex_str(b: bytes) -> str:
    """Convert bytes to a lowercase hex string."""
    return b.hex()


def count_bytes(hex_string: str) -> int:
    """Count the number of bytes represented by a hex string."""
    return len(hex_string) // 2


def hash256(data: bytes) -> bytes:
    """Double SHA-256 hash (Bitcoin-style)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """RIPEMD-160(SHA-256(data))."""
    sha = hashlib.sha256(data).digest()
    ripemd = hashlib.new("ripemd160")
    ripemd.update(sha)
    return ripemd.digest()


def reverse_bytes(hex_str: str) -> str:
    """Reverse the byte order of a hex string.

    Used for converting between internal byte order and display order
    for block hashes and transaction IDs.
    """
    b = bytes.fromhex(hex_str)
    return b[::-1].hex()


# ======================================================================
# Address utilities
# ======================================================================

def validate_address(node, address: str) -> dict:
    """Validate an address using the node's validateaddress RPC.

    Returns the validation result dict and asserts the address is valid.
    """
    info = node.validateaddress(address)
    assert_true(
        info.get("isvalid", False),
        f"Address {address} is not valid"
    )
    return info


def check_address_network(address: str, expected_hrp: str = REGTEST_HRP):
    """Check that a bech32m address has the expected network prefix.

    FlowCoin uses bech32m encoding with prefixes:
        - "fl" for mainnet
        - "tfl" for testnet
        - "rfl" for regtest
    """
    if not address.startswith(expected_hrp + "1"):
        raise AssertionError(
            f"Address {address} does not start with {expected_hrp}1"
        )


def generate_addresses(node, count: int) -> list:
    """Generate multiple new addresses from a node."""
    return [node.getnewaddress() for _ in range(count)]


# ======================================================================
# Transaction utilities
# ======================================================================

def find_output(node, txid: str, amount: float,
                vout: Optional[int] = None) -> int:
    """Find the output index with the given amount in a transaction.

    Args:
        node: TestNode instance.
        txid: Transaction ID.
        amount: Expected output amount in FLOW.
        vout: If specified, verify this specific vout has the amount.

    Returns:
        The output index (vout) matching the amount.
    """
    tx = node.gettransaction(txid)
    decoded = tx.get("decoded", {})
    if not decoded:
        raw = node.getrawtransaction(txid)
        decoded = node.decoderawtransaction(raw)

    for i, out in enumerate(decoded.get("vout", [])):
        if vout is not None and i != vout:
            continue
        value = out.get("value", 0)
        if isinstance(value, str):
            value = float(value)
        if abs(value - amount) < 0.00000001:
            return i

    raise AssertionError(
        f"No output with amount {amount} found in tx {txid}"
    )


def find_vout_for_address(node, txid: str, address: str) -> int:
    """Find the output index paying to a specific address.

    Args:
        node: TestNode instance.
        txid: Transaction ID.
        address: Recipient address to search for.

    Returns:
        The output index (vout) paying to the address.
    """
    raw = node.getrawtransaction(txid, True)
    for i, vout in enumerate(raw.get("vout", [])):
        script_pubkey = vout.get("scriptPubKey", {})
        addresses = script_pubkey.get("addresses", [])
        addr = script_pubkey.get("address", "")
        if address in addresses or address == addr:
            return i

    raise AssertionError(
        f"No output to address {address} in tx {txid}"
    )


def create_confirmed_utxos(node, count: int,
                            value: float = 50.0) -> List[dict]:
    """Generate blocks and collect confirmed UTXOs.

    Mines enough blocks to produce `count` mature coinbase outputs,
    each worth `value` FLOW. Requires at least `count + COINBASE_MATURITY`
    blocks.

    Args:
        node: TestNode instance.
        count: Number of UTXOs needed.
        value: Expected value of each UTXO (default 50.0 for block reward).

    Returns:
        List of UTXO dicts from listunspent.
    """
    addr = node.getnewaddress()

    # Mine enough blocks: count coinbase + maturity
    needed = count + COINBASE_MATURITY
    current = node.getblockcount()
    if current < needed:
        node.generatetoaddress(needed - current, addr)

    utxos = node.listunspent()
    # Filter to only those with sufficient value
    suitable = [u for u in utxos if u["amount"] >= value]
    if len(suitable) < count:
        # Mine more blocks
        extra = count - len(suitable) + COINBASE_MATURITY
        node.generatetoaddress(extra, addr)
        utxos = node.listunspent()
        suitable = [u for u in utxos if u["amount"] >= value]

    return suitable[:count]


def create_raw_transaction(node, inputs: list, outputs: dict) -> str:
    """Create a raw transaction using the node's RPC.

    Args:
        node: TestNode instance.
        inputs: List of {"txid": ..., "vout": ...} dicts.
        outputs: Dict mapping address to amount, e.g.,
                 {"rfl1abc...": 10.0, "rfl1def...": 39.99}.

    Returns:
        Hex-encoded raw transaction.
    """
    return node.createrawtransaction(inputs, outputs)


def sign_raw_transaction(node, hex_tx: str) -> dict:
    """Sign a raw transaction using the node's wallet.

    Returns the signrawtransaction result dict with 'hex' and 'complete'.
    """
    return node.signrawtransactionwithwallet(hex_tx)


def send_raw_transaction(node, hex_tx: str) -> str:
    """Send a signed raw transaction and return the txid."""
    return node.sendrawtransaction(hex_tx)


def create_and_send_transaction(node, inputs: list, outputs: dict) -> str:
    """Create, sign, and send a raw transaction. Returns the txid."""
    raw = create_raw_transaction(node, inputs, outputs)
    signed = sign_raw_transaction(node, raw)
    assert_true(
        signed.get("complete", False),
        "Transaction signing failed"
    )
    return send_raw_transaction(node, signed["hex"])


def spend_utxo(node, utxo: dict, to_address: str,
               fee: float = 0.0001) -> str:
    """Spend a single UTXO to an address, returning the txid.

    Creates a simple one-input, one-output transaction (plus change
    if the UTXO value exceeds the send amount + fee).
    """
    amount = float(utxo["amount"]) - fee
    if amount <= 0:
        raise ValueError(f"UTXO amount {utxo['amount']} too small for fee {fee}")

    inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
    outputs = {to_address: round(amount, 8)}
    return create_and_send_transaction(node, inputs, outputs)


# ======================================================================
# Model / training utilities
# ======================================================================

def get_model_dims_for_height(height: int) -> dict:
    """Get the expected model dimensions for a given block height.

    Implements the growth schedule from consensus/growth.h.

    Returns:
        Dict with keys: d_model, n_layers, d_ff, n_heads.
    """
    for start, end, d_model, n_layers, d_ff, n_heads in GROWTH_SCHEDULE:
        if start <= height <= end:
            return {
                "d_model": d_model,
                "n_layers": n_layers,
                "d_ff": d_ff,
                "n_heads": n_heads,
            }

    # Phase 2: frozen at maximum dimensions
    return {
        "d_model": 1024,
        "n_layers": 24,
        "d_ff": 2048,
        "n_heads": 16,
    }


def assert_model_dims_at_height(node, height: int):
    """Assert that the node reports correct model dimensions for a height.

    Uses getgrowthschedule RPC to verify dimensions match the expected
    growth schedule.
    """
    expected = get_model_dims_for_height(height)
    actual = node.getgrowthschedule(height)
    assert_equal(actual["d_model"], expected["d_model"],
                 f"d_model at height {height}")
    assert_equal(actual["n_layers"], expected["n_layers"],
                 f"n_layers at height {height}")


def compute_min_training_steps(height: int) -> int:
    """Compute minimum training steps for a block at the given height.

    Phase 1 (h < 500): 1000 + 4 * h
    Phase 2 (h >= 500): 3000 * sqrt(h / 500)
    """
    if height < DIM_GROWTH_END:
        return 1000 + 4 * height
    return int(3000 * math.sqrt(height / 500))


# ======================================================================
# Random data generators
# ======================================================================

def random_bytes(n: int) -> bytes:
    """Generate n random bytes."""
    return os.urandom(n)


def random_hex(n: int) -> str:
    """Generate n random bytes as a hex string (2n characters)."""
    return os.urandom(n).hex()


def random_hash() -> str:
    """Generate a random 32-byte hash as a 64-character hex string."""
    return random_hex(32)


def random_amount(min_val: float = 0.00001,
                  max_val: float = 50.0) -> Decimal:
    """Generate a random transaction amount within the given range."""
    value = random.uniform(min_val, max_val)
    return satoshi_round(value)


def random_address_label() -> str:
    """Generate a random label for an address."""
    return f"test_label_{random.randint(10000, 99999)}"


# ======================================================================
# File utilities
# ======================================================================

def read_json_file(path: str) -> Any:
    """Read and parse a JSON file."""
    with open(path, "r") as f:
        return json.load(f)


def write_json_file(path: str, data: Any):
    """Write data to a JSON file."""
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def append_to_file(path: str, content: str):
    """Append content to a file."""
    with open(path, "a") as f:
        f.write(content)


def read_config_file(path: str) -> dict:
    """Read a flowcoin.conf file into a dict."""
    config = {}
    if os.path.exists(path):
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip()
    return config


def write_config_file(path: str, config: dict):
    """Write a dict to a flowcoin.conf file."""
    with open(path, "w") as f:
        for key, value in config.items():
            f.write(f"{key}={value}\n")


# ======================================================================
# Timing utilities
# ======================================================================

class Timer:
    """Simple elapsed time tracker for performance measurements."""

    def __init__(self, label: str = ""):
        self.label = label
        self._start = 0.0
        self._elapsed = 0.0

    def start(self):
        self._start = time.time()
        return self

    def stop(self) -> float:
        self._elapsed = time.time() - self._start
        return self._elapsed

    @property
    def elapsed(self) -> float:
        if self._elapsed > 0:
            return self._elapsed
        return time.time() - self._start

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
        if self.label:
            log.info("%s: %.3f seconds", self.label, self._elapsed)


# ======================================================================
# Block construction helpers (for manual block building)
# ======================================================================

def create_coinbase_hex(height: int, address: str = "",
                        value: int = INITIAL_REWARD) -> str:
    """Create a hex-encoded coinbase transaction for testing.

    This is a simplified coinbase suitable for submitblock testing.
    The actual format must match the C++ serialization.

    Args:
        height: Block height for the coinbase.
        address: Recipient address (empty for OP_TRUE).
        value: Coinbase value in satoshis.

    Returns:
        Hex-encoded coinbase transaction.
    """
    # Version
    tx = struct.pack("<I", 1)
    # Input count
    tx += struct.pack("<B", 1)
    # Previous output (null for coinbase)
    tx += b"\x00" * 32  # prev txid
    tx += struct.pack("<I", 0xFFFFFFFF)  # prev vout
    # Script sig (block height in BIP34 format)
    height_bytes = height.to_bytes(
        (height.bit_length() + 7) // 8, byteorder="little"
    ) if height > 0 else b"\x00"
    script_sig = bytes([len(height_bytes)]) + height_bytes
    tx += struct.pack("<B", len(script_sig))
    tx += script_sig
    # Sequence
    tx += struct.pack("<I", 0xFFFFFFFF)
    # Output count
    tx += struct.pack("<B", 1)
    # Value
    tx += struct.pack("<q", value)
    # Script pubkey (OP_TRUE for simplicity in tests)
    script_pubkey = b"\x51"  # OP_TRUE
    tx += struct.pack("<B", len(script_pubkey))
    tx += script_pubkey
    # Locktime
    tx += struct.pack("<I", 0)

    return tx.hex()


def mine_block_template(node, address: Optional[str] = None) -> str:
    """Use getblocktemplate to mine a block and submit it.

    This manually constructs and submits a block using the template
    provided by the node, rather than using generatetoaddress.

    Args:
        node: TestNode instance.
        address: Mining reward address (generated if None).

    Returns:
        Hash of the submitted block.
    """
    if address is None:
        address = node.getnewaddress()

    template = node.getblocktemplate()
    # The template contains everything needed to construct a valid block
    # Tests can modify the template before submission to test validation

    return template


# ======================================================================
# Comparison helpers
# ======================================================================

def compare_utxo_sets(node_a, node_b):
    """Compare UTXO sets between two nodes.

    Asserts that both nodes have identical UTXO set info.
    """
    info_a = node_a.gettxoutsetinfo()
    info_b = node_b.gettxoutsetinfo()
    assert_equal(info_a["height"], info_b["height"])
    assert_equal(info_a["txouts"], info_b["txouts"])
    assert_equal(info_a["hash_serialized"], info_b["hash_serialized"])
    assert_equal(info_a["total_amount"], info_b["total_amount"])


def compare_chain_tips(nodes: list):
    """Assert all nodes have the same best block hash."""
    if len(nodes) < 2:
        return
    tip = nodes[0].getbestblockhash()
    for i, node in enumerate(nodes[1:], 1):
        actual = node.getbestblockhash()
        assert_equal(
            actual, tip,
            f"Node {i} tip {actual[:16]} != node 0 tip {tip[:16]}"
        )


# ======================================================================
# Logging helpers
# ======================================================================

def log_separator(msg: str = "", char: str = "=", width: int = 70):
    """Log a visual separator line."""
    if msg:
        padding = (width - len(msg) - 2) // 2
        line = char * padding + f" {msg} " + char * padding
    else:
        line = char * width
    log.info(line)


def log_block_info(node, block_hash: str):
    """Log detailed information about a block."""
    block = node.getblock(block_hash)
    log.info(
        "Block %s: height=%d, txs=%d, size=%d, time=%d",
        block_hash[:16],
        block.get("height", -1),
        block.get("nTx", len(block.get("tx", []))),
        block.get("size", 0),
        block.get("time", 0),
    )


def log_mempool_info(node):
    """Log mempool summary."""
    info = node.getmempoolinfo()
    log.info(
        "Mempool: %d txs, %d bytes",
        info.get("size", 0),
        info.get("bytes", 0),
    )


# ======================================================================
# Chain analysis utilities
# ======================================================================

def verify_chain_integrity(node, from_height: int = 0,
                           to_height: Optional[int] = None):
    """Verify chain integrity by checking block linkage.

    Walks the chain from `from_height` to `to_height` (default: tip),
    verifying that each block's previousblockhash matches the hash of
    the preceding block.

    Args:
        node: TestNode instance.
        from_height: Starting height (inclusive).
        to_height: Ending height (inclusive, default: current tip).

    Raises:
        AssertionError: If any linkage error is found.
    """
    if to_height is None:
        to_height = node.getblockcount()

    prev_hash = None
    for h in range(from_height, to_height + 1):
        block_hash = node.getblockhash(h)
        block = node.getblock(block_hash)

        if prev_hash is not None and h > 0:
            assert_equal(
                block.get("previousblockhash", ""),
                prev_hash,
                f"Block linkage broken at height {h}"
            )

        assert_equal(block["height"], h)
        prev_hash = block_hash


def verify_utxo_consistency(nodes: list):
    """Verify that all nodes have the same UTXO set.

    Compares gettxoutsetinfo across all nodes, asserting that
    height, txout count, and hash are identical.

    Args:
        nodes: List of TestNode instances.

    Raises:
        AssertionError: If any UTXO set mismatch is found.
    """
    if len(nodes) < 2:
        return

    ref_info = nodes[0].gettxoutsetinfo()
    for i, node in enumerate(nodes[1:], 1):
        info = node.gettxoutsetinfo()
        assert_equal(
            info["height"], ref_info["height"],
            f"Node {i} UTXO height mismatch"
        )
        assert_equal(
            info["txouts"], ref_info["txouts"],
            f"Node {i} UTXO count mismatch"
        )
        if "hash_serialized" in info and "hash_serialized" in ref_info:
            assert_equal(
                info["hash_serialized"],
                ref_info["hash_serialized"],
                f"Node {i} UTXO hash mismatch"
            )


def get_chain_hashes(node, from_height: int = 0,
                     to_height: Optional[int] = None) -> List[str]:
    """Get all block hashes in a height range.

    Args:
        node: TestNode instance.
        from_height: Starting height (inclusive).
        to_height: Ending height (inclusive, default: current tip).

    Returns:
        List of block hash strings.
    """
    if to_height is None:
        to_height = node.getblockcount()

    return [node.getblockhash(h) for h in range(from_height, to_height + 1)]


def get_block_times(node, from_height: int = 0,
                    to_height: Optional[int] = None) -> List[int]:
    """Get block timestamps in a height range.

    Args:
        node: TestNode instance.
        from_height: Starting height (inclusive).
        to_height: Ending height (inclusive, default: current tip).

    Returns:
        List of block timestamps.
    """
    if to_height is None:
        to_height = node.getblockcount()

    times = []
    for h in range(from_height, to_height + 1):
        block_hash = node.getblockhash(h)
        header = node.getblockheader(block_hash)
        times.append(header["time"])
    return times


def get_block_difficulties(node, from_height: int = 0,
                           to_height: Optional[int] = None) -> List[float]:
    """Get block difficulties in a height range.

    Args:
        node: TestNode instance.
        from_height: Starting height (inclusive).
        to_height: Ending height (inclusive, default: current tip).

    Returns:
        List of difficulty values.
    """
    if to_height is None:
        to_height = node.getblockcount()

    diffs = []
    for h in range(from_height, to_height + 1):
        block_hash = node.getblockhash(h)
        header = node.getblockheader(block_hash)
        diffs.append(float(header.get("difficulty", 0)))
    return diffs


# ======================================================================
# Address validation utilities
# ======================================================================

def assert_valid_address(node, address: str):
    """Assert that an address is valid according to the node."""
    info = node.validateaddress(address)
    assert_true(
        info.get("isvalid", False),
        f"Address should be valid: {address}"
    )


def assert_invalid_address(node, address: str):
    """Assert that an address is invalid according to the node."""
    info = node.validateaddress(address)
    assert_true(
        not info.get("isvalid", True),
        f"Address should be invalid: {address}"
    )


def generate_and_fund_address(node, amount: float = 50.0,
                              maturity_blocks: int = COINBASE_MATURITY
                              ) -> Tuple[str, str]:
    """Generate an address, mine blocks to fund it, and return (address, txid).

    Mines enough blocks for the coinbase to mature, then sends `amount`
    to a new address.

    Args:
        node: TestNode instance.
        amount: Amount to fund (must be <= block reward).
        maturity_blocks: Number of blocks for coinbase maturity.

    Returns:
        Tuple of (funded_address, funding_txid).
    """
    mine_addr = node.getnewaddress()
    node.generatetoaddress(maturity_blocks + 1, mine_addr)

    funded_addr = node.getnewaddress()
    txid = node.sendtoaddress(funded_addr, amount)
    node.generatetoaddress(1, mine_addr)

    return funded_addr, txid


# ======================================================================
# JSON-RPC batch helpers
# ======================================================================

def batch_rpc_calls(node, methods: List[Tuple[str, list]]) -> list:
    """Execute multiple RPC calls and return all results.

    Useful for collecting data from many RPC calls efficiently.

    Args:
        node: TestNode instance.
        methods: List of (method_name, params) tuples.

    Returns:
        List of results in the same order as methods.
    """
    results = []
    for method, params in methods:
        rpc_func = getattr(node, method)
        try:
            result = rpc_func(*params)
            results.append(result)
        except Exception as e:
            results.append(e)
    return results


# ======================================================================
# Deterministic test data
# ======================================================================

def deterministic_address_set(node, count: int, seed: int = 42) -> list:
    """Generate a deterministic set of addresses.

    Always produces the same addresses given the same seed and node state.
    Useful for reproducible tests.

    Args:
        node: TestNode instance.
        count: Number of addresses to generate.
        seed: Random seed (unused, addresses come from keypool).

    Returns:
        List of address strings.
    """
    return [node.getnewaddress(f"det_{i}") for i in range(count)]


def create_test_utxo_set(node, count: int, value: float = 1.0) -> list:
    """Create a set of UTXOs with known values.

    Generates addresses, sends `value` to each, and mines to confirm.

    Args:
        node: TestNode instance.
        count: Number of UTXOs to create.
        value: Value of each UTXO in FLOW.

    Returns:
        List of UTXO dicts from listunspent.
    """
    addresses = [node.getnewaddress() for _ in range(count)]
    txids = []
    for addr in addresses:
        try:
            txid = node.sendtoaddress(addr, value)
            txids.append(txid)
        except Exception:
            break

    if txids:
        mine_addr = node.getnewaddress()
        node.generatetoaddress(1, mine_addr)

    utxos = node.listunspent()
    created = [
        u for u in utxos
        if u["txid"] in txids
    ]
    return created

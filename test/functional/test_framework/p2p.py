#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""P2P connection for functional testing.

Provides low-level and high-level interfaces for connecting directly to
flowcoind's P2P port, exchanging messages, and testing protocol behavior.
This bypasses the RPC layer entirely, allowing tests to verify wire protocol
handling, message validation, ban logic, and peer management.

Architecture:
    P2PConnection  - Raw socket connection with send/receive buffering.
    P2PInterface   - Higher-level interface with version handshake,
                     message routing, and convenience methods.
    P2PDataStore   - Interface that stores received blocks/txs for inspection.
    MiniNode       - Full-featured miniature node for advanced tests.

Usage::

    p2p = P2PInterface()
    p2p.connect("127.0.0.1", 29333)
    p2p.perform_handshake()
    p2p.send_message("ping", msg_ping(12345))
    response = p2p.wait_for_message("pong")
    p2p.disconnect()
"""

import collections
import hashlib
import logging
import os
import queue
import random
import select
import socket
import struct
import threading
import time
from io import BytesIO
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from test_framework.messages import (
    MAGIC_REGTEST,
    PROTOCOL_VERSION,
    NODE_NETWORK,
    NODE_TRAINING,
    MAX_MESSAGE_SIZE,
    MessageHeader,
    CBlock,
    CBlockHeader,
    CTransaction,
    CInv,
    NetAddress,
    BlockLocator,
    sha256d,
    compute_checksum,
    ser_uint256,
    deser_uint256,
    ser_compact_size,
    deser_compact_size,
    uint256_from_hex,
    uint256_to_hex,
    msg_version,
    msg_verack,
    msg_ping,
    msg_pong,
    msg_getblocks,
    msg_getheaders,
    msg_headers,
    msg_inv,
    msg_getdata,
    msg_block,
    msg_tx,
    msg_addr,
    msg_getaddr,
    msg_mempool,
    msg_reject,
    msg_sendheaders,
    msg_feefilter,
    MSG_TX,
    MSG_BLOCK,
)

log = logging.getLogger("P2P")


# ======================================================================
# Connection state
# ======================================================================

class ConnectionState:
    """Track the state of a P2P connection."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    HANDSHAKING = "handshaking"
    READY = "ready"
    CLOSING = "closing"


# ======================================================================
# Received message container
# ======================================================================

class ReceivedMessage:
    """A message received from a peer.

    Attributes:
        command: The message command name (e.g., "version", "block").
        payload: The raw payload bytes.
        timestamp: When the message was received.
    """

    def __init__(self, command: str, payload: bytes):
        self.command = command
        self.payload = payload
        self.timestamp = time.time()

    def __repr__(self) -> str:
        return (
            f"<ReceivedMessage cmd={self.command!r} "
            f"size={len(self.payload)}>"
        )


# ======================================================================
# P2PConnection: Raw socket layer
# ======================================================================

class P2PConnection:
    """Direct P2P socket connection to a flowcoind node.

    Handles:
        - TCP connection establishment and teardown.
        - Send buffering and framing (header + payload).
        - Receive buffering with automatic message parsing.
        - Background receive thread for non-blocking operation.

    This is the low-level transport; use P2PInterface for protocol logic.
    """

    def __init__(self, magic: int = MAGIC_REGTEST):
        self.magic = magic
        self.sock: Optional[socket.socket] = None
        self.recvbuf = b""
        self.sendbuf = b""
        self.messages: List[ReceivedMessage] = []
        self.message_queue: queue.Queue = queue.Queue()
        self.connected = False
        self.state = ConnectionState.DISCONNECTED
        self._recv_thread: Optional[threading.Thread] = None
        self._send_lock = threading.Lock()
        self._recv_lock = threading.Lock()
        self._message_callbacks: Dict[str, List[Callable]] = {}
        self._total_bytes_sent = 0
        self._total_bytes_recv = 0
        self._message_count_sent = 0
        self._message_count_recv = 0
        self._last_recv_time = 0.0
        self._last_send_time = 0.0
        self._peer_host = ""
        self._peer_port = 0
        self._log = logging.getLogger(f"P2PConnection")

    def connect(self, host: str, port: int, timeout: int = 10):
        """Establish a TCP connection to the peer.

        Args:
            host: Peer hostname or IP address.
            port: Peer P2P port.
            timeout: Connection timeout in seconds.

        Raises:
            ConnectionError: If the connection fails.
        """
        self._peer_host = host
        self._peer_port = port
        self.state = ConnectionState.CONNECTING
        self._log = logging.getLogger(f"P2P({host}:{port})")

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.sock.connect((host, port))
            self.connected = True
            self.state = ConnectionState.CONNECTED
            self._log.debug("Connected to %s:%d", host, port)

            # Start background receive thread
            self._recv_thread = threading.Thread(
                target=self._recv_loop, daemon=True,
                name=f"P2P-recv-{host}:{port}"
            )
            self._recv_thread.start()

        except (socket.error, OSError) as e:
            self.state = ConnectionState.DISCONNECTED
            raise ConnectionError(f"Failed to connect to {host}:{port}: {e}")

    def send_message(self, command: str, payload: bytes = b""):
        """Send a P2P message with proper framing.

        Constructs the 24-byte header (magic, command, size, checksum)
        and sends header + payload as a single write.

        Args:
            command: Message command name (max 12 chars).
            payload: Message payload bytes.

        Raises:
            ConnectionError: If the socket is not connected.
        """
        if not self.connected:
            raise ConnectionError("Not connected")

        if len(payload) > MAX_MESSAGE_SIZE:
            raise ValueError(
                f"Payload too large: {len(payload)} > {MAX_MESSAGE_SIZE}"
            )

        # Build header
        checksum = compute_checksum(payload)
        cmd_bytes = command.encode("ascii")[:12].ljust(12, b"\x00")
        header = (
            struct.pack("<I", self.magic) +
            cmd_bytes +
            struct.pack("<I", len(payload)) +
            checksum
        )

        data = header + payload

        with self._send_lock:
            try:
                self.sock.sendall(data)
                self._total_bytes_sent += len(data)
                self._message_count_sent += 1
                self._last_send_time = time.time()
                self._log.debug(
                    "Sent %s (%d bytes payload)", command, len(payload)
                )
            except (socket.error, OSError) as e:
                self.connected = False
                self.state = ConnectionState.DISCONNECTED
                raise ConnectionError(f"Send failed: {e}")

    def send_raw(self, data: bytes):
        """Send raw bytes without message framing.

        Used for testing malformed message handling.
        """
        if not self.connected:
            raise ConnectionError("Not connected")
        with self._send_lock:
            self.sock.sendall(data)
            self._total_bytes_sent += len(data)

    def wait_for_message(self, command: str,
                         timeout: int = 10) -> ReceivedMessage:
        """Wait for a specific message type to be received.

        Scans both the message backlog and incoming messages.

        Args:
            command: The message command to wait for.
            timeout: Maximum seconds to wait.

        Returns:
            The received message.

        Raises:
            TimeoutError: If the message is not received in time.
        """
        start = time.time()

        # Check existing messages first
        with self._recv_lock:
            for msg in self.messages:
                if msg.command == command:
                    self.messages.remove(msg)
                    return msg

        # Wait for new messages
        while time.time() - start < timeout:
            try:
                msg = self.message_queue.get(timeout=0.1)
                if msg.command == command:
                    return msg
                # Store non-matching messages
                with self._recv_lock:
                    self.messages.append(msg)
            except queue.Empty:
                continue

        raise TimeoutError(
            f"Did not receive '{command}' message within {timeout}s"
        )

    def wait_for_any_message(self, timeout: int = 10) -> ReceivedMessage:
        """Wait for any message to arrive."""
        try:
            return self.message_queue.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError(
                f"No message received within {timeout}s"
            )

    def has_message(self, command: str) -> bool:
        """Check if a message of the given type has been received."""
        with self._recv_lock:
            return any(m.command == command for m in self.messages)

    def get_messages(self, command: str) -> List[ReceivedMessage]:
        """Get all received messages of a given type."""
        with self._recv_lock:
            matching = [m for m in self.messages if m.command == command]
            self.messages = [m for m in self.messages if m.command != command]
            return matching

    def clear_messages(self):
        """Clear all received messages."""
        with self._recv_lock:
            self.messages.clear()
        # Drain queue
        while not self.message_queue.empty():
            try:
                self.message_queue.get_nowait()
            except queue.Empty:
                break

    def register_callback(self, command: str, callback: Callable):
        """Register a callback for a specific message type.

        The callback receives (command, payload) and is called from the
        receive thread.
        """
        if command not in self._message_callbacks:
            self._message_callbacks[command] = []
        self._message_callbacks[command].append(callback)

    def disconnect(self):
        """Close the connection gracefully."""
        self._log.debug("Disconnecting")
        self.connected = False
        self.state = ConnectionState.DISCONNECTED
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except (socket.error, OSError):
                pass
            try:
                self.sock.close()
            except (socket.error, OSError):
                pass
            self.sock = None

        # Wait for receive thread to finish
        if self._recv_thread and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=2)

    def _recv_loop(self):
        """Background thread: continuously receive and parse messages.

        Reads data from the socket into recvbuf, then extracts complete
        messages (header + payload) and dispatches them to callbacks
        and the message queue.
        """
        while self.connected:
            try:
                # Use select for non-blocking read with timeout
                ready, _, _ = select.select([self.sock], [], [], 0.5)
                if not ready:
                    continue

                data = self.sock.recv(65536)
                if not data:
                    self._log.debug("Connection closed by peer")
                    self.connected = False
                    self.state = ConnectionState.DISCONNECTED
                    break

                self._total_bytes_recv += len(data)
                self._last_recv_time = time.time()

                with self._recv_lock:
                    self.recvbuf += data
                self._process_buffer()

            except socket.timeout:
                continue
            except (socket.error, OSError) as e:
                if self.connected:
                    self._log.debug("Receive error: %s", e)
                self.connected = False
                self.state = ConnectionState.DISCONNECTED
                break

    def _process_buffer(self):
        """Parse complete messages from the receive buffer.

        Extracts messages one at a time, verifying the magic bytes,
        payload length, and checksum.
        """
        with self._recv_lock:
            while len(self.recvbuf) >= MessageHeader.SIZE:
                # Check magic
                magic = struct.unpack("<I", self.recvbuf[:4])[0]
                if magic != self.magic:
                    self._log.warning(
                        "Bad magic: 0x%08X (expected 0x%08X), "
                        "discarding 1 byte",
                        magic, self.magic
                    )
                    self.recvbuf = self.recvbuf[1:]
                    continue

                # Parse header
                command = self.recvbuf[4:16].rstrip(b"\x00").decode(
                    "ascii", errors="replace"
                )
                payload_size = struct.unpack(
                    "<I", self.recvbuf[16:20]
                )[0]
                msg_checksum = self.recvbuf[20:24]

                # Sanity check payload size
                if payload_size > MAX_MESSAGE_SIZE:
                    self._log.warning(
                        "Message too large: %d bytes for %s",
                        payload_size, command
                    )
                    self.recvbuf = self.recvbuf[MessageHeader.SIZE:]
                    continue

                # Wait for complete payload
                total_size = MessageHeader.SIZE + payload_size
                if len(self.recvbuf) < total_size:
                    break

                payload = self.recvbuf[
                    MessageHeader.SIZE:total_size
                ]
                self.recvbuf = self.recvbuf[total_size:]

                # Verify checksum
                expected_checksum = compute_checksum(payload)
                if msg_checksum != expected_checksum:
                    self._log.warning(
                        "Bad checksum for %s: got %s, expected %s",
                        command,
                        msg_checksum.hex(),
                        expected_checksum.hex()
                    )
                    continue

                self._message_count_recv += 1
                msg = ReceivedMessage(command, payload)

                self._log.debug(
                    "Received %s (%d bytes)", command, payload_size
                )

                # Dispatch to callbacks
                if command in self._message_callbacks:
                    for cb in self._message_callbacks[command]:
                        try:
                            cb(command, payload)
                        except Exception as e:
                            self._log.error(
                                "Callback error for %s: %s",
                                command, e
                            )

                # Add to queue
                self.message_queue.put(msg)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Get connection statistics."""
        return {
            "connected": self.connected,
            "state": self.state,
            "bytes_sent": self._total_bytes_sent,
            "bytes_recv": self._total_bytes_recv,
            "messages_sent": self._message_count_sent,
            "messages_recv": self._message_count_recv,
            "pending_messages": len(self.messages),
            "queue_size": self.message_queue.qsize(),
        }


# ======================================================================
# P2PInterface: Protocol-aware layer
# ======================================================================

class P2PInterface(P2PConnection):
    """Higher-level P2P interface with protocol-aware operations.

    Builds on P2PConnection to provide:
        - Version/verack handshake.
        - Automatic ping/pong response.
        - Block and transaction sending with serialization.
        - Inventory management.
        - Message inspection utilities.
    """

    def __init__(self, magic: int = MAGIC_REGTEST,
                 services: int = NODE_NETWORK):
        super().__init__(magic)
        self.services = services
        self.user_agent = "/FlowCoinTest:0.1/"
        self.peer_version: Optional[dict] = None
        self.handshake_complete = False
        self._auto_respond_ping = True
        self._received_blocks: Dict[int, CBlock] = {}
        self._received_txs: Dict[int, CTransaction] = {}
        self._received_inv: List[CInv] = []
        self._reject_messages: List[dict] = []
        self._ban_score = 0

        # Register auto-responders
        self.register_callback("ping", self._handle_ping)

    def perform_handshake(self, our_height: int = 0,
                          our_port: int = 0,
                          timeout: int = 10):
        """Perform the version/verack handshake with the peer.

        Sends our version message, waits for the peer's version and
        verack, then sends our verack. After this, the connection is
        fully established and ready for data exchange.

        Args:
            our_height: Our claimed block height.
            our_port: Our claimed P2P port.
            timeout: Handshake timeout in seconds.
        """
        self.state = ConnectionState.HANDSHAKING

        # Send our version
        version_payload = msg_version(
            height=our_height,
            port=our_port,
            services=self.services,
            user_agent=self.user_agent
        )
        self.send_message("version", version_payload)

        # Wait for peer's version
        peer_version_msg = self.wait_for_message("version", timeout=timeout)
        self.peer_version = self._parse_version(peer_version_msg.payload)

        # Send verack
        self.send_message("verack", msg_verack())

        # Wait for peer's verack
        self.wait_for_message("verack", timeout=timeout)

        self.handshake_complete = True
        self.state = ConnectionState.READY
        self._log.debug(
            "Handshake complete (peer version: %s)",
            self.peer_version.get("user_agent", "unknown")
        )

    def _parse_version(self, payload: bytes) -> dict:
        """Parse a version message payload into a dict."""
        f = BytesIO(payload)
        result = {}
        try:
            result["protocol_version"] = struct.unpack("<I", f.read(4))[0]
            result["services"] = struct.unpack("<Q", f.read(8))[0]
            result["timestamp"] = struct.unpack("<q", f.read(8))[0]

            # addr_recv (26 bytes)
            recv_addr = NetAddress()
            recv_addr.deserialize(f)
            result["addr_recv"] = {
                "ip": recv_addr.ip, "port": recv_addr.port
            }

            # addr_from (26 bytes)
            from_addr = NetAddress()
            from_addr.deserialize(f)
            result["addr_from"] = {
                "ip": from_addr.ip, "port": from_addr.port
            }

            result["nonce"] = struct.unpack("<Q", f.read(8))[0]

            # User agent (var_str)
            ua_len = deser_compact_size(f)
            result["user_agent"] = f.read(ua_len).decode("utf-8", "replace")

            result["start_height"] = struct.unpack("<i", f.read(4))[0]

            # Relay flag (optional)
            remaining = f.read(1)
            if remaining:
                result["relay"] = bool(remaining[0])
            else:
                result["relay"] = True

        except (struct.error, IndexError) as e:
            self._log.warning("Version parse incomplete: %s", e)

        return result

    def _handle_ping(self, command: str, payload: bytes):
        """Auto-respond to ping with pong."""
        if self._auto_respond_ping and len(payload) >= 8:
            nonce = struct.unpack("<Q", payload[:8])[0]
            try:
                self.send_message("pong", msg_pong(nonce))
            except ConnectionError:
                pass

    def set_auto_ping_response(self, enabled: bool):
        """Enable or disable automatic ping/pong response."""
        self._auto_respond_ping = enabled

    # ------------------------------------------------------------------
    # Block operations
    # ------------------------------------------------------------------

    def send_block(self, block: CBlock):
        """Send a block to the peer."""
        self.send_message("block", msg_block(block))

    def send_block_hex(self, hex_str: str):
        """Send a block from its hex representation."""
        block = CBlock.from_hex(hex_str)
        self.send_block(block)

    def request_block(self, block_hash: int):
        """Request a specific block via getdata."""
        inv = CInv(MSG_BLOCK, block_hash)
        self.send_message("getdata", msg_getdata([inv]))

    def request_block_hex(self, hash_hex: str):
        """Request a block by hex hash string."""
        self.request_block(uint256_from_hex(hash_hex))

    def wait_for_block(self, timeout: int = 10) -> CBlock:
        """Wait for a block message and parse it."""
        msg = self.wait_for_message("block", timeout=timeout)
        block = CBlock()
        block.deserialize(BytesIO(msg.payload))
        return block

    def send_headers(self, headers: List[CBlockHeader]):
        """Send block headers to the peer."""
        self.send_message("headers", msg_headers(headers))

    def request_headers(self, locator_hashes: List[int],
                        stop_hash: int = 0):
        """Send a getheaders request."""
        self.send_message(
            "getheaders",
            msg_getheaders(locator_hashes, stop_hash)
        )

    def wait_for_headers(self, timeout: int = 10) -> List[CBlockHeader]:
        """Wait for a headers message and parse it."""
        msg = self.wait_for_message("headers", timeout=timeout)
        f = BytesIO(msg.payload)
        count = deser_compact_size(f)
        headers = []
        for _ in range(count):
            header = CBlockHeader()
            header.deserialize(f)
            # Read trailing tx_count byte
            f.read(1)
            headers.append(header)
        return headers

    # ------------------------------------------------------------------
    # Transaction operations
    # ------------------------------------------------------------------

    def send_tx(self, tx: CTransaction):
        """Send a transaction to the peer."""
        self.send_message("tx", msg_tx(tx))

    def send_tx_hex(self, hex_str: str):
        """Send a transaction from its hex representation."""
        tx = CTransaction.from_hex(hex_str)
        self.send_tx(tx)

    def request_tx(self, txid: int):
        """Request a specific transaction via getdata."""
        inv = CInv(MSG_TX, txid)
        self.send_message("getdata", msg_getdata([inv]))

    def wait_for_tx(self, timeout: int = 10) -> CTransaction:
        """Wait for a tx message and parse it."""
        msg = self.wait_for_message("tx", timeout=timeout)
        tx = CTransaction()
        tx.deserialize(BytesIO(msg.payload))
        return tx

    # ------------------------------------------------------------------
    # Inventory operations
    # ------------------------------------------------------------------

    def send_inv(self, items: List[CInv]):
        """Send inventory announcements to the peer."""
        self.send_message("inv", msg_inv(items))

    def announce_block(self, block_hash: int):
        """Announce a block via inv message."""
        self.send_inv([CInv(MSG_BLOCK, block_hash)])

    def announce_tx(self, txid: int):
        """Announce a transaction via inv message."""
        self.send_inv([CInv(MSG_TX, txid)])

    def wait_for_inv(self, timeout: int = 10) -> List[CInv]:
        """Wait for an inv message and parse it."""
        msg = self.wait_for_message("inv", timeout=timeout)
        f = BytesIO(msg.payload)
        count = deser_compact_size(f)
        items = []
        for _ in range(count):
            inv = CInv()
            inv.deserialize(f)
            items.append(inv)
        return items

    def wait_for_getdata(self, timeout: int = 10) -> List[CInv]:
        """Wait for a getdata message and parse it."""
        msg = self.wait_for_message("getdata", timeout=timeout)
        f = BytesIO(msg.payload)
        count = deser_compact_size(f)
        items = []
        for _ in range(count):
            inv = CInv()
            inv.deserialize(f)
            items.append(inv)
        return items

    # ------------------------------------------------------------------
    # Ping / pong
    # ------------------------------------------------------------------

    def send_ping(self, nonce: Optional[int] = None) -> int:
        """Send a ping and return the nonce."""
        if nonce is None:
            nonce = random.randint(0, 2**64 - 1)
        self.send_message("ping", msg_ping(nonce))
        return nonce

    def send_pong(self, nonce: int):
        """Send a pong response."""
        self.send_message("pong", msg_pong(nonce))

    def ping_and_wait(self, timeout: int = 10) -> float:
        """Send a ping and wait for pong, measuring round-trip time.

        Returns the round-trip time in seconds.
        """
        nonce = random.randint(0, 2**64 - 1)
        start = time.time()
        self.send_message("ping", msg_ping(nonce))
        pong_msg = self.wait_for_message("pong", timeout=timeout)
        elapsed = time.time() - start
        received_nonce = struct.unpack("<Q", pong_msg.payload[:8])[0]
        if received_nonce != nonce:
            raise ValueError(
                f"Pong nonce mismatch: sent {nonce}, got {received_nonce}"
            )
        return elapsed

    # ------------------------------------------------------------------
    # Address operations
    # ------------------------------------------------------------------

    def send_getaddr(self):
        """Request addresses from the peer."""
        self.send_message("getaddr", msg_getaddr())

    def send_addr(self, addresses: List[Tuple[int, NetAddress]]):
        """Send address announcements to the peer."""
        self.send_message("addr", msg_addr(addresses))

    def wait_for_addr(self, timeout: int = 10) -> List[dict]:
        """Wait for an addr message and parse it."""
        msg = self.wait_for_message("addr", timeout=timeout)
        f = BytesIO(msg.payload)
        count = deser_compact_size(f)
        results = []
        for _ in range(count):
            timestamp = struct.unpack("<I", f.read(4))[0]
            addr = NetAddress()
            addr.deserialize(f)
            results.append({
                "timestamp": timestamp,
                "ip": addr.ip,
                "port": addr.port,
                "services": addr.services,
            })
        return results

    # ------------------------------------------------------------------
    # Mempool operations
    # ------------------------------------------------------------------

    def send_mempool_request(self):
        """Send a mempool request to get inv messages for mempool txs."""
        self.send_message("mempool", msg_mempool())

    # ------------------------------------------------------------------
    # Fee filter
    # ------------------------------------------------------------------

    def send_feefilter(self, feerate: int):
        """Send a feefilter message (minimum feerate)."""
        self.send_message("feefilter", msg_feefilter(feerate))

    # ------------------------------------------------------------------
    # Send headers preference
    # ------------------------------------------------------------------

    def send_sendheaders(self):
        """Tell peer to send headers instead of inv for new blocks."""
        self.send_message("sendheaders", msg_sendheaders())

    # ------------------------------------------------------------------
    # Reject inspection
    # ------------------------------------------------------------------

    def wait_for_reject(self, timeout: int = 10) -> dict:
        """Wait for a reject message and parse it."""
        msg = self.wait_for_message("reject", timeout=timeout)
        f = BytesIO(msg.payload)
        msg_name_len = deser_compact_size(f)
        msg_name = f.read(msg_name_len).decode("utf-8", "replace")
        code = struct.unpack("<B", f.read(1))[0]
        reason_len = deser_compact_size(f)
        reason = f.read(reason_len).decode("utf-8", "replace")
        extra = f.read()
        return {
            "message": msg_name,
            "code": code,
            "reason": reason,
            "data": extra.hex() if extra else "",
        }

    # ------------------------------------------------------------------
    # Testing malformed messages
    # ------------------------------------------------------------------

    def send_malformed_header(self, bad_magic: int = 0xDEADBEEF):
        """Send a message with a bad magic value."""
        header = struct.pack("<I", bad_magic)
        header += b"version\x00\x00\x00\x00\x00"
        header += struct.pack("<I", 0)
        header += b"\x00\x00\x00\x00"
        self.send_raw(header)

    def send_oversized_message(self, command: str = "ping",
                               size: int = MAX_MESSAGE_SIZE + 1):
        """Send a message with an oversized payload.

        The header claims a payload of `size` bytes, but we only send
        a small actual payload. This tests the peer's size validation.
        """
        payload = b"\x00" * min(size, 1024)
        checksum = compute_checksum(payload)
        cmd_bytes = command.encode("ascii")[:12].ljust(12, b"\x00")
        header = (
            struct.pack("<I", self.magic) +
            cmd_bytes +
            struct.pack("<I", size) +
            checksum
        )
        self.send_raw(header + payload)

    def send_bad_checksum(self, command: str = "ping",
                          payload: bytes = b"\x00" * 8):
        """Send a message with an incorrect checksum."""
        bad_checksum = b"\xFF\xFF\xFF\xFF"
        cmd_bytes = command.encode("ascii")[:12].ljust(12, b"\x00")
        header = (
            struct.pack("<I", self.magic) +
            cmd_bytes +
            struct.pack("<I", len(payload)) +
            bad_checksum
        )
        self.send_raw(header + payload)

    def send_unknown_command(self, command: str = "xyzzy",
                             payload: bytes = b""):
        """Send a message with an unknown command name."""
        self.send_message(command, payload)


# ======================================================================
# P2PDataStore: Block/TX storage interface
# ======================================================================

class P2PDataStore(P2PInterface):
    """P2P interface that automatically stores received blocks and txs.

    Registers callbacks for block and tx messages, storing them in
    dictionaries keyed by hash. Useful for tests that need to inspect
    relayed data.
    """

    def __init__(self, magic: int = MAGIC_REGTEST):
        super().__init__(magic)
        self.blocks: Dict[str, CBlock] = {}
        self.txs: Dict[str, CTransaction] = {}
        self.block_store_lock = threading.Lock()
        self.tx_store_lock = threading.Lock()
        self._block_count = 0
        self._tx_count = 0

        self.register_callback("block", self._store_block)
        self.register_callback("tx", self._store_tx)

    def _store_block(self, command: str, payload: bytes):
        """Store a received block."""
        try:
            block = CBlock()
            block.deserialize(BytesIO(payload))
            block_hash = block.get_hash_hex()
            with self.block_store_lock:
                self.blocks[block_hash] = block
                self._block_count += 1
        except Exception as e:
            self._log.warning("Failed to parse block: %s", e)

    def _store_tx(self, command: str, payload: bytes):
        """Store a received transaction."""
        try:
            tx = CTransaction()
            tx.deserialize(BytesIO(payload))
            txid = tx.get_txid()
            with self.tx_store_lock:
                self.txs[txid] = tx
                self._tx_count += 1
        except Exception as e:
            self._log.warning("Failed to parse tx: %s", e)

    def get_block(self, block_hash: str) -> Optional[CBlock]:
        """Get a stored block by hash."""
        with self.block_store_lock:
            return self.blocks.get(block_hash)

    def get_tx(self, txid: str) -> Optional[CTransaction]:
        """Get a stored transaction by ID."""
        with self.tx_store_lock:
            return self.txs.get(txid)

    def has_block(self, block_hash: str) -> bool:
        """Check if a block has been received."""
        with self.block_store_lock:
            return block_hash in self.blocks

    def has_tx(self, txid: str) -> bool:
        """Check if a transaction has been received."""
        with self.tx_store_lock:
            return txid in self.txs

    def clear_store(self):
        """Clear all stored blocks and transactions."""
        with self.block_store_lock:
            self.blocks.clear()
        with self.tx_store_lock:
            self.txs.clear()


# ======================================================================
# MiniNode: Full-featured test peer
# ======================================================================

class MiniNode(P2PDataStore):
    """A miniature FlowCoin node for comprehensive protocol testing.

    Extends P2PDataStore with:
        - Automatic getdata responses (serving blocks/txs from store).
        - Simulated chain state tracking.
        - Ban score tracking.
        - Message sequence verification.
    """

    def __init__(self, magic: int = MAGIC_REGTEST):
        super().__init__(magic)
        self.best_block_hash: int = 0
        self.best_height: int = 0
        self._serve_blocks = True
        self._serve_txs = True
        self._message_log: List[Tuple[str, str, float]] = []
        self._max_log_size = 10000

        self.register_callback("getdata", self._handle_getdata)
        self.register_callback("inv", self._handle_inv)
        self.register_callback("reject", self._handle_reject)

    def _handle_getdata(self, command: str, payload: bytes):
        """Respond to getdata requests by serving stored blocks/txs."""
        f = BytesIO(payload)
        count = deser_compact_size(f)
        for _ in range(count):
            inv = CInv()
            inv.deserialize(f)
            hash_hex = uint256_to_hex(inv.hash)

            if inv.type == MSG_BLOCK and self._serve_blocks:
                block = self.get_block(hash_hex)
                if block:
                    self.send_block(block)

            elif inv.type == MSG_TX and self._serve_txs:
                tx = self.get_tx(hash_hex)
                if tx:
                    self.send_tx(tx)

    def _handle_inv(self, command: str, payload: bytes):
        """Track received inventory announcements."""
        f = BytesIO(payload)
        count = deser_compact_size(f)
        for _ in range(count):
            inv = CInv()
            inv.deserialize(f)
            self._received_inv.append(inv)

    def _handle_reject(self, command: str, payload: bytes):
        """Track received reject messages."""
        f = BytesIO(payload)
        try:
            msg_len = deser_compact_size(f)
            msg_name = f.read(msg_len).decode("utf-8", "replace")
            code = struct.unpack("<B", f.read(1))[0]
            reason_len = deser_compact_size(f)
            reason = f.read(reason_len).decode("utf-8", "replace")
            self._reject_messages.append({
                "message": msg_name,
                "code": code,
                "reason": reason,
            })
        except (struct.error, IndexError):
            pass

    def set_serve_blocks(self, enabled: bool):
        """Enable or disable automatic block serving."""
        self._serve_blocks = enabled

    def set_serve_txs(self, enabled: bool):
        """Enable or disable automatic transaction serving."""
        self._serve_txs = enabled

    def get_reject_messages(self) -> List[dict]:
        """Get all received reject messages."""
        return list(self._reject_messages)

    def clear_reject_messages(self):
        """Clear stored reject messages."""
        self._reject_messages.clear()

    def update_best_block(self, block_hash: int, height: int):
        """Update our tracked best block state."""
        self.best_block_hash = block_hash
        self.best_height = height

    def sync_with_node(self, node, timeout: int = 30):
        """Synchronize our chain state with an RPC-connected node.

        Requests blocks via P2P until our height matches the node's.
        """
        target_height = node.getblockcount()
        target_hash = uint256_from_hex(node.getbestblockhash())

        if self.best_height >= target_height:
            return

        # Request blocks
        locator = [self.best_block_hash] if self.best_block_hash else [0]
        self.send_message(
            "getblocks",
            msg_getblocks(locator, target_hash)
        )

        start = time.time()
        while time.time() - start < timeout:
            if self.best_height >= target_height:
                return
            time.sleep(0.25)

        raise TimeoutError(
            f"MiniNode sync timeout: at height {self.best_height}, "
            f"target {target_height}"
        )

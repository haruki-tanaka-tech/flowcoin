#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""P2P protocol message definitions for testing.

Provides Python implementations of the FlowCoin wire protocol messages,
including serialization and deserialization. These mirror the C++ message
structures in src/net/protocol.h and src/primitives/.

Wire format:
    - All multi-byte integers are little-endian.
    - Message structure: [header (24 bytes)] [payload (variable)]
    - Header: [magic (4)] [command (12)] [payload_size (4)] [checksum (4)]
    - Checksum: first 4 bytes of double-SHA256 of payload.

Block header layout (308 bytes total):
    Bytes   0-  3: version           (4 bytes, LE)
    Bytes   4- 35: prev_block_hash  (32 bytes)
    Bytes  36- 67: merkle_root      (32 bytes)
    Bytes  68- 99: delta_hash       (32 bytes)
    Bytes 100-103: timestamp        (4 bytes, LE)
    Bytes 104-107: bits             (4 bytes, LE)
    Bytes 108-139: nonce            (32 bytes)
    Bytes 140-143: height           (4 bytes, LE)
    Bytes 144-151: total_work       (8 bytes, LE)
    Bytes 152-155: tx_count_hint    (4 bytes, LE)
    Bytes 156-159: d_model          (4 bytes, LE)
    Bytes 160-163: n_layers         (4 bytes, LE)
    Bytes 164-167: d_ff             (4 bytes, LE)
    Bytes 168-171: n_heads          (4 bytes, LE)
    Bytes 172-175: gru_dim          (4 bytes, LE)
    Bytes 176-179: n_slots          (4 bytes, LE)
    Bytes 180-183: training_steps   (4 bytes, LE)
    Bytes 184-187: lr_micros        (4 bytes, LE)
    Bytes 188-195: val_loss_micro   (8 bytes, LE)
    Bytes 196-227: model_hash       (32 bytes)
    Bytes 228-259: optimizer_hash   (32 bytes)
    Bytes 260-263: delta_count      (4 bytes, LE)
    Bytes 264-271: delta_size       (8 bytes, LE)
    Bytes 272-275: improvement_flag (4 bytes, LE)
    Bytes 276-307: reserved         (32 bytes)
"""

import hashlib
import os
import random
import struct
import time
from io import BytesIO
from typing import List, Optional, Tuple

# ======================================================================
# Network magic values
# ======================================================================

MAGIC_MAINNET = 0x464C4F57  # "FLOW"
MAGIC_TESTNET = 0x54464C57  # "TFLW"
MAGIC_REGTEST = 0x52464C57  # "RFLW"

# Protocol version
PROTOCOL_VERSION = 1

# Service flags
NODE_NONE = 0
NODE_NETWORK = 1 << 0
NODE_TRAINING = 1 << 1
NODE_BLOOM = 1 << 2

# Message size limits
MAX_MESSAGE_SIZE = 32 * 1024 * 1024  # 32 MB
MAX_INV_SIZE = 50000
MAX_HEADERS_SIZE = 2000

# Inventory types
MSG_TX = 1
MSG_BLOCK = 2
MSG_FILTERED_BLOCK = 3
MSG_DELTA = 4

# Reject codes
REJECT_MALFORMED = 0x01
REJECT_INVALID = 0x10
REJECT_OBSOLETE = 0x11
REJECT_DUPLICATE = 0x12
REJECT_NONSTANDARD = 0x40
REJECT_DUST = 0x41
REJECT_INSUFFICIENTFEE = 0x42
REJECT_CHECKPOINT = 0x43


# ======================================================================
# Serialization helpers
# ======================================================================

def ser_uint256(value: int) -> bytes:
    """Serialize a 256-bit integer as 32 bytes little-endian."""
    return value.to_bytes(32, byteorder="little")


def deser_uint256(data: bytes) -> int:
    """Deserialize a 256-bit integer from 32 bytes little-endian."""
    return int.from_bytes(data[:32], byteorder="little")


def ser_string(s: bytes) -> bytes:
    """Serialize a variable-length byte string (compact size prefix)."""
    length = len(s)
    return ser_compact_size(length) + s


def deser_string(f: BytesIO) -> bytes:
    """Deserialize a variable-length byte string."""
    length = deser_compact_size(f)
    return f.read(length)


def ser_compact_size(n: int) -> bytes:
    """Serialize a compact size integer (Bitcoin varint encoding)."""
    if n < 253:
        return struct.pack("<B", n)
    elif n < 0x10000:
        return struct.pack("<BH", 253, n)
    elif n < 0x100000000:
        return struct.pack("<BI", 254, n)
    else:
        return struct.pack("<BQ", 255, n)


def deser_compact_size(f: BytesIO) -> int:
    """Deserialize a compact size integer."""
    first = struct.unpack("<B", f.read(1))[0]
    if first < 253:
        return first
    elif first == 253:
        return struct.unpack("<H", f.read(2))[0]
    elif first == 254:
        return struct.unpack("<I", f.read(4))[0]
    else:
        return struct.unpack("<Q", f.read(8))[0]


def ser_vector(v: list) -> bytes:
    """Serialize a vector of serializable objects."""
    result = ser_compact_size(len(v))
    for item in v:
        result += item.serialize()
    return result


def deser_vector(f: BytesIO, cls) -> list:
    """Deserialize a vector of objects of the given class."""
    count = deser_compact_size(f)
    result = []
    for _ in range(count):
        obj = cls()
        obj.deserialize(f)
        result.append(obj)
    return result


def ser_string_vector(v: list) -> bytes:
    """Serialize a vector of byte strings."""
    result = ser_compact_size(len(v))
    for s in v:
        result += ser_string(s)
    return result


def deser_string_vector(f: BytesIO) -> list:
    """Deserialize a vector of byte strings."""
    count = deser_compact_size(f)
    return [deser_string(f) for _ in range(count)]


def sha256d(data: bytes) -> bytes:
    """Double SHA-256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compute_checksum(payload: bytes) -> bytes:
    """Compute the 4-byte message checksum (first 4 bytes of SHA256d)."""
    return sha256d(payload)[:4]


def uint256_from_hex(hex_str: str) -> int:
    """Convert a hex hash string (big-endian display) to uint256."""
    return int.from_bytes(bytes.fromhex(hex_str), byteorder="big")


def uint256_to_hex(value: int) -> str:
    """Convert a uint256 to hex hash string (big-endian display)."""
    return value.to_bytes(32, byteorder="big").hex()


# ======================================================================
# Message header
# ======================================================================

class MessageHeader:
    """P2P message header (24 bytes).

    Format:
        magic:        4 bytes (network identifier)
        command:     12 bytes (null-padded ASCII command name)
        payload_size: 4 bytes (little-endian payload length)
        checksum:     4 bytes (first 4 bytes of SHA256d of payload)
    """

    SIZE = 24

    def __init__(self, magic: int = MAGIC_REGTEST, command: str = "",
                 payload_size: int = 0, checksum: bytes = b"\x00" * 4):
        self.magic = magic
        self.command = command
        self.payload_size = payload_size
        self.checksum = checksum

    def serialize(self) -> bytes:
        """Serialize the header to 24 bytes."""
        cmd_bytes = self.command.encode("ascii")[:12].ljust(12, b"\x00")
        return (
            struct.pack("<I", self.magic) +
            cmd_bytes +
            struct.pack("<I", self.payload_size) +
            self.checksum[:4]
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "MessageHeader":
        """Deserialize a header from 24 bytes."""
        if len(data) < cls.SIZE:
            raise ValueError(f"Header too short: {len(data)} bytes")
        magic = struct.unpack("<I", data[0:4])[0]
        command = data[4:16].rstrip(b"\x00").decode("ascii")
        payload_size = struct.unpack("<I", data[16:20])[0]
        checksum = data[20:24]
        return cls(magic, command, payload_size, checksum)

    def __repr__(self) -> str:
        return (
            f"<MessageHeader magic=0x{self.magic:08X} "
            f"cmd={self.command!r} size={self.payload_size} "
            f"checksum={self.checksum.hex()}>"
        )


# ======================================================================
# Transaction structures
# ======================================================================

class COutPoint:
    """Transaction output reference (txid + vout index)."""

    def __init__(self, txid: int = 0, vout: int = 0):
        self.txid = txid  # uint256
        self.vout = vout   # uint32

    def serialize(self) -> bytes:
        return ser_uint256(self.txid) + struct.pack("<I", self.vout)

    def deserialize(self, f: BytesIO):
        self.txid = deser_uint256(f.read(32))
        self.vout = struct.unpack("<I", f.read(4))[0]

    def is_null(self) -> bool:
        return self.txid == 0 and self.vout == 0xFFFFFFFF

    def __repr__(self) -> str:
        return f"<COutPoint txid={uint256_to_hex(self.txid)[:16]}... vout={self.vout}>"


class CTxIn:
    """Transaction input."""

    def __init__(self, outpoint: Optional[COutPoint] = None,
                 script_sig: bytes = b"", sequence: int = 0xFFFFFFFF):
        self.prevout = outpoint or COutPoint()
        self.script_sig = script_sig
        self.sequence = sequence

    def serialize(self) -> bytes:
        result = self.prevout.serialize()
        result += ser_string(self.script_sig)
        result += struct.pack("<I", self.sequence)
        return result

    def deserialize(self, f: BytesIO):
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.script_sig = deser_string(f)
        self.sequence = struct.unpack("<I", f.read(4))[0]

    def is_coinbase(self) -> bool:
        return self.prevout.is_null()

    def __repr__(self) -> str:
        return f"<CTxIn prevout={self.prevout} seq={self.sequence:#x}>"


class CTxOut:
    """Transaction output."""

    def __init__(self, value: int = -1, script_pubkey: bytes = b""):
        self.value = value  # int64, in satoshis
        self.script_pubkey = script_pubkey

    def serialize(self) -> bytes:
        return struct.pack("<q", self.value) + ser_string(self.script_pubkey)

    def deserialize(self, f: BytesIO):
        self.value = struct.unpack("<q", f.read(8))[0]
        self.script_pubkey = deser_string(f)

    def __repr__(self) -> str:
        return f"<CTxOut value={self.value} script={self.script_pubkey.hex()[:20]}>"


class CTransaction:
    """A complete transaction."""

    def __init__(self):
        self.version = 1
        self.vin: List[CTxIn] = []
        self.vout: List[CTxOut] = []
        self.locktime = 0
        self._hash: Optional[int] = None

    def serialize(self) -> bytes:
        result = struct.pack("<I", self.version)
        result += ser_compact_size(len(self.vin))
        for txin in self.vin:
            result += txin.serialize()
        result += ser_compact_size(len(self.vout))
        for txout in self.vout:
            result += txout.serialize()
        result += struct.pack("<I", self.locktime)
        return result

    def deserialize(self, f: BytesIO):
        self.version = struct.unpack("<I", f.read(4))[0]
        self.vin = deser_vector(f, CTxIn)
        self.vout = deser_vector(f, CTxOut)
        self.locktime = struct.unpack("<I", f.read(4))[0]
        self._hash = None

    def calc_hash(self) -> int:
        """Calculate the transaction hash (txid)."""
        data = self.serialize()
        hash_bytes = sha256d(data)
        self._hash = deser_uint256(hash_bytes)
        return self._hash

    def get_txid(self) -> str:
        """Get the transaction ID as a hex string."""
        if self._hash is None:
            self.calc_hash()
        return uint256_to_hex(self._hash)

    def is_coinbase(self) -> bool:
        return len(self.vin) == 1 and self.vin[0].is_coinbase()

    def __repr__(self) -> str:
        return (
            f"<CTransaction version={self.version} "
            f"vin={len(self.vin)} vout={len(self.vout)} "
            f"locktime={self.locktime}>"
        )

    @staticmethod
    def from_hex(hex_str: str) -> "CTransaction":
        """Deserialize a transaction from hex."""
        tx = CTransaction()
        tx.deserialize(BytesIO(bytes.fromhex(hex_str)))
        return tx


# ======================================================================
# Block structures
# ======================================================================

class CBlockHeader:
    """Block header (308 bytes).

    Contains all fields necessary for block validation including the
    standard blockchain fields and FlowCoin's training-specific fields.
    """

    SIZE = 308

    def __init__(self):
        self.version = 1
        self.prev_block_hash = 0    # uint256
        self.merkle_root = 0        # uint256
        self.delta_hash = 0         # uint256
        self.timestamp = 0          # uint32
        self.bits = 0               # uint32 (compact difficulty)
        self.nonce = b"\x00" * 32   # 32 bytes
        self.height = 0             # uint32
        self.total_work = 0         # uint64
        self.tx_count_hint = 0      # uint32
        self.d_model = 0            # uint32
        self.n_layers = 0           # uint32
        self.d_ff = 0               # uint32
        self.n_heads = 0            # uint32
        self.gru_dim = 0            # uint32
        self.n_slots = 0            # uint32
        self.training_steps = 0     # uint32
        self.lr_micros = 0          # uint32
        self.val_loss_micro = 0     # uint64
        self.model_hash = 0         # uint256
        self.optimizer_hash = 0     # uint256
        self.delta_count = 0        # uint32
        self.delta_size = 0         # uint64
        self.improvement_flag = 0   # uint32
        self.reserved = b"\x00" * 32  # 32 bytes

    def serialize(self) -> bytes:
        """Serialize the block header to 308 bytes."""
        result = b""
        result += struct.pack("<I", self.version)             # 0-3
        result += ser_uint256(self.prev_block_hash)           # 4-35
        result += ser_uint256(self.merkle_root)               # 36-67
        result += ser_uint256(self.delta_hash)                # 68-99
        result += struct.pack("<I", self.timestamp)           # 100-103
        result += struct.pack("<I", self.bits)                # 104-107
        result += self.nonce[:32].ljust(32, b"\x00")          # 108-139
        result += struct.pack("<I", self.height)              # 140-143
        result += struct.pack("<Q", self.total_work)          # 144-151
        result += struct.pack("<I", self.tx_count_hint)       # 152-155
        result += struct.pack("<I", self.d_model)             # 156-159
        result += struct.pack("<I", self.n_layers)            # 160-163
        result += struct.pack("<I", self.d_ff)                # 164-167
        result += struct.pack("<I", self.n_heads)             # 168-171
        result += struct.pack("<I", self.gru_dim)             # 172-175
        result += struct.pack("<I", self.n_slots)             # 176-179
        result += struct.pack("<I", self.training_steps)      # 180-183
        result += struct.pack("<I", self.lr_micros)           # 184-187
        result += struct.pack("<Q", self.val_loss_micro)      # 188-195
        result += ser_uint256(self.model_hash)                # 196-227
        result += ser_uint256(self.optimizer_hash)            # 228-259
        result += struct.pack("<I", self.delta_count)         # 260-263
        result += struct.pack("<Q", self.delta_size)          # 264-271
        result += struct.pack("<I", self.improvement_flag)    # 272-275
        result += self.reserved[:32].ljust(32, b"\x00")       # 276-307
        return result

    def deserialize(self, f: BytesIO):
        """Deserialize the block header from a stream."""
        self.version = struct.unpack("<I", f.read(4))[0]
        self.prev_block_hash = deser_uint256(f.read(32))
        self.merkle_root = deser_uint256(f.read(32))
        self.delta_hash = deser_uint256(f.read(32))
        self.timestamp = struct.unpack("<I", f.read(4))[0]
        self.bits = struct.unpack("<I", f.read(4))[0]
        self.nonce = f.read(32)
        self.height = struct.unpack("<I", f.read(4))[0]
        self.total_work = struct.unpack("<Q", f.read(8))[0]
        self.tx_count_hint = struct.unpack("<I", f.read(4))[0]
        self.d_model = struct.unpack("<I", f.read(4))[0]
        self.n_layers = struct.unpack("<I", f.read(4))[0]
        self.d_ff = struct.unpack("<I", f.read(4))[0]
        self.n_heads = struct.unpack("<I", f.read(4))[0]
        self.gru_dim = struct.unpack("<I", f.read(4))[0]
        self.n_slots = struct.unpack("<I", f.read(4))[0]
        self.training_steps = struct.unpack("<I", f.read(4))[0]
        self.lr_micros = struct.unpack("<I", f.read(4))[0]
        self.val_loss_micro = struct.unpack("<Q", f.read(8))[0]
        self.model_hash = deser_uint256(f.read(32))
        self.optimizer_hash = deser_uint256(f.read(32))
        self.delta_count = struct.unpack("<I", f.read(4))[0]
        self.delta_size = struct.unpack("<Q", f.read(8))[0]
        self.improvement_flag = struct.unpack("<I", f.read(4))[0]
        self.reserved = f.read(32)

    def calc_hash(self) -> int:
        """Calculate the block header hash."""
        data = self.serialize()
        return deser_uint256(sha256d(data))

    def get_hash_hex(self) -> str:
        """Get the block hash as a hex string."""
        return uint256_to_hex(self.calc_hash())

    def __repr__(self) -> str:
        return (
            f"<CBlockHeader height={self.height} "
            f"d_model={self.d_model} n_layers={self.n_layers} "
            f"timestamp={self.timestamp}>"
        )


class CBlock:
    """A complete block (header + transactions + delta payload).

    Serialization:
        [header (308 bytes)]
        [transaction count (compact_size)]
        [transactions ...]
        [delta payload (variable)]
    """

    def __init__(self):
        self.header = CBlockHeader()
        self.vtx: List[CTransaction] = []
        self.delta_payload = b""

    def serialize(self) -> bytes:
        """Serialize the complete block."""
        result = self.header.serialize()
        result += ser_compact_size(len(self.vtx))
        for tx in self.vtx:
            result += tx.serialize()
        result += ser_string(self.delta_payload)
        return result

    def deserialize(self, f: BytesIO):
        """Deserialize a block from a stream."""
        self.header = CBlockHeader()
        self.header.deserialize(f)
        self.vtx = deser_vector(f, CTransaction)
        self.delta_payload = deser_string(f)

    def calc_merkle_root(self) -> int:
        """Calculate the merkle root of transactions."""
        if not self.vtx:
            return 0
        hashes = [tx.calc_hash() for tx in self.vtx]
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])
            new_hashes = []
            for i in range(0, len(hashes), 2):
                combined = ser_uint256(hashes[i]) + ser_uint256(hashes[i + 1])
                new_hashes.append(deser_uint256(sha256d(combined)))
            hashes = new_hashes
        return hashes[0]

    def update_merkle_root(self):
        """Recalculate and set the merkle root."""
        self.header.merkle_root = self.calc_merkle_root()

    def get_hash_hex(self) -> str:
        """Get the block hash as a hex string."""
        return self.header.get_hash_hex()

    @staticmethod
    def from_hex(hex_str: str) -> "CBlock":
        """Deserialize a block from hex."""
        block = CBlock()
        block.deserialize(BytesIO(bytes.fromhex(hex_str)))
        return block

    def __repr__(self) -> str:
        return (
            f"<CBlock height={self.header.height} "
            f"txs={len(self.vtx)} "
            f"hash={self.get_hash_hex()[:16]}>"
        )


# ======================================================================
# P2P message payloads
# ======================================================================

class NetAddress:
    """Network address structure used in version messages."""

    def __init__(self, ip: str = "127.0.0.1", port: int = 0,
                 services: int = NODE_NETWORK):
        self.services = services
        self.ip = ip
        self.port = port

    def serialize(self) -> bytes:
        """Serialize the network address (26 bytes)."""
        result = struct.pack("<Q", self.services)
        # IPv4-mapped IPv6 address
        ip_bytes = b"\x00" * 10 + b"\xff\xff"
        parts = self.ip.split(".")
        for p in parts:
            ip_bytes += struct.pack("B", int(p))
        result += ip_bytes
        result += struct.pack(">H", self.port)  # port is big-endian
        return result

    def deserialize(self, f: BytesIO):
        self.services = struct.unpack("<Q", f.read(8))[0]
        addr_bytes = f.read(16)
        # Extract IPv4 from mapped address
        if addr_bytes[:12] == b"\x00" * 10 + b"\xff\xff":
            self.ip = ".".join(str(b) for b in addr_bytes[12:16])
        else:
            self.ip = addr_bytes.hex()
        self.port = struct.unpack(">H", f.read(2))[0]


class CInv:
    """Inventory vector (type + hash)."""

    def __init__(self, inv_type: int = 0, inv_hash: int = 0):
        self.type = inv_type
        self.hash = inv_hash

    def serialize(self) -> bytes:
        return struct.pack("<I", self.type) + ser_uint256(self.hash)

    def deserialize(self, f: BytesIO):
        self.type = struct.unpack("<I", f.read(4))[0]
        self.hash = deser_uint256(f.read(32))

    def __repr__(self) -> str:
        type_names = {1: "TX", 2: "BLOCK", 3: "FILTERED_BLOCK", 4: "DELTA"}
        name = type_names.get(self.type, str(self.type))
        return f"<CInv {name} {uint256_to_hex(self.hash)[:16]}>"


class BlockLocator:
    """Block locator structure for getblocks/getheaders."""

    def __init__(self, hashes: Optional[List[int]] = None):
        self.version = PROTOCOL_VERSION
        self.hashes = hashes or []

    def serialize(self) -> bytes:
        result = struct.pack("<I", self.version)
        result += ser_compact_size(len(self.hashes))
        for h in self.hashes:
            result += ser_uint256(h)
        return result

    def deserialize(self, f: BytesIO):
        self.version = struct.unpack("<I", f.read(4))[0]
        count = deser_compact_size(f)
        self.hashes = [deser_uint256(f.read(32)) for _ in range(count)]


# ======================================================================
# Message builders
# ======================================================================

def msg_version(height: int = 0, port: int = 0,
                services: int = NODE_NETWORK,
                user_agent: str = "/FlowCoinTest:0.1/") -> bytes:
    """Build a version message payload.

    Fields:
        protocol_version: uint32
        services:         uint64
        timestamp:        int64
        addr_recv:        NetAddress (26 bytes)
        addr_from:        NetAddress (26 bytes)
        nonce:            uint64
        user_agent:       var_str
        start_height:     int32
        relay:            bool (1 byte)
    """
    result = struct.pack("<I", PROTOCOL_VERSION)
    result += struct.pack("<Q", services)
    result += struct.pack("<q", int(time.time()))
    result += NetAddress("127.0.0.1", port, services).serialize()
    result += NetAddress("127.0.0.1", 0, services).serialize()
    result += struct.pack("<Q", random.randint(0, 2**64 - 1))
    ua_bytes = user_agent.encode("utf-8")
    result += ser_compact_size(len(ua_bytes))
    result += ua_bytes
    result += struct.pack("<i", height)
    result += struct.pack("<B", 1)  # relay = true
    return result


def msg_verack() -> bytes:
    """Build a verack message payload (empty)."""
    return b""


def msg_ping(nonce: Optional[int] = None) -> bytes:
    """Build a ping message payload."""
    if nonce is None:
        nonce = random.randint(0, 2**64 - 1)
    return struct.pack("<Q", nonce)


def msg_pong(nonce: int) -> bytes:
    """Build a pong message payload."""
    return struct.pack("<Q", nonce)


def msg_getblocks(locator_hashes: List[int],
                  stop_hash: int = 0) -> bytes:
    """Build a getblocks message payload.

    Asks the peer for inventory vectors of blocks after the
    locator hashes, up to stop_hash (0 = no limit).
    """
    locator = BlockLocator(locator_hashes)
    result = locator.serialize()
    result += ser_uint256(stop_hash)
    return result


def msg_getheaders(locator_hashes: List[int],
                   stop_hash: int = 0) -> bytes:
    """Build a getheaders message payload."""
    locator = BlockLocator(locator_hashes)
    result = locator.serialize()
    result += ser_uint256(stop_hash)
    return result


def msg_headers(headers: List[CBlockHeader]) -> bytes:
    """Build a headers message payload."""
    result = ser_compact_size(len(headers))
    for header in headers:
        result += header.serialize()
        result += struct.pack("<B", 0)  # tx count (always 0 in headers msg)
    return result


def msg_inv(items: List[CInv]) -> bytes:
    """Build an inv message payload."""
    result = ser_compact_size(len(items))
    for item in items:
        result += item.serialize()
    return result


def msg_getdata(items: List[CInv]) -> bytes:
    """Build a getdata message payload."""
    return msg_inv(items)  # Same format as inv


def msg_block(block: CBlock) -> bytes:
    """Build a block message payload."""
    return block.serialize()


def msg_tx(tx: CTransaction) -> bytes:
    """Build a tx message payload."""
    return tx.serialize()


def msg_addr(addresses: List[Tuple[int, NetAddress]]) -> bytes:
    """Build an addr message payload.

    Each entry is (timestamp, NetAddress).
    """
    result = ser_compact_size(len(addresses))
    for timestamp, addr in addresses:
        result += struct.pack("<I", timestamp)
        result += addr.serialize()
    return result


def msg_getaddr() -> bytes:
    """Build a getaddr message payload (empty)."""
    return b""


def msg_mempool() -> bytes:
    """Build a mempool message payload (empty)."""
    return b""


def msg_reject(message: str, code: int, reason: str,
               extra_data: bytes = b"") -> bytes:
    """Build a reject message payload."""
    msg_bytes = message.encode("utf-8")
    reason_bytes = reason.encode("utf-8")
    result = ser_compact_size(len(msg_bytes)) + msg_bytes
    result += struct.pack("<B", code)
    result += ser_compact_size(len(reason_bytes)) + reason_bytes
    result += extra_data
    return result


def msg_sendheaders() -> bytes:
    """Build a sendheaders message payload (empty)."""
    return b""


def msg_feefilter(feerate: int) -> bytes:
    """Build a feefilter message payload."""
    return struct.pack("<Q", feerate)


# ======================================================================
# Block construction helpers for testing
# ======================================================================

def create_coinbase_tx(height: int, value: int = 50 * 10**8,
                       script_pubkey: bytes = b"\x51") -> CTransaction:
    """Create a coinbase transaction for block construction.

    Args:
        height: Block height (used for BIP34 script sig).
        value: Coinbase reward in satoshis.
        script_pubkey: Output script (default OP_TRUE).

    Returns:
        A CTransaction with a single coinbase input and output.
    """
    tx = CTransaction()

    # Coinbase input
    txin = CTxIn()
    txin.prevout = COutPoint(0, 0xFFFFFFFF)
    # BIP34: encode height in scriptSig
    if height == 0:
        height_script = b"\x00"
    elif height <= 0xFF:
        height_script = b"\x01" + struct.pack("<B", height)
    elif height <= 0xFFFF:
        height_script = b"\x02" + struct.pack("<H", height)
    else:
        height_script = b"\x03" + struct.pack("<I", height)[:3]
    txin.script_sig = height_script
    txin.sequence = 0xFFFFFFFF
    tx.vin = [txin]

    # Coinbase output
    txout = CTxOut(value, script_pubkey)
    tx.vout = [txout]

    return tx


def create_test_block(prev_hash: int = 0, height: int = 0,
                      timestamp: int = 0,
                      d_model: int = 512, n_layers: int = 8,
                      transactions: Optional[List[CTransaction]] = None
                      ) -> CBlock:
    """Create a test block with sensible defaults.

    Args:
        prev_hash: Previous block hash as uint256.
        height: Block height.
        timestamp: Block timestamp (defaults to current time).
        d_model: Model dimension for the header.
        n_layers: Number of layers for the header.
        transactions: List of transactions (coinbase auto-created if empty).

    Returns:
        A CBlock ready for serialization or modification.
    """
    block = CBlock()
    block.header.version = 1
    block.header.prev_block_hash = prev_hash
    block.header.timestamp = timestamp or int(time.time())
    block.header.bits = 0x207FFFFF  # Minimum difficulty for regtest
    block.header.nonce = os.urandom(32)
    block.header.height = height
    block.header.d_model = d_model
    block.header.n_layers = n_layers
    block.header.d_ff = d_model * 2
    block.header.n_heads = max(8, d_model // 64)
    block.header.training_steps = 1000 + 4 * height
    block.header.val_loss_micro = 1000000  # 1.0

    if transactions:
        block.vtx = transactions
    else:
        coinbase = create_coinbase_tx(height)
        block.vtx = [coinbase]

    block.update_merkle_root()
    return block


# ======================================================================
# Script construction helpers
# ======================================================================

# Opcodes
OP_0 = 0x00
OP_FALSE = 0x00
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e
OP_1NEGATE = 0x4f
OP_RESERVED = 0x50
OP_1 = 0x51
OP_TRUE = 0x51
OP_2 = 0x52
OP_3 = 0x53
OP_4 = 0x54
OP_5 = 0x55
OP_6 = 0x56
OP_7 = 0x57
OP_8 = 0x58
OP_9 = 0x59
OP_10 = 0x5a
OP_11 = 0x5b
OP_12 = 0x5c
OP_13 = 0x5d
OP_14 = 0x5e
OP_15 = 0x5f
OP_16 = 0x60
OP_NOP = 0x61
OP_IF = 0x63
OP_NOTIF = 0x64
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_VERIFY = 0x69
OP_RETURN = 0x6a
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xa9
OP_HASH256 = 0xaa
OP_CHECKSIG = 0xac
OP_CHECKMULTISIG = 0xae
OP_CHECKLOCKTIMEVERIFY = 0xb1
OP_CHECKSEQUENCEVERIFY = 0xb2


def CScript(data: list) -> bytes:
    """Construct a script from a list of opcodes and data pushes.

    Each element can be:
        - An int: treated as an opcode byte.
        - A bytes: treated as a data push (with length prefix).

    Example::

        script = CScript([OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG])
    """
    result = b""
    for item in data:
        if isinstance(item, int):
            result += bytes([item])
        elif isinstance(item, bytes):
            length = len(item)
            if length < OP_PUSHDATA1:
                result += bytes([length]) + item
            elif length <= 0xFF:
                result += bytes([OP_PUSHDATA1, length]) + item
            elif length <= 0xFFFF:
                result += bytes([OP_PUSHDATA2]) + struct.pack("<H", length) + item
            else:
                result += bytes([OP_PUSHDATA4]) + struct.pack("<I", length) + item
        else:
            raise TypeError(f"Unsupported script element type: {type(item)}")
    return result


def script_to_p2pkh(pubkey_hash: bytes) -> bytes:
    """Create a P2PKH (pay-to-pubkey-hash) script.

    OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    """
    return CScript([OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG])


def script_to_op_return(data: bytes) -> bytes:
    """Create an OP_RETURN script (unspendable, data carrier).

    OP_RETURN <data>
    """
    return CScript([OP_RETURN, data])


def script_to_multisig(m: int, pubkeys: list) -> bytes:
    """Create an m-of-n multisig script.

    OP_m <pubkey1> <pubkey2> ... <pubkeyn> OP_n OP_CHECKMULTISIG
    """
    n = len(pubkeys)
    assert 1 <= m <= n <= 16, f"Invalid multisig: {m}-of-{n}"
    elements = [OP_1 + m - 1]
    for pk in pubkeys:
        elements.append(pk)
    elements.append(OP_1 + n - 1)
    elements.append(OP_CHECKMULTISIG)
    return CScript(elements)


# ======================================================================
# Wire protocol helpers
# ======================================================================

def build_message(magic: int, command: str, payload: bytes) -> bytes:
    """Build a complete P2P message (header + payload).

    Constructs the 24-byte header and concatenates the payload.
    Used for tests that need to inject raw messages.
    """
    checksum = compute_checksum(payload)
    cmd_bytes = command.encode("ascii")[:12].ljust(12, b"\x00")
    header = (
        struct.pack("<I", magic) +
        cmd_bytes +
        struct.pack("<I", len(payload)) +
        checksum
    )
    return header + payload


def parse_message(data: bytes) -> tuple:
    """Parse a complete P2P message from raw bytes.

    Returns (command, payload, remaining_bytes).
    Raises ValueError if data is incomplete.
    """
    if len(data) < 24:
        raise ValueError("Incomplete header")

    magic = struct.unpack("<I", data[0:4])[0]
    command = data[4:16].rstrip(b"\x00").decode("ascii", errors="replace")
    payload_size = struct.unpack("<I", data[16:20])[0]
    checksum = data[20:24]

    total = 24 + payload_size
    if len(data) < total:
        raise ValueError(f"Incomplete payload: need {total}, have {len(data)}")

    payload = data[24:total]
    remaining = data[total:]

    # Verify checksum
    expected = compute_checksum(payload)
    if checksum != expected:
        raise ValueError(
            f"Checksum mismatch for {command}: "
            f"got {checksum.hex()}, expected {expected.hex()}"
        )

    return command, payload, remaining


def parse_inv_payload(payload: bytes) -> list:
    """Parse an inv/getdata message payload into a list of CInv objects."""
    f = BytesIO(payload)
    count = deser_compact_size(f)
    items = []
    for _ in range(count):
        inv = CInv()
        inv.deserialize(f)
        items.append(inv)
    return items


def parse_headers_payload(payload: bytes) -> list:
    """Parse a headers message payload into a list of CBlockHeader objects."""
    f = BytesIO(payload)
    count = deser_compact_size(f)
    headers = []
    for _ in range(count):
        header = CBlockHeader()
        header.deserialize(f)
        f.read(1)  # trailing tx_count byte
        headers.append(header)
    return headers


# ======================================================================
# Test data generators
# ======================================================================

def create_spending_tx(coinbase_tx: CTransaction, output_index: int = 0,
                       value: int = 49 * 10**8,
                       script_pubkey: bytes = b"\x51") -> CTransaction:
    """Create a transaction spending a coinbase output.

    Used to construct test transactions for mempool and relay testing.

    Args:
        coinbase_tx: The coinbase transaction to spend from.
        output_index: Which output of the coinbase to spend.
        value: Output value in satoshis (must be <= input - fee).
        script_pubkey: Output script (default OP_TRUE).

    Returns:
        A CTransaction spending the specified coinbase output.
    """
    tx = CTransaction()

    # Input: spend from coinbase
    coinbase_hash = coinbase_tx.calc_hash()
    txin = CTxIn()
    txin.prevout = COutPoint(coinbase_hash, output_index)
    txin.script_sig = b"\x00"  # Minimal valid scriptSig for OP_TRUE outputs
    txin.sequence = 0xFFFFFFFF
    tx.vin = [txin]

    # Output
    txout = CTxOut(value, script_pubkey)
    tx.vout = [txout]

    return tx


def create_tx_chain(base_tx: CTransaction, chain_length: int,
                    value_per_output: int = 10**8) -> list:
    """Create a chain of dependent transactions.

    Each transaction spends the first output of the previous one.
    Useful for testing mempool ordering and relay behavior.

    Args:
        base_tx: The initial transaction to spend from.
        chain_length: Number of chained transactions to create.
        value_per_output: Output value for each transaction.

    Returns:
        List of CTransaction objects forming the chain.
    """
    chain = []
    prev_tx = base_tx
    for i in range(chain_length):
        tx = CTransaction()
        prev_hash = prev_tx.calc_hash()
        txin = CTxIn()
        txin.prevout = COutPoint(prev_hash, 0)
        txin.script_sig = b"\x00"
        txin.sequence = 0xFFFFFFFF
        tx.vin = [txin]

        remaining = value_per_output - 1000  # Subtract fee
        txout = CTxOut(remaining, b"\x51")
        tx.vout = [txout]

        chain.append(tx)
        prev_tx = tx
        value_per_output = remaining

    return chain


def create_block_chain(start_hash: int, start_height: int,
                       count: int, d_model: int = 512,
                       n_layers: int = 8) -> list:
    """Create a chain of linked test blocks.

    Each block references the previous one's hash. Blocks contain
    only a coinbase transaction.

    Args:
        start_hash: Hash of the block to build upon.
        start_height: Height of the first new block.
        count: Number of blocks to create.
        d_model: Model dimension for all blocks.
        n_layers: Layer count for all blocks.

    Returns:
        List of CBlock objects forming the chain.
    """
    blocks = []
    prev_hash = start_hash
    for i in range(count):
        height = start_height + i
        block = create_test_block(
            prev_hash=prev_hash,
            height=height,
            d_model=d_model,
            n_layers=n_layers,
        )
        prev_hash = block.header.calc_hash()
        blocks.append(block)
    return blocks

#!/usr/bin/env python3
"""FlowCoin Miner — ResonanceNet V5 training for Proof-of-Training consensus."""

import argparse
import base64
import json
import math
import os
import socket
import struct
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F


# ===================================================================
# Keccak-256 (pad=0x01, NOT SHA-3)
# ===================================================================

try:
    from Crypto.Hash import keccak as _keccak

    def keccak256(data: bytes) -> bytes:
        return _keccak.new(digest_bits=256, data=data).digest()

except ImportError:
    try:
        import sha3

        def keccak256(data: bytes) -> bytes:
            return sha3.keccak_256(data).digest()

    except ImportError:
        print("ERROR: Install pycryptodome or pysha3 for Keccak-256")
        sys.exit(1)


def keccak256d(data: bytes) -> bytes:
    """Double Keccak-256: keccak256(keccak256(data))."""
    return keccak256(keccak256(data))


# ===================================================================
# Ed25519 signing (using pycryptodome)
# ===================================================================

try:
    from Crypto.PublicKey import ECC
    from Crypto.Signature import eddsa

    def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
        """Generate a new Ed25519 keypair.
        Returns (privkey_seed_32_bytes, pubkey_32_bytes)."""
        key = ECC.generate(curve='Ed25519')
        privkey_seed = key.seed
        pub_bytes = key.public_key().export_key(format='raw')
        return privkey_seed, pub_bytes

    def ed25519_sign(message: bytes, privkey_seed: bytes) -> bytes:
        """Sign a message with Ed25519. Returns 64-byte signature."""
        key = ECC.construct(seed=privkey_seed, curve='Ed25519')
        signer = eddsa.new(key, mode='rfc8032')
        return signer.sign(message)

    def ed25519_pubkey_from_seed(privkey_seed: bytes) -> bytes:
        """Derive the 32-byte public key from a 32-byte private key seed."""
        key = ECC.construct(seed=privkey_seed, curve='Ed25519')
        return key.public_key().export_key(format='raw')

    _HAS_ED25519 = True

except (ImportError, AttributeError):
    # Fallback: try nacl
    try:
        import nacl.signing

        def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
            sk = nacl.signing.SigningKey.generate()
            return bytes(sk), bytes(sk.verify_key)

        def ed25519_sign(message: bytes, privkey_seed: bytes) -> bytes:
            sk = nacl.signing.SigningKey(privkey_seed)
            return sk.sign(message).signature

        def ed25519_pubkey_from_seed(privkey_seed: bytes) -> bytes:
            sk = nacl.signing.SigningKey(privkey_seed)
            return bytes(sk.verify_key)

        _HAS_ED25519 = True

    except ImportError:
        _HAS_ED25519 = False

        def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
            print("ERROR: No Ed25519 library. Install pycryptodome or PyNaCl.")
            sys.exit(1)

        def ed25519_sign(message: bytes, privkey_seed: bytes) -> bytes:
            raise RuntimeError("No Ed25519 library available")

        def ed25519_pubkey_from_seed(privkey_seed: bytes) -> bytes:
            raise RuntimeError("No Ed25519 library available")


# ===================================================================
# RPC Client (raw sockets, no dependencies)
# ===================================================================

class RPCError(Exception):
    pass


class RPC:
    """JSON-RPC client using raw sockets (no urllib)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9334,
                 user: str = "", pw: str = ""):
        self.host = host
        self.port = port
        self.auth = base64.b64encode(f"{user}:{pw}".encode()).decode()

    def call(self, method: str, params=None):
        body = json.dumps({
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": 1,
        })
        req = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Authorization: Basic {self.auth}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        try:
            sock.connect((self.host, self.port))
            sock.sendall(req.encode())
            resp = b""
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                resp += chunk
        finally:
            sock.close()

        idx = resp.find(b"\r\n\r\n")
        if idx < 0:
            raise RPCError("Invalid HTTP response")
        result = json.loads(resp[idx + 4:])
        if result.get("error"):
            e = result["error"]
            raise RPCError(f"RPC error {e.get('code')}: {e.get('message')}")
        return result.get("result")


# ===================================================================
# ResonanceNet V5 — Model Classes
# ===================================================================

class RMSNorm(nn.Module):
    """Root Mean Square Layer Normalization."""

    def __init__(self, d_model: int, eps: float = 1e-6):
        super().__init__()
        self.weight = nn.Parameter(torch.ones(d_model))
        self.eps = eps

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        rms = torch.sqrt(torch.mean(x ** 2, dim=-1, keepdim=True) + self.eps)
        return x * self.weight / rms


class MultiScaleCausalConv(nn.Module):
    """Depthwise causal convolutions at multiple scales (3, 7, 15).

    Three parallel depthwise causal 1D convolutions capture local patterns
    at different receptive-field sizes. Their outputs are summed and projected
    through a linear mix layer.
    """

    def __init__(self, d_model: int):
        super().__init__()
        self.d_model = d_model
        self.conv3 = nn.Conv1d(
            d_model, d_model, kernel_size=3, padding=2,
            groups=d_model, bias=False
        )
        self.conv7 = nn.Conv1d(
            d_model, d_model, kernel_size=7, padding=6,
            groups=d_model, bias=False
        )
        self.conv15 = nn.Conv1d(
            d_model, d_model, kernel_size=15, padding=14,
            groups=d_model, bias=False
        )
        self.mix = nn.Linear(d_model, d_model, bias=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: [batch, seq_len, d_model]
        Returns:
            [batch, seq_len, d_model]
        """
        seq_len = x.size(1)
        xt = x.transpose(1, 2)  # [batch, d_model, seq_len]

        c3 = self.conv3(xt)[:, :, :seq_len]
        c7 = self.conv7(xt)[:, :, :seq_len]
        c15 = self.conv15(xt)[:, :, :seq_len]

        combined = (c3 + c7 + c15).transpose(1, 2)  # [batch, seq_len, d_model]
        return self.mix(combined)


class MinGRU(nn.Module):
    """Minimal Gated Recurrent Unit with O(1) state per token.

    A simplified GRU variant:
        z = sigmoid(Wz @ x)
        h_tilde = Wh @ x
        h = (1 - z) * h_prev + z * h_tilde

    No reset gate, no hidden-to-hidden connections. This makes inference
    O(1) memory per step.
    """

    def __init__(self, d_model: int):
        super().__init__()
        self.d_model = d_model
        self.Wz = nn.Linear(d_model, d_model)  # gate projection
        self.Wh = nn.Linear(d_model, d_model)  # candidate projection

    def forward(
        self, x: torch.Tensor, h_prev: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            x: [batch, seq_len, d_model]
            h_prev: [batch, d_model] or None (defaults to zeros)
        Returns:
            output: [batch, seq_len, d_model]
            h_last: [batch, d_model] final hidden state
        """
        B, T, D = x.shape
        if h_prev is None:
            h_prev = torch.zeros(B, D, device=x.device, dtype=x.dtype)

        # Pre-compute ALL projections in parallel (2 big matmuls instead of 2*T small ones)
        z_all = torch.sigmoid(self.Wz(x))    # [B, T, D]
        h_tilde_all = self.Wh(x)              # [B, T, D]

        # Sequential scan — only element-wise ops, very fast
        outputs = torch.empty_like(x)
        h = h_prev
        for t in range(T):
            z = z_all[:, t, :]
            h = (1 - z) * h + z * h_tilde_all[:, t, :]
            outputs[:, t, :] = h

        return outputs, h


class SlotMemory(nn.Module):
    """Sparse slot-addressed external memory with top-k routing.

    Maintains a fixed bank of (key, value) slots. Each token queries the
    memory, routes to the top-k most relevant slots via softmax attention,
    and retrieves a weighted combination of their values.
    """

    def __init__(self, d_model: int, n_slots: int, top_k: int = 2):
        super().__init__()
        self.d_model = d_model
        self.n_slots = n_slots
        self.top_k = top_k

        self.slot_keys = nn.Parameter(torch.randn(n_slots, d_model) * 0.02)
        self.slot_values = nn.Parameter(torch.randn(n_slots, d_model) * 0.02)
        self.proj_q = nn.Linear(d_model, d_model, bias=False)
        self.proj_out = nn.Linear(d_model, d_model, bias=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: [batch, seq_len, d_model]
        Returns:
            [batch, seq_len, d_model]
        """
        B, T, D = x.shape
        q = self.proj_q(x)  # [B, T, D]

        scores = torch.matmul(q, self.slot_keys.T) / math.sqrt(D)  # [B, T, n_slots]

        topk_vals, topk_ids = torch.topk(scores, self.top_k, dim=-1)  # [B, T, k]
        attn = F.softmax(topk_vals, dim=-1)  # [B, T, k]

        topk_ids_flat = topk_ids.reshape(-1, self.top_k)  # [B*T, k]
        gathered = self.slot_values[topk_ids_flat]  # [B*T, k, D]
        gathered = gathered.reshape(B, T, self.top_k, D)  # [B, T, k, D]

        retrieved = (attn.unsqueeze(-1) * gathered).sum(dim=2)  # [B, T, D]
        return self.proj_out(retrieved)


class SwiGLUFFN(nn.Module):
    """SwiGLU Feed-Forward Network.

    Splits the up-projection into a gate and value branch:
        out = down(SiLU(gate(x)) * up(x))

    Uses ~3 * d_model * d_ff parameters (no bias).
    """

    def __init__(self, d_model: int, d_ff: int):
        super().__init__()
        self.gate = nn.Linear(d_model, d_ff, bias=False)
        self.up = nn.Linear(d_model, d_ff, bias=False)
        self.down = nn.Linear(d_ff, d_model, bias=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.down(F.silu(self.gate(x)) * self.up(x))


class ResonanceLayer(nn.Module):
    """One ResonanceNet V5 layer.

    Composition:
        1. RMSNorm + MultiScaleCausalConv (residual)
        2. RMSNorm + MinGRU (residual)
        3. RMSNorm + SlotMemory (residual)
        4. RMSNorm + SwiGLU FFN (residual)
    """

    def __init__(
        self, d_model: int, d_ff: int, n_slots: int, top_k: int = 2
    ):
        super().__init__()
        self.norm1 = RMSNorm(d_model)
        self.conv = MultiScaleCausalConv(d_model)
        self.norm2 = RMSNorm(d_model)
        self.gru = MinGRU(d_model)
        self.norm3 = RMSNorm(d_model)
        self.slot_mem = SlotMemory(d_model, n_slots, top_k)
        self.norm4 = RMSNorm(d_model)
        self.ffn = SwiGLUFFN(d_model, d_ff)

    def forward(
        self, x: torch.Tensor, h_prev: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            x: [batch, seq_len, d_model]
            h_prev: [batch, d_model] GRU hidden state or None
        Returns:
            x: [batch, seq_len, d_model]
            h_new: [batch, d_model]
        """
        # 1. Multi-Scale Causal Conv
        x = x + self.conv(self.norm1(x))
        # 2. MinGRU
        gru_out, h_new = self.gru(self.norm2(x), h_prev)
        x = x + gru_out
        # 3. Slot Memory
        x = x + self.slot_mem(self.norm3(x))
        # 4. SwiGLU FFN
        x = x + self.ffn(self.norm4(x))
        return x, h_new


class ResonanceNetV5(nn.Module):
    """Complete ResonanceNet V5 model.

    Architecture:
        - Byte-level embedding (vocab=256)
        - N ResonanceLayers (conv + GRU + slot memory + FFN)
        - Final RMSNorm
        - Weight-tied output projection (embedding.weight.T)

    All hyperparameters are consensus-determined by block height.
    """

    def __init__(
        self,
        vocab: int = 256,
        d_model: int = 512,
        n_layers: int = 8,
        d_ff: int = 1024,
        n_slots: int = 1024,
        top_k: int = 2,
    ):
        super().__init__()
        self.vocab = vocab
        self.d_model = d_model
        self.n_layers = n_layers

        self.embedding = nn.Embedding(vocab, d_model)
        self.layers = nn.ModuleList([
            ResonanceLayer(d_model, d_ff, n_slots, top_k)
            for _ in range(n_layers)
        ])
        self.final_norm = RMSNorm(d_model)

    def forward(
        self,
        tokens: torch.Tensor,
        hidden_states: Optional[List[Optional[torch.Tensor]]] = None,
    ) -> Tuple[torch.Tensor, List[torch.Tensor]]:
        """
        Args:
            tokens: [batch, seq_len] long tensor of byte values (0-255)
            hidden_states: list of [batch, d_model] per layer, or None

        Returns:
            logits: [batch, seq_len, vocab]
            new_hidden_states: list of [batch, d_model]
        """
        x = self.embedding(tokens)  # [B, T, D]

        if hidden_states is None:
            hidden_states = [None] * self.n_layers

        new_hiddens = []
        for i, layer in enumerate(self.layers):
            x, h = layer(x, hidden_states[i])
            new_hiddens.append(h)

        x = self.final_norm(x)
        logits = F.linear(x, self.embedding.weight)  # [B, T, vocab]
        return logits, new_hiddens


# ===================================================================
# Growth schedule — mirrors consensus/growth.cpp
# ===================================================================

def compute_growth(height: int) -> dict:
    """Compute model dimensions at a given block height."""
    d_model = min(512 + min(height, 512), 1024)
    n_layers = min(8 + height // 32, 24)
    d_ff = 2 * d_model
    n_slots = 1024 + height * 4
    return {
        "d_model": d_model,
        "n_layers": n_layers,
        "d_ff": d_ff,
        "n_slots": n_slots,
    }


# ===================================================================
# Target derivation
# ===================================================================

def derive_target(nbits: int) -> int:
    """Decode compact target (nBits) into a 256-bit integer."""
    exp = (nbits >> 24) & 0xFF
    mantissa = nbits & 0x00FFFFFF
    if exp <= 3:
        return mantissa >> (8 * (3 - exp))
    return mantissa << (8 * (exp - 3))


# ===================================================================
# Training data
# ===================================================================

class TrainingData:
    """Load byte-level training data from ~/.flowcoin/training/."""

    def __init__(self, datadir: str, seq_len: int = 256, batch_size: int = 32):
        tdir = os.path.join(datadir, "training")
        os.makedirs(tdir, exist_ok=True)

        raw = bytearray()
        count = 0
        for f in sorted(Path(tdir).iterdir()):
            if f.is_file():
                raw.extend(f.read_bytes())
                count += 1

        if not raw:
            print(f"  No training data in {tdir}/")
            print(f"  Place .txt or .bin files there.")
            sys.exit(1)

        self.data = torch.tensor(list(raw), dtype=torch.long)
        self.hash = keccak256(bytes(raw))
        self.seq_len = seq_len
        self.batch_size = batch_size
        self.pos = 0

        print(f"  Data: {len(raw):,} bytes ({count} files)")
        print(f"  Hash: {self.hash[:8].hex()}")

    def get_batch(self, device: torch.device) -> Tuple[torch.Tensor, torch.Tensor]:
        """Return (input, target) tensors of shape [batch, seq_len]."""
        B, T = self.batch_size, self.seq_len
        chunks = []
        for _ in range(B):
            if self.pos + T + 1 > len(self.data):
                self.pos = 0
            chunks.append(self.data[self.pos:self.pos + T + 1])
            self.pos += T
        batch = torch.stack(chunks).to(device)
        return batch[:, :-1], batch[:, 1:]


# ===================================================================
# Delta computation
# ===================================================================

def compute_fast_hash(model: ResonanceNetV5) -> bytes:
    """Fast hash: sample every 1000th parameter. Zero overhead."""
    with torch.no_grad():
        all_params = torch.cat([p.data.flatten() for p in model.parameters()])
        subset = all_params[::1000].cpu().numpy().tobytes()
    return keccak256(subset)


def compute_full_delta(
    model: ResonanceNetV5,
    consensus_state: dict,
    sparse_threshold: float = 1e-3,
) -> Tuple[bytes, bytes, int]:
    """Compute sparse delta. Returns (delta_hash, sparse_bytes, nonzero_count).

    Sparse format: [uint32 count][count × (uint32 index, float32 value)]
    Only entries where |delta| > threshold are stored.
    Hash is computed on the FULL dense delta (for consensus), but the
    block payload uses the sparse encoding (compact for transmission).
    """
    import numpy as np

    # Collect full delta for hashing
    all_delta = []
    with torch.no_grad():
        for key in sorted(model.state_dict().keys()):
            delta = (model.state_dict()[key].cpu().float()
                     - consensus_state[key].cpu().float())
            all_delta.append(delta.numpy().flatten())
    full_delta = np.concatenate(all_delta)

    # Hash the full dense delta (consensus-compatible)
    full_bytes = full_delta.tobytes()
    delta_hash = keccak256(full_bytes)

    # Sparse encode: only significant changes
    mask = np.abs(full_delta) > sparse_threshold
    indices = np.where(mask)[0].astype(np.uint32)
    values = full_delta[mask].astype(np.float32)
    nonzero = len(indices)

    # Sparse format: [count:u32][idx:u32, val:f32] × count
    sparse_data = struct.pack('<I', nonzero)
    for i in range(nonzero):
        sparse_data += struct.pack('<If', indices[i], values[i])

    return delta_hash, sparse_data, nonzero


# ===================================================================
# CompactSize encoding (Bitcoin-style varint)
# ===================================================================

def encode_compact_size(n: int) -> bytes:
    """Encode an integer as a Bitcoin-style CompactSize.
    Matches the C++ CompactSize::encode format exactly."""
    if n < 253:
        return struct.pack('<B', n)
    elif n <= 0xFFFF:
        return struct.pack('<BH', 0xFD, n)
    elif n <= 0xFFFFFFFF:
        return struct.pack('<BI', 0xFE, n)
    else:
        return struct.pack('<BQ', 0xFF, n)


# ===================================================================
# Consensus constants (from consensus/params.h)
# ===================================================================

COIN = 100_000_000
INITIAL_REWARD = 50 * COIN
HALVING_INTERVAL = 210_000


def compute_block_reward(height: int) -> int:
    """Compute block subsidy at a given height."""
    halvings = height // HALVING_INTERVAL
    if halvings >= 64:
        return 0
    return INITIAL_REWARD >> halvings


# ===================================================================
# Transaction serialization (matching CTransaction in transaction.cpp)
# ===================================================================

def serialize_coinbase_tx(height: int, reward: int,
                          miner_pubkey: bytes) -> bytes:
    """Build and serialize a coinbase transaction.

    Transaction wire format (from transaction.cpp):
        version      (4 bytes, uint32 LE)
        vin_count    (CompactSize)
        vin[]:
            txid       (32 bytes)       -- all zeros for coinbase
            index      (4 bytes, LE)    -- 0 for coinbase
            pubkey     (32 bytes)       -- height encoded in first 8 bytes (BIP34)
            signature  (64 bytes)       -- arbitrary data (coinbase message)
        vout_count   (CompactSize)
        vout[]:
            amount     (8 bytes, int64 LE)
            pubkey_hash (32 bytes)      -- keccak256(miner_pubkey)
        locktime     (8 bytes, int64 LE)
    """
    buf = bytearray()

    # version = 1
    buf += struct.pack('<I', 1)

    # vin_count = 1
    buf += encode_compact_size(1)

    # Coinbase input:
    # prevout txid = 32 zero bytes (null)
    buf += b'\x00' * 32
    # prevout index = 0
    buf += struct.pack('<I', 0)
    # pubkey: height encoded in first 8 bytes (BIP34 style), rest zero
    cb_pubkey = bytearray(32)
    struct.pack_into('<Q', cb_pubkey, 0, height)
    buf += bytes(cb_pubkey)
    # signature: 64 zero bytes (no coinbase message for mined blocks)
    buf += b'\x00' * 64

    # vout_count = 1
    buf += encode_compact_size(1)

    # Coinbase output:
    # amount (int64 LE)
    buf += struct.pack('<q', reward)
    # pubkey_hash = keccak256(miner_pubkey)[0:32]
    pkh = keccak256(miner_pubkey)
    buf += pkh[:32]

    # locktime = 0
    buf += struct.pack('<q', 0)

    return bytes(buf)


def serialize_coinbase_tx_for_hash(height: int, reward: int,
                                   miner_pubkey: bytes) -> bytes:
    """Serialize a coinbase tx for txid computation (excludes signatures).

    Format (from transaction.cpp serialize_for_hash):
        version      (4 bytes, uint32 LE)
        vin_count    (CompactSize)
        vin[]:
            txid       (32 bytes)
            index      (4 bytes, LE)
            pubkey     (32 bytes)
            [NO signature]
        vout_count   (CompactSize)
        vout[]:
            amount     (8 bytes, int64 LE)
            pubkey_hash (32 bytes)
        locktime     (8 bytes, int64 LE)
    """
    buf = bytearray()

    # version = 1
    buf += struct.pack('<I', 1)

    # vin_count = 1
    buf += encode_compact_size(1)

    # Coinbase input (no signature):
    buf += b'\x00' * 32         # prevout txid
    buf += struct.pack('<I', 0)  # prevout index
    cb_pubkey = bytearray(32)
    struct.pack_into('<Q', cb_pubkey, 0, height)
    buf += bytes(cb_pubkey)
    # No signature field for hash computation

    # vout_count = 1
    buf += encode_compact_size(1)

    # Coinbase output:
    buf += struct.pack('<q', reward)
    pkh = keccak256(miner_pubkey)
    buf += pkh[:32]

    # locktime = 0
    buf += struct.pack('<q', 0)

    return bytes(buf)


def compute_txid(height: int, reward: int, miner_pubkey: bytes) -> bytes:
    """Compute the coinbase txid = keccak256d(serialize_for_hash)."""
    data = serialize_coinbase_tx_for_hash(height, reward, miner_pubkey)
    return keccak256d(data)


def compute_merkle_root(tx_hashes: List[bytes]) -> bytes:
    """Compute the Merkle root from a list of transaction hashes.
    Matches the C++ compute_merkle_root in hash/merkle.cpp.
    Each pair is hashed with keccak256d(left || right).
    Odd levels duplicate the last hash."""
    if not tx_hashes:
        return b'\x00' * 32

    level = list(tx_hashes)
    while len(level) > 1:
        if len(level) % 2 != 0:
            level.append(level[-1])
        next_level = []
        for i in range(0, len(level), 2):
            combined = level[i] + level[i + 1]
            next_level.append(keccak256d(combined))
        level = next_level

    return level[0]


# ===================================================================
# Block building
# ===================================================================

def build_block_header(
    prev_hash: bytes,
    merkle_root: bytes,
    training_hash: bytes,
    dataset_hash: bytes,
    height: int,
    timestamp: int,
    nbits: int,
    val_loss: float,
    prev_val_loss: float,
    dims: dict,
    delta_offset: int,
    delta_length: int,
    sparse_count: int,
    sparse_threshold: float,
    nonce: int,
    version: int,
    miner_pubkey: bytes,
    miner_privkey: bytes,
) -> Tuple[bytes, bytes]:
    """Build a complete 308-byte block header.

    Layout matches CBlockHeader::serialize() in block.cpp exactly:
        Bytes   0- 31: prev_hash        (32 bytes, raw)
        Bytes  32- 63: merkle_root      (32 bytes)
        Bytes  64- 95: training_hash    (32 bytes)
        Bytes  96-127: dataset_hash     (32 bytes)
        Bytes 128-135: height           (uint64 LE)
        Bytes 136-143: timestamp        (int64 LE)
        Bytes 144-147: nbits            (uint32 LE)
        Bytes 148-151: val_loss         (float32 IEEE754)
        Bytes 152-155: prev_val_loss    (float32 IEEE754)
        Bytes 156-159: d_model          (uint32 LE)
        Bytes 160-163: n_layers         (uint32 LE)
        Bytes 164-167: d_ff             (uint32 LE)
        Bytes 168-171: n_heads          (uint32 LE)
        Bytes 172-175: gru_dim          (uint32 LE)
        Bytes 176-179: n_slots          (uint32 LE)
        Bytes 180-183: reserved_field   (uint32 LE, must be 0)
        Bytes 184-187: stagnation       (uint32 LE)
        Bytes 188-191: delta_offset     (uint32 LE)
        Bytes 192-195: delta_length     (uint32 LE)
        Bytes 196-199: sparse_count     (uint32 LE)
        Bytes 200-203: sparse_threshold (float32 IEEE754)
        Bytes 204-207: nonce            (uint32 LE)
        Bytes 208-211: version          (uint32 LE)
        Bytes 212-243: miner_pubkey     (32 bytes)
        Bytes 244-307: miner_sig        (64 bytes, Ed25519)

    Returns (header_308_bytes, block_hash).
    """
    header = bytearray(308)

    # 32-byte hash fields (stored as raw bytes, no reversal)
    header[0:32] = prev_hash[:32]
    header[32:64] = merkle_root[:32]
    header[64:96] = training_hash[:32]
    header[96:128] = dataset_hash[:32]

    # 8-byte integer fields
    struct.pack_into('<Q', header, 128, height)
    struct.pack_into('<q', header, 136, timestamp)

    # 4-byte fields
    struct.pack_into('<I', header, 144, nbits)
    struct.pack_into('<f', header, 148, val_loss)
    struct.pack_into('<f', header, 152, prev_val_loss)

    # Architecture dimensions
    d_model = dims['d_model']
    n_layers = dims['n_layers']
    d_ff = dims['d_ff']
    n_heads = dims.get('n_heads', d_model // 64)
    gru_dim = dims.get('gru_dim', d_model)
    n_slots = dims['n_slots']

    struct.pack_into('<I', header, 156, d_model)
    struct.pack_into('<I', header, 160, n_layers)
    struct.pack_into('<I', header, 164, d_ff)
    struct.pack_into('<I', header, 168, n_heads)
    struct.pack_into('<I', header, 172, gru_dim)
    struct.pack_into('<I', header, 176, n_slots)

    # reserved_field = 0 (already zero)
    # stagnation = 0
    struct.pack_into('<I', header, 180, 0)   # reserved
    struct.pack_into('<I', header, 184, 0)   # stagnation

    # Delta reference
    struct.pack_into('<I', header, 188, delta_offset)
    struct.pack_into('<I', header, 192, delta_length)
    struct.pack_into('<I', header, 196, sparse_count)
    struct.pack_into('<f', header, 200, sparse_threshold)

    # Nonce + version
    struct.pack_into('<I', header, 204, nonce)
    struct.pack_into('<I', header, 208, version)

    # Miner pubkey
    header[212:244] = miner_pubkey[:32]

    # Sign the unsigned portion (bytes 0-243)
    unsigned_data = bytes(header[:244])
    signature = ed25519_sign(unsigned_data, miner_privkey)
    header[244:308] = signature[:64]

    # Block hash = keccak256d(unsigned portion, bytes 0-243)
    block_hash = keccak256d(unsigned_data)

    return bytes(header), block_hash


def build_block(
    height: int,
    prev_hash_hex: str,
    nbits: int,
    dims: dict,
    val_loss: float,
    prev_val_loss: float,
    delta_hash: bytes,
    dataset_hash: bytes,
    delta_bytes: bytes,
    miner_privkey: bytes,
    miner_pubkey: bytes,
) -> Tuple[str, str]:
    """Build a complete serialized block and return (block_hex, block_hash_hex).

    Block wire format (from block.cpp CBlock::serialize):
        header           (308 bytes)
        tx_count         (CompactSize)
        transactions[]   (each serialized per transaction.cpp)
        delta_len        (CompactSize)
        delta_payload    (raw bytes)
    """
    # Compute block reward
    reward = compute_block_reward(height)

    # Compute training_hash = keccak256(delta_hash || dataset_hash)
    training_hash = keccak256(delta_hash + dataset_hash)

    # Build coinbase transaction
    coinbase_data = serialize_coinbase_tx(height, reward, miner_pubkey)
    coinbase_txid = compute_txid(height, reward, miner_pubkey)

    # Compute Merkle root (single tx = keccak256d of txid paired with itself
    # is NOT correct -- for a single leaf, merkle root IS the leaf)
    merkle_root = compute_merkle_root([coinbase_txid])

    # Compute delta_offset: offset of delta payload within the block body
    # header(308) + compact_size(1 tx) + coinbase_tx_size + compact_size(delta_len)
    cs_tx_count = encode_compact_size(1)
    cs_delta_len = encode_compact_size(len(delta_bytes))
    delta_offset = 308 + len(cs_tx_count) + len(coinbase_data) + len(cs_delta_len)

    # Decode prev_hash from hex (raw byte order, no reversal needed)
    prev_hash = bytes.fromhex(prev_hash_hex)

    # Build the header
    timestamp = int(time.time())
    header_bytes, block_hash = build_block_header(
        prev_hash=prev_hash,
        merkle_root=merkle_root,
        training_hash=training_hash,
        dataset_hash=dataset_hash,
        height=height,
        timestamp=timestamp,
        nbits=nbits,
        val_loss=val_loss,
        prev_val_loss=prev_val_loss,
        dims=dims,
        delta_offset=delta_offset,
        delta_length=len(delta_bytes),
        sparse_count=0,
        sparse_threshold=0.0,
        nonce=0,
        version=1,
        miner_pubkey=miner_pubkey,
        miner_privkey=miner_privkey,
    )

    # Assemble the full block
    block_data = bytearray()
    block_data += header_bytes                     # 308 bytes
    block_data += cs_tx_count                      # CompactSize(1)
    block_data += coinbase_data                    # coinbase transaction
    block_data += cs_delta_len                     # CompactSize(delta_len)
    block_data += delta_bytes                      # delta payload

    return block_data.hex(), block_hash.hex()


# ===================================================================
# Miner key management
# ===================================================================

def load_or_create_miner_key(datadir: str) -> Tuple[bytes, bytes]:
    """Load miner Ed25519 keypair from disk, or generate a new one.
    Stores the 32-byte private key seed in datadir/miner_key.bin.
    Returns (privkey_seed, pubkey)."""
    keypath = os.path.join(datadir, "miner_key.bin")
    if os.path.exists(keypath):
        with open(keypath, 'rb') as f:
            privkey_seed = f.read(32)
        if len(privkey_seed) == 32:
            pubkey = ed25519_pubkey_from_seed(privkey_seed)
            print(f"  Miner key: {pubkey[:8].hex()}... (loaded)")
            return privkey_seed, pubkey
        else:
            print(f"  Warning: corrupt miner key, generating new one")

    privkey_seed, pubkey = generate_ed25519_keypair()
    os.makedirs(datadir, exist_ok=True)
    with open(keypath, 'wb') as f:
        f.write(privkey_seed[:32])
    os.chmod(keypath, 0o600)
    print(f"  Miner key: {pubkey[:8].hex()}... (new)")
    return privkey_seed, pubkey


# ===================================================================
# Config
# ===================================================================

def read_conf(datadir: str) -> dict:
    """Read flowcoin.conf from the data directory."""
    conf = {}
    path = os.path.join(datadir, "flowcoin.conf")
    if os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    conf[k.strip()] = v.strip()
    return conf


# ===================================================================
# Device selection
# ===================================================================

def select_device(force_cpu: bool = False) -> torch.device:
    """Auto-detect best device: CUDA > MPS > CPU."""
    if not force_cpu and torch.cuda.is_available():
        name = torch.cuda.get_device_name(0)
        mem = torch.cuda.get_device_properties(0).total_memory / 1024**3
        print(f"  GPU: {name} ({mem:.1f} GB)")
        return torch.device("cuda")
    if not force_cpu and hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        print(f"  GPU: Apple MPS")
        return torch.device("mps")
    print(f"  CPU mode")
    return torch.device("cpu")


# ===================================================================
# Main mining loop
# ===================================================================

def mine(args: argparse.Namespace) -> None:
    """Main training/mining loop."""
    device = select_device(args.cpu)
    rpc = RPC(port=args.rpcport, user=args.rpcuser, pw=args.rpcpassword)
    data = TrainingData(args.datadir, batch_size=args.batch)

    # Load or generate miner keypair
    miner_privkey, miner_pubkey = load_or_create_miner_key(args.datadir)

    # Test RPC connection
    try:
        height = rpc.call("getblockcount")
        print(f"  Node: 127.0.0.1:{args.rpcport} (height {height})")
    except Exception as e:
        print(f"  Cannot connect to node: {e}")
        print(f"  Make sure flowcoind is running.")
        sys.exit(1)

    print()

    total_steps = 0
    total_checks = 0
    blocks_found = 0
    session_start = time.time()

    while True:
        try:
            # Get block template
            tmpl = rpc.call("getblocktemplate")
            height = tmpl["height"]
            nbits = tmpl.get("nbits", 0x1f00ffff)
            target = derive_target(nbits)
            prev_hash_hex = tmpl["previousblockhash"]
            prev_val_loss = tmpl.get("prev_val_loss", 100.0)
            dims = compute_growth(height)

            # Use template dims if available (authoritative from node)
            if "model" in tmpl:
                mdims = tmpl["model"]
                dims['d_model'] = mdims.get('d_model', dims['d_model'])
                dims['n_layers'] = mdims.get('n_layers', dims['n_layers'])
                dims['d_ff'] = mdims.get('d_ff', dims['d_ff'])
                dims['n_slots'] = mdims.get('n_slots', dims['n_slots'])
                dims['n_heads'] = mdims.get('n_heads', dims['d_model'] // 64)
                dims['gru_dim'] = mdims.get('gru_dim', dims['d_model'])

            print(f"  Mining block {height} | d={dims['d_model']} "
                  f"L={dims['n_layers']} slots={dims['n_slots']}")

            # Create model
            model = ResonanceNetV5(
                d_model=dims["d_model"],
                n_layers=dims["n_layers"],
                d_ff=dims["d_ff"],
                n_slots=dims["n_slots"],
            ).to(device)

            params = sum(p.numel() for p in model.parameters())
            print(f"  Params: {params:,} | Target: {hex(nbits)}")

            # Consensus weights = zeros (genesis model has no initial state)
            consensus = {k: torch.zeros_like(v) for k, v in model.state_dict().items()}

            # Pre-cache flattened consensus on GPU for fast hash check
            consensus_flat = torch.zeros(
                sum(p.numel() for p in model.parameters()),
                device=device, dtype=torch.float32
            )

            # Optimizer
            optimizer = torch.optim.AdamW(
                model.parameters(), lr=args.lr, weight_decay=0.01
            )

            # Training loop
            step = 0
            best_loss = float("inf")
            cycle_start = time.time()
            model.train()

            while True:
                x, y = data.get_batch(device)
                logits, _ = model(x)
                loss = F.cross_entropy(logits.reshape(-1, 256), y.reshape(-1))

                optimizer.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()

                step += 1
                total_steps += 1
                lv = loss.item()
                if lv < best_loss:
                    best_loss = lv

                total_checks += 1

                # Hash check every step — hash first param tensor only (small, fast, unique)
                with torch.no_grad():
                    first_param = next(model.parameters()).data.cpu().numpy().tobytes()
                delta_hash = keccak256(first_param)
                training_hash = keccak256(delta_hash + data.hash)
                training_int = int.from_bytes(training_hash, "big")

                # Status every 10 steps
                if step % 10 == 0:
                    elapsed = time.time() - cycle_start
                    st_s = step / elapsed
                    tok_s = step * args.batch * 256 / elapsed
                    print(
                        f"\r  step {step:>6d} | loss {lv:.4f} | "
                        f"best {best_loss:.4f} | {st_s:.1f} st/s "
                        f"{tok_s:.0f} tok/s | checks {total_checks}",
                        end="", flush=True,
                    )

                if training_int < target:
                    # Candidate found. Compute sparse delta for block.
                    delta_hash, sparse_bytes, nonzero = compute_full_delta(
                        model, consensus, sparse_threshold=0.01)
                    elapsed = time.time() - cycle_start
                    blocks_found += 1

                    total_params = sum(p.numel() for p in model.parameters())
                    sparsity = (1 - nonzero / total_params) * 100

                    print(f"\n\n  *** BLOCK {height} FOUND! ***")
                    print(f"  Step: {step} | Loss: {best_loss:.4f} | "
                          f"Time: {elapsed:.1f}s")
                    print(f"  Hash:     {training_hash.hex()[:16]}...")
                    print(f"  Delta:    {nonzero:,} / {total_params:,} params "
                          f"({sparsity:.1f}% sparse)")
                    print(f"  Payload:  {len(sparse_bytes):,} bytes "
                          f"({len(sparse_bytes)/1e6:.1f} MB)")

                    # Build the actual block
                    block_hex, block_hash_hex = build_block(
                        height=height,
                        prev_hash_hex=prev_hash_hex,
                        nbits=nbits,
                        dims=dims,
                        val_loss=best_loss,
                        prev_val_loss=prev_val_loss,
                        delta_hash=delta_hash,
                        dataset_hash=data.hash,
                        delta_bytes=sparse_bytes,
                        miner_privkey=miner_privkey,
                        miner_pubkey=miner_pubkey,
                    )

                    print(f"  Block:    {len(block_hex) // 2:,} bytes")
                    print(f"  Submitting...")

                    try:
                        result = rpc.call("submitblock", [block_hex])
                        if result is None:
                            print(f"  Accepted!")
                        else:
                            print(f"  Rejected: {result}")
                    except RPCError as e:
                        print(f"  Error: {e}")
                    except Exception as e:
                        print(f"  Error: {e}")

                    print()
                    break

                # Check for new blocks from network every 100 steps
                if step % 100 == 0:
                    try:
                        cur = rpc.call("getblockcount")
                        if cur >= height:
                            print(f"\n  New block from network, restarting...")
                            break
                    except RPCError:
                        pass

        except KeyboardInterrupt:
            elapsed = time.time() - session_start
            print(f"\n\n  Miner stopped.")
            print(f"  Steps: {total_steps} | Checks: {total_checks} | "
                  f"Blocks: {blocks_found} | Time: {elapsed:.0f}s")
            break

        except RPCError as e:
            print(f"\n  RPC error: {e}")
            time.sleep(5)

        except Exception as e:
            print(f"\n  Error: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(5)


# ===================================================================
# Entry point
# ===================================================================

def main():
    p = argparse.ArgumentParser(description="FlowCoin Miner")
    p.add_argument("--datadir", default=os.path.expanduser("~/.flowcoin"))
    p.add_argument("--rpcport", type=int, default=0)
    p.add_argument("--rpcuser", default="")
    p.add_argument("--rpcpassword", default="")
    p.add_argument("--batch", type=int, default=32)
    p.add_argument("--lr", type=float, default=0.001)
    p.add_argument("--cpu", action="store_true")
    args = p.parse_args()

    # Read config file for defaults
    conf = read_conf(args.datadir)
    if not args.rpcuser:
        args.rpcuser = conf.get("rpcuser", "flowcoin")
    if not args.rpcpassword:
        args.rpcpassword = conf.get("rpcpassword", "")
    if args.rpcport == 0:
        args.rpcport = int(conf.get("rpcport", "9334"))

    print()
    print(f"  FlowCoin Miner v1.0.0")
    print(f"  PyTorch {torch.__version__}")
    print()

    mine(args)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
FlowCoin Miner — PyTorch GPU Training
Trains ResonanceNet V5 and submits blocks to flowcoind.

Usage:
    python3 flowminer.py --dataset ~/data/ --node http://127.0.0.1:9334

Requirements:
    pip install torch zstandard pycryptodome
"""

import argparse
import base64
import json
import math
import os
import signal
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F

# ════════════════════════════════════════════════════════════════
# Keccak-256 (pad=0x01, NOT SHA-3)
# ════════════════════════════════════════════════════════════════
# Use pycryptodome's Keccak (pad=0x01) or pysha3
try:
    from Crypto.Hash import keccak as pycrypto_keccak

    def keccak256(data: bytes) -> bytes:
        h = pycrypto_keccak.new(digest_bits=256, data=data)
        return h.digest()
except ImportError:
    try:
        import sha3  # pysha3 library

        def keccak256(data: bytes) -> bytes:
            return sha3.keccak_256(data).digest()
    except ImportError:
        print("ERROR: Neither pycryptodome nor pysha3 is installed.")
        print("Install one: pip install pycryptodome")
        sys.exit(1)


def keccak256d(data: bytes) -> bytes:
    """Double Keccak-256 (analogous to Bitcoin's SHA256d)."""
    return keccak256(keccak256(data))


# ════════════════════════════════════════════════════════════════
# Constants — must match consensus/params.h
# ════════════════════════════════════════════════════════════════

COIN = 100_000_000
EVAL_TOKENS = 4096
EVAL_SEQ_LEN = 256
VALIDATION_SEED = "flowcoin validation dataset v1"

# Genesis model dimensions
GENESIS_D_MODEL = 512
GENESIS_N_LAYERS = 8
GENESIS_D_FF = 1024
GENESIS_N_SLOTS = 1024
GENESIS_N_HEADS = 8
GENESIS_D_HEAD = 64
GENESIS_TOP_K = 2
GENESIS_VOCAB = 256
GENESIS_SEQ_LEN = 256
GENESIS_GRU_DIM = 512
GENESIS_SEED = 42

# Growth constants — continuous growth, no phases, no cap
DIM_FREEZE_HEIGHT = 512
MAX_D_MODEL = 1024
MAX_N_LAYERS = 24
SLOT_GROWTH_PER_BLOCK = 4


# ════════════════════════════════════════════════════════════════
# Model growth schedule — mirrors consensus/growth.cpp
# ════════════════════════════════════════════════════════════════

def compute_growth(height: int) -> dict:
    """Compute model dimensions at a given block height.

    Every block grows the model. No phases, no plateaus, no cap on slots.
    Dimensions grow linearly then freeze; slots grow forever.
    """
    # Dimensions grow linearly, then freeze at max
    raw_d = 512 + min(height, 512)
    d_model = min(raw_d, MAX_D_MODEL)

    # Layers grow 1 per 32 blocks, max 24
    n_layers = min(8 + height // 32, MAX_N_LAYERS)

    # Derived
    d_ff = 2 * d_model
    n_heads = d_model // 64  # 8 at 512, 16 at 1024
    gru_dim = d_model

    # Slots grow EVERY block, NO CAP
    n_slots = GENESIS_N_SLOTS + height * SLOT_GROWTH_PER_BLOCK

    return {
        "d_model": d_model,
        "n_layers": n_layers,
        "d_ff": d_ff,
        "n_heads": n_heads,
        "d_head": 64,  # always 64
        "n_slots": n_slots,
        "top_k": GENESIS_TOP_K,
        "gru_dim": gru_dim,
        "conv_kernel": 4,
        "vocab": GENESIS_VOCAB,
        "seq_len": GENESIS_SEQ_LEN,
    }


# compute_min_steps removed: difficulty alone regulates mining


# ════════════════════════════════════════════════════════════════
# RPC Client
# ════════════════════════════════════════════════════════════════

class RPCError(Exception):
    """Raised when an RPC call fails."""
    pass


class RPCClient:
    """JSON-RPC client for communicating with flowcoind."""

    def __init__(self, url: str, user: str, password: str, timeout: int = 300):
        self.url = url
        self.user = user
        self.password = password
        self.timeout = timeout
        self.id_counter = 0
        self._credentials = base64.b64encode(
            f"{self.user}:{self.password}".encode()
        ).decode()

    def call(self, method: str, params=None):
        """Make a JSON-RPC call to flowcoind.

        Args:
            method: RPC method name.
            params: List of positional parameters.

        Returns:
            The 'result' field from the JSON-RPC response.

        Raises:
            RPCError: If the node returns an error or is unreachable.
        """
        self.id_counter += 1
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": self.id_counter,
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(self.url, data=data)
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Basic {self._credentials}")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
                result = json.loads(body)
                if result.get("error"):
                    err = result["error"]
                    code = err.get("code", -1)
                    msg = err.get("message", str(err))
                    raise RPCError(f"RPC error {code}: {msg}")
                return result.get("result")
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            raise RPCError(f"HTTP {e.code}: {body[:200]}")
        except urllib.error.URLError as e:
            raise RPCError(f"Cannot connect to node at {self.url}: {e.reason}")
        except json.JSONDecodeError as e:
            raise RPCError(f"Invalid JSON response from node: {e}")

    def is_connected(self) -> bool:
        """Check whether the node is reachable."""
        try:
            self.call("getblockcount")
            return True
        except RPCError:
            return False


# ════════════════════════════════════════════════════════════════
# ResonanceNet V5 — PyTorch Implementation
# Must produce IDENTICAL architecture to ggml consensus model
# ════════════════════════════════════════════════════════════════

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
        # Depthwise causal convolutions with appropriate padding for causality
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

        # Apply convolutions and trim to enforce causality (no future leakage)
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

        outputs = []
        h = h_prev
        for t in range(T):
            xt = x[:, t, :]
            z = torch.sigmoid(self.Wz(xt))
            h_tilde = self.Wh(xt)
            h = (1 - z) * h + z * h_tilde
            outputs.append(h.unsqueeze(1))

        return torch.cat(outputs, dim=1), h


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

        # Compute attention scores against all slot keys
        scores = torch.matmul(q, self.slot_keys.T) / math.sqrt(D)  # [B, T, n_slots]

        # Top-k sparse routing
        topk_vals, topk_ids = torch.topk(scores, self.top_k, dim=-1)  # [B, T, k]
        attn = F.softmax(topk_vals, dim=-1)  # [B, T, k]

        # Gather the values for the selected slots
        topk_ids_flat = topk_ids.reshape(-1, self.top_k)  # [B*T, k]
        gathered = self.slot_values[topk_ids_flat]  # [B*T, k, D]
        gathered = gathered.reshape(B, T, self.top_k, D)  # [B, T, k, D]

        # Weighted sum of retrieved values
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
        # Output projection is weight-tied with embedding

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
        # Tied output: logits = x @ embedding.weight.T
        logits = F.linear(x, self.embedding.weight)  # [B, T, vocab]
        return logits, new_hiddens

    def param_count(self) -> int:
        """Total number of trainable parameters."""
        return sum(p.numel() for p in self.parameters())


# ════════════════════════════════════════════════════════════════
# Deterministic weight initialization (must match ggml consensus)
# ════════════════════════════════════════════════════════════════

def keccak_prng_init(seed: int) -> bytes:
    """Initialize a Keccak-256 PRNG state from a 32-bit seed."""
    return struct.pack("<I", seed)


def keccak_prng_generate(state: bytes, num_bytes: int) -> Tuple[bytes, bytes]:
    """Generate pseudo-random bytes using Keccak-256 in counter mode.

    Produces deterministic output identical to the C++ consensus implementation.

    Args:
        state: Current PRNG seed bytes.
        num_bytes: Number of bytes to generate.

    Returns:
        (random_bytes, updated_state)
    """
    output = bytearray()
    counter = 0
    while len(output) < num_bytes:
        block_input = state + struct.pack("<I", counter)
        block = keccak256(block_input)
        output.extend(block)
        counter += 1
    return bytes(output[:num_bytes]), state


def init_weights_deterministic(model: ResonanceNetV5, seed: int = GENESIS_SEED):
    """Initialize model weights deterministically from a Keccak-256 PRNG.

    Produces the same weight values as the ggml consensus model initialized
    with the same seed, ensuring miners start from the exact consensus state.

    Args:
        model: The model to initialize.
        seed: RNG seed (default: GENESIS_SEED = 42).
    """
    state = keccak_prng_init(seed)

    with torch.no_grad():
        for name, param in sorted(model.named_parameters()):
            num_bytes = param.numel() * 4  # float32
            random_bytes, state = keccak_prng_generate(state, num_bytes)

            # Convert bytes to float32 tensor
            values = torch.frombuffer(
                bytearray(random_bytes), dtype=torch.float32
            ).clone()

            # Scale to small values for stable training start
            # Xavier-like: scale by 1/sqrt(fan_in)
            fan_in = param.shape[-1] if len(param.shape) > 1 else param.shape[0]
            scale = 1.0 / math.sqrt(fan_in)
            values = values * scale

            # Reshape and assign
            param.copy_(values.reshape(param.shape))


# ════════════════════════════════════════════════════════════════
# Validation data generation (mirrors C++ consensus)
# ════════════════════════════════════════════════════════════════

def generate_validation_data(
    seed_str: str = VALIDATION_SEED, num_tokens: int = EVAL_TOKENS
) -> bytes:
    """Generate deterministic validation data using Keccak-256 counter mode.

    Produces output identical to flow::generate_validation_data() in C++.

    Args:
        seed_str: Seed string (default: consensus validation seed).
        num_tokens: Number of bytes/tokens to generate.

    Returns:
        Byte string of length num_tokens.
    """
    seed_bytes = seed_str.encode("utf-8")
    output = bytearray()
    counter = 0
    while len(output) < num_tokens:
        block_input = seed_bytes + struct.pack("<I", counter)
        block = keccak256(block_input)
        output.extend(block)
        counter += 1
    return bytes(output[:num_tokens])


def compute_dataset_hash() -> bytes:
    """Compute the hash of the standard validation dataset."""
    data = generate_validation_data()
    return keccak256(data)


# ════════════════════════════════════════════════════════════════
# Training data loader
# ════════════════════════════════════════════════════════════════

class TrainingDataLoader:
    """Load byte-level text data for training.

    Reads .txt files from a directory (recursively) or a single file,
    and produces (input, target) batches for next-byte prediction training.
    """

    def __init__(self, path: str, seq_len: int = 256, batch_size: int = 1):
        self.seq_len = seq_len
        self.batch_size = batch_size

        # Load all .txt files from directory or single file
        raw_path = Path(path)
        if raw_path.is_dir():
            data = b""
            txt_files = sorted(raw_path.glob("**/*.txt"))
            if not txt_files:
                # Fall back to all files
                txt_files = sorted(
                    f for f in raw_path.glob("**/*") if f.is_file()
                )
            for f in txt_files:
                try:
                    data += f.read_bytes()
                except (OSError, PermissionError):
                    continue
        elif raw_path.is_file():
            data = raw_path.read_bytes()
        else:
            raise FileNotFoundError(f"Dataset path not found: {path}")

        if len(data) < seq_len + 1:
            raise ValueError(
                f"Dataset too small: {len(data)} bytes, need at least {seq_len + 1}. "
                f"Add more training data to {path}"
            )

        self.data = torch.tensor(list(data), dtype=torch.long)
        self.pos = 0
        self.total_bytes = len(self.data)

    def get_batch(self, device: torch.device) -> Tuple[torch.Tensor, torch.Tensor]:
        """Get a batch of (input, target) pairs.

        Returns:
            x: [batch_size, seq_len] input tokens
            y: [batch_size, seq_len] target tokens (shifted by 1)
        """
        chunks = []
        for _ in range(self.batch_size):
            if self.pos + self.seq_len + 1 > self.total_bytes:
                self.pos = 0

            chunk = self.data[self.pos : self.pos + self.seq_len + 1]
            if len(chunk) < self.seq_len + 1:
                # Wrap around
                remainder = self.seq_len + 1 - len(chunk)
                chunk = torch.cat([chunk, self.data[:remainder]])
                self.pos = remainder
            else:
                self.pos += self.seq_len + 1

            chunks.append(chunk)

        batch = torch.stack(chunks)
        x = batch[:, :-1].to(device)  # input
        y = batch[:, 1:].to(device)   # target (shifted by 1)
        return x, y

    def reset(self):
        """Reset the data position to the beginning."""
        self.pos = 0


# ════════════════════════════════════════════════════════════════
# Delta computation and serialization
# ════════════════════════════════════════════════════════════════

def compute_delta(
    model: ResonanceNetV5,
    consensus_weights: Dict[str, torch.Tensor],
) -> Dict[str, torch.Tensor]:
    """Compute the weight delta: current_weights - consensus_weights.

    Args:
        model: The model after training.
        consensus_weights: Snapshot of weights before training.

    Returns:
        Dictionary mapping parameter names to delta tensors.
    """
    current = {k: v.detach().cpu() for k, v in model.state_dict().items()}
    delta = {}
    for key in sorted(current.keys()):
        if key in consensus_weights:
            delta[key] = current[key] - consensus_weights[key]
        else:
            delta[key] = current[key]
    return delta


def delta_to_bytes(delta: Dict[str, torch.Tensor]) -> bytes:
    """Serialize a delta dictionary to a flat float32 byte buffer.

    Parameters are sorted by name and concatenated as contiguous float32.

    Args:
        delta: Parameter name -> delta tensor.

    Returns:
        Raw bytes of concatenated float32 values.
    """
    parts = []
    for key in sorted(delta.keys()):
        parts.append(delta[key].float().contiguous().numpy().tobytes())
    return b"".join(parts)


def sparsify_delta(
    delta_bytes: bytes, threshold: float = 1e-6
) -> Tuple[bytes, int, float]:
    """Sparsify a delta by zeroing values below threshold.

    Values with absolute magnitude below the threshold are set to zero,
    improving zstd compression ratio.

    Args:
        delta_bytes: Raw float32 delta bytes.
        threshold: Absolute magnitude threshold.

    Returns:
        (sparsified_bytes, nonzero_count, threshold_used)
    """
    import numpy as np

    arr = np.frombuffer(delta_bytes, dtype=np.float32).copy()
    mask = np.abs(arr) >= threshold
    nonzero_count = int(np.sum(mask))
    arr[~mask] = 0.0
    return arr.tobytes(), nonzero_count, threshold


def compress_delta(data: bytes, level: int = 3) -> bytes:
    """Compress delta bytes using zstd.

    Args:
        data: Raw delta bytes.
        level: Zstd compression level (1-22, default 3).

    Returns:
        Zstd-compressed bytes.
    """
    import zstandard as zstd

    cctx = zstd.ZstdCompressor(level=level)
    return cctx.compress(data)


def decompress_delta(data: bytes) -> bytes:
    """Decompress zstd-compressed delta bytes.

    Args:
        data: Zstd-compressed bytes.

    Returns:
        Decompressed raw bytes.
    """
    import zstandard as zstd

    dctx = zstd.ZstdDecompressor()
    return dctx.decompress(data, max_output_size=500_000_000)


# ════════════════════════════════════════════════════════════════
# Training hash computation (consensus-critical)
# ════════════════════════════════════════════════════════════════

def compute_training_hash(delta_bytes: bytes, dataset_hash: bytes) -> bytes:
    """Compute the training hash that is compared against the PoW target.

    training_hash = keccak256(keccak256(delta_bytes) || dataset_hash)

    This binds the specific training work to the evaluation dataset,
    preventing pre-computation attacks.

    Args:
        delta_bytes: Raw (possibly sparsified) delta bytes.
        dataset_hash: keccak256 of the validation dataset.

    Returns:
        32-byte training hash.
    """
    delta_hash = keccak256(delta_bytes)
    return keccak256(delta_hash + dataset_hash)


def hash_to_int(h: bytes) -> int:
    """Convert a 32-byte hash to a 256-bit integer (big-endian)."""
    return int.from_bytes(h, "big")


def target_from_nbits(nbits: int) -> int:
    """Decode a compact target (nBits) into a 256-bit integer.

    Format: exponent = nbits >> 24, mantissa = nbits & 0xFFFFFF
    target = mantissa << (8 * (exponent - 3))

    Args:
        nbits: Compact target representation.

    Returns:
        256-bit target as Python integer.
    """
    exponent = (nbits >> 24) & 0xFF
    mantissa = nbits & 0x00FFFFFF
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    else:
        return mantissa << (8 * (exponent - 3))


# ════════════════════════════════════════════════════════════════
# Block serialization for submission
# ════════════════════════════════════════════════════════════════

def serialize_block_header(
    prev_hash: bytes,
    merkle_root: bytes,
    training_hash: bytes,
    dataset_hash: bytes,
    height: int,
    timestamp: int,
    nbits: int,
    val_loss: float,
    prev_val_loss: float,
    d_model: int,
    n_layers: int,
    d_ff: int,
    n_heads: int,
    gru_dim: int,
    n_slots: int,
    stagnation: int,
    delta_offset: int,
    delta_length: int,
    sparse_count: int,
    sparse_threshold: float,
    nonce: int,
    version: int,
    miner_pubkey: bytes,
    miner_sig: bytes,
) -> bytes:
    """Serialize a block header to its 308-byte wire format.

    Layout matches the C++ CBlockHeader::get_unsigned_data() for the first
    244 bytes, with the 64-byte miner_sig appended.

    Returns:
        308-byte header.
    """
    parts = []
    parts.append(prev_hash)           # 32 bytes
    parts.append(merkle_root)          # 32 bytes
    parts.append(training_hash)        # 32 bytes
    parts.append(dataset_hash)         # 32 bytes
    parts.append(struct.pack("<Q", height))         # 8 bytes
    parts.append(struct.pack("<q", timestamp))       # 8 bytes
    parts.append(struct.pack("<I", nbits))           # 4 bytes
    parts.append(struct.pack("<f", val_loss))        # 4 bytes
    parts.append(struct.pack("<f", prev_val_loss))   # 4 bytes
    parts.append(struct.pack("<I", d_model))         # 4 bytes
    parts.append(struct.pack("<I", n_layers))        # 4 bytes
    parts.append(struct.pack("<I", d_ff))            # 4 bytes
    parts.append(struct.pack("<I", n_heads))         # 4 bytes
    parts.append(struct.pack("<I", gru_dim))         # 4 bytes
    parts.append(struct.pack("<I", n_slots))         # 4 bytes
    parts.append(struct.pack("<I", 0))                # 4 bytes (reserved)
    parts.append(struct.pack("<I", stagnation))      # 4 bytes
    parts.append(struct.pack("<I", delta_offset))    # 4 bytes
    parts.append(struct.pack("<I", delta_length))    # 4 bytes
    parts.append(struct.pack("<I", sparse_count))    # 4 bytes
    parts.append(struct.pack("<f", sparse_threshold))# 4 bytes
    parts.append(struct.pack("<I", nonce))           # 4 bytes
    parts.append(struct.pack("<I", version))         # 4 bytes
    parts.append(miner_pubkey)         # 32 bytes
    parts.append(miner_sig)            # 64 bytes
    return b"".join(parts)


# ════════════════════════════════════════════════════════════════
# Evaluation engine (mirrors C++ EvalEngine)
# ════════════════════════════════════════════════════════════════

def evaluate_model(
    model: ResonanceNetV5,
    val_data: bytes,
    seq_len: int = EVAL_SEQ_LEN,
    device: torch.device = torch.device("cpu"),
) -> float:
    """Evaluate the model on validation data and return cross-entropy loss.

    Processes the validation data in chunks of seq_len tokens, computing
    the average cross-entropy loss across all positions.

    Args:
        model: The model to evaluate.
        val_data: Byte-level validation tokens.
        seq_len: Chunk size for processing.
        device: Device to evaluate on.

    Returns:
        Average cross-entropy loss (float32).
    """
    model.eval()
    tokens = torch.tensor(list(val_data), dtype=torch.long)
    total_loss = 0.0
    total_tokens = 0

    with torch.no_grad():
        num_chunks = (len(tokens) - 1) // seq_len
        for i in range(num_chunks):
            start = i * seq_len
            end = start + seq_len + 1
            if end > len(tokens):
                break

            chunk = tokens[start:end].unsqueeze(0).to(device)
            x = chunk[:, :-1]
            y = chunk[:, 1:]

            logits, _ = model(x)
            loss = F.cross_entropy(
                logits.reshape(-1, model.vocab),
                y.reshape(-1),
                reduction="sum",
            )
            total_loss += loss.item()
            total_tokens += y.numel()

    if total_tokens == 0:
        return float("inf")

    return total_loss / total_tokens


# ════════════════════════════════════════════════════════════════
# Mining statistics tracker
# ════════════════════════════════════════════════════════════════

class MiningStats:
    """Track and display mining performance metrics."""

    def __init__(self):
        self.start_time = time.time()
        self.total_steps = 0
        self.total_hash_checks = 0
        self.blocks_found = 0
        self.best_loss = float("inf")
        self.last_display_time = 0.0
        self.step_times: List[float] = []

    def record_step(self, loss: float, elapsed: float):
        """Record a single training step."""
        self.total_steps += 1
        self.step_times.append(elapsed)
        if len(self.step_times) > 1000:
            self.step_times = self.step_times[-500:]
        if loss < self.best_loss:
            self.best_loss = loss

    def record_hash_check(self):
        """Record a hash comparison against the target."""
        self.total_hash_checks += 1

    def record_block_found(self):
        """Record a successful block find."""
        self.blocks_found += 1

    def steps_per_second(self) -> float:
        """Compute the recent training throughput."""
        if len(self.step_times) < 2:
            return 0.0
        recent = self.step_times[-100:]
        return len(recent) / max(sum(recent), 1e-9)

    def elapsed_str(self) -> str:
        """Return a formatted elapsed time string."""
        elapsed = time.time() - self.start_time
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        seconds = int(elapsed % 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def display(
        self, step: int, loss: float, height: int, force: bool = False
    ):
        """Display current mining status if enough time has passed.

        Shows loss, throughput, hash checks, and elapsed time.

        Args:
            step: Current training step.
            loss: Current training loss.
            height: Block height being mined.
            force: Display regardless of time throttle.
        """
        now = time.time()
        if not force and now - self.last_display_time < 1.0:
            return  # Throttle to 1 update/sec

        self.last_display_time = now
        sps = self.steps_per_second()
        elapsed = self.elapsed_str()

        sys.stdout.write(
            f"\r  [{elapsed}] block {height} | "
            f"step {step:>7d} | "
            f"loss {loss:.4f} | "
            f"best {self.best_loss:.4f} | "
            f"{sps:.0f} steps/s | "
            f"checks {self.total_hash_checks}"
        )
        sys.stdout.flush()


# ════════════════════════════════════════════════════════════════
# Weight snapshot management
# ════════════════════════════════════════════════════════════════

def snapshot_weights(model: ResonanceNetV5) -> Dict[str, torch.Tensor]:
    """Take a CPU snapshot of all model weights.

    Args:
        model: The model to snapshot.

    Returns:
        Dictionary of parameter_name -> cpu tensor copies.
    """
    return {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}


def load_weights_from_node(
    rpc: RPCClient, model: ResonanceNetV5
) -> Dict[str, torch.Tensor]:
    """Download and load consensus model weights from the node.

    Calls the getmodelweights RPC method, decodes the base64 response,
    and loads the flat float32 buffer into the model.

    Args:
        rpc: Connected RPC client.
        model: Model to load weights into.

    Returns:
        Snapshot of the loaded consensus weights.

    Raises:
        RPCError: If the weights cannot be downloaded.
    """
    try:
        result = rpc.call("getmodelweights")
        if result is None:
            print("  Node returned no model weights, using deterministic init")
            return snapshot_weights(model)

        if isinstance(result, str):
            weight_bytes = base64.b64decode(result)
        elif isinstance(result, dict) and "data" in result:
            weight_bytes = base64.b64decode(result["data"])
        else:
            print("  Unexpected weight format, using deterministic init")
            return snapshot_weights(model)

        # Convert flat float32 buffer to state dict
        weights = torch.frombuffer(
            bytearray(weight_bytes), dtype=torch.float32
        ).clone()

        # Distribute across parameters in sorted order
        offset = 0
        state_dict = model.state_dict()
        for key in sorted(state_dict.keys()):
            param = state_dict[key]
            numel = param.numel()
            if offset + numel > len(weights):
                print(f"  WARNING: Weight buffer too short at {key}, "
                      f"using deterministic init")
                return snapshot_weights(model)
            state_dict[key] = weights[offset : offset + numel].reshape(param.shape)
            offset += numel

        model.load_state_dict(state_dict)
        print(f"  Loaded {offset:,} weight values from node")
        return snapshot_weights(model)

    except RPCError as e:
        print(f"  Could not load weights from node: {e}")
        print("  Using deterministic init")
        return snapshot_weights(model)


# ════════════════════════════════════════════════════════════════
# Block template handling
# ════════════════════════════════════════════════════════════════

class BlockTemplate:
    """Parsed block template from the node."""

    def __init__(self, data: dict):
        self.height = data["height"]
        self.target_hex = data.get("target", "")
        self.target = int(self.target_hex, 16) if self.target_hex else 0
        self.nbits = data.get("nbits", 0)
        self.prev_hash = bytes.fromhex(data.get("prev_hash", "00" * 32))
        self.prev_val_loss = data.get("prev_val_loss", 0.0)
        self.d_model = data.get("d_model", GENESIS_D_MODEL)
        self.n_layers = data.get("n_layers", GENESIS_N_LAYERS)
        self.d_ff = data.get("d_ff", GENESIS_D_FF)
        self.n_slots = data.get("n_slots", GENESIS_N_SLOTS)
        self.n_heads = data.get("n_heads", GENESIS_N_HEADS)
        self.gru_dim = data.get("gru_dim", GENESIS_GRU_DIM)
        self.stagnation = data.get("stagnation", 0)
        self.improving_blocks = data.get("improving_blocks", 0)
        self.coinbase_value = data.get("coinbase_value", 50 * COIN)
        self.coinbase_address = data.get("coinbase_address", "")
        self.transactions = data.get("transactions", [])
        self.dataset_hash = bytes.fromhex(
            data.get("dataset_hash", "00" * 32)
        )
        # min_train_steps removed: difficulty alone regulates mining

    def dims(self) -> dict:
        """Return model dimensions as a dict."""
        return {
            "d_model": self.d_model,
            "n_layers": self.n_layers,
            "d_ff": self.d_ff,
            "n_slots": self.n_slots,
            "n_heads": self.n_heads,
            "gru_dim": self.gru_dim,
        }


# ════════════════════════════════════════════════════════════════
# Main mining loop
# ════════════════════════════════════════════════════════════════

def select_device(gpu_id: int) -> torch.device:
    """Select the best available compute device.

    Args:
        gpu_id: GPU device index, or -1 for auto-selection.

    Returns:
        A torch.device.
    """
    if gpu_id >= 0:
        if not torch.cuda.is_available():
            print(f"  WARNING: CUDA GPU {gpu_id} requested but CUDA not available")
            return torch.device("cpu")
        return torch.device(f"cuda:{gpu_id}")
    elif torch.cuda.is_available():
        device = torch.device("cuda")
        gpu_name = torch.cuda.get_device_name(0)
        gpu_mem = torch.cuda.get_device_properties(0).total_mem / (1024 ** 3)
        print(f"  GPU: {gpu_name} ({gpu_mem:.1f} GB)")
        return device
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    else:
        return torch.device("cpu")


def create_model(template: BlockTemplate, device: torch.device) -> ResonanceNetV5:
    """Create and initialize a ResonanceNet V5 model from a block template.

    Args:
        template: Block template with model dimensions.
        device: Target device.

    Returns:
        Initialized model on the target device.
    """
    model = ResonanceNetV5(
        vocab=GENESIS_VOCAB,
        d_model=template.d_model,
        n_layers=template.n_layers,
        d_ff=template.d_ff,
        n_slots=template.n_slots,
        top_k=GENESIS_TOP_K,
    ).to(device)
    return model


def submit_block(
    rpc: RPCClient,
    template: BlockTemplate,
    delta_bytes: bytes,
    compressed_delta: bytes,
    sparse_count: int,
    sparse_threshold: float,
    val_loss: float,
) -> bool:
    """Submit a mined block to the node.

    Constructs the block submission payload and calls submitblock RPC.

    Args:
        rpc: Connected RPC client.
        template: The block template this block is based on.
        delta_bytes: Raw sparsified delta bytes.
        compressed_delta: Zstd-compressed delta.
        sparse_count: Number of non-zero elements.
        sparse_threshold: Sparsification threshold used.
        val_loss: Achieved validation loss.

    Returns:
        True if the block was accepted by the node.
    """
    try:
        delta_b64 = base64.b64encode(compressed_delta).decode()
        result = rpc.call("submitblock", [{
            "height": template.height,
            "prev_hash": template.prev_hash.hex(),
            "delta": delta_b64,
            "delta_length": len(compressed_delta),
            "sparse_count": sparse_count,
            "sparse_threshold": sparse_threshold,
            "val_loss": val_loss,
            "prev_val_loss": template.prev_val_loss,
        }])

        if result is None or result == "accepted":
            return True
        else:
            print(f"\n  Block rejected: {result}")
            return False

    except RPCError as e:
        print(f"\n  Block submission failed: {e}")
        return False


def mining_loop(args):
    """Main mining loop.

    1. Connect to flowcoind
    2. Get block template
    3. Initialize or load model
    4. Train on user data
    5. Periodically check if training_hash < target
    6. Submit block when found
    7. Repeat

    Args:
        args: Parsed command-line arguments.
    """
    device = select_device(args.gpu)
    print(f"  Device: {device}")
    print(f"  Dataset: {args.dataset}")
    print(f"  Node: {args.node}")
    print(f"  Learning rate: {args.lr}")
    print(f"  Batch size: {args.batch}")
    print(f"  Sequence length: {args.seq}")
    print(f"  Steps per hash check: {args.steps_per_check}")
    print()

    rpc = RPCClient(args.node, args.user, args.password)
    stats = MiningStats()

    # Pre-load training data
    print("Loading training data...")
    loader = TrainingDataLoader(args.dataset, seq_len=args.seq, batch_size=args.batch)
    print(f"  {loader.total_bytes:,} bytes loaded")
    print()

    # Pre-compute validation dataset hash
    dataset_hash = compute_dataset_hash()
    val_data = generate_validation_data()
    print(f"  Dataset hash: {dataset_hash.hex()[:16]}...")
    print()

    while True:
        try:
            # ── Step 1: Get block template from node ──
            print("Requesting block template...")
            raw_template = rpc.call("getblocktemplate")
            template = BlockTemplate(raw_template)

            print(f"  Block height: {template.height}")
            print(f"  Model: d={template.d_model} L={template.n_layers} "
                  f"ff={template.d_ff} slots={template.n_slots}")
            print(f"  Target: {template.target_hex[:16]}...")
            # min_steps removed: difficulty alone regulates mining
            print(f"  Prev val_loss: {template.prev_val_loss:.4f}")
            print()

            # ── Step 2: Initialize model ──
            print("Initializing model...")
            model = create_model(template, device)
            param_count = model.param_count()
            print(f"  Parameters: {param_count:,}")

            # Load consensus weights from node
            consensus_weights = load_weights_from_node(rpc, model)
            print()

            # ── Step 3: Setup optimizer ──
            optimizer = torch.optim.AdamW(
                model.parameters(),
                lr=args.lr,
                weight_decay=args.weight_decay,
                betas=(0.9, 0.95),
            )

            # Learning rate warmup + cosine decay schedule
            warmup_steps = min(200, args.max_steps // 5)

            def lr_schedule(step: int) -> float:
                if step < warmup_steps:
                    return (step + 1) / warmup_steps
                progress = (step - warmup_steps) / max(
                    args.max_steps - warmup_steps, 1
                )
                return 0.5 * (1.0 + math.cos(math.pi * min(progress, 1.0)))

            scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lr_schedule)

            # ── Step 4: Training loop ──
            print("Training started...")
            loader.reset()
            step = 0
            best_loss = float("inf")
            block_found = False

            while True:
                step_start = time.time()

                # Forward pass
                model.train()
                x, y = loader.get_batch(device)
                logits, _ = model(x)
                loss = F.cross_entropy(logits.reshape(-1, GENESIS_VOCAB), y.reshape(-1))

                # Backward pass
                optimizer.zero_grad(set_to_none=True)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                scheduler.step()

                step += 1
                step_elapsed = time.time() - step_start
                current_loss = loss.item()
                stats.record_step(current_loss, step_elapsed)

                if current_loss < best_loss:
                    best_loss = current_loss

                # Display progress
                stats.display(step, current_loss, template.height)

                # ── Step 5: Check hash every N steps ──
                if step % args.steps_per_check == 0 and step > 0:
                    stats.record_hash_check()

                    # Compute model delta
                    delta = compute_delta(model, consensus_weights)
                    raw_delta_bytes = delta_to_bytes(delta)

                    # Sparsify
                    sparse_bytes, sparse_count, threshold = sparsify_delta(
                        raw_delta_bytes, threshold=args.sparse_threshold
                    )

                    # Compute training hash
                    training_hash = compute_training_hash(sparse_bytes, dataset_hash)
                    training_int = hash_to_int(training_hash)

                    if training_int < template.target:
                        print(f"\n\n  *** BLOCK FOUND at step {step}! ***")
                        print(f"  Training hash: {training_hash.hex()[:32]}...")

                        # Evaluate on validation data
                        val_loss = evaluate_model(model, val_data, device=device)
                        print(f"  Val loss: {val_loss:.4f}")

                        # Compress delta
                        compressed = compress_delta(sparse_bytes)
                        ratio = len(compressed) / max(len(raw_delta_bytes), 1) * 100
                        print(f"  Delta: {len(raw_delta_bytes):,} bytes "
                              f"-> {len(compressed):,} compressed ({ratio:.1f}%)")
                        print(f"  Sparse: {sparse_count:,} / "
                              f"{len(raw_delta_bytes) // 4:,} non-zero")

                        # Submit block
                        print(f"  Submitting block {template.height}...")
                        accepted = submit_block(
                            rpc, template, sparse_bytes, compressed,
                            sparse_count, threshold, step, val_loss,
                        )

                        if accepted:
                            print(f"  Block {template.height} ACCEPTED!")
                            stats.record_block_found()
                        else:
                            print(f"  Block {template.height} rejected, "
                                  f"continuing training...")

                        block_found = True
                        break

                # ── Step 6: Check for new block from network ──
                if step % 500 == 0:
                    try:
                        current_height = rpc.call("getblockcount")
                        if current_height >= template.height:
                            print(f"\n  New block detected at height "
                                  f"{current_height}, restarting...")
                            block_found = True
                            break
                    except RPCError:
                        pass  # Node temporarily unavailable, keep mining

                # ── Step 7: Safety check for extreme loss ──
                if math.isnan(current_loss) or math.isinf(current_loss):
                    print(f"\n  WARNING: Loss diverged ({current_loss}), "
                          f"restarting with lower learning rate")
                    args.lr *= 0.5
                    break

            if not block_found:
                # Learning rate issue, will restart with adjusted lr
                print(f"\n  Restarting training cycle (lr={args.lr:.6f})")

            print()

        except KeyboardInterrupt:
            print("\n\n  Miner stopped by user.")
            print(f"  Total steps: {stats.total_steps:,}")
            print(f"  Hash checks: {stats.total_hash_checks:,}")
            print(f"  Blocks found: {stats.blocks_found}")
            print(f"  Elapsed: {stats.elapsed_str()}")
            break

        except RPCError as e:
            print(f"\n  RPC error: {e}")
            print("  Retrying in 10 seconds...")
            time.sleep(10)

        except Exception as e:
            print(f"\n  Unexpected error: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            print("  Retrying in 10 seconds...")
            time.sleep(10)


# ════════════════════════════════════════════════════════════════
# Standalone evaluation mode
# ════════════════════════════════════════════════════════════════

def eval_mode(args):
    """Run standalone model evaluation without mining.

    Creates a model with genesis dimensions, optionally loads a checkpoint,
    and evaluates on the consensus validation dataset.

    Args:
        args: Parsed command-line arguments.
    """
    device = select_device(args.gpu)

    dims = compute_growth(args.eval_height)
    model = ResonanceNetV5(
        vocab=GENESIS_VOCAB,
        d_model=dims["d_model"],
        n_layers=dims["n_layers"],
        d_ff=dims["d_ff"],
        n_slots=dims["n_slots"],
        top_k=GENESIS_TOP_K,
    ).to(device)

    print(f"Model: d={dims['d_model']} L={dims['n_layers']} "
          f"ff={dims['d_ff']} slots={dims['n_slots']}")
    print(f"Parameters: {model.param_count():,}")

    if args.checkpoint:
        print(f"Loading checkpoint: {args.checkpoint}")
        state = torch.load(args.checkpoint, map_location=device, weights_only=True)
        model.load_state_dict(state)

    val_data = generate_validation_data()
    val_loss = evaluate_model(model, val_data, device=device)
    print(f"Validation loss: {val_loss:.6f}")

    dataset_hash = compute_dataset_hash()
    print(f"Dataset hash: {dataset_hash.hex()}")


# ════════════════════════════════════════════════════════════════
# Benchmark mode
# ════════════════════════════════════════════════════════════════

def benchmark_mode(args):
    """Run a training throughput benchmark.

    Creates a model, generates random data, and measures steps/second
    for the specified number of steps.

    Args:
        args: Parsed command-line arguments.
    """
    device = select_device(args.gpu)

    dims = compute_growth(args.bench_height)
    model = ResonanceNetV5(
        vocab=GENESIS_VOCAB,
        d_model=dims["d_model"],
        n_layers=dims["n_layers"],
        d_ff=dims["d_ff"],
        n_slots=dims["n_slots"],
        top_k=GENESIS_TOP_K,
    ).to(device)

    print(f"Model: d={dims['d_model']} L={dims['n_layers']} "
          f"ff={dims['d_ff']} slots={dims['n_slots']}")
    print(f"Parameters: {model.param_count():,}")
    print(f"Device: {device}")
    print(f"Batch size: {args.batch}, Seq len: {args.seq}")
    print()

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr)

    # Warmup
    print("Warming up (5 steps)...")
    for _ in range(5):
        x = torch.randint(0, 256, (args.batch, args.seq), device=device)
        y = torch.randint(0, 256, (args.batch, args.seq), device=device)
        logits, _ = model(x)
        loss = F.cross_entropy(logits.reshape(-1, 256), y.reshape(-1))
        optimizer.zero_grad(set_to_none=True)
        loss.backward()
        optimizer.step()

    if device.type == "cuda":
        torch.cuda.synchronize()

    # Benchmark
    n_steps = args.bench_steps
    print(f"Benchmarking {n_steps} steps...")
    start = time.time()
    for i in range(n_steps):
        x = torch.randint(0, 256, (args.batch, args.seq), device=device)
        y = torch.randint(0, 256, (args.batch, args.seq), device=device)
        logits, _ = model(x)
        loss = F.cross_entropy(logits.reshape(-1, 256), y.reshape(-1))
        optimizer.zero_grad(set_to_none=True)
        loss.backward()
        optimizer.step()
        if (i + 1) % 10 == 0:
            sys.stdout.write(f"\r  Step {i + 1}/{n_steps}")
            sys.stdout.flush()

    if device.type == "cuda":
        torch.cuda.synchronize()

    elapsed = time.time() - start
    sps = n_steps / elapsed
    tokens_per_sec = sps * args.batch * args.seq
    print(f"\n\nResults:")
    print(f"  Time: {elapsed:.2f}s")
    print(f"  Steps/sec: {sps:.1f}")
    print(f"  Tokens/sec: {tokens_per_sec:,.0f}")
    print(f"  Tokens/step: {args.batch * args.seq:,}")

    if device.type == "cuda":
        mem_gb = torch.cuda.max_memory_allocated() / (1024 ** 3)
        print(f"  Peak GPU memory: {mem_gb:.2f} GB")


# ════════════════════════════════════════════════════════════════
# Info mode — print model architecture details
# ════════════════════════════════════════════════════════════════

def info_mode(args):
    """Print model architecture details for a given height.

    Args:
        args: Parsed command-line arguments.
    """
    height = args.info_height
    dims = compute_growth(height)

    model = ResonanceNetV5(
        vocab=GENESIS_VOCAB,
        d_model=dims["d_model"],
        n_layers=dims["n_layers"],
        d_ff=dims["d_ff"],
        n_slots=dims["n_slots"],
        top_k=GENESIS_TOP_K,
    )

    print(f"ResonanceNet V5 at block height {height}")
    print(f"  d_model:   {dims['d_model']}")
    print(f"  n_layers:  {dims['n_layers']}")
    print(f"  d_ff:      {dims['d_ff']}")
    print(f"  n_heads:   {dims['n_heads']}")
    print(f"  d_head:    {dims['d_head']}")
    print(f"  n_slots:   {dims['n_slots']}")
    print(f"  top_k:     {dims['top_k']}")
    print(f"  gru_dim:   {dims['gru_dim']}")
    print(f"  vocab:     {dims['vocab']}")
    print(f"  seq_len:   {dims['seq_len']}")
    print(f"  Parameters: {model.param_count():,}")
    # min_steps display removed (not a consensus rule)
    print()

    # Per-layer breakdown
    print("Layer breakdown:")
    for name, param in sorted(model.named_parameters()):
        size_str = "x".join(str(s) for s in param.shape)
        print(f"  {name:50s} {size_str:>20s}  ({param.numel():>10,})")

    total = model.param_count()
    weight_bytes = total * 4
    print(f"\n  Total: {total:,} params ({weight_bytes:,} bytes as float32)")


# ════════════════════════════════════════════════════════════════
# Signal handling
# ════════════════════════════════════════════════════════════════

_shutdown_requested = False


def signal_handler(signum, frame):
    """Handle SIGINT/SIGTERM gracefully."""
    global _shutdown_requested
    if _shutdown_requested:
        print("\n  Force quitting...")
        sys.exit(1)
    _shutdown_requested = True
    raise KeyboardInterrupt


# ════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="FlowCoin Miner — PyTorch GPU Training",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Mine with local data:
    python3 flowminer.py --dataset ~/data/ --node http://127.0.0.1:9334

  Benchmark training speed:
    python3 flowminer.py --benchmark --batch 4 --seq 256

  Show model info at height 200:
    python3 flowminer.py --info --info-height 200

  Evaluate model:
    python3 flowminer.py --eval --checkpoint model.pt
""",
    )

    # Mode selection
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--benchmark", action="store_true",
        help="Run training throughput benchmark",
    )
    mode.add_argument(
        "--eval", action="store_true",
        help="Evaluate model on validation data",
    )
    mode.add_argument(
        "--info", action="store_true",
        help="Print model architecture info",
    )

    # Mining arguments
    parser.add_argument(
        "--dataset", type=str, default=None,
        help="Path to training data (directory or file)",
    )
    parser.add_argument(
        "--node", type=str, default="http://127.0.0.1:9334",
        help="flowcoind JSON-RPC URL (default: http://127.0.0.1:9334)",
    )
    parser.add_argument(
        "--user", type=str, default="flowcoin",
        help="RPC username (default: flowcoin)",
    )
    parser.add_argument(
        "--password", type=str, default="flowcoin",
        help="RPC password (default: flowcoin)",
    )
    parser.add_argument(
        "--gpu", type=int, default=-1,
        help="GPU device index (-1 = auto-detect, default: -1)",
    )
    parser.add_argument(
        "--lr", type=float, default=0.001,
        help="Learning rate (default: 0.001)",
    )
    parser.add_argument(
        "--weight-decay", type=float, default=0.01,
        help="Weight decay (default: 0.01)",
    )
    parser.add_argument(
        "--batch", type=int, default=1,
        help="Batch size (default: 1)",
    )
    parser.add_argument(
        "--seq", type=int, default=256,
        help="Sequence length (default: 256)",
    )
    parser.add_argument(
        "--steps-per-check", type=int, default=100,
        help="Steps between hash checks (default: 100)",
    )
    parser.add_argument(
        "--sparse-threshold", type=float, default=1e-6,
        help="Sparsification threshold (default: 1e-6)",
    )

    # Benchmark arguments
    parser.add_argument(
        "--bench-steps", type=int, default=100,
        help="Number of benchmark steps (default: 100)",
    )
    parser.add_argument(
        "--bench-height", type=int, default=0,
        help="Block height for benchmark model dims (default: 0)",
    )

    # Eval arguments
    parser.add_argument(
        "--checkpoint", type=str, default=None,
        help="Model checkpoint file for eval mode",
    )
    parser.add_argument(
        "--eval-height", type=int, default=0,
        help="Block height for eval model dims (default: 0)",
    )

    # Info arguments
    parser.add_argument(
        "--info-height", type=int, default=0,
        help="Block height for model info (default: 0)",
    )

    return parser.parse_args()


def main():
    """Entry point for the FlowCoin miner."""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    args = parse_args()

    print("FlowCoin Miner v1.0.0")
    print(f"  PyTorch {torch.__version__}")
    if torch.cuda.is_available():
        print(f"  CUDA {torch.version.cuda}")
    print()

    if args.benchmark:
        benchmark_mode(args)
    elif args.eval:
        eval_mode(args)
    elif args.info:
        info_mode(args)
    else:
        # Mining mode
        if args.dataset is None:
            print("ERROR: --dataset is required for mining mode")
            print("Usage: python3 flowminer.py --dataset ~/data/")
            sys.exit(1)

        mining_loop(args)


if __name__ == "__main__":
    main()

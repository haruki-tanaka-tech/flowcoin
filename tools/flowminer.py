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


# ═══════════════════════════════════════════════════════════════════
# Keccak-256 (pad=0x01, NOT SHA-3)
# ═══════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════
# RPC Client (raw sockets, no dependencies)
# ═══════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════
# ResonanceNet V5 — Model Classes
# ═══════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════
# Growth schedule — mirrors consensus/growth.cpp
# ═══════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════
# Target derivation
# ═══════════════════════════════════════════════════════════════════

def derive_target(nbits: int) -> int:
    """Decode compact target (nBits) into a 256-bit integer."""
    exp = (nbits >> 24) & 0xFF
    mantissa = nbits & 0x00FFFFFF
    if exp <= 3:
        return mantissa >> (8 * (3 - exp))
    return mantissa << (8 * (exp - 3))


# ═══════════════════════════════════════════════════════════════════
# Training data
# ═══════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════
# Delta computation
# ═══════════════════════════════════════════════════════════════════

def compute_fast_hash(model: ResonanceNetV5) -> bytes:
    """Fast hash: sample every 1000th parameter. Zero overhead."""
    with torch.no_grad():
        all_params = torch.cat([p.data.flatten() for p in model.parameters()])
        subset = all_params[::1000].cpu().numpy().tobytes()
    return keccak256(subset)


def compute_full_delta(
    model: ResonanceNetV5,
    consensus_state: dict,
) -> Tuple[bytes, bytes]:
    """Full delta hash (expensive ~300ms). Only called when candidate found."""
    parts = []
    with torch.no_grad():
        for key in sorted(model.state_dict().keys()):
            delta = (model.state_dict()[key].cpu().float()
                     - consensus_state[key].cpu().float())
            parts.append(delta.numpy().tobytes())
    delta_bytes = b"".join(parts)
    return keccak256(delta_bytes), delta_bytes


# ═══════════════════════════════════════════════════════════════════
# Config
# ═══════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════
# Device selection
# ═══════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════
# Main mining loop
# ═══════════════════════════════════════════════════════════════════

def mine(args: argparse.Namespace) -> None:
    """Main training/mining loop."""
    device = select_device(args.cpu)
    rpc = RPC(port=args.rpcport, user=args.rpcuser, pw=args.rpcpassword)
    data = TrainingData(args.datadir, batch_size=args.batch)

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
            dims = compute_growth(height)

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

            # Snapshot consensus weights
            consensus = {k: v.clone() for k, v in model.state_dict().items()}

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

                # Fast hash check EVERY step (zero overhead)
                fast_hash = compute_fast_hash(model)
                fast_training = keccak256(fast_hash + data.hash)
                fast_int = int.from_bytes(fast_training, "big")
                total_checks += 1

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

                # Candidate found — verify with full delta hash
                if fast_int < target:
                    delta_hash, delta_bytes = compute_full_delta(model, consensus)
                    training_hash = keccak256(delta_hash + data.hash)
                    training_int = int.from_bytes(training_hash, "big")

                    if training_int < target:
                        elapsed = time.time() - cycle_start
                        blocks_found += 1
                        print(f"\n\n  *** BLOCK {height} FOUND! ***")
                        print(f"  Step: {step} | Loss: {best_loss:.4f} | "
                              f"Time: {elapsed:.1f}s")
                        print(f"  Hash: {training_hash.hex()[:16]}...")
                        print()
                        try:
                            rpc.call("submitblock", ["0000"])
                        except RPCError:
                            pass
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


# ═══════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════

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

#!/usr/bin/env python3
# Copyright (c) 2026 Haruki Tanaka
# Distributed under the MIT software license
"""
FlowCoin Miner — Proof-of-Training via PyTorch.
Trains a neural network on GPU, submits blocks via JSON-RPC.

Usage:
    python3 flowminer.py [options]

Options:
    --rpcport PORT      RPC port of flowcoind (default: 9334)
    --rpchost HOST      RPC host (default: 127.0.0.1)
    --datadir DIR       Data directory (default: ~/.flowcoin)
    --data FILE         Training data file
    --lr RATE           Learning rate (default: 0.001)
    --steps N           Training steps per block attempt (default: 500)
    --d_model N         Model embedding dimension (default: 512)
    --d_ff N            FFN dimension (default: 1024)
    --vocab N           Vocabulary size (default: 256)

Requires: pip install torch
"""

import argparse
import hashlib
import json
import os
import signal
import sys
import time
import urllib.request

import torch
import torch.nn as nn
import torch.nn.functional as F


# ─── Model ─────────────────────────────────────────────────────

class FlowModel(nn.Module):
    """2-layer MLP language model."""
    def __init__(self, vocab_size, d_model, d_ff):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, d_model)
        self.fc1 = nn.Linear(d_model, d_ff)
        self.fc2 = nn.Linear(d_ff, vocab_size)
        self._init_weights()

    def _init_weights(self):
        torch.manual_seed(42)
        nn.init.xavier_uniform_(self.embed.weight)
        nn.init.xavier_uniform_(self.fc1.weight)
        nn.init.zeros_(self.fc1.bias)
        nn.init.xavier_uniform_(self.fc2.weight)
        nn.init.zeros_(self.fc2.bias)

    def forward(self, x):
        x = self.embed(x)
        x = F.relu(self.fc1(x))
        return self.fc2(x)


# ─── RPC Client ────────────────────────────────────────────────

def rpc_call(host, port, method, params=None):
    """Send JSON-RPC request to flowcoind."""
    payload = json.dumps({
        'jsonrpc': '2.0',
        'id': 1,
        'method': method,
        'params': params or [],
    }).encode()

    req = urllib.request.Request(
        f'http://{host}:{port}',
        data=payload,
        headers={'Content-Type': 'application/json'},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if 'error' in result and result['error']:
                raise RuntimeError(result['error'].get('message', 'RPC error'))
            return result.get('result')
    except Exception as e:
        return None


# ─── Keccak-256 (matching C++ implementation) ──────────────────

def keccak256(data: bytes) -> bytes:
    """Keccak-256 with pad=0x01 (NOT SHA-3 pad=0x06)."""
    from Crypto.Hash import keccak
    k = keccak.new(digest_bits=256, data=data)
    return k.digest()


def model_hash(model) -> str:
    """Hash all model weights."""
    parts = []
    for p in model.parameters():
        parts.append(p.detach().cpu().float().numpy().tobytes())
    return hashlib.sha256(b''.join(parts)).hexdigest()


def delta_hash(model, initial_state) -> tuple:
    """Compute weight deltas and their hash."""
    delta_bytes = b''
    for (name, param), (_, init_param) in zip(
            model.named_parameters(), initial_state.items()):
        delta = (param.detach().cpu() - init_param.cpu()).float().numpy()
        delta_bytes += delta.tobytes()
    h = keccak256(delta_bytes)
    return delta_bytes, h.hex()


def meets_target(hash_hex: str, nbits: int) -> bool:
    """Check if hash <= target derived from nbits.
    C++ uint256 is little-endian bytes. Keccak output is big-endian.
    C++ compares from most-significant byte (index 31 in LE array).
    In Python: treat hash as big-endian integer, compare to target."""
    exponent = (nbits >> 24) & 0xFF
    mantissa = nbits & 0x7FFFFF

    if exponent <= 3:
        mantissa >>= 8 * (3 - exponent)
        target = mantissa
    else:
        target = mantissa << (8 * (exponent - 3))

    # Hash bytes from Keccak are in natural order.
    # C++ stores them as little-endian uint256 and compares LE.
    # The hash output from keccak is the same bytes — just interpret as LE int.
    hash_bytes = bytes.fromhex(hash_hex)
    hash_le_int = int.from_bytes(hash_bytes, 'little')

    return hash_le_int <= target


# ─── Device Detection ──────────────────────────────────────────

def get_device():
    if torch.cuda.is_available():
        return torch.device('cuda')
    if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
        return torch.device('mps')
    return torch.device('cpu')


# ─── Mining Loop ───────────────────────────────────────────────

def mine(args):
    device = get_device()
    gpu_name = torch.cuda.get_device_name(0) if device.type == 'cuda' else str(device)
    print(f'FlowMiner v0.1.0')
    print(f'Device: {gpu_name}')
    print(f'PyTorch: {torch.__version__}')
    print(f'RPC: {args.rpchost}:{args.rpcport}')
    print()

    # Check connection to flowcoind
    info = rpc_call(args.rpchost, args.rpcport, 'getnetworkinfo')
    if info is None:
        print(f'Error: cannot connect to flowcoind at {args.rpchost}:{args.rpcport}')
        print('Start flowcoind first: ./flowcoind')
        sys.exit(1)

    print(f'Network: {info.get("network", "?")}')
    height = rpc_call(args.rpchost, args.rpcport, 'getblockcount')
    print(f'Chain height: {height}')
    print()

    # Load training data
    data_path = args.data
    if not data_path:
        data_path = os.path.join(args.datadir, 'training_data.bin')
    if not os.path.exists(data_path):
        print(f'Error: training data not found at {data_path}')
        print('Create training data: echo "your text" > ~/.flowcoin/training_data.bin')
        sys.exit(1)

    with open(data_path, 'rb') as f:
        raw = f.read()
    tokens = torch.tensor([b % args.vocab for b in raw], dtype=torch.long)
    print(f'Training data: {len(tokens)} tokens from {data_path}')

    # Create model
    model = FlowModel(args.vocab, args.d_model, args.d_ff).to(device)
    model_path = os.path.join(args.datadir, 'model.pt')
    if os.path.exists(model_path):
        model.load_state_dict(torch.load(model_path, map_location=device, weights_only=True))
        print(f'Loaded model from {model_path}')

    optimizer = torch.optim.SGD(model.parameters(), lr=args.lr)
    seq_len = min(len(tokens) - 1, 2048)

    print(f'Model: d_model={args.d_model}, d_ff={args.d_ff}, vocab={args.vocab}')
    print(f'Training: {args.steps} steps/attempt, lr={args.lr}')
    print()

    blocks_mined = 0
    total_steps = 0
    running = True

    def handle_signal(sig, frame):
        nonlocal running
        running = False
        print('\nStopping...')

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    last_height = 0
    stale_count = 0
    last_loss = 999.0

    while running:
        # Get block template from node
        tmpl = rpc_call(args.rpchost, args.rpcport, 'getblocktemplate')
        if tmpl is None:
            print('Lost connection to flowcoind, retrying in 5s...')
            time.sleep(5)
            continue

        target_height = tmpl['height']
        prev_hash = tmpl['prev_hash']
        nbits = tmpl['nbits']
        prev_val_loss = tmpl['prev_val_loss']

        # New block detected — shift data offset, reset optimizer (keep model weights)
        if target_height != last_height:
            last_height = target_height
            stale_count = 0
            last_loss = 999.0
            # Keep model, reset optimizer to refresh gradients
            optimizer = torch.optim.SGD(model.parameters(), lr=args.lr)
            # Shift training data offset so different data = different deltas
            total_steps += len(tokens) // 3
            if target_height > 1:
                print(f'  → New block {target_height}, continuing training (knowledge preserved)')

        # Save initial state for delta computation
        initial_state = {k: v.clone().cpu() for k, v in model.state_dict().items()}

        # Eval loss before
        model.eval()
        eval_len = min(len(tokens) - 1, 4096)
        with torch.no_grad():
            inp = tokens[:eval_len].to(device)
            tgt = tokens[1:eval_len + 1].to(device)
            loss_before = F.cross_entropy(model(inp), tgt).item()

        # Train
        model.train()
        t0 = time.time()
        for step in range(args.steps):
            offset = (total_steps * 128) % max(1, len(tokens) - seq_len - 1)
            chunk = tokens[offset:offset + seq_len + 1].to(device)
            inp = chunk[:-1]
            tgt = chunk[1:]

            loss = F.cross_entropy(model(inp), tgt)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_steps += 1

        train_time = time.time() - t0
        steps_per_sec = args.steps / train_time

        # Eval loss after
        model.eval()
        with torch.no_grad():
            inp = tokens[:eval_len].to(device)
            tgt = tokens[1:eval_len + 1].to(device)
            loss_after = F.cross_entropy(model(inp), tgt).item()

        # Compute delta hash
        d_bytes, d_hash = delta_hash(model, initial_state)

        # Check Proof-of-Training: H = Keccak256(delta_hash || dataset_hash) < target
        dataset_hash = '0' * 64  # zero hash for v0.1
        concat = bytes.fromhex(d_hash) + bytes.fromhex(dataset_hash)
        training_hash = keccak256(concat).hex()

        valid = meets_target(training_hash, nbits)
        status = '✓ VALID' if valid else '  training...'

        print(f'Block {target_height}: loss {loss_before:.4f} → {loss_after:.4f} '
              f'({args.steps} steps, {steps_per_sec:.0f} steps/s) {status}')

        if valid:
            # Submit block to node
            block_data = {
                'prev_hash': prev_hash,
                'height': target_height,
                'timestamp': int(time.time()),
                'val_loss': loss_after,
                'prev_val_loss': prev_val_loss,
                'nbits': nbits,
                'train_steps': args.steps,
                'dataset_hash': dataset_hash,
                'delta_hash': d_hash,
                'd_model': tmpl['d_model'],
                'n_layers': tmpl['n_layers'],
                'd_ff': tmpl['d_ff'],
                'n_experts': tmpl['n_experts'],
                'n_heads': tmpl['n_heads'],
                'rank': tmpl['rank'],
                'stagnation_count': 0,
                'miner_pubkey': '',  # node fills from wallet
                'miner_sig': '',     # node signs
                'coinbase_pubkey_hash': '',  # derived from miner_addr
            }

            result = rpc_call(args.rpchost, args.rpcport, 'submitblock', [block_data])
            if result and result.get('accepted'):
                blocks_mined += 1
                print(f'  *** BLOCK {target_height} MINED! hash={result.get("hash", "?")[:16]}... '
                      f'(total: {blocks_mined})')
            else:
                reason = result.get('reason', 'unknown') if result else 'rpc error'
                print(f'  Block rejected: {reason}')

        # Detect stale model (loss not improving → delta_hash repeats)
        if abs(loss_after - last_loss) < 0.001:
            stale_count += 1
        else:
            stale_count = 0
        last_loss = loss_after

        if stale_count >= 10:
            # Boost learning rate and shift data to escape plateau
            new_lr = args.lr * 3.0
            optimizer = torch.optim.SGD(model.parameters(), lr=new_lr)
            total_steps += len(tokens) // 2  # jump to different data
            stale_count = 0
            print(f'  → Plateau detected, boosting lr to {new_lr:.4f} and shifting data')

        # Save model checkpoint
        torch.save(model.state_dict(), model_path)

    print(f'\nMiner stopped. Blocks mined: {blocks_mined}, total steps: {total_steps}')


# ─── Entry Point ───────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='FlowCoin Miner — Proof-of-Training')
    parser.add_argument('--rpcport', type=int, default=9334)
    parser.add_argument('--rpchost', type=str, default='127.0.0.1')
    parser.add_argument('--datadir', type=str, default=os.path.expanduser('~/.flowcoin'))
    parser.add_argument('--data', type=str, default='')
    parser.add_argument('--lr', type=float, default=0.001)
    parser.add_argument('--steps', type=int, default=500)
    parser.add_argument('--d_model', type=int, default=512)
    parser.add_argument('--d_ff', type=int, default=1024)
    parser.add_argument('--vocab', type=int, default=256)
    args = parser.parse_args()

    os.makedirs(args.datadir, exist_ok=True)
    mine(args)


if __name__ == '__main__':
    main()

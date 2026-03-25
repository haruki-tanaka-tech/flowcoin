#!/usr/bin/env python3
"""
ResonanceNet V5 benchmark — test training speed without node.
Usage: python3 tools/bench_resonancenet.py [--batch 1] [--seq 256] [--steps 100]
"""
import sys
import time
import argparse

import torch
import torch.nn as nn
import torch.nn.functional as F

# Import model from miner
sys.path.insert(0, "tools")
from flowminer import ResonanceNetV5, compute_growth

def main():
    parser = argparse.ArgumentParser(description="ResonanceNet V5 Benchmark")
    parser.add_argument("--batch", type=int, default=1)
    parser.add_argument("--seq", type=int, default=256)
    parser.add_argument("--steps", type=int, default=200)
    parser.add_argument("--height", type=int, default=0)
    parser.add_argument("--cpu", action="store_true")
    args = parser.parse_args()

    # Device
    if args.cpu or not torch.cuda.is_available():
        device = torch.device("cpu")
        print(f"Device: CPU")
    else:
        device = torch.device("cuda")
        name = torch.cuda.get_device_name(0)
        mem = torch.cuda.get_device_properties(0).total_memory / (1024**3)
        print(f"Device: {name} ({mem:.1f} GB)")

    # Model dims
    dims = compute_growth(args.height)
    print(f"Height: {args.height}")
    print(f"Model:  d={dims['d_model']} L={dims['n_layers']} ff={dims['d_ff']} slots={dims['n_slots']}")

    # Create model
    model = ResonanceNetV5(
        vocab=256,
        d_model=dims['d_model'],
        n_layers=dims['n_layers'],
        d_ff=dims['d_ff'],
        n_slots=dims['n_slots'],
        top_k=2,
    ).to(device)

    n_params = sum(p.numel() for p in model.parameters())
    print(f"Params: {n_params:,} ({n_params * 4 / 1024**2:.1f} MB)")
    print(f"Batch:  {args.batch} | Seq: {args.seq} | Steps: {args.steps}")
    print()

    # No torch.compile — use eager mode for reliability

    # Random data
    data = torch.randint(0, 256, (args.batch * args.seq * 10,), dtype=torch.long, device=device)

    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001)

    # Warmup (more steps for compile)
    print("Warming up (10 steps, compile may take a moment)...")
    for _ in range(10):
        x = data[:args.batch * args.seq].view(args.batch, args.seq)
        y = data[1:args.batch * args.seq + 1].view(args.batch, args.seq)
        logits, _ = model(x)
        loss = F.cross_entropy(logits.reshape(-1, 256), y.reshape(-1))
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

    if device.type == "cuda":
        torch.cuda.synchronize()

    # Benchmark
    print(f"Benchmarking {args.steps} steps...")
    start = time.perf_counter()
    losses = []
    pos = 0

    for step in range(args.steps):
        if pos + args.batch * (args.seq + 1) > len(data):
            pos = 0
        x = data[pos:pos + args.batch * args.seq].view(args.batch, args.seq)
        y = data[pos + 1:pos + args.batch * args.seq + 1].view(args.batch, args.seq)
        pos += args.batch * args.seq

        logits, _ = model(x)
        loss = F.cross_entropy(logits.reshape(-1, 256), y.reshape(-1))
        optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()

        losses.append(loss.item())

        if (step + 1) % 20 == 0:
            elapsed = time.perf_counter() - start
            st_per_s = (step + 1) / elapsed
            tok_per_s = (step + 1) * args.batch * args.seq / elapsed
            print(f"  step {step+1:>5d} | loss {loss.item():.4f} | "
                  f"{st_per_s:.1f} st/s | {tok_per_s:.0f} tok/s")

    if device.type == "cuda":
        torch.cuda.synchronize()

    elapsed = time.perf_counter() - start
    steps_per_sec = args.steps / elapsed
    tokens_per_sec = args.steps * args.batch * args.seq / elapsed

    print()
    print(f"═══ Results ═══")
    print(f"  Steps/sec:  {steps_per_sec:.1f}")
    print(f"  Tokens/sec: {tokens_per_sec:.0f}")
    print(f"  Total time: {elapsed:.1f}s")
    print(f"  Start loss: {losses[0]:.4f}")
    print(f"  End loss:   {losses[-1]:.4f}")
    print(f"  Loss drop:  {losses[0] - losses[-1]:.4f}")

if __name__ == "__main__":
    main()

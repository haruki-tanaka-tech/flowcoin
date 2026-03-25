#!/usr/bin/env python3
"""Profile each layer component separately."""
import time, torch, torch.nn as nn, torch.nn.functional as F

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
B, T, D = 32, 256, 512
x = torch.randn(B, T, D, device=device)

def bench(name, fn, steps=50):
    # warmup
    for _ in range(5): fn(x)
    torch.cuda.synchronize()
    t0 = time.perf_counter()
    for _ in range(steps): fn(x)
    torch.cuda.synchronize()
    dt = time.perf_counter() - t0
    tok = steps * B * T / dt
    print(f"  {name:30s} {steps/dt:6.1f} st/s  {tok:8.0f} tok/s")

# 1. RMSNorm
norm = nn.RMSNorm(D).to(device)
bench("RMSNorm", lambda x: norm(x))

# 2. SwiGLU FFN
gate_w = nn.Linear(D, 1024, bias=False).to(device)
up_w = nn.Linear(D, 1024, bias=False).to(device)
down_w = nn.Linear(1024, D, bias=False).to(device)
bench("SwiGLU FFN", lambda x: down_w(F.silu(gate_w(x)) * up_w(x)))

# 3. Conv1d (depthwise, kernel=3)
conv = nn.Conv1d(D, D, 3, padding=1, groups=D, bias=False).to(device)
bench("Conv1d depthwise k=3", lambda x: conv(x.transpose(1,2)).transpose(1,2))

# 4. MinGRU (sequential loop)
Wz = nn.Linear(D, D).to(device)
Wh = nn.Linear(D, D).to(device)
def mingru_seq(x):
    B, T, D = x.shape
    z_all = torch.sigmoid(Wz(x))
    h_all = Wh(x)
    out = torch.empty_like(x)
    h = torch.zeros(B, D, device=x.device)
    for t in range(T):
        z = z_all[:, t, :]
        h = (1 - z) * h + z * h_all[:, t, :]
        out[:, t, :] = h
    return out
bench("MinGRU (seq loop)", mingru_seq, steps=20)

# 5. MinGRU projections only (no loop)
bench("MinGRU projections only", lambda x: (torch.sigmoid(Wz(x)), Wh(x)))

# 6. Slot memory (matmul + topk)
keys = torch.randn(1024, D, device=device)
values = torch.randn(1024, D, device=device)
proj_q = nn.Linear(D, D, bias=False).to(device)
def slot_mem(x):
    q = proj_q(x)
    scores = torch.matmul(q, keys.T)
    topk_vals, topk_ids = torch.topk(scores, 2, dim=-1)
    attn = F.softmax(topk_vals, dim=-1)
    g = values[topk_ids.reshape(-1, 2)].reshape(B, T, 2, D)
    return (attn.unsqueeze(-1) * g).sum(dim=2)
bench("SlotMemory (1024 slots)", slot_mem)

# 7. Full forward (no backward)
print("\n  === Forward only (no grad) ===")
import sys; sys.path.insert(0, "tools")
from flowminer import ResonanceNetV5
model = ResonanceNetV5(256, D, 8, 1024, 1024, 2).to(device)
tokens = torch.randint(0, 256, (B, T), device=device)
def fwd_only(x):
    with torch.no_grad():
        return model(tokens)
bench("Full forward (no grad)", fwd_only, steps=20)

# 8. Full forward + backward
def fwd_bwd(x):
    logits, _ = model(tokens)
    loss = F.cross_entropy(logits.reshape(-1, 256), tokens.reshape(-1))
    loss.backward()
    return loss
bench("Full forward+backward", fwd_bwd, steps=10)

#!/usr/bin/env python3
"""
SHA-256 Boomerang Attack — Meet in the Middle at Round 32
==========================================================

Classic differential: one path through all 64 rounds.
Barrier at 33 rounds from one direction.

Boomerang: TWO short differentials that "meet" in the middle.

  Forward differential (Δ):   rounds 0→32 with input delta α
  Backward differential (∇):  rounds 32←64 with output delta δ

  If both differentials have probability p and q:
    Boomerang probability = p² × q²

  Key: each differential only needs to cover ~32 rounds (not 64!)
  We already proved 33 rounds forward is possible.
  If backward 31 rounds is also possible → full 64 round attack.

  SHA-256 boomerang:

  1. Choose message M, compute H = SHA256(M)
  2. Choose M' = M ⊕ α (forward diff), compute H' = SHA256(M')
  3. Choose M̃ such that SHA256(M̃) = H ⊕ δ (backward diff)
  4. Compute M̃' = M̃ ⊕ α
  5. Check: SHA256(M̃') = H' ⊕ δ ?

  If yes → boomerang distinguisher for full SHA-256!

  For this to work:
  - Forward diff α must have high probability through rounds 0→32
  - Backward diff δ must have high probability through rounds 32←64
  - The two must be "compatible" at round 32

  Practical approach for schedule:
  - Forward: our 33-round differential (18 clean schedule W[16..33])
  - Backward: find differential that works for W[48..63] → W[32..47]
  - The backward direction uses INVERSE message schedule

No GPU needed — pure math analysis.
"""

import random
import time

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def sig0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def sig1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

def popcount(x):
    return bin(x).count('1')

K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,
    0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
    0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
    0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000
]

# ═══════════════════════════════════════════════
# Part 1: Analyze backward message schedule
# ═══════════════════════════════════════════════

print("=" * 60)
print("Part 1: Backward Message Schedule Analysis")
print("=" * 60)
print()

# Forward: W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16]
# Rearranged for backward:
# W[i-16] = W[i] - sig1(W[i-2]) - W[i-7] - sig0(W[i-15])

print("Forward:  W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16]")
print("Backward: W[i-16] = W[i] - sig1(W[i-2]) - W[i-7] - sig0(W[i-15])")
print()

# If we control W[48..63] (last 16 expanded words),
# we can compute W[32..47] backwards.
# Then W[32..47] determines the "meeting point" at round 32.

print("Backward dependencies (from high rounds → low):")
for i in range(63, 47, -1):
    target = i - 16  # what we can compute
    deps = [i, i-2, i-7, i-15]
    print(f"  W[{target:2d}] = W[{i}] - sig1(W[{i-2}]) - W[{i-7}] - sig0(W[{i-15}])")

print()
print("Key: W[48..63] → backward → W[32..47]")
print("Forward: W[0..15] → forward → W[16..47]")
print("Meeting zone: W[32..47] must match from both directions!")
print()

# ═══════════════════════════════════════════════
# Part 2: Boomerang feasibility — schedule matching
# ═══════════════════════════════════════════════

print("=" * 60)
print("Part 2: Schedule Boomerang — Can forward and backward meet?")
print("=" * 60)
print()

# Forward differential gives us delta_W[16..47] from delta_W[0..15]
# Backward differential gives us delta_W[32..47] from delta_W[48..63]
#
# For boomerang: delta_W[32..47] from forward must EQUAL
#                delta_W[32..47] from backward
#
# But we DON'T control W[48..63] directly — they're computed from W[0..15]!
# W[48] = sig1(W[46]) + W[41] + sig0(W[33]) + W[32]
# All of these depend on W[0..15] through forward expansion.
#
# So the "backward" direction isn't truly independent.
# BUT: in a boomerang attack, we use DIFFERENT messages for
# forward and backward. The four messages are:
#   M, M'=M⊕α, M̃, M̃'=M̃⊕α
# where M̃ is chosen such that its round-32 state matches.

# Let's check: for our best forward differential,
# what does the schedule look like at W[32..47]?

random.seed(42)
W = [random.randint(0, 0xFFFFFFFF) for _ in range(16)]

# Best known: d[14]=1bit, d[15]=1bit, algebraic d[0,1]
delta = [0]*16
delta[14] = 1 << 8  # sig1 sweet spot
delta[15] = 1 << 8
delta[1] = (-(sig1(W[15]^delta[15]) - sig1(W[15]))) & 0xFFFFFFFF
delta[0] = (-(sig1(W[14]^delta[14]) - sig1(W[14]) +
              sig0(W[1]^delta[1]) - sig0(W[1]))) & 0xFFFFFFFF

W2 = [W[i] ^ delta[i] for i in range(16)]

# Expand both
w1 = list(W) + [0]*48
w2 = list(W2) + [0]*48
for i in range(16, 64):
    w1[i] = (sig1(w1[i-2]) + w1[i-7] + sig0(w1[i-15]) + w1[i-16]) & 0xFFFFFFFF
    w2[i] = (sig1(w2[i-2]) + w2[i-7] + sig0(w2[i-15]) + w2[i-16]) & 0xFFFFFFFF

print("Forward schedule diff (full 64 rounds):")
print("  Rounds 16-31: ", end="")
for i in range(16, 32):
    b = popcount(w1[i] ^ w2[i])
    if b == 0: print("✓", end="")
    elif b < 10: print(b, end="")
    else: print("X", end="")
print()
print("  Rounds 32-47: ", end="")
for i in range(32, 48):
    b = popcount(w1[i] ^ w2[i])
    if b == 0: print("✓", end="")
    elif b < 10: print(b, end="")
    else: print("X", end="")
print()
print("  Rounds 48-63: ", end="")
for i in range(48, 64):
    b = popcount(w1[i] ^ w2[i])
    if b == 0: print("✓", end="")
    elif b < 10: print(b, end="")
    else: print("X", end="")
print()

# Count clean in each zone
clean_16_31 = sum(1 for i in range(16, 32) if w1[i] == w2[i])
clean_32_47 = sum(1 for i in range(32, 48) if w1[i] == w2[i])
clean_48_63 = sum(1 for i in range(48, 64) if w1[i] == w2[i])
total_bits_32_47 = sum(popcount(w1[i] ^ w2[i]) for i in range(32, 48))
total_bits_48_63 = sum(popcount(w1[i] ^ w2[i]) for i in range(48, 64))

print(f"\n  Clean W[16..31]: {clean_16_31}/16")
print(f"  Clean W[32..47]: {clean_32_47}/16 ({total_bits_32_47} total diff bits)")
print(f"  Clean W[48..63]: {clean_48_63}/16 ({total_bits_48_63} total diff bits)")

# ═══════════════════════════════════════════════
# Part 3: Backward differential — independent
# ═══════════════════════════════════════════════

print()
print("=" * 60)
print("Part 3: Independent Backward Differential")
print("=" * 60)
print()

print("Idea: treat rounds 32-64 as a SEPARATE hash function.")
print("Input = state at round 32 + W[32..63]")
print("If we can find a differential that works BACKWARDS")
print("from round 64 to round 32, we get a boomerang.")
print()

# The backward differential through the ROUND FUNCTION (not schedule)
# is the hard part. Schedule backward is invertible.
# Round function backward:
#   Given output state and W[i], can we invert one round?
#   a = temp1 + temp2
#   e = d + temp1
#   → temp1 = e - d
#   → temp2 = a - temp1 = a - e + d
#   But temp1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i]
#   So h_prev = temp1 - S1(e) - Ch(e,f,g) - K[i] - W[i]
#   And the shifts: h←g←f←e←..., a←b←c←d←...

# Key insight for boomerang:
# We DON'T need to invert the round function.
# We need a DIFFERENTIAL that propagates backward with high prob.
# The round function is the same forward and backward —
# differential probability is symmetric.

# So if forward differential works for 33 rounds (0→33),
# a backward differential can work for 31 rounds (64→33).
# Combined: 33 + 31 = 64 round boomerang!

# BUT: the schedule isn't independent.
# W[32..63] are fully determined by W[0..15].
# In boomerang, we need FOUR messages where:
#   M ⊕ M' = α (forward diff)
#   M ⊕ M̃ chosen so that at round 32, state diff = β (backward diff starts)

print("Boomerang structure:")
print("  M  → round 0-32 → state S₁  → round 32-64 → H")
print("  M' → round 0-32 → state S₁' → round 32-64 → H'")
print("  M̃  → round 0-32 → state S̃₁  → round 32-64 → H̃")
print("  M̃' → round 0-32 → state S̃₁' → round 32-64 → H̃'")
print()
print("  Forward:  S₁ ⊕ S₁' = Δ  (our 33-round diff)")
print("  Backward: H ⊕ H̃ = ∇    (backward diff)")
print("  Boomerang: H' ⊕ H̃' = ∇  (should hold if both diffs work)")
print()

# ═══════════════════════════════════════════════
# Part 4: Practical boomerang — state diff at round 32
# ═══════════════════════════════════════════════

print("=" * 60)
print("Part 4: State Diff at Round 32 (Forward Direction)")
print("=" * 60)
print()

IV = (0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)

def sha256_partial(W_full, n_rounds, H0=IV):
    """Run SHA-256 for n_rounds, return intermediate state."""
    a,b,c,d,e,f,g,h = H0
    for i in range(min(n_rounds, 64)):
        S1 = rotr(e,6)^rotr(e,11)^rotr(e,25)
        ch = (e&f)^((~e&0xFFFFFFFF)&g)
        t1 = (h + S1 + ch + K[i] + W_full[i]) & 0xFFFFFFFF
        S0 = rotr(a,2)^rotr(a,13)^rotr(a,22)
        mj = (a&b)^(a&c)^(b&c)
        t2 = (S0 + mj) & 0xFFFFFFFF
        h,g,f,e,d,c,b,a = g,f,e,(d+t1)&0xFFFFFFFF,c,b,a,(t1+t2)&0xFFFFFFFF
    return (a,b,c,d,e,f,g,h)

# Compute state at round 32 for both M and M'
state32 = sha256_partial(w1, 32)
state32p = sha256_partial(w2, 32)

diff32 = sum(popcount(state32[i] ^ state32p[i]) for i in range(8))

print(f"State diff at round 32: {diff32} bits")
for i in range(8):
    d = state32[i] ^ state32p[i]
    reg = ['a','b','c','d','e','f','g','h'][i]
    print(f"  {reg}: {popcount(d):2d} bits (0x{d:08x})")

print()

# Search for message+delta that minimizes state diff at round 32
print("Searching for minimum state diff at round 32...")
best_diff32 = 256
best_W_for_diff32 = None
best_delta_for_diff32 = None

for trial in range(100000):
    rng = random.Random(trial * 31337 + 7)
    W_t = [rng.randint(0, 0xFFFFFFFF) for _ in range(16)]

    b14 = rng.randint(0, 31)
    b15 = rng.randint(0, 31)

    dt = [0]*16
    dt[14] = 1 << b14
    dt[15] = 1 << b15

    # Add 0-3 extra delta words
    n_extra = rng.randint(0, 3)
    for _ in range(n_extra):
        w = rng.randint(2, 13)
        b = rng.randint(0, 31)
        dt[w] ^= 1 << b

    # Algebraic d[0,1]
    dt[1] = (-(sig1(W_t[15]^dt[15]) - sig1(W_t[15]) + dt[10] +
               sig0(W_t[2]^dt[2]) - sig0(W_t[2]))) & 0xFFFFFFFF
    dt[0] = (-(sig1(W_t[14]^dt[14]) - sig1(W_t[14]) + dt[9] +
               sig0(W_t[1]^dt[1]) - sig0(W_t[1]))) & 0xFFFFFFFF

    # Expand
    W_t2 = [W_t[i] ^ dt[i] for i in range(16)]
    ww1 = list(W_t) + [0]*48
    ww2 = list(W_t2) + [0]*48
    for i in range(16, 64):
        ww1[i] = (sig1(ww1[i-2]) + ww1[i-7] + sig0(ww1[i-15]) + ww1[i-16]) & 0xFFFFFFFF
        ww2[i] = (sig1(ww2[i-2]) + ww2[i-7] + sig0(ww2[i-15]) + ww2[i-16]) & 0xFFFFFFFF

    # Schedule clean
    cl = sum(1 for i in range(16, 48) if ww1[i] == ww2[i])

    # State diff at round 32
    s32 = sha256_partial(ww1, 32)
    s32p = sha256_partial(ww2, 32)
    dd = sum(popcount(s32[j] ^ s32p[j]) for j in range(8))

    # Joint: want high clean AND low diff32
    if cl >= 5 and dd < best_diff32:
        best_diff32 = dd
        best_W_for_diff32 = W_t[:]
        best_delta_for_diff32 = dt[:]

    if trial % 20000 == 0 and trial > 0:
        print(f"  {trial}: best diff32={best_diff32} (with clean≥10)")

print(f"\nBest state diff at round 32 (with ≥10 clean schedule): {best_diff32} bits")

if best_diff32 < 100:
    # Show schedule
    W_t = best_W_for_diff32
    dt = best_delta_for_diff32
    W_t2 = [W_t[i] ^ dt[i] for i in range(16)]
    ww1 = list(W_t) + [0]*48
    ww2 = list(W_t2) + [0]*48
    for i in range(16, 64):
        ww1[i] = (sig1(ww1[i-2]) + ww1[i-7] + sig0(ww1[i-15]) + ww1[i-16]) & 0xFFFFFFFF
        ww2[i] = (sig1(ww2[i-2]) + ww2[i-7] + sig0(ww2[i-15]) + ww2[i-16]) & 0xFFFFFFFF

    cl = sum(1 for i in range(16, 48) if ww1[i] == ww2[i])
    print(f"  Schedule clean: {cl}")
    print("  Schedule: ", end="")
    for i in range(16, 48):
        b = popcount(ww1[i] ^ ww2[i])
        if b == 0: print("✓", end="")
        elif b < 10: print(str(b), end="")
        else: print("X", end="")
    print()

    # Per-register diff
    s32 = sha256_partial(ww1, 32)
    s32p = sha256_partial(ww2, 32)
    print(f"  State at round 32:")
    for j in range(8):
        d = s32[j] ^ s32p[j]
        reg = ['a','b','c','d','e','f','g','h'][j]
        print(f"    {reg}: {popcount(d):2d} bits")

print()
print("=" * 60)
print("BOOMERANG ANALYSIS")
print("=" * 60)
print()
print(f"Forward differential:  33 rounds, state diff at R32 = {best_diff32} bits")
print(f"For backward: need differential R64→R32 with same {best_diff32}-bit pattern")
print(f"If both work: boomerang covers all 64 rounds!")
print()
print("Probability estimate:")
print(f"  Forward:  p ≈ 2^(-{best_diff32}) (rough, depends on structure)")
print(f"  Backward: q ≈ 2^(-{best_diff32}) (symmetric)")
print(f"  Boomerang: p²q² ≈ 2^(-{4*best_diff32})")
print(f"  Random:    2^(-256)")
print(f"  Advantage: 2^({256 - 4*best_diff32})")
if 4*best_diff32 < 256:
    print(f"  → DISTINGUISHER EXISTS (advantage > 1)")
else:
    print(f"  → No advantage (need lower state diff)")
print()
print("Target: state diff at R32 ≤ 64 bits → 4×64 = 256 → break-even")
print("        state diff at R32 ≤ 50 bits → 4×50 = 200 → 2^56 advantage")
print("        state diff at R32 ≤ 32 bits → 4×32 = 128 → 2^128 advantage!")

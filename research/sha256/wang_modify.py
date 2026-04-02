#!/usr/bin/env python3
"""
SHA-256 Wang-style Message Modification
========================================

Instead of brute force, COMPUTE corrections:
  1. Run SHA-256 with M and M^delta
  2. At each round, measure state diff
  3. Find which message bit can CORRECT the diff
  4. Flip that bit, re-run, verify improvement

This is O(rounds × 32) corrections, not O(2^n) brute force.

Key: SHA-256 round function is:
  temp1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i]
  temp2 = S0(a) + Maj(a,b,c)
  new_a = temp1 + temp2
  new_e = d + temp1

  delta_W[i] adds DIRECTLY to temp1.
  If delta_state has diff in 'h', it flows into temp1.
  If delta_W[i] cancels delta_h, the diff is reduced.

  For rounds 0-15: delta_W[i] = delta[i] (directly controlled)
  For rounds 16+: delta_W[i] = f(delta[0..15]) (schedule)

  Message modification: adjust W[j] (j<16) to influence
  W[i] (i>=16) through schedule, targeting specific corrections.

No GPU needed — pure computation.
"""

import random
import copy

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def sig0(x): return rotr(x,7) ^ rotr(x,18) ^ (x >> 3)
def sig1(x): return rotr(x,17) ^ rotr(x,19) ^ (x >> 10)
def S0(a): return rotr(a,2) ^ rotr(a,13) ^ rotr(a,22)
def S1(e): return rotr(e,6) ^ rotr(e,11) ^ rotr(e,25)
def Ch(e,f,g): return (e & f) ^ ((~e & 0xFFFFFFFF) & g)
def Maj(a,b,c): return (a & b) ^ (a & c) ^ (b & c)
def popcount(x): return bin(x).count('1')
def add32(*args):
    s = 0
    for a in args: s = (s + a) & 0xFFFFFFFF
    return s

K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,
    0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]+[0]*33

IV = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]

def expand_schedule(W):
    w = list(W) + [0]*48
    for i in range(16, 64):
        w[i] = add32(sig1(w[i-2]), w[i-7], sig0(w[i-15]), w[i-16])
    return w

def compress_trace(W):
    """Run compression, return state at EVERY round."""
    w = expand_schedule(W)
    states = [list(IV)]
    a,b,c,d,e,f,g,h = IV
    for i in range(64):
        t1 = add32(h, S1(e), Ch(e,f,g), K[i], w[i])
        t2 = add32(S0(a), Maj(a,b,c))
        h,g,f,e,d,c,b,a = g,f,e,add32(d,t1),c,b,a,add32(t1,t2)
        states.append([a,b,c,d,e,f,g,h])
    return states, w

def state_diff(s1, s2):
    return sum(popcount(s1[i] ^ s2[i]) for i in range(8))

def per_reg_diff(s1, s2):
    return [popcount(s1[i] ^ s2[i]) for i in range(8)]

# ═══════════════════════════════════════════════
# Wang-style message modification
# ═══════════════════════════════════════════════

def modify_message(W_orig, delta, max_iterations=1000):
    """
    Given message W and delta, try to modify W to minimize
    state diff at round 64 between compress(W) and compress(W^delta).

    Strategy: for each round where diff increases,
    find a message word adjustment that reduces it.
    """

    W = list(W_orig)
    best_diff = 999
    best_W = list(W)

    for iteration in range(max_iterations):
        # Current state
        W2 = [W[i] ^ delta[i] for i in range(16)]
        states1, w1 = compress_trace(W)
        states2, w2 = compress_trace(W2)

        total_diff = state_diff(states1[64], states2[64])

        if total_diff < best_diff:
            best_diff = total_diff
            best_W = list(W)
            if total_diff == 0:
                return best_W, 0

        # Find the round with biggest diff INCREASE
        worst_round = -1
        worst_increase = -1
        for r in range(1, 64):
            d_prev = state_diff(states1[r-1], states2[r-1])
            d_curr = state_diff(states1[r], states2[r])
            increase = d_curr - d_prev
            if increase > worst_increase:
                worst_increase = increase
                worst_round = r

        if worst_round < 0 or worst_increase <= 0:
            # No round increases diff — try random perturbation
            bit = random.randint(0, 511)
            W[bit // 32] ^= 1 << (bit % 32)
            continue

        # Try to fix the worst round
        # Round worst_round uses W[worst_round] if < 16,
        # or W[worst_round] through schedule if >= 16

        # Strategy: try flipping each bit of each input word
        # and keep the one that reduces diff at worst_round most

        # But that's expensive. Faster: target the specific dependency
        # W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16]
        # For round r, W[r] depends on specific input words

        # Direct approach: try 32 random bit flips, keep best
        improved = False
        for attempt in range(64):
            word = random.randint(0, 15)
            bit = random.randint(0, 31)

            W_try = list(W)
            W_try[word] ^= 1 << bit

            W2_try = [W_try[i] ^ delta[i] for i in range(16)]
            s1_try, _ = compress_trace(W_try)
            s2_try, _ = compress_trace(W2_try)

            new_diff = state_diff(s1_try[64], s2_try[64])

            if new_diff < total_diff:
                W = W_try
                improved = True
                break

        if not improved:
            # Random restart from best known
            W = list(best_W)
            word = random.randint(0, 15)
            W[word] ^= random.randint(1, 0xFFFFFFFF)

    return best_W, best_diff

# ═══════════════════════════════════════════════
# Advanced: greedy round-by-round correction
# ═══════════════════════════════════════════════

def greedy_correction(W_orig, delta, rounds_to_fix=64):
    """
    For each round 0→63:
      1. Compute current state diff at this round
      2. Find input word bit that REDUCES diff here
         WITHOUT making earlier rounds worse
      3. Apply correction

    This is O(64 * 16 * 32) = O(32768) evaluations.
    """

    W = list(W_orig)

    for target_round in range(16, min(rounds_to_fix, 64)):
        W2 = [W[i] ^ delta[i] for i in range(16)]
        states1, _ = compress_trace(W)
        states2, _ = compress_trace(W2)

        current_diff = state_diff(states1[target_round], states2[target_round])

        if current_diff == 0:
            continue

        # Try each input word × bit
        best_improvement = 0
        best_word = -1
        best_bit = -1

        for word in range(16):
            for bit in range(32):
                W_try = list(W)
                W_try[word] ^= 1 << bit
                W2_try = [W_try[i] ^ delta[i] for i in range(16)]
                s1, _ = compress_trace(W_try)
                s2, _ = compress_trace(W2_try)

                new_diff = state_diff(s1[target_round], s2[target_round])

                # Also check: don't make final round worse
                final_diff = state_diff(s1[64], s2[64])
                states1_64 = state_diff(states1[64], states2[64])

                improvement = (current_diff - new_diff) * 10 + (states1_64 - final_diff)

                if improvement > best_improvement:
                    best_improvement = improvement
                    best_word = word
                    best_bit = bit

        if best_word >= 0 and best_improvement > 0:
            W[best_word] ^= 1 << best_bit
            W2 = [W[i] ^ delta[i] for i in range(16)]
            s1, _ = compress_trace(W)
            s2, _ = compress_trace(W2)
            new_total = state_diff(s1[64], s2[64])
            new_at_r = state_diff(s1[target_round], s2[target_round])
            print(f"  R{target_round:2d}: corrected W[{best_word}] bit {best_bit:2d} → "
                  f"diff@R{target_round}={new_at_r} total@R64={new_total}")

    # Final evaluation
    W2 = [W[i] ^ delta[i] for i in range(16)]
    s1, _ = compress_trace(W)
    s2, _ = compress_trace(W2)
    final_diff = state_diff(s1[64], s2[64])
    return W, final_diff

# ═══════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════

print("SHA-256 Wang-style Message Modification")
print("═══════════════════════════════════════")
print()

random.seed(42)
W = [random.randint(0, 0xFFFFFFFF) for _ in range(16)]

# Simple delta
delta = [0]*16
delta[14] = 1 << 8
delta[15] = 1 << 8
# Fix d[0,1]
delta[1] = (-(sig1(W[15]^delta[15]) - sig1(W[15]))) & 0xFFFFFFFF
delta[0] = (-(sig1(W[14]^delta[14]) - sig1(W[14]) + sig0(W[1]^delta[1]) - sig0(W[1]))) & 0xFFFFFFFF

# Initial diff
W2 = [W[i] ^ delta[i] for i in range(16)]
s1, _ = compress_trace(W)
s2, _ = compress_trace(W2)
init_diff = state_diff(s1[64], s2[64])
print(f"Initial state diff at R64: {init_diff} bits")
print(f"Per-register: {per_reg_diff(s1[64], s2[64])}")
print()

# Method 1: Random modification
print("=== Method 1: Random message modification (1000 iter) ===")
W_mod, diff_mod = modify_message(W, delta, max_iterations=1000)
print(f"After modification: {diff_mod} bits (was {init_diff})")
print()

# Method 2: Greedy round-by-round
print("=== Method 2: Greedy round-by-round correction ===")
W_greedy, diff_greedy = greedy_correction(W, delta, rounds_to_fix=40)
print(f"\nAfter greedy correction (up to R40): {diff_greedy} bits (was {init_diff})")

# Show trajectory
W2g = [W_greedy[i] ^ delta[i] for i in range(16)]
s1g, _ = compress_trace(W_greedy)
s2g, _ = compress_trace(W2g)
print("\nTrajectory after greedy:")
for r in [16,20,24,28,32,36,40,44,48,52,56,60,64]:
    d = state_diff(s1g[r], s2g[r])
    regs = per_reg_diff(s1g[r], s2g[r])
    print(f"  R{r:2d}: {d:3d} bits | {regs}")

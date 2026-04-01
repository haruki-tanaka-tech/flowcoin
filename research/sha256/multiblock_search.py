#!/usr/bin/env python3
"""
SHA-256 Multi-block Search — Joint optimization on CPU
Find delta pattern with BOTH high schedule clean AND low H1 delta.

Runs on CPU — no GPU overheating.
Uses multiprocessing for parallel search.
"""

import random
import multiprocessing as mp
import time
import sys

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
    0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
    0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000
]

IV = (0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)

def sha256_compress(H, W):
    w = list(W) + [0]*48
    for i in range(16, 64):
        w[i] = (sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16]) & 0xFFFFFFFF
    a,b,c,d,e,f,g,h = H
    for i in range(64):
        S1 = rotr(e,6)^rotr(e,11)^rotr(e,25)
        ch = (e&f)^((~e&0xFFFFFFFF)&g)
        t1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
        S0 = rotr(a,2)^rotr(a,13)^rotr(a,22)
        mj = (a&b)^(a&c)^(b&c)
        t2 = (S0 + mj) & 0xFFFFFFFF
        h,g,f,e,d,c,b,a = g,f,e,(d+t1)&0xFFFFFFFF,c,b,a,(t1+t2)&0xFFFFFFFF
    return tuple((H[i]+v)&0xFFFFFFFF for i,v in enumerate([a,b,c,d,e,f,g,h]))

def schedule_clean(W, delta):
    """Count clean schedule words and total diff bits."""
    W2 = [W[i] ^ delta[i] for i in range(16)]
    w1 = list(W) + [0]*48
    w2 = list(W2) + [0]*48
    for i in range(16, 48):
        w1[i] = (sig1(w1[i-2]) + w1[i-7] + sig0(w1[i-15]) + w1[i-16]) & 0xFFFFFFFF
        w2[i] = (sig1(w2[i-2]) + w2[i-7] + sig0(w2[i-15]) + w2[i-16]) & 0xFFFFFFFF
    clean = sum(1 for i in range(16, 48) if w1[i] == w2[i])
    total = sum(popcount(w1[i] ^ w2[i]) for i in range(16, 48))
    return clean, total

def h1_delta(W, delta):
    """Compute H1 XOR delta (hamming weight)."""
    W2 = [W[i] ^ delta[i] for i in range(16)]
    H1 = sha256_compress(IV, W)
    H1p = sha256_compress(IV, W2)
    return sum(popcount(H1[i] ^ H1p[i]) for i in range(8)), H1, H1p

def make_delta(W, b14, b15, extra_words):
    """Build delta: d[14],d[15] fixed, d[0,1] algebraic, extra_words = [(word,bit),...]"""
    d = [0]*16
    d[14] = 1 << b14
    d[15] = 1 << b15
    for w, b in extra_words:
        d[w] ^= 1 << b
    # Solve d[1]: cancel W[17]
    d[1] = (-(sig1(W[15]^d[15]) - sig1(W[15]) + d[10] +
              sig0(W[2]^d[2]) - sig0(W[2]))) & 0xFFFFFFFF
    # Solve d[0]: cancel W[16]
    d[0] = (-(sig1(W[14]^d[14]) - sig1(W[14]) + d[9] +
              sig0(W[1]^d[1]) - sig0(W[1]))) & 0xFFFFFFFF
    return d

def score(clean, h1d):
    """Joint score: want high clean AND low h1d."""
    # Pareto: clean >= 12 AND h1d <= 60 is excellent
    return clean * 100 - h1d

def worker_search(args):
    """Worker process: search for best (clean, h1_delta) pair."""
    worker_id, n_trials, seed = args
    rng = random.Random(seed)

    best_score = -9999
    best_result = None

    for trial in range(n_trials):
        # Random message
        W = [rng.randint(0, 0xFFFFFFFF) for _ in range(16)]

        # Random bit positions
        b14 = rng.randint(0, 31)
        b15 = rng.randint(0, 31)

        # Random extra delta words (1-5 words)
        n_extra = rng.randint(1, 5)
        extras = []
        for _ in range(n_extra):
            w = rng.randint(2, 13)
            b = rng.randint(0, 31)
            extras.append((w, b))

        delta = make_delta(W, b14, b15, extras)

        # Must have nonzero
        if all(d == 0 for d in delta):
            continue

        cl, sched_total = schedule_clean(W, delta)
        h1d, _, _ = h1_delta(W, delta)

        s = score(cl, h1d)

        if s > best_score:
            best_score = s
            best_result = {
                'clean': cl,
                'h1_delta': h1d,
                'sched_total': sched_total,
                'b14': b14,
                'b15': b15,
                'extras': extras,
                'score': s,
                'W': W[:],
                'delta': delta[:]
            }

    return best_result

def main():
    print("SHA-256 Multi-block Joint Optimization (CPU)")
    print("════════════════════════════════════════════")
    print()

    n_workers = mp.cpu_count()
    trials_per_worker = 50000
    n_rounds = 20

    print(f"Workers: {n_workers}")
    print(f"Trials per worker per round: {trials_per_worker}")
    print(f"Rounds: {n_rounds}")
    print(f"Total: {n_workers * trials_per_worker * n_rounds:,} evaluations")
    print()

    global_best_score = -9999
    global_best = None

    pool = mp.Pool(n_workers)

    for round_num in range(n_rounds):
        t0 = time.time()

        args = [(i, trials_per_worker, round_num * 1000000 + i * 12345 + 42)
                for i in range(n_workers)]
        results = pool.map(worker_search, args)

        # Find best in this round
        for r in results:
            if r and r['score'] > global_best_score:
                global_best_score = r['score']
                global_best = r

        elapsed = time.time() - t0
        rate = n_workers * trials_per_worker / elapsed

        if global_best:
            # Show schedule pattern
            W = global_best['W']
            delta = global_best['delta']
            W2 = [W[i] ^ delta[i] for i in range(16)]
            w1 = list(W) + [0]*48
            w2 = list(W2) + [0]*48
            for i in range(16, 48):
                w1[i] = (sig1(w1[i-2]) + w1[i-7] + sig0(w1[i-15]) + w1[i-16]) & 0xFFFFFFFF
                w2[i] = (sig1(w2[i-2]) + w2[i-7] + sig0(w2[i-15]) + w2[i-16]) & 0xFFFFFFFF

            sched_str = ""
            for i in range(16, 48):
                b = popcount(w1[i] ^ w2[i])
                if b == 0: sched_str += "✓"
                elif b < 10: sched_str += str(b)
                else: sched_str += "X"

            print(f"R{round_num:2d}: clean={global_best['clean']:2d} h1d={global_best['h1_delta']:3d} "
                  f"| {rate:.0f}/s | {sched_str}")

            if global_best['clean'] >= 15 and global_best['h1_delta'] <= 50:
                print(f"\n  *** EXCELLENT: clean={global_best['clean']}, h1_delta={global_best['h1_delta']} ***")
                print(f"  Extras: {global_best['extras']}")
                print(f"  b14={global_best['b14']}, b15={global_best['b15']}")

    pool.close()

    print()
    print("=" * 60)
    print("FINAL BEST:")
    print(f"  Schedule clean: {global_best['clean']}")
    print(f"  H1 delta: {global_best['h1_delta']} bits")
    print(f"  Score: {global_best['score']}")
    print()

    # Multi-block simulation with best
    W = global_best['W']
    delta = global_best['delta']
    W2 = [W[i] ^ delta[i] for i in range(16)]
    H1 = sha256_compress(IV, W)
    H1p = sha256_compress(IV, W2)

    print(f"Block 1: H1 delta = {sum(popcount(H1[i]^H1p[i]) for i in range(8))} bits")

    # Block 2 search
    print(f"\nSearching 100K block2 messages with this H1 delta...")
    best_h2 = 256
    for t in range(100000):
        rng2 = random.Random(t * 7919)
        W2b = [rng2.randint(0, 0xFFFFFFFF) for _ in range(16)]
        d2 = [0]*16
        d2[14] = global_best['delta'][14]
        d2[15] = global_best['delta'][15]
        d2[1] = (-(sig1(W2b[15]^d2[15])-sig1(W2b[15]))) & 0xFFFFFFFF
        d2[0] = (-(sig1(W2b[14]^d2[14])-sig1(W2b[14])+sig0(W2b[1]^d2[1])-sig0(W2b[1]))) & 0xFFFFFFFF
        W2bp = [W2b[i]^d2[i] for i in range(16)]

        H2 = sha256_compress(H1, W2b)
        H2p = sha256_compress(H1p, W2bp)
        h2d = sum(popcount(H2[i]^H2p[i]) for i in range(8))
        if h2d < best_h2:
            best_h2 = h2d

    print(f"Best H2 delta: {best_h2} bits")
    print(f"Improvement over random: {128 - best_h2} bits below random")

if __name__ == '__main__':
    main()

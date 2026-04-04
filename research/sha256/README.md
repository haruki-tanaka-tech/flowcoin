# SHA-256 Differential Analysis

**Author:** Kristian, 16
**Date:** March 2026
**Status:** Experimental — not peer-reviewed

## Disclaimer

This is NOT a break of SHA-256. SHA-256 remains fully secure.

This is an experimental study of differential properties of the SHA-256
message schedule and compression function. All results are empirical
observations unless stated otherwise. Direct comparison with published
collision results (Mendel et al. 28R, Dobraunig et al. 31R) is not
applicable — the attack models and success metrics differ.

## What was done

### 1. Message Schedule Difference Cancellation (Algebraic)

The SHA-256 message schedule expands 16 input words into 64 via:

    W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]

W[28] is the first expanded word depending on all 16 inputs. Before
that point, input differences can be chosen algebraically to cancel
expanded word differences.

**Result:** 18 expanded words (W[16..33]) forced to zero difference
through algebraic choice of input differences. This is deterministic
and verifiable.

**Extended result:** GPU simulated annealing (512K threads x 8K steps,
3 phases) found delta patterns with up to 24 clean schedule words.
This is a heuristic result — not proven optimal.

**Important:** This controls the MESSAGE SCHEDULE difference only.
It does NOT control the compression function state (a,b,c,d,e,f,g,h).
The nonlinear operations (Ch, Maj, modular addition) cause state
differences to grow even when schedule differences are zero.

### 2. Full 64-Round State Difference Measurement (Empirical)

For delta patterns achieving 18+ clean schedule words, the XOR Hamming
weight of two compression function outputs was measured over 10^8+
random message pairs.

**Observation:** State difference consistently measured 70-78 bits
(mode ~74), lower than the ~128 bits expected from a random function.

**Caveats:**
- Statistical observation, not a proven bound
- No formal probability distribution analysis
- No confidence intervals computed
- Depends on specific delta pattern
- Does NOT directly translate to a collision attack
- The informal "2^54 advantage" calculation is INCORRECT as a
  security claim

### 3. Free-Start Observations (Empirical)

With freely chosen initial state (not SHA-256 IV):

**Observation:** 71-bit state difference at round 64.

**Not comparable** with published free-start results (Mendel 2013,
Dobraunig 2016) because:
- Published results are proven collisions/near-collisions
- Our result is a state difference measurement
- Attack models differ
- Published results are peer-reviewed

### 4. Truncated Differential (Empirical)

**Observation:** Register 'a' can show zero difference through all
64 rounds with specific delta patterns, while registers b-h retain
nonzero differences. This is 32/256 bits — not analyzed for
exploitability.

### 5. Early Rejection Filter (Practical)

By examining the intermediate state after 33 rounds, nonces that will
not produce leading zeros can be predicted with ~95-99% accuracy
(measured over 10^7 nonces). Potential ~30% mining speedup.

**Not validated** against real Bitcoin block headers.

## Methods

- Algebraic analysis (Python): dependency graph, cascade cancellation
- GPU simulated annealing (CUDA): 40+ kernels, 10^10 total evaluations
- MITM framework (C, SHA-NI, AVX2): split at round 32
- Birthday attack (CUDA VRAM): 2^30+ stored states
- SAT encoding (Python/CryptoMiniSat): reduced rounds
- Statistical measurement: state diff across 10^8+ samples

## Hardware

- NVIDIA GeForce RTX 5080 Laptop GPU (CUDA)
- Intel Core Ultra 9 275HX (24 cores, 36MB L3, SHA-NI, AVX2)

## Summary Table

| Experiment              | Model       | Result          | Verified     | Rigorous |
|-------------------------|-------------|-----------------|--------------|----------|
| Schedule cancel (18 W)  | Standard IV | Algebraic       | Deterministic| Yes      |
| Schedule extend (24 W)  | Standard IV | Heuristic       | Empirical    | No       |
| State diff 74 bits R64  | Standard IV | Statistical     | Reproducible | No       |
| Free-start 71 bits R64  | Free-start  | Best observed   | Single run   | No       |
| Truncated (reg a = 0)   | Standard IV | Observed        | Empirical    | No       |
| Early rejection filter  | Mining      | ~95-99% accuracy| Reproducible | Partial  |

## Correct Framing

Experimental differential analysis of the SHA-256 message schedule
achieving algebraic difference cancellation through 33 expanded words,
extending beyond the previously observed 18-word algebraic boundary.
Accompanied by empirical state difference measurements on the full
64-round compression function.

These are differential observations on the message schedule, not
attacks on the compression function. Direct comparison with published
collision results is not applicable as the attack models and success
metrics differ.

## What This Is

- Pre-research / early-stage cryptanalysis
- Genuine exploration of known attack directions
- Significant engineering effort (40+ CUDA kernels)
- The algebraic schedule cancellation is correct
- The empirical observations need formal analysis

## What This Is NOT

- Not a break of SHA-256
- Not a collision attack
- Not a proven security reduction
- Not peer-reviewed
- Not directly comparable with Mendel/Dobraunig results

## Path Forward

To reach publication quality (SAC/FSE workshop level):

1. Formal probability distribution of state difference (10^9+ trials,
   chi-squared test, confidence intervals)
2. Exact comparison with prior art using identical models
3. Analysis of WHY 74 bits arises (structural or artifact?)
4. Reproducibility package (exact deltas, seeds, instructions)
5. Honest framing without overclaiming

## Files

- `*.cu` — CUDA GPU kernels (annealing, birthday, optimization)
- `*.c` — CPU implementations (MITM, mining shortcuts, linear solve)
- `*.py` — Analysis scripts (barrier analysis, boomerang, Wang method)

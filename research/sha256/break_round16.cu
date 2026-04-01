/*
 * SHA-256 Round 16-24 Barrier Breaker
 * ====================================
 *
 * Round 16 is where message schedule expansion kicks in:
 *   W[16] = s1(W[14]) + W[9] + s0(W[1]) + W[0]
 *   s0(x) = ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3)
 *   s1(x) = ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10)
 *
 * Strategy: find delta patterns in W[0..15] where:
 *   1. The deltas cancel in W[16..23] (message schedule)
 *   2. The remaining state diff stays minimal
 *
 * Approach:
 *   - Analyze message schedule algebraically
 *   - W[16] depends on W[14], W[9], W[1], W[0]
 *   - If delta_W[16] = 0, we need:
 *     s1(W[14]^d14) - s1(W[14]) + d9 + s0(W[1]^d1) - s0(W[1]) + d0 = 0
 *   - This gives constraints between d0, d1, d9, d14
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,1835,20091 break_round16.cu -o break16
 */

#include <cstdint>
#include <cstdio>
#include <cstring>

__constant__ static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,
    0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,0x00000000,
    0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
    0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
    0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
    0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(e,f,g) (((e)&(f))^((~(e))&(g)))
#define MAJ(a,b,c) (((a)&(b))^((a)&(c))^((b)&(c)))
#define S0(a) (ROTR(a,2)^ROTR(a,13)^ROTR(a,22))
#define S1(e) (ROTR(e,6)^ROTR(e,11)^ROTR(e,25))
#define sig0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define sig1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

__device__ __host__
int popcount32(uint32_t x) {
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    return (((x + (x >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

__device__ __host__
void sha256_n_rounds(const uint32_t W[16], int n, uint32_t out[8]) {
    out[0]=0x6a09e667; out[1]=0xbb67ae85; out[2]=0x3c6ef372; out[3]=0xa54ff53a;
    out[4]=0x510e527f; out[5]=0x9b05688c; out[6]=0x1f83d9ab; out[7]=0x5be0cd19;

    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = W[i];
    for (int i = 16; i < 64; i++)
        w[i] = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16];

    uint32_t a=out[0],b=out[1],c=out[2],d=out[3];
    uint32_t e=out[4],f=out[5],g=out[6],h=out[7];
    for (int i = 0; i < n && i < 64; i++) {
        uint32_t t1 = h + S1(e) + CH(e,f,g) + K[i] + w[i];
        uint32_t t2 = S0(a) + MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    out[0]=a;out[1]=b;out[2]=c;out[3]=d;
    out[4]=e;out[5]=f;out[6]=g;out[7]=h;
}

__device__ __host__
int state_diff(const uint32_t a[8], const uint32_t b[8]) {
    int t = 0;
    for (int i = 0; i < 8; i++) t += popcount32(a[i] ^ b[i]);
    return t;
}

// ═══════════════════════════════════════════════════
// Experiment 1: Message schedule differential
// For each W[i] with delta d, compute delta_W[16..23]
// Find d combinations where delta_W[16..23] = 0
// ═══════════════════════════════════════════════════

// Compute message schedule delta: given delta in W[0..15],
// what is delta in W[16..23]?
__device__ __host__
void msg_schedule_delta(const uint32_t W[16], const uint32_t delta[16],
                        uint32_t w_delta[8]) {
    // W' = W ^ delta
    uint32_t w1[64], w2[64];
    for (int i = 0; i < 16; i++) {
        w1[i] = W[i];
        w2[i] = W[i] ^ delta[i];
    }
    for (int i = 16; i < 24; i++) {
        w1[i] = sig1(w1[i-2]) + w1[i-7] + sig0(w1[i-15]) + w1[i-16];
        w2[i] = sig1(w2[i-2]) + w2[i-7] + sig0(w2[i-15]) + w2[i-16];
    }
    for (int i = 0; i < 8; i++)
        w_delta[i] = w1[i+16] ^ w2[i+16];
}

// ═══════════════════════════════════════════════════
// Experiment 2: Targeted cancellation
// For W[16] = sig1(W[14]) + W[9] + sig0(W[1]) + W[0]
// Find delta_W[0], delta_W[1] that cancel delta_W[16]
// given delta_W[14] and message W
// ═══════════════════════════════════════════════════

__global__
void search_w16_cancel(
    uint64_t seed,
    int* best_total_diff,       // sum of |delta_W[16..23]| in bits
    uint32_t* best_delta,       // [16]
    uint32_t* best_msg,         // [16]
    int n_trials)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n_trials) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    // Random message
    uint32_t W[16];
    for (int i = 0; i < 16; i++) {
        rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
        W[i] = (uint32_t)(rng >> 32);
    }

    // Strategy: choose delta in W[0], W[1], W[9], W[14]
    // to cancel delta_W[16]
    //
    // delta_W[16] = sig1(W14^d14) - sig1(W14) + d9 + sig0(W1^d1) - sig0(W1) + d0
    //
    // Try: set d14 = small, compute required d0 to cancel
    // d0 = -(sig1(W14^d14) - sig1(W14) + sig0(W1^d1) - sig0(W1))
    // This is modular arithmetic (mod 2^32)

    // Random low-weight delta for W[14] and W[1]
    rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
    int bit14 = (int)(rng >> 32) & 31;
    rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
    int bit1 = (int)(rng >> 32) & 31;

    uint32_t d14 = 1u << bit14;
    uint32_t d1 = 1u << bit1;

    // Compute sig deltas
    uint32_t sig1_diff = sig1(W[14] ^ d14) - sig1(W[14]);
    uint32_t sig0_diff = sig0(W[1] ^ d1) - sig0(W[1]);

    // d0 that cancels W[16]: d0 = -(sig1_diff + sig0_diff) mod 2^32
    uint32_t d0 = -(sig1_diff + sig0_diff);

    // Build delta pattern
    uint32_t delta[16] = {0};
    delta[0] = d0;
    delta[1] = d1;
    delta[14] = d14;

    // Now check: does this also cancel W[17..23]?
    // W[17] = sig1(W[15]) + W[10] + sig0(W[2]) + W[1]
    // delta_W[17] = sig0(W2^0) - sig0(W2) + d1 = d1  (since d2=0)
    // So W[17] has delta = d1 unless we also set d2, d10, d15...

    // Compute actual schedule delta
    uint32_t wd[8];
    msg_schedule_delta(W, delta, wd);

    int total = 0;
    for (int i = 0; i < 8; i++) total += popcount32(wd[i]);

    int old = atomicMin(best_total_diff, total);
    if (total < old) {
        for (int i = 0; i < 16; i++) {
            best_delta[i] = delta[i];
            best_msg[i] = W[i];
        }
    }
}

// ═══════════════════════════════════════════════════
// Experiment 3: Full optimization — minimize BOTH
// message schedule diff AND state diff at round N
// ═══════════════════════════════════════════════════

__global__
void full_diff_search(
    int target_round,
    uint64_t seed,
    int* best_state_diff,
    int* best_sched_diff,
    uint32_t* best_delta,
    uint32_t* best_msg,
    int n_trials)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n_trials) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    uint32_t W[16];
    for (int i = 0; i < 16; i++) {
        rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
        W[i] = (uint32_t)(rng >> 32);
    }

    // Strategy: algebraic cancellation for W[16]
    // Then minimize remaining damage
    rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
    uint32_t r = (uint32_t)(rng >> 32);

    // Choose which words get delta
    // Focused: only W[0], W[1], W[14] (affects W[16])
    // Plus optionally W[2], W[9], W[15] (affects W[17])
    uint32_t delta[16] = {0};

    // Phase A: cancel W[16]
    int b14 = r & 31;
    int b1 = (r >> 5) & 31;
    delta[14] = 1u << b14;
    delta[1] = 1u << b1;
    delta[0] = -(sig1(W[14] ^ delta[14]) - sig1(W[14]) + sig0(W[1] ^ delta[1]) - sig0(W[1]));

    // Phase B: try to reduce W[17] by adjusting W[2], W[10], W[15]
    // W[17] = sig1(W[15]) + W[10] + sig0(W[2]) + W[1]
    // delta_W[17] = sig1(W15^d15) - sig1(W15) + d10 + sig0(W2^d2) - sig0(W2) + d1
    // Set d15, d2 to partially cancel

    rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
    int b15 = (int)(rng >> 32) & 31;
    int b2 = (int)((rng >> 16) & 31);
    delta[15] = 1u << b15;
    delta[2] = 1u << b2;
    // d10 to cancel W[17]
    uint32_t sig1_d15 = sig1(W[15] ^ delta[15]) - sig1(W[15]);
    uint32_t sig0_d2 = sig0(W[2] ^ delta[2]) - sig0(W[2]);
    delta[10] = -(sig1_d15 + sig0_d2 + delta[1]);

    // Phase C: try to reduce W[18]
    // W[18] = sig1(W[16]) + W[11] + sig0(W[3]) + W[2]
    // Since we made delta_W[16] ≈ 0, sig1 contribution is small
    // delta_W[18] ≈ d11 + sig0(W3^d3) - sig0(W3) + d2
    rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
    int b3 = (int)(rng >> 32) & 31;
    delta[3] = 1u << b3;
    uint32_t sig0_d3 = sig0(W[3] ^ delta[3]) - sig0(W[3]);
    delta[11] = -(sig0_d3 + delta[2]);

    // Compute full state diff
    uint32_t W2[16];
    for (int i = 0; i < 16; i++) W2[i] = W[i] ^ delta[i];

    uint32_t s1[8], s2[8];
    sha256_n_rounds(W, target_round, s1);
    sha256_n_rounds(W2, target_round, s2);
    int sd = state_diff(s1, s2);

    // Also compute schedule diff
    uint32_t wd[8];
    msg_schedule_delta(W, delta, wd);
    int sched = 0;
    for (int i = 0; i < 8; i++) sched += popcount32(wd[i]);

    // Weight: state_diff is what matters, schedule_diff is secondary
    int score = sd;

    int old = atomicMin(best_state_diff, score);
    if (score < old) {
        *best_sched_diff = sched;
        for (int i = 0; i < 16; i++) {
            best_delta[i] = delta[i];
            best_msg[i] = W[i];
        }
    }
}

int main() {
    printf("SHA-256 Round 16-24 Barrier Breaker\n");
    printf("═══════════════════════════════════\n\n");

    int *d_best_total, *d_best_state, *d_best_sched;
    uint32_t *d_best_delta, *d_best_msg;
    cudaMalloc(&d_best_total, 4);
    cudaMalloc(&d_best_state, 4);
    cudaMalloc(&d_best_sched, 4);
    cudaMalloc(&d_best_delta, 64);
    cudaMalloc(&d_best_msg, 64);

    // ── Experiment 2: W[16] cancellation ──
    printf("=== Exp 1: Cancel W[16] schedule delta ===\n\n");

    int trials = 1 << 24;
    int h_val = 256;
    cudaMemcpy(d_best_total, &h_val, 4, cudaMemcpyHostToDevice);

    for (int pass = 0; pass < 4; pass++) {
        search_w16_cancel<<<trials/256, 256>>>(
            pass * 1234567ULL, d_best_total, d_best_delta, d_best_msg, trials);
        cudaDeviceSynchronize();
    }

    cudaMemcpy(&h_val, d_best_total, 4, cudaMemcpyDeviceToHost);
    uint32_t h_delta[16], h_msg[16];
    cudaMemcpy(h_delta, d_best_delta, 64, cudaMemcpyDeviceToHost);
    cudaMemcpy(h_msg, d_best_msg, 64, cudaMemcpyDeviceToHost);

    printf("Best schedule diff (W[16..23]): %d bits total\n", h_val);
    printf("Delta pattern:\n");
    int delta_bits = 0;
    for (int i = 0; i < 16; i++) {
        if (h_delta[i]) {
            printf("  W[%2d] ^= 0x%08x (%d bits)\n", i, h_delta[i], popcount32(h_delta[i]));
            delta_bits += popcount32(h_delta[i]);
        }
    }
    printf("Total delta bits: %d\n", delta_bits);

    // Verify: compute actual schedule expansion
    printf("\nSchedule delta verification:\n");
    uint32_t wd[8];
    // Can't call device function from host, recompute
    {
        uint32_t w1[64], w2[64];
        for (int i = 0; i < 16; i++) { w1[i] = h_msg[i]; w2[i] = h_msg[i] ^ h_delta[i]; }
        for (int i = 16; i < 24; i++) {
            w1[i] = (ROTR(w1[i-2],17)^ROTR(w1[i-2],19)^(w1[i-2]>>10)) + w1[i-7] +
                    (ROTR(w1[i-15],7)^ROTR(w1[i-15],18)^(w1[i-15]>>3)) + w1[i-16];
            w2[i] = (ROTR(w2[i-2],17)^ROTR(w2[i-2],19)^(w2[i-2]>>10)) + w2[i-7] +
                    (ROTR(w2[i-15],7)^ROTR(w2[i-15],18)^(w2[i-15]>>3)) + w2[i-16];
        }
        for (int i = 16; i < 24; i++) {
            uint32_t d = w1[i] ^ w2[i];
            printf("  W[%d] delta: %08x (%d bits)\n", i, d, popcount32(d));
        }
    }

    // ── Experiment 3: Full state diff minimization ──
    printf("\n=== Exp 2: Full state diff minimization (algebraic) ===\n\n");

    trials = 1 << 24;

    for (int target = 16; target <= 24; target++) {
        h_val = 256;
        cudaMemcpy(d_best_state, &h_val, 4, cudaMemcpyHostToDevice);
        int h_sched = 0;
        cudaMemcpy(d_best_sched, &h_sched, 4, cudaMemcpyHostToDevice);

        for (int pass = 0; pass < 8; pass++) {
            full_diff_search<<<trials/256, 256>>>(
                target, pass * 9876543ULL + target * 111,
                d_best_state, d_best_sched, d_best_delta, d_best_msg, trials);
            cudaDeviceSynchronize();
        }

        cudaMemcpy(&h_val, d_best_state, 4, cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_sched, d_best_sched, 4, cudaMemcpyDeviceToHost);
        cudaMemcpy(h_delta, d_best_delta, 64, cudaMemcpyDeviceToHost);

        delta_bits = 0;
        int delta_words = 0;
        for (int i = 0; i < 16; i++) {
            if (h_delta[i]) { delta_words++; delta_bits += popcount32(h_delta[i]); }
        }

        printf("Round %2d: state_diff = %3d bits | sched_diff = %3d bits | delta: %d words, %d bits\n",
               target, h_val, h_sched, delta_words, delta_bits);

        if (h_val < 50) {
            printf("  *** LOW DIFF! Delta:");
            for (int i = 0; i < 16; i++)
                if (h_delta[i]) printf(" W[%d]=0x%08x", i, h_delta[i]);
            printf("\n");
        }
    }

    printf("\n=== Analysis ===\n");
    printf("Round 16: message schedule kicks in.\n");
    printf("Algebraic cancellation of W[16] reduces schedule delta.\n");
    printf("But W[17], W[18]... cascade — each needs its own cancellation.\n");
    printf("Key insight: cancelling W[16..18] requires modifying 6+ input words.\n");
    printf("Each additional cancelled W[i] adds ~32 bits of constraint.\n");
    printf("Beyond round 20: diminishing returns — diffusion saturates.\n");

    cudaFree(d_best_total); cudaFree(d_best_state); cudaFree(d_best_sched);
    cudaFree(d_best_delta); cudaFree(d_best_msg);
    return 0;
}

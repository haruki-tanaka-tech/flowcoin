/*
 * SHA-256 Round-by-Round Differential Analysis
 * =============================================
 *
 * Goal: find input differentials that survive maximum rounds
 * with minimum output difference (measured in changed bits).
 *
 * SHA-256 round function:
 *   S1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25)
 *   Ch = (e & f) ^ (~e & g)
 *   temp1 = h + S1 + Ch + K[i] + W[i]
 *   S0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22)
 *   Maj = (a & b) ^ (a & c) ^ (b & c)
 *   temp2 = S0 + Maj
 *   h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2
 *
 * Message schedule (rounds 16+):
 *   s0 = ROTR(W[i-15],7) ^ ROTR(W[i-15],18) ^ (W[i-15] >> 3)
 *   s1 = ROTR(W[i-2],17) ^ ROTR(W[i-2],19) ^ (W[i-2] >> 10)
 *   W[i] = W[i-16] + s0 + W[i-7] + s1
 *
 * Strategy:
 *   Phase 1: Single-bit differentials in W[0] — measure propagation
 *   Phase 2: Multi-word cascade — low hamming weight deltas
 *   Phase 3: Find pairs where diff stays minimal through N rounds
 *   Phase 4: Universal deltas that work for ANY message
 *
 * Build: nvcc -O3 -arch=sm_120 round_analysis.cu -o sha256_analysis
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>

// SHA-256 constants
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
#define s0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define s1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

// Count bits set
__device__ __host__
int popcount32(uint32_t x) {
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    return (((x + (x >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

// SHA-256 partial round function — returns state after N rounds
__device__ __host__
void sha256_rounds(const uint32_t W[16], int n_rounds,
                   uint32_t state[8]) {
    // Initial hash values (H0)
    state[0] = 0x6a09e667; state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
    state[4] = 0x510e527f; state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;

    // Expand message schedule
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = W[i];
    for (int i = 16; i < 64; i++)
        w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];

    uint32_t a=state[0],b=state[1],c=state[2],d=state[3];
    uint32_t e=state[4],f=state[5],g=state[6],h=state[7];

    for (int i = 0; i < n_rounds && i < 64; i++) {
        uint32_t temp1 = h + S1(e) + CH(e,f,g) + K[i] + w[i];
        uint32_t temp2 = S0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
    }

    state[0]=a; state[1]=b; state[2]=c; state[3]=d;
    state[4]=e; state[5]=f; state[6]=g; state[7]=h;
}

// Measure differential: hamming distance between two states
__device__ __host__
int state_diff_bits(const uint32_t s1[8], const uint32_t s2[8]) {
    int total = 0;
    for (int i = 0; i < 8; i++)
        total += popcount32(s1[i] ^ s2[i]);
    return total;
}

// ═══════════════════════════════════════════════════════════
// Experiment 1: Single-bit deltas in each W word
// For each of 512 single-bit positions, measure propagation
// ═══════════════════════════════════════════════════════════

__global__
void scan_single_bit_deltas(
    const uint32_t* base_msg,  // [16] base message
    int* results,              // [512 * 64] = bits_diff per (bit_pos, round)
    int max_rounds)
{
    int bit_pos = blockIdx.x * blockDim.x + threadIdx.x;
    if (bit_pos >= 512) return;

    int word = bit_pos / 32;
    int bit = bit_pos % 32;

    // Original message
    uint32_t W1[16], W2[16];
    for (int i = 0; i < 16; i++) {
        W1[i] = base_msg[i];
        W2[i] = base_msg[i];
    }

    // Flip one bit
    W2[word] ^= (1u << bit);

    // Measure diff at each round
    for (int r = 1; r <= max_rounds; r++) {
        uint32_t s1[8], s2[8];
        sha256_rounds(W1, r, s1);
        sha256_rounds(W2, r, s2);
        results[bit_pos * max_rounds + (r-1)] = state_diff_bits(s1, s2);
    }
}

// ═══════════════════════════════════════════════════════════
// Experiment 2: Search for low-diff pairs at round N
// Try random messages, measure diff after N rounds with given delta
// ═══════════════════════════════════════════════════════════

__global__
void search_low_diff_pairs(
    int target_round,
    int delta_word,           // which word to perturb
    uint32_t delta_value,     // XOR delta
    uint64_t seed,
    int* best_diff,           // [1] best (minimum) diff found
    uint32_t* best_msg,       // [16] message that gave best diff
    int n_trials)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n_trials) return;

    // Generate random message from seed + tid
    uint32_t W1[16], W2[16];
    uint64_t state = seed + tid * 6364136223846793005ULL + 1;
    for (int i = 0; i < 16; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        W1[i] = (uint32_t)(state >> 32);
        W2[i] = W1[i];
    }

    // Apply delta
    W2[delta_word] ^= delta_value;

    // Compute rounds
    uint32_t s1[8], s2[8];
    sha256_rounds(W1, target_round, s1);
    sha256_rounds(W2, target_round, s2);

    int diff = state_diff_bits(s1, s2);

    // Update best (atomic min)
    int old = atomicMin(best_diff, diff);
    if (diff < old) {
        // Store the message (race condition OK — we just want any good one)
        for (int i = 0; i < 16; i++)
            best_msg[i] = W1[i];
    }
}

// ═══════════════════════════════════════════════════════════
// Experiment 3: Multi-word differential cascade
// Apply carefully chosen deltas to multiple W words
// to cancel propagation through rounds
// ═══════════════════════════════════════════════════════════

__global__
void cascade_search(
    int target_round,
    uint64_t seed,
    int* best_diff,
    uint32_t* best_delta,     // [16] best delta pattern
    uint32_t* best_msg,       // [16] best message
    int n_trials)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n_trials) return;

    // Random message
    uint32_t W1[16], W2[16];
    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;
    for (int i = 0; i < 16; i++) {
        rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
        W1[i] = (uint32_t)(rng >> 32);
        W2[i] = W1[i];
    }

    // Generate random low-weight delta pattern
    // Each word gets a random delta with 1-3 bits set
    uint32_t delta[16];
    for (int i = 0; i < 16; i++) {
        rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
        uint32_t r = (uint32_t)(rng >> 32);

        // 50% chance of delta in this word
        if (r & 1) {
            // 1-2 bit delta
            int b1 = (r >> 1) & 31;
            int b2 = (r >> 6) & 31;
            delta[i] = (1u << b1);
            if ((r >> 11) & 1) delta[i] |= (1u << b2);
        } else {
            delta[i] = 0;
        }

        W2[i] ^= delta[i];
    }

    // Check if any delta at all
    uint32_t any = 0;
    for (int i = 0; i < 16; i++) any |= delta[i];
    if (!any) return;

    // Measure diff
    uint32_t s1[8], s2[8];
    sha256_rounds(W1, target_round, s1);
    sha256_rounds(W2, target_round, s2);

    int diff = state_diff_bits(s1, s2);

    int old = atomicMin(best_diff, diff);
    if (diff < old) {
        for (int i = 0; i < 16; i++) {
            best_delta[i] = delta[i];
            best_msg[i] = W1[i];
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Host
// ═══════════════════════════════════════════════════════════

int main() {
    printf("SHA-256 Round-by-Round Differential Analysis\n");
    printf("════════════════════════════════════════════\n\n");

    int max_rounds = 24;

    // ── Experiment 1: Single-bit propagation ──
    printf("=== Experiment 1: Single-bit delta propagation ===\n\n");

    uint32_t base_msg[16] = {0};
    // Use a specific message (can change later)
    for (int i = 0; i < 16; i++) base_msg[i] = (uint32_t)i * 0x11111111u;

    uint32_t* d_msg;
    int* d_results;
    cudaMalloc(&d_msg, 64);
    cudaMalloc(&d_results, 512 * max_rounds * sizeof(int));
    cudaMemcpy(d_msg, base_msg, 64, cudaMemcpyHostToDevice);

    scan_single_bit_deltas<<<4, 128>>>(d_msg, d_results, max_rounds);
    cudaDeviceSynchronize();

    int* h_results = (int*)malloc(512 * max_rounds * sizeof(int));
    cudaMemcpy(h_results, d_results, 512 * max_rounds * sizeof(int), cudaMemcpyDeviceToHost);

    // Find best single-bit delta for each round
    printf("Round | Best single-bit delta | Bits changed | Position\n");
    printf("------+-----------------------+--------------+---------\n");
    for (int r = 0; r < max_rounds; r++) {
        int best = 256;
        int best_pos = 0;
        for (int b = 0; b < 512; b++) {
            int d = h_results[b * max_rounds + r];
            if (d < best) { best = d; best_pos = b; }
        }
        printf("  %2d  | W[%d] bit %2d           |     %3d      | %d\n",
               r+1, best_pos/32, best_pos%32, best, best_pos);
    }

    // ── Experiment 2: Search for low-diff pairs ──
    printf("\n=== Experiment 2: Random search for low-diff pairs ===\n\n");

    int* d_best_diff;
    uint32_t* d_best_msg;
    cudaMalloc(&d_best_diff, sizeof(int));
    cudaMalloc(&d_best_msg, 64);

    int n_trials = 1 << 22; // 4M trials

    for (int target_round = 10; target_round <= max_rounds; target_round += 2) {
        // Try different single-word deltas
        int global_best = 256;
        int best_word = 0;
        uint32_t best_delta = 0;

        for (int dw = 0; dw < 16; dw++) {
            // Try 1-bit delta in word dw
            for (int db = 0; db < 32; db++) {
                int h_best = 256;
                cudaMemcpy(d_best_diff, &h_best, sizeof(int), cudaMemcpyHostToDevice);

                search_low_diff_pairs<<<n_trials/256, 256>>>(
                    target_round, dw, 1u << db,
                    42 + dw * 32 + db,
                    d_best_diff, d_best_msg, n_trials);
                cudaDeviceSynchronize();

                cudaMemcpy(&h_best, d_best_diff, sizeof(int), cudaMemcpyDeviceToHost);
                if (h_best < global_best) {
                    global_best = h_best;
                    best_word = dw;
                    best_delta = 1u << db;
                }
            }
        }
        printf("Round %2d: best diff = %3d bits (delta W[%d] ^= 0x%08x)\n",
               target_round, global_best, best_word, best_delta);
    }

    // ── Experiment 3: Multi-word cascade search ──
    printf("\n=== Experiment 3: Multi-word cascade search ===\n\n");

    uint32_t* d_best_delta_arr;
    uint32_t* d_best_msg2;
    cudaMalloc(&d_best_delta_arr, 64);
    cudaMalloc(&d_best_msg2, 64);

    int cascade_trials = 1 << 24; // 16M trials

    for (int target_round = 10; target_round <= max_rounds; target_round += 2) {
        int h_best = 256;
        cudaMemcpy(d_best_diff, &h_best, sizeof(int), cudaMemcpyHostToDevice);

        cascade_search<<<cascade_trials/256, 256>>>(
            target_round, target_round * 7 + 13,
            d_best_diff, d_best_delta_arr, d_best_msg2, cascade_trials);
        cudaDeviceSynchronize();

        cudaMemcpy(&h_best, d_best_diff, sizeof(int), cudaMemcpyDeviceToHost);

        uint32_t h_delta[16];
        cudaMemcpy(h_delta, d_best_delta_arr, 64, cudaMemcpyDeviceToHost);

        int delta_words = 0;
        int delta_bits = 0;
        for (int i = 0; i < 16; i++) {
            if (h_delta[i]) { delta_words++; delta_bits += popcount32(h_delta[i]); }
        }

        printf("Round %2d: best diff = %3d bits (cascade: %d words, %d delta bits)\n",
               target_round, h_best, delta_words, delta_bits);

        if (h_best < 20) {
            printf("  Delta pattern:");
            for (int i = 0; i < 16; i++)
                if (h_delta[i]) printf(" W[%d]=0x%08x", i, h_delta[i]);
            printf("\n");
        }
    }

    printf("\n=== Summary ===\n");
    printf("SHA-256 has 64 rounds.\n");
    printf("Goal: find deltas where output diff < 128 bits at round 20+\n");
    printf("This would indicate structural weakness exploitable for preimage.\n");

    cudaFree(d_msg); cudaFree(d_results);
    cudaFree(d_best_diff); cudaFree(d_best_msg);
    cudaFree(d_best_delta_arr); cudaFree(d_best_msg2);
    free(h_results);
    return 0;
}

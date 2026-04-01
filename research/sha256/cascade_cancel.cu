/*
 * SHA-256 Cascade Cancellation — Zero all W[16..23] deltas
 * =========================================================
 *
 * From break16: we can cancel W[16]=0, but W[17],W[19],W[21],W[23] leak.
 *
 * Message schedule dependencies:
 *   W[16] = sig1(W[14]) + W[ 9] + sig0(W[ 1]) + W[ 0]
 *   W[17] = sig1(W[15]) + W[10] + sig0(W[ 2]) + W[ 1]
 *   W[18] = sig1(W[16]) + W[11] + sig0(W[ 3]) + W[ 2]
 *   W[19] = sig1(W[17]) + W[12] + sig0(W[ 4]) + W[ 3]
 *   W[20] = sig1(W[18]) + W[13] + sig0(W[ 5]) + W[ 4]
 *   W[21] = sig1(W[19]) + W[14] + sig0(W[ 6]) + W[ 5]
 *   W[22] = sig1(W[20]) + W[15] + sig0(W[ 7]) + W[ 6]
 *   W[23] = sig1(W[21]) + W[ 0] + sig0(W[ 8]) + W[ 7]
 *
 * To cancel W[16]: constrain d0 from d1, d14
 * To cancel W[17]: constrain d1 from d2, d10, d15  (but d1 already set!)
 * → CONFLICT. Must solve simultaneously.
 *
 * Approach: solve the system iteratively
 *   1. Fix d14, d15 (small, 1-bit each)
 *   2. Compute required d1 to cancel W[17]
 *   3. Compute required d0 to cancel W[16] (using d1 from step 2)
 *   4. Compute required d2 to cancel W[18] (using d16 delta from remaining terms)
 *   5. Continue chain...
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,1835,20091 cascade_cancel.cu -o cascade
 */

#include <cstdint>
#include <cstdio>
#include <cstring>

__constant__ static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,
    0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(e,f,g) (((e)&(f))^((~(e))&(g)))
#define MAJ(a,b,c) (((a)&(b))^((a)&(c))^((b)&(c)))
#define S0(a) (ROTR(a,2)^ROTR(a,13)^ROTR(a,22))
#define S1(e) (ROTR(e,6)^ROTR(e,11)^ROTR(e,25))
#define sig0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define sig1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

__device__ __host__
int popcnt(uint32_t x) {
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    return (((x + (x >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

// Compute sig0 delta: sig0(x^d) - sig0(x)
__device__ __host__
uint32_t sig0_delta(uint32_t x, uint32_t d) {
    return sig0(x ^ d) - sig0(x);
}

// Compute sig1 delta: sig1(x^d) - sig1(x)
__device__ __host__
uint32_t sig1_delta(uint32_t x, uint32_t d) {
    return sig1(x ^ d) - sig1(x);
}

__device__ __host__
void sha256_n_rounds(const uint32_t W[16], int n, uint32_t out[8]) {
    out[0]=0x6a09e667;out[1]=0xbb67ae85;out[2]=0x3c6ef372;out[3]=0xa54ff53a;
    out[4]=0x510e527f;out[5]=0x9b05688c;out[6]=0x1f83d9ab;out[7]=0x5be0cd19;
    uint32_t w[64];
    for(int i=0;i<16;i++) w[i]=W[i];
    for(int i=16;i<64;i++) w[i]=sig1(w[i-2])+w[i-7]+sig0(w[i-15])+w[i-16];
    uint32_t a=out[0],b=out[1],c=out[2],d=out[3],e=out[4],f=out[5],g=out[6],h=out[7];
    for(int i=0;i<n&&i<64;i++){
        uint32_t t1=h+S1(e)+CH(e,f,g)+K[i]+w[i];
        uint32_t t2=S0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    out[0]=a;out[1]=b;out[2]=c;out[3]=d;out[4]=e;out[5]=f;out[6]=g;out[7]=h;
}

__device__ __host__
int state_diff(const uint32_t a[8], const uint32_t b[8]) {
    int t=0; for(int i=0;i<8;i++) t+=popcnt(a[i]^b[i]); return t;
}

// ═══════════════════════════════════════════════════
// Algebraic cascade solver
// Cancel W[16..16+N] simultaneously for given message
// ═══════════════════════════════════════════════════

// For a given message W and free parameters (bit positions for d14, d15),
// solve the cascade to cancel as many expanded W as possible
__device__ __host__
int solve_cascade(const uint32_t W[16], int bit14, int bit15,
                  uint32_t delta_out[16], int max_cancel) {

    uint32_t d[16] = {0};

    // Free parameters: single bit in W[14] and W[15]
    d[14] = 1u << bit14;
    d[15] = 1u << bit15;

    // === Cancel W[17] first (simpler, determines d1) ===
    // W[17] = sig1(W[15]) + W[10] + sig0(W[2]) + W[1]
    // delta_W[17] = sig1_delta(W[15],d15) + d10 + sig0_delta(W[2],d2) + d1
    // With d10=0, d2=0: d1 = -sig1_delta(W[15],d15)
    d[1] = (uint32_t)(-(int32_t)sig1_delta(W[15], d[15]));

    // === Cancel W[16] (determines d0) ===
    // W[16] = sig1(W[14]) + W[9] + sig0(W[1]) + W[0]
    // delta_W[16] = sig1_delta(W[14],d14) + d9 + sig0_delta(W[1],d1) + d0
    // With d9=0: d0 = -(sig1_delta(W[14],d14) + sig0_delta(W[1],d1))
    d[0] = (uint32_t)(-(int32_t)(sig1_delta(W[14],d[14]) + sig0_delta(W[1],d[1])));

    if (max_cancel <= 2) goto done;

    // === Cancel W[18] (determines d2) ===
    // W[18] = sig1(W[16]) + W[11] + sig0(W[3]) + W[2]
    // Since we cancelled W[16] (delta_W[16]=0), sig1_delta(W16, 0) = 0
    // But we need actual W[16] values...
    // Actually: W[16]' has delta=0 by construction, so sig1(W16') = sig1(W16)
    // delta_W[18] = sig1_delta(W[16],delta_W16) + d11 + sig0_delta(W[3],d3) + d2
    // delta_W16 = 0, so sig1_delta = 0
    // d2 = -(d11 + sig0_delta(W[3],d3))
    // With d11=0, d3=0: d2 = 0 (already cancelled!)
    // Wait — but W[16] is computed FROM W[14], W[9], W[1], W[0] which have deltas
    // Need to recompute actual delta_W[16]
    {
        uint32_t w1_16 = sig1(W[14]) + W[9] + sig0(W[1]) + W[0];
        uint32_t w2_16 = sig1(W[14]^d[14]) + W[9] + sig0(W[1]^d[1]) + (W[0]^d[0]);
        uint32_t dw16 = w2_16 - w1_16; // Should be 0 if cancellation worked

        // Now W[18]:
        // delta_W[18] = sig1_delta(w1_16, dw16) + d11 + sig0_delta(W[3],d3) + d2
        // With d11=0, d3=0: d2 = -sig1_delta(w1_16, dw16)
        d[2] = (uint32_t)(-(int32_t)sig1_delta(w1_16, dw16));
    }

    if (max_cancel <= 3) goto done;

    // === Cancel W[19] (determines d3) ===
    // W[19] = sig1(W[17]) + W[12] + sig0(W[4]) + W[3]
    {
        uint32_t w1_17 = sig1(W[15]) + W[10] + sig0(W[2]) + W[1];
        uint32_t w2_17 = sig1(W[15]^d[15]) + W[10] + sig0(W[2]^d[2]) + (W[1]^d[1]);
        uint32_t dw17 = w2_17 - w1_17;

        // d3 = -(sig1_delta(w1_17, dw17) + d12 + sig0_delta(W[4],d4))
        // With d12=0, d4=0:
        d[3] = (uint32_t)(-(int32_t)sig1_delta(w1_17, dw17));
    }

    if (max_cancel <= 4) goto done;

    // === Cancel W[20] (determines d4) ===
    // W[20] = sig1(W[18]) + W[13] + sig0(W[5]) + W[4]
    {
        uint32_t w1[64], w2[64];
        for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
        for(int i=16;i<21;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }
        uint32_t dw18 = w2[18] - w1[18];
        // d4 = -(sig1_delta(w1[18], dw18) + d13 + sig0_delta(W[5],d5))
        d[4] = (uint32_t)(-(int32_t)(sig1_delta(w1[18], dw18)));
    }

    if (max_cancel <= 5) goto done;

    // === Cancel W[21] (determines d5) ===
    {
        uint32_t w1[64], w2[64];
        for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
        for(int i=16;i<22;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }
        uint32_t dw19 = w2[19] - w1[19];
        // W[21] = sig1(W[19]) + W[14] + sig0(W[6]) + W[5]
        // delta = sig1_delta + d14 + sig0_delta(W6,d6) + d5
        // d5 = -(sig1_delta(w1[19],dw19) + d14)  (d6=0)
        d[5] = (uint32_t)(-(int32_t)(sig1_delta(w1[19], dw19) + d[14]));
    }

    if (max_cancel <= 6) goto done;

    // === Cancel W[22] (determines d6) ===
    {
        uint32_t w1[64], w2[64];
        for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
        for(int i=16;i<23;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }
        uint32_t dw20 = w2[20] - w1[20];
        // W[22] = sig1(W[20]) + W[15] + sig0(W[7]) + W[6]
        d[6] = (uint32_t)(-(int32_t)(sig1_delta(w1[20], dw20) + d[15]));
    }

    if (max_cancel <= 7) goto done;

    // === Cancel W[23] (determines d7) ===
    {
        uint32_t w1[64], w2[64];
        for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
        for(int i=16;i<24;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }
        uint32_t dw21 = w2[21] - w1[21];
        // W[23] = sig1(W[21]) + W[0] + sig0(W[8]) + W[7]
        // delta = sig1_delta + d0 + sig0_delta(W8,d8) + d7
        // d7 = -(sig1_delta(w1[21],dw21) + d0)  (d8=0)
        d[7] = (uint32_t)(-(int32_t)(sig1_delta(w1[21], dw21) + d[0]));
    }

done:
    for(int i=0;i<16;i++) delta_out[i] = d[i];

    // Verify: compute actual schedule diff
    uint32_t w1[64], w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<24;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }

    int total = 0;
    for(int i=16;i<24;i++) total += popcnt(w1[i]^w2[i]);
    return total;
}

// ═══════════════════════════════════════════════════
// GPU: search over messages and bit positions
// ═══════════════════════════════════════════════════

__global__
void search_cascade(
    uint64_t seed,
    int max_cancel,      // how many W[16..] to cancel (2..8)
    int* best_sched_diff,
    int* best_state_diff,
    uint32_t* best_delta,
    uint32_t* best_msg,
    int* best_round_diffs, // [8] per-round schedule diff for best
    int target_round,      // measure state diff at this round
    int n_trials)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n_trials) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    // Random message
    uint32_t W[16];
    for(int i=0;i<16;i++){
        rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
        W[i] = (uint32_t)(rng >> 32);
    }

    // Random bit positions for free parameters
    rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
    int bit14 = (int)(rng >> 32) & 31;
    int bit15 = (int)((rng >> 16) & 31);

    uint32_t delta[16];
    int sched_diff = solve_cascade(W, bit14, bit15, delta, max_cancel);

    // Compute state diff
    uint32_t W2[16];
    for(int i=0;i<16;i++) W2[i] = W[i] ^ delta[i];

    uint32_t s1[8], s2[8];
    sha256_n_rounds(W, target_round, s1);
    sha256_n_rounds(W2, target_round, s2);
    int sd = state_diff(s1, s2);

    // Score: prioritize low schedule diff, then low state diff
    int score = sched_diff * 1000 + sd;

    int old_sched = atomicMin(best_sched_diff, sched_diff);
    if (sched_diff < old_sched || (sched_diff == old_sched && sd < *best_state_diff)) {
        *best_state_diff = sd;
        for(int i=0;i<16;i++){
            best_delta[i] = delta[i];
            best_msg[i] = W[i];
        }
        // Per-round schedule diffs
        uint32_t w1[64], w2[64];
        for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W2[i];}
        for(int i=16;i<24;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }
        for(int i=0;i<8;i++) best_round_diffs[i] = popcnt(w1[i+16]^w2[i+16]);
    }
}

int main() {
    printf("SHA-256 Cascade Cancellation\n");
    printf("════════════════════════════\n");
    printf("Goal: zero ALL W[16..23] deltas algebraically\n\n");

    int *d_sched, *d_state, *d_rdiffs;
    uint32_t *d_delta, *d_msg;
    cudaMalloc(&d_sched, 4); cudaMalloc(&d_state, 4);
    cudaMalloc(&d_rdiffs, 32);
    cudaMalloc(&d_delta, 64); cudaMalloc(&d_msg, 64);

    int trials = 1 << 24; // 16M per pass

    for (int cancel = 2; cancel <= 8; cancel++) {
        printf("=== Cancelling W[16..%d] (%d words) ===\n", 15+cancel, cancel);

        int h_sched = 9999, h_state = 256;
        cudaMemcpy(d_sched, &h_sched, 4, cudaMemcpyHostToDevice);
        cudaMemcpy(d_state, &h_state, 4, cudaMemcpyHostToDevice);

        // Search with different target rounds
        for (int target = 16+cancel; target <= 24; target += 2) {
            for (int pass = 0; pass < 4; pass++) {
                search_cascade<<<trials/256, 256>>>(
                    pass * 777777ULL + cancel * 13 + target * 37,
                    cancel, d_sched, d_state, d_delta, d_msg, d_rdiffs,
                    target, trials);
                cudaDeviceSynchronize();
            }
        }

        cudaMemcpy(&h_sched, d_sched, 4, cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_state, d_state, 4, cudaMemcpyDeviceToHost);

        uint32_t h_delta[16], h_msg[16];
        int h_rdiffs[8];
        cudaMemcpy(h_delta, d_delta, 64, cudaMemcpyDeviceToHost);
        cudaMemcpy(h_msg, d_msg, 64, cudaMemcpyDeviceToHost);
        cudaMemcpy(h_rdiffs, d_rdiffs, 32, cudaMemcpyDeviceToHost);

        printf("  Schedule diff total: %d bits\n", h_sched);
        printf("  State diff: %d bits\n", h_state);
        printf("  Per-word schedule delta: ");
        for(int i=0;i<8;i++) printf("W[%d]=%d ", i+16, h_rdiffs[i]);
        printf("\n");

        int dbits=0, dwords=0;
        for(int i=0;i<16;i++) if(h_delta[i]){dwords++;dbits+=popcnt(h_delta[i]);}
        printf("  Input: %d words modified, %d delta bits\n", dwords, dbits);

        printf("  Delta:");
        for(int i=0;i<16;i++) if(h_delta[i]) printf(" W[%d]=0x%08x(%d)", i, h_delta[i], popcnt(h_delta[i]));
        printf("\n");

        // Verify on host
        printf("  Verify schedule:\n");
        {
            uint32_t w1[64],w2[64];
            for(int i=0;i<16;i++){w1[i]=h_msg[i];w2[i]=h_msg[i]^h_delta[i];}
            for(int i=16;i<32;i++){
                w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
                w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
            }
            for(int i=16;i<32;i++){
                uint32_t xd=w1[i]^w2[i];
                if(popcnt(xd)>0 || i<24)
                    printf("    W[%d]: delta=%08x (%d bits)%s\n", i, xd, popcnt(xd),
                           popcnt(xd)==0?" ✓":"");
            }
        }
        printf("\n");
    }

    printf("=== Summary ===\n");
    printf("Each cancelled W[i] uses one degree of freedom (d[i-16]).\n");
    printf("With 8 cancellations: d[0..7] determined, d[14],d[15] free.\n");
    printf("Remaining delta in W[24..31] determines state diff at round 24+.\n");
    printf("If schedule stays clean past round 24 → differential through 30+ rounds!\n");

    cudaFree(d_sched);cudaFree(d_state);cudaFree(d_rdiffs);
    cudaFree(d_delta);cudaFree(d_msg);
    return 0;
}

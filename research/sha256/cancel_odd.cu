/*
 * SHA-256 Cancel Odd W — Target W[21],W[23],W[25],W[27]
 * ======================================================
 *
 * From nonlinear_push:
 *   Even W[16,18,20,22,24,26] = 0 (algebraic + d[6])
 *   Odd W[21,23,25,27] leak 5-17 bits
 *
 * Observation: adding d[6] creates alternating pattern.
 * Hypothesis: adding another delta word (d[5]? d[7]? d[9]?)
 * might cancel the odd terms.
 *
 * Schedule dependencies for odd terms:
 *   W[21] = sig1(W[19]) + W[14] + sig0(W[6]) + W[5]
 *   W[23] = sig1(W[21]) + W[16] + sig0(W[8]) + W[7]
 *   W[25] = sig1(W[23]) + W[18] + sig0(W[10]) + W[9]
 *   W[27] = sig1(W[25]) + W[20] + sig0(W[12]) + W[11]
 *
 * If we can zero W[19] (which we do — it's even-indexed in expanded):
 *   W[21] = sig1(0_delta) + d14 + sig0(W[6]^d6) - sig0(W[6]) + d5
 *   → d5 can cancel if sig1 term is zero (W[19] delta = 0)
 *   → d5 = -(d14 + sig0_delta(W[6],d6))
 *
 * This is message-dependent due to sig0(W[6]^d6).
 *
 * Strategy:
 *   Phase 1: algebraic cancel W[16..20] (d[0],d[1],d[14],d[15])
 *   Phase 2: set d[6] for W[22]=0 pattern
 *   Phase 3: compute d[5] to cancel W[21]
 *   Phase 4: compute d[7] to cancel W[23]
 *   Phase 5: compute d[9] to cancel W[25]
 *   Phase 6: compute d[11] to cancel W[27]
 *   GPU search over messages + bit positions for best results
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,1835,20091 cancel_odd.cu -o cancel_odd
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
int popcnt(uint32_t x){x=x-((x>>1)&0x55555555);x=(x&0x33333333)+((x>>2)&0x33333333);return(((x+(x>>4))&0x0F0F0F0F)*0x01010101)>>24;}

__device__ __host__
void sha256_n(const uint32_t W[16],int n,uint32_t out[8]){
    out[0]=0x6a09e667;out[1]=0xbb67ae85;out[2]=0x3c6ef372;out[3]=0xa54ff53a;
    out[4]=0x510e527f;out[5]=0x9b05688c;out[6]=0x1f83d9ab;out[7]=0x5be0cd19;
    uint32_t w[64];for(int i=0;i<16;i++)w[i]=W[i];
    for(int i=16;i<64;i++)w[i]=sig1(w[i-2])+w[i-7]+sig0(w[i-15])+w[i-16];
    uint32_t a=out[0],b=out[1],c=out[2],d=out[3],e=out[4],f=out[5],g=out[6],h=out[7];
    for(int i=0;i<n&&i<64;i++){
        uint32_t t1=h+S1(e)+CH(e,f,g)+K[i]+w[i];uint32_t t2=S0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
    out[0]=a;out[1]=b;out[2]=c;out[3]=d;out[4]=e;out[5]=f;out[6]=g;out[7]=h;
}

__device__ __host__
int sdiff(const uint32_t a[8],const uint32_t b[8]){
    int t=0;for(int i=0;i<8;i++)t+=popcnt(a[i]^b[i]);return t;}

// Compute full expanded schedule and return per-word diffs
__device__ __host__
void full_schedule_diff(const uint32_t W[16], const uint32_t delta[16],
                        int diffs[48], int n_expanded) {
    uint32_t w1[64], w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^delta[i];}
    for(int i=16;i<16+n_expanded;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    for(int i=0;i<n_expanded;i++)
        diffs[i] = popcnt(w1[i+16]^w2[i+16]);
}

// Main search kernel: try to cancel BOTH even AND odd W
// by computing d[0..7] algebraically from d[14],d[15],d[6]
// and adding d[5],d[7],d[9],d[11] for odd cancellation
__global__
void search_full_cancel(
    uint64_t seed,
    int target_round,
    int* best_clean,       // most zero-delta schedule words
    int* best_state_diff,
    uint32_t* best_delta,
    uint32_t* best_msg,
    int n_trials)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_trials) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    // Random message
    uint32_t W[16];
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
    }

    // Free parameters
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int b14 = (int)(rng>>32) & 31;
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int b15 = (int)(rng>>32) & 31;
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int b6 = (int)(rng>>32) & 31;

    uint32_t delta[16] = {0};
    delta[14] = 1u << b14;
    delta[15] = 1u << b15;
    delta[6] = 1u << b6;

    // ── Step 1: Cancel W[17] → solve d[1] ──
    // W[17] = sig1(W[15]) + W[10] + sig0(W[2]) + W[1]
    // d1 = -(sig1(W15^d15) - sig1(W15))
    delta[1] = (uint32_t)(-(int32_t)(sig1(W[15]^delta[15]) - sig1(W[15])));

    // ── Step 2: Cancel W[16] → solve d[0] ──
    // W[16] = sig1(W[14]) + W[9] + sig0(W[1]) + W[0]
    // d0 = -(sig1_delta(W14,d14) + sig0_delta(W1,d1))
    delta[0] = (uint32_t)(-(int32_t)(
        sig1(W[14]^delta[14]) - sig1(W[14]) +
        sig0((W[1]^delta[1])) - sig0(W[1])
    ));

    // ── Step 3: Cancel W[21] → solve d[5] ──
    // W[21] = sig1(W[19]) + W[14] + sig0(W[6]) + W[5]
    // First compute w1[16..19] and w2[16..19]
    uint32_t w1[32], w2[32];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^delta[i];}
    for(int i=16;i<20;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    // delta_W[19] = w2[19] - w1[19]
    uint32_t dw19 = w2[19] - w1[19];
    // delta_W[21] = sig1_delta(w1[19],dw19) + d14 + sig0_delta(W6,d6) + d5
    // d5 = -(sig1_delta + d14 + sig0_delta)
    delta[5] = (uint32_t)(-(int32_t)(
        sig1(w1[19] + dw19) - sig1(w1[19]) +
        delta[14] +
        sig0(W[6]^delta[6]) - sig0(W[6])
    ));

    // Refresh w2 with d[5]
    w2[5] = W[5] ^ delta[5];
    // Recompute w2[16..21]
    for(int i=16;i<22;i++)
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    for(int i=16;i<22;i++)
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];

    // ── Step 4: Cancel W[23] → solve d[7] ──
    // W[23] = sig1(W[21]) + W[16] + sig0(W[8]) + W[7]
    uint32_t dw21 = w2[21] - w1[21];
    // delta_W16 should be ≈ 0 if cancellation worked
    uint32_t dw16 = w2[16] - w1[16];
    delta[7] = (uint32_t)(-(int32_t)(
        sig1(w1[21] + dw21) - sig1(w1[21]) +
        dw16 +
        sig0(W[8]) - sig0(W[8])  // d8 = 0
    ));

    // Refresh
    w2[7] = W[7] ^ delta[7];
    for(int i=16;i<24;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }

    // ── Step 5: Cancel W[25] → solve d[9] ──
    // W[25] = sig1(W[23]) + W[18] + sig0(W[10]) + W[9]
    uint32_t dw23 = w2[23] - w1[23];
    uint32_t dw18 = w2[18] - w1[18];
    delta[9] = (uint32_t)(-(int32_t)(
        sig1(w1[23] + dw23) - sig1(w1[23]) +
        dw18
    ));

    w2[9] = W[9] ^ delta[9];
    for(int i=16;i<26;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }

    // ── Step 6: Cancel W[27] → solve d[11] ──
    // W[27] = sig1(W[25]) + W[20] + sig0(W[12]) + W[11]
    uint32_t dw25 = w2[25] - w1[25];
    uint32_t dw20 = w2[20] - w1[20];
    delta[11] = (uint32_t)(-(int32_t)(
        sig1(w1[25] + dw25) - sig1(w1[25]) +
        dw20
    ));

    w2[11] = W[11] ^ delta[11];

    // ── Compute final schedule diffs ──
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^delta[i];}
    int n_exp = (target_round > 16) ? (target_round - 16) : 0;
    if(n_exp > 32) n_exp = 32;
    for(int i=16;i<16+n_exp;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }

    int clean = 0;
    for(int i=16;i<16+n_exp;i++)
        if(w1[i] == w2[i]) clean++;

    // State diff
    uint32_t s1[8],s2[8];
    uint32_t WW2[16];
    for(int i=0;i<16;i++) WW2[i] = W[i] ^ delta[i];
    sha256_n(W,target_round,s1);
    sha256_n(WW2,target_round,s2);
    int sd = sdiff(s1,s2);

    int old = atomicMax(best_clean, clean);
    if(clean > old || (clean == old && sd < *best_state_diff)) {
        *best_state_diff = sd;
        for(int i=0;i<16;i++){best_delta[i]=delta[i];best_msg[i]=W[i];}
    }
}

int main() {
    printf("SHA-256 Cancel Odd W — Push to 28+ rounds\n");
    printf("══════════════════════════════════════════\n");
    printf("Strategy: d[14,15] + d[0,1] (even) + d[6] (even) + d[5,7,9,11] (odd)\n\n");

    int *d_clean, *d_state;
    uint32_t *d_delta, *d_msg;
    cudaMalloc(&d_clean,4);cudaMalloc(&d_state,4);
    cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);

    int trials = 1 << 24;

    for(int target = 24; target <= 36; target += 2) {
        int h_clean=0, h_state=256;
        cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_state,&h_state,4,cudaMemcpyHostToDevice);

        for(int pass=0; pass<16; pass++) {
            search_full_cancel<<<trials/256,256>>>(
                pass*31337ULL+target*41,
                target, d_clean, d_state, d_delta, d_msg, trials);
            cudaDeviceSynchronize();
        }

        cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_state,d_state,4,cudaMemcpyDeviceToHost);
        uint32_t h_delta[16], h_msg[16];
        cudaMemcpy(h_delta,d_delta,64,cudaMemcpyDeviceToHost);
        cudaMemcpy(h_msg,d_msg,64,cudaMemcpyDeviceToHost);

        int dbits=0,dwords=0;
        for(int i=0;i<16;i++)if(h_delta[i]){dwords++;dbits+=popcnt(h_delta[i]);}

        printf("Round %2d: %2d clean schedule | state_diff = %3d | %d words, %d delta bits\n",
               target, h_clean, h_state, dwords, dbits);

        // Show schedule detail
        uint32_t w1[48],w2[48];
        for(int i=0;i<16;i++){w1[i]=h_msg[i];w2[i]=h_msg[i]^h_delta[i];}
        int n_exp = target - 16; if(n_exp>32) n_exp=32;
        for(int i=16;i<16+n_exp;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }
        printf("  Sched:");
        for(int i=16;i<16+n_exp;i++){
            int b=popcnt(w1[i]^w2[i]);
            if(b==0) printf(" [%d]=✓",i);
            else printf(" [%d]=%d",i,b);
        }
        printf("\n");

        if(h_clean >= 10) {
            printf("  *** Delta:");
            for(int i=0;i<16;i++)if(h_delta[i])printf(" W[%d]=0x%08x",i,h_delta[i]);
            printf("\n");
        }
        printf("\n");
    }

    cudaFree(d_clean);cudaFree(d_state);cudaFree(d_delta);cudaFree(d_msg);
    return 0;
}

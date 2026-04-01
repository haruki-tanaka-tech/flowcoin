/*
 * SHA-256 Unified Cancellation — Combine even + odd strategies
 * =============================================================
 *
 * Previous results:
 *   Even-only (d[0,1,6,14,15]):  W[16,18,20,22,24,26] = 0 (even clean)
 *   Odd-only  (d[0,1,5,7,9,11,14,15]): W[16,17,19,21,23] = 0 (odd clean)
 *
 * Goal: use ALL delta words d[0..15] to cancel as many W[16..N] as possible.
 *
 * Approach: massive GPU search over delta patterns
 *   - Fix d[14], d[15] (1 bit each) — 32x32 = 1024 combinations
 *   - For each combo, try random d[2..13] with low hamming weight
 *   - Algebraically solve d[0], d[1] to cancel W[16], W[17]
 *   - Measure total clean W[16..35] words
 *   - Keep best
 *
 * This exhausts the algebraic degrees of freedom and relies on
 * GPU brute force for the nonlinear parts.
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,1835,20091 unified_cancel.cu -o unified
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

// Core: given W[16] and delta[0..15], algebraically solve d[0] and d[1]
// to cancel W[16] and W[17], then evaluate schedule
__device__
void solve_and_eval(const uint32_t W[16], uint32_t delta[16],
                    int target_round, int* clean_out, int* state_diff_out,
                    int* sched_bits_out) {
    // Cancel W[17]: d1 absorbs sig1_delta(W15,d15) + sig0_delta(W2,d2) + d10
    // W[17] = sig1(W[15]) + W[10] + sig0(W[2]) + W[1]
    uint32_t sig1_d15 = sig1(W[15]^delta[15]) - sig1(W[15]);
    uint32_t sig0_d2 = sig0(W[2]^delta[2]) - sig0(W[2]);
    delta[1] = (uint32_t)(-(int32_t)(sig1_d15 + delta[10] + sig0_d2));

    // Cancel W[16]: d0 absorbs sig1_delta(W14,d14) + sig0_delta(W1,d1) + d9
    // W[16] = sig1(W[14]) + W[9] + sig0(W[1]) + W[0]
    uint32_t sig1_d14 = sig1(W[14]^delta[14]) - sig1(W[14]);
    uint32_t sig0_d1 = sig0((W[1]^delta[1])) - sig0(W[1]);
    delta[0] = (uint32_t)(-(int32_t)(sig1_d14 + delta[9] + sig0_d1));

    // Compute full schedule
    uint32_t w1[48], w2[48];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^delta[i];}
    int n_exp = target_round - 16;
    if(n_exp > 32) n_exp = 32;
    if(n_exp < 0) n_exp = 0;
    for(int i=16;i<16+n_exp;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }

    int clean = 0;
    int total_bits = 0;
    for(int i=16;i<16+n_exp;i++){
        int b = popcnt(w1[i]^w2[i]);
        if(b==0) clean++;
        total_bits += b;
    }

    // State diff
    uint32_t s1[8],s2[8];
    uint32_t WW[16];
    for(int i=0;i<16;i++) WW[i]=W[i]^delta[i];
    sha256_n(W,target_round,s1);
    sha256_n(WW,target_round,s2);

    *clean_out = clean;
    *state_diff_out = sdiff(s1,s2);
    *sched_bits_out = total_bits;
}

// Main search: random delta in d[2..13] + algebraic d[0,1]
__global__
void unified_search(
    uint64_t seed,
    int target_round,
    int* best_clean,
    int* best_state,
    int* best_sched_bits,
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

    uint32_t delta[16] = {0};

    // Free params: d[14], d[15] — 1 bit each
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    delta[14] = 1u << ((int)(rng>>32) & 31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    delta[15] = 1u << ((int)(rng>>32) & 31);

    // Random low-weight deltas in d[2..13]
    // Strategy: pick 2-6 of {2,3,4,5,6,7,8,9,10,11,12,13} and set 1-bit delta
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int n_extra = 2 + ((int)(rng>>32) % 5); // 2-6 words

    for(int f=0;f<n_extra;f++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        int word = 2 + ((int)(rng>>32) % 12); // d[2..13]
        int bit = (int)((rng>>16) & 31);
        delta[word] ^= (1u << bit);
    }

    // d[0], d[1] solved algebraically
    int clean, sd, sb;
    solve_and_eval(W, delta, target_round, &clean, &sd, &sb);

    int old = atomicMax(best_clean, clean);
    if(clean > old || (clean == old && sb < *best_sched_bits)) {
        *best_state = sd;
        *best_sched_bits = sb;
        for(int i=0;i<16;i++){best_delta[i]=delta[i];best_msg[i]=W[i];}
    }
}

// Focused search: fix number of delta words, try all combinations
__global__
void focused_search(
    uint64_t seed,
    int target_round,
    int delta_words_mask,  // bitmask: which of d[2..13] to use
    int* best_clean,
    int* best_state,
    int* best_sched_bits,
    uint32_t* best_delta,
    uint32_t* best_msg,
    int n_trials)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_trials) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    uint32_t W[16];
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
    }

    uint32_t delta[16] = {0};

    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    delta[14] = 1u << ((int)(rng>>32) & 31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    delta[15] = 1u << ((int)(rng>>32) & 31);

    // Set delta for words indicated by mask
    for(int w=2;w<=13;w++){
        if(delta_words_mask & (1<<(w-2))){
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            delta[w] = 1u << ((int)(rng>>32) & 31);
        }
    }

    int clean, sd, sb;
    solve_and_eval(W, delta, target_round, &clean, &sd, &sb);

    int old = atomicMax(best_clean, clean);
    if(clean > old || (clean == old && sb < *best_sched_bits)) {
        *best_state = sd;
        *best_sched_bits = sb;
        for(int i=0;i<16;i++){best_delta[i]=delta[i];best_msg[i]=W[i];}
    }
}

int main() {
    printf("SHA-256 Unified Cancellation — All delta words\n");
    printf("══════════════════════════════════════════════\n");
    printf("d[0,1] algebraic (cancel W[16,17])\n");
    printf("d[2..13] GPU search (cancel W[18..29])\n");
    printf("d[14,15] free params (1 bit each)\n\n");

    int *d_clean, *d_state, *d_sched;
    uint32_t *d_delta, *d_msg;
    cudaMalloc(&d_clean,4);cudaMalloc(&d_state,4);cudaMalloc(&d_sched,4);
    cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);

    int trials = 1 << 24;

    // ── Phase 1: Unified random search ──
    printf("=== Phase 1: Unified random search (256M trials per round) ===\n\n");

    for(int target=24; target<=36; target+=2){
        int h_clean=0,h_state=256,h_sched=9999;
        cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_state,&h_state,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_sched,&h_sched,4,cudaMemcpyHostToDevice);

        for(int pass=0;pass<16;pass++){
            unified_search<<<trials/256,256>>>(
                pass*7919ULL+target*131,target,
                d_clean,d_state,d_sched,d_delta,d_msg,trials);
            cudaDeviceSynchronize();
        }

        cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_state,d_state,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_sched,d_sched,4,cudaMemcpyDeviceToHost);

        uint32_t h_delta[16],h_msg[16];
        cudaMemcpy(h_delta,d_delta,64,cudaMemcpyDeviceToHost);
        cudaMemcpy(h_msg,d_msg,64,cudaMemcpyDeviceToHost);

        int dbits=0,dwords=0;
        for(int i=0;i<16;i++)if(h_delta[i]){dwords++;dbits+=popcnt(h_delta[i]);}

        printf("Round %2d: %2d clean | sched=%3d bits | state=%3d | %d words %d bits\n",
               target,h_clean,h_sched,h_state,dwords,dbits);

        // Show schedule
        uint32_t w1[48],w2[48];
        for(int i=0;i<16;i++){w1[i]=h_msg[i];w2[i]=h_msg[i]^h_delta[i];}
        int ne=target-16;if(ne>32)ne=32;
        for(int i=16;i<16+ne;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }
        printf("  ");
        for(int i=16;i<16+ne;i++){
            int b=popcnt(w1[i]^w2[i]);
            if(b==0) printf("✓");
            else if(b<10) printf("%d",b);
            else printf("X");
        }
        printf("\n");

        if(h_clean >= 8){
            printf("  *** GOOD! Delta:");
            for(int i=0;i<16;i++)if(h_delta[i])printf(" d[%d]=%08x",i,h_delta[i]);
            printf("\n");
        }
    }

    // ── Phase 2: Focused search with specific delta word combos ──
    printf("\n=== Phase 2: Focused search — best delta word combinations ===\n\n");

    // Try specific combinations known to work well
    // From previous: d[6] for evens, d[5,7,9,11] for odds
    int masks[] = {
        (1<<4)|(1<<5),                       // d[6,7]
        (1<<3)|(1<<4)|(1<<5),                // d[5,6,7]
        (1<<3)|(1<<4)|(1<<5)|(1<<7)|(1<<9),  // d[5,6,7,9,11]
        (1<<2)|(1<<3)|(1<<4)|(1<<5)|(1<<6)|(1<<7)|(1<<8)|(1<<9)|(1<<10)|(1<<11), // d[4..13]
        (1<<4)|(1<<7)|(1<<9)|(1<<11),        // d[6,9,11,13]
        0xFFF,                                // all d[2..13]
    };
    const char* mask_names[] = {
        "d[6,7]", "d[5,6,7]", "d[5,6,7,9,11]", "d[4..13]", "d[6,9,11,13]", "all d[2..13]"
    };

    int target = 32;
    for(int m=0;m<6;m++){
        int h_clean=0,h_state=256,h_sched=9999;
        cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_state,&h_state,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_sched,&h_sched,4,cudaMemcpyHostToDevice);

        for(int pass=0;pass<16;pass++){
            focused_search<<<trials/256,256>>>(
                pass*4649ULL+m*997,target,masks[m],
                d_clean,d_state,d_sched,d_delta,d_msg,trials);
            cudaDeviceSynchronize();
        }

        cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_sched,d_sched,4,cudaMemcpyDeviceToHost);

        uint32_t h_delta[16],h_msg[16];
        cudaMemcpy(h_delta,d_delta,64,cudaMemcpyDeviceToHost);
        cudaMemcpy(h_msg,d_msg,64,cudaMemcpyDeviceToHost);

        printf("%-14s: %2d clean | sched=%3d bits | ", mask_names[m], h_clean, h_sched);

        uint32_t w1[48],w2[48];
        for(int i=0;i<16;i++){w1[i]=h_msg[i];w2[i]=h_msg[i]^h_delta[i];}
        for(int i=16;i<48;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }
        for(int i=16;i<32;i++){
            int b=popcnt(w1[i]^w2[i]);
            if(b==0) printf("✓");
            else if(b<10) printf("%d",b);
            else printf("X");
        }
        printf("\n");
    }

    printf("\n=== Summary ===\n");
    printf("✓ = zero delta, digits = bits of diff, X = 10+ bits\n");
    printf("Goal: maximize consecutive ✓ from W[16] onwards\n");
    printf("Each clean W = one more round of SHA-256 with controlled differential\n");

    cudaFree(d_clean);cudaFree(d_state);cudaFree(d_sched);
    cudaFree(d_delta);cudaFree(d_msg);
    return 0;
}

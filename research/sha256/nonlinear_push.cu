/*
 * SHA-256 Nonlinear Push — Rounds 21-32
 * =======================================
 *
 * Known: algebraic cascade gives W[16..20] = 0 (5 clean rounds)
 * Challenge: W[21..23] leak 1,1,2 bits — need nonlinear search
 *
 * Strategy: evolutionary search
 *   - Start from algebraic solution (d[0],d[1],d[14],d[15])
 *   - Add mutations to d[2..13] (currently zero)
 *   - Each mutation: flip 1-3 bits in a random delta word
 *   - Keep mutations that reduce total diff at target round
 *   - Repeat until convergence
 *
 * Key insight: d[2..13] are FREE — they don't affect W[16..17]
 * cancellation (which depends only on d[0],d[1],d[14],d[15]).
 * But they DO affect W[18+] through the cascade.
 * So we can tune d[2..13] to minimize W[18..N] delta
 * without breaking W[16..17] = 0.
 *
 * Actually that's wrong — d[2] affects sig0(W[2]) in W[17].
 * So we need to be more careful.
 *
 * Better approach: full GPU random search over ALL delta patterns
 * with low hamming weight, measuring state diff at round N.
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,1835,20091 nonlinear_push.cu -o nlpush
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

// Compute schedule diff for specific range of W
__device__ __host__
int sched_diff(const uint32_t W1[16], const uint32_t W2[16], int from, int to) {
    uint32_t w1[64], w2[64];
    for(int i=0;i<16;i++){w1[i]=W1[i];w2[i]=W2[i];}
    for(int i=16;i<to;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    int t=0;
    for(int i=from;i<to;i++) t+=popcnt(w1[i]^w2[i]);
    return t;
}

// Count zero-delta schedule words
__device__ __host__
int count_clean_schedule(const uint32_t W1[16], const uint32_t W2[16], int from, int to) {
    uint32_t w1[64], w2[64];
    for(int i=0;i<16;i++){w1[i]=W1[i];w2[i]=W2[i];}
    for(int i=16;i<to;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    int clean=0;
    for(int i=from;i<to;i++) if(w1[i]==w2[i]) clean++;
    return clean;
}

// ═══════════════════════════════════════════════════
// Approach 1: Pure random search with low hamming weight delta
// For each trial: generate random message + random low-weight delta
// Measure: state diff at target round + schedule diff
// ═══════════════════════════════════════════════════

__global__
void random_low_weight_search(
    int target_round,
    int max_delta_bits,   // max total hamming weight of delta
    uint64_t seed,
    int* best_state,
    int* best_clean,      // most clean schedule words [16..target]
    uint32_t* best_delta,
    uint32_t* best_msg,
    int n_trials)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_trials) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    // Random message
    uint32_t W[16], W2[16];
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
    }

    // Generate low-weight delta: pick 2-6 random (word,bit) pairs
    uint32_t delta[16]={0};
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int n_flips = 2 + ((int)(rng>>32) % (max_delta_bits-1));

    for(int f=0; f<n_flips; f++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        int word = (int)((rng>>32) & 15);
        int bit = (int)((rng>>16) & 31);
        delta[word] ^= (1u << bit);
    }

    // Must have nonzero delta
    uint32_t any=0; for(int i=0;i<16;i++)any|=delta[i];
    if(!any) return;

    for(int i=0;i<16;i++) W2[i] = W[i] ^ delta[i];

    // Count clean schedule words
    int clean = count_clean_schedule(W, W2, 16, target_round);

    // State diff
    uint32_t s1[8],s2[8];
    sha256_n(W,target_round,s1);
    sha256_n(W2,target_round,s2);
    int sd = sdiff(s1,s2);

    // Score: maximize clean words, minimize state diff
    // Pack: clean * 1000 - sd (higher = better)
    // We minimize negative score
    int neg_score = -clean * 1000 + sd;

    // Use best_clean as the primary metric (atomicMax on clean)
    int old_clean = atomicMax(best_clean, clean);
    if(clean > old_clean || (clean == old_clean && sd < *best_state)) {
        *best_state = sd;
        for(int i=0;i<16;i++){best_delta[i]=delta[i];best_msg[i]=W[i];}
    }
}

// ═══════════════════════════════════════════════════
// Approach 2: Hybrid — algebraic cancel W[16..17] +
// random search for d[2..13] to extend clean region
// ═══════════════════════════════════════════════════

__global__
void hybrid_search(
    int target_round,
    uint64_t seed,
    int* best_state,
    int* best_clean,
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

    // Step 1: algebraic cancel W[16..17]
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int b14 = (int)(rng>>32) & 31;
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int b15 = (int)(rng>>32) & 31;

    uint32_t d14 = 1u << b14;
    uint32_t d15 = 1u << b15;

    // d1 cancels W[17]: d1 = -sig1_delta(W[15], d15)
    uint32_t d1 = (uint32_t)(-(int32_t)(sig1(W[15]^d15) - sig1(W[15])));
    // d0 cancels W[16]: d0 = -(sig1_delta(W[14],d14) + sig0_delta(W[1],d1))
    uint32_t d0 = (uint32_t)(-(int32_t)(sig1(W[14]^d14) - sig1(W[14]) +
                                         sig0(W[1]^d1) - sig0(W[1])));

    uint32_t delta[16] = {0};
    delta[0] = d0;
    delta[1] = d1;
    delta[14] = d14;
    delta[15] = d15;

    // Step 2: add random perturbations to d[2..13]
    // These affect W[18+] through the schedule
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int n_extra = 1 + ((int)(rng>>32) % 4); // 1-4 extra delta words

    for(int f=0; f<n_extra; f++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        int word = 2 + ((int)(rng>>32) % 12); // d[2..13]
        int bit = (int)((rng>>16) & 31);
        delta[word] ^= (1u << bit);

        // Optionally: add second bit
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        if((rng>>32) & 1) {
            int bit2 = (int)((rng>>16) & 31);
            delta[word] ^= (1u << bit2);
        }
    }

    uint32_t W2[16];
    for(int i=0;i<16;i++) W2[i] = W[i] ^ delta[i];

    // Measure
    int clean = count_clean_schedule(W, W2, 16, target_round);
    uint32_t s1[8],s2[8];
    sha256_n(W,target_round,s1);
    sha256_n(W2,target_round,s2);
    int sd = sdiff(s1,s2);

    int old_clean = atomicMax(best_clean, clean);
    if(clean > old_clean || (clean == old_clean && sd < *best_state)) {
        *best_state = sd;
        for(int i=0;i<16;i++){best_delta[i]=delta[i];best_msg[i]=W[i];}
    }
}

// ═══════════════════════════════════════════════════
// Approach 3: Message-dependent optimization
// Fix delta, search for message where diff is minimal
// (differential characteristic depends on actual values)
// ═══════════════════════════════════════════════════

__global__
void message_search(
    int target_round,
    const uint32_t* fixed_delta, // [16] fixed delta pattern
    uint64_t seed,
    int* best_state,
    int* best_clean,
    uint32_t* best_msg,
    int n_trials)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_trials) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    uint32_t W[16], W2[16];
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
        W2[i] = W[i] ^ fixed_delta[i];
    }

    int clean = count_clean_schedule(W, W2, 16, target_round);
    uint32_t s1[8],s2[8];
    sha256_n(W,target_round,s1);
    sha256_n(W2,target_round,s2);
    int sd = sdiff(s1,s2);

    int old_clean = atomicMax(best_clean, clean);
    if(clean > old_clean || (clean == old_clean && sd < *best_state)) {
        *best_state = sd;
        for(int i=0;i<16;i++) best_msg[i] = W[i];
    }
}

int main() {
    printf("SHA-256 Nonlinear Push — Beyond Round 20\n");
    printf("════════════════════════════════════════\n\n");

    int *d_state, *d_clean;
    uint32_t *d_delta, *d_msg;
    cudaMalloc(&d_state,4);cudaMalloc(&d_clean,4);
    cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);

    int trials = 1 << 24; // 16M

    // ── Approach 1: Pure random low-weight ──
    printf("=== Approach 1: Random low-weight delta ===\n\n");

    for(int target=20; target<=32; target+=2) {
        for(int max_bits=3; max_bits<=8; max_bits+=5) {
            int h_state=256, h_clean=0;
            cudaMemcpy(d_state,&h_state,4,cudaMemcpyHostToDevice);
            cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);

            for(int pass=0;pass<4;pass++){
                random_low_weight_search<<<trials/256,256>>>(
                    target,max_bits,pass*11111ULL+target*7+max_bits*3,
                    d_state,d_clean,d_delta,d_msg,trials);
                cudaDeviceSynchronize();
            }

            cudaMemcpy(&h_state,d_state,4,cudaMemcpyDeviceToHost);
            cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);

            if(max_bits==3)
                printf("Round %2d: ", target);
            printf("[%dbit: %d clean, %3d sdiff] ", max_bits, h_clean, h_state);
        }
        printf("\n");
    }

    // ── Approach 2: Hybrid algebraic+random ──
    printf("\n=== Approach 2: Hybrid (algebraic W[16..17] + random d[2..13]) ===\n\n");

    for(int target=20; target<=32; target+=2) {
        int h_state=256, h_clean=0;
        cudaMemcpy(d_state,&h_state,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);

        for(int pass=0;pass<8;pass++){
            hybrid_search<<<trials/256,256>>>(
                target,pass*99999ULL+target*13,
                d_state,d_clean,d_delta,d_msg,trials);
            cudaDeviceSynchronize();
        }

        cudaMemcpy(&h_state,d_state,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);
        uint32_t h_delta[16];
        cudaMemcpy(h_delta,d_delta,64,cudaMemcpyDeviceToHost);

        int dbits=0;
        for(int i=0;i<16;i++) dbits+=popcnt(h_delta[i]);

        printf("Round %2d: %d clean schedule words | state_diff = %3d | %d delta bits\n",
               target, h_clean, h_state, dbits);

        if(h_clean >= 5) {
            printf("  *** Delta:");
            for(int i=0;i<16;i++) if(h_delta[i]) printf(" W[%d]=0x%08x", i, h_delta[i]);
            printf("\n");

            // Verify schedule
            uint32_t h_msg[16];
            cudaMemcpy(h_msg,d_msg,64,cudaMemcpyDeviceToHost);
            uint32_t w1[40],w2[40];
            for(int i=0;i<16;i++){w1[i]=h_msg[i];w2[i]=h_msg[i]^h_delta[i];}
            for(int i=16;i<40&&i<target;i++){
                w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
                w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
            }
            printf("  Schedule: ");
            for(int i=16;i<target&&i<40;i++){
                int b=popcnt(w1[i]^w2[i]);
                printf("W[%d]=%d ", i, b);
            }
            printf("\n");
        }
    }

    // ── Approach 3: Fix best delta, search messages ──
    printf("\n=== Approach 3: Fix best hybrid delta, optimize message ===\n\n");

    // Get best delta from approach 2 (round 24)
    {
        int h_state=256, h_clean=0;
        cudaMemcpy(d_state,&h_state,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);

        for(int pass=0;pass<16;pass++){
            hybrid_search<<<trials/256,256>>>(
                24,pass*77777ULL,
                d_state,d_clean,d_delta,d_msg,trials);
            cudaDeviceSynchronize();
        }

        uint32_t h_delta[16];
        cudaMemcpy(h_delta,d_delta,64,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_state,d_state,4,cudaMemcpyDeviceToHost);

        printf("Best hybrid delta at round 24: %d clean, %d state_diff\n", h_clean, h_state);

        // Now search for optimal message with this delta
        uint32_t* d_fixed_delta;
        cudaMalloc(&d_fixed_delta, 64);
        cudaMemcpy(d_fixed_delta, h_delta, 64, cudaMemcpyHostToDevice);

        h_state=256; h_clean=0;
        cudaMemcpy(d_state,&h_state,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);

        for(int pass=0;pass<32;pass++){
            message_search<<<trials/256,256>>>(
                24, d_fixed_delta, pass*55555ULL,
                d_state,d_clean,d_msg,trials);
            cudaDeviceSynchronize();
        }

        cudaMemcpy(&h_state,d_state,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);

        printf("After message optimization: %d clean, %d state_diff\n", h_clean, h_state);
        printf("(512M messages tested)\n");

        cudaFree(d_fixed_delta);
    }

    printf("\n=== Summary ===\n");
    printf("Algebraic: 20 rounds (W[16..20] = 0)\n");
    printf("Hybrid: extends clean region using nonlinear search\n");
    printf("Message-dependent: same delta, different message = different diff\n");
    printf("Key: SHA-256 differential is message-DEPENDENT (nonlinear ops)\n");

    cudaFree(d_state);cudaFree(d_clean);cudaFree(d_delta);cudaFree(d_msg);
    return 0;
}

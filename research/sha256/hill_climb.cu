/*
 * SHA-256 Hill Climbing + Meet-in-the-Middle
 * ============================================
 *
 * Best so far: 8 clean schedule words (23 controlled rounds)
 * Pattern: d[0,1,7,14,15] → ✓✓✓✓✓_✓_✓_✓_
 *
 * Approach 1: Hill climbing from best known solution
 *   - Start with best delta pattern
 *   - Mutate: flip 1 bit in one delta word
 *   - Keep if improvement (more clean or lower total sched diff)
 *   - Run millions of iterations on GPU
 *
 * Approach 2: Meet-in-the-middle on message schedule
 *   - Split W[0..15] into two halves: W[0..7] and W[8..15]
 *   - Forward: enumerate d[8..15] → compute partial schedule contribution
 *   - Backward: for each forward result, compute required d[0..7]
 *   - This effectively squares the search space we can cover
 *
 * Approach 3: Constraint propagation
 *   - Model each bit of sig0/sig1 as boolean function
 *   - Propagate constraints from "W[i] delta = 0" backwards
 *   - Find satisfying assignment for d[0..15]
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,1835,20091 hill_climb.cu -o hillclimb
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
#define sig0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define sig1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))
#define S0(a) (ROTR(a,2)^ROTR(a,13)^ROTR(a,22))
#define S1(e) (ROTR(e,6)^ROTR(e,11)^ROTR(e,25))
#define CH(e,f,g) (((e)&(f))^((~(e))&(g)))
#define MAJ(a,b,c) (((a)&(b))^((a)&(c))^((b)&(c)))

__device__ __host__
int popcnt(uint32_t x){x=x-((x>>1)&0x55555555);x=(x&0x33333333)+((x>>2)&0x33333333);return(((x+(x>>4))&0x0F0F0F0F)*0x01010101)>>24;}

// Evaluate delta quality: returns (clean_words, total_sched_bits, state_diff)
__device__ __host__
void evaluate(const uint32_t W[16], const uint32_t delta[16], int target_round,
              int* clean, int* sched_bits, int* state_diff) {
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^delta[i];}
    for(int i=16;i<64;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }

    *clean = 0; *sched_bits = 0;
    int ne = target_round - 16; if(ne>48) ne=48;
    for(int i=16;i<16+ne;i++){
        int b=popcnt(w1[i]^w2[i]);
        if(b==0) (*clean)++;
        *sched_bits += b;
    }

    // State diff
    uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a;
    uint32_t e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
    for(int i=0;i<target_round&&i<64;i++){
        uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;
    }
    *state_diff = popcnt(a1^a2)+popcnt(b1^b2)+popcnt(c1^c2)+popcnt(d1^d2)+
                  popcnt(e1^e2)+popcnt(f1^f2)+popcnt(g1^g2)+popcnt(h1^h2);
}

// Score: higher = better. Prioritize clean words, then low sched bits
__device__ __host__
int score(int clean, int sched_bits, int state_diff) {
    return clean * 10000 - sched_bits * 10 - state_diff;
}

// ═══════════════════════════════════════════════════
// Hill Climbing Kernel
// Each thread: start from seed delta, do N mutations, keep best
// ═══════════════════════════════════════════════════

__global__
void hill_climb_kernel(
    const uint32_t* seed_msg,     // [16] starting message
    const uint32_t* seed_delta,   // [16] starting delta
    int target_round,
    int n_mutations,              // mutations per thread
    uint64_t rng_seed,
    int* best_score,
    int* best_clean,
    int* best_sched,
    int* best_state,
    uint32_t* best_delta,
    uint32_t* best_msg,
    int n_threads)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_threads) return;

    uint64_t rng = rng_seed + tid * 6364136223846793005ULL + 1;

    // Start from seed + small random perturbation to message
    uint32_t W[16], delta[16];
    for(int i=0;i<16;i++){
        W[i] = seed_msg[i];
        delta[i] = seed_delta[i];
    }

    // Randomize message slightly (each thread different message)
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int msg_word = (int)(rng>>32) & 15;
    W[msg_word] ^= (uint32_t)(rng & 0xFFFFFFFF);

    // Evaluate initial
    int cl, sb, sd;
    evaluate(W, delta, target_round, &cl, &sb, &sd);
    int cur_score = score(cl, sb, sd);

    uint32_t best_local_delta[16];
    for(int i=0;i<16;i++) best_local_delta[i] = delta[i];
    int best_local_score = cur_score;

    // Hill climb: try mutations
    for(int m=0; m<n_mutations; m++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r = (uint32_t)(rng>>32);

        // Mutation type
        int mut_type = r & 3;
        uint32_t trial_delta[16];
        for(int i=0;i<16;i++) trial_delta[i] = delta[i];

        if(mut_type == 0) {
            // Flip 1 bit in existing delta word
            int word = (r >> 2) & 15;
            int bit = (r >> 6) & 31;
            trial_delta[word] ^= (1u << bit);
        } else if(mut_type == 1) {
            // Add new 1-bit delta to a zero word
            int word = 2 + ((r >> 2) % 12);
            if(trial_delta[word] == 0) {
                int bit = (r >> 6) & 31;
                trial_delta[word] = (1u << bit);
            }
        } else if(mut_type == 2) {
            // Clear one delta word (set to 0)
            int word = 2 + ((r >> 2) % 12);
            trial_delta[word] = 0;
        } else {
            // Swap bits between two words
            int w1 = (r >> 2) & 15;
            int w2 = (r >> 6) & 15;
            int b = (r >> 10) & 31;
            trial_delta[w1] ^= (1u << b);
            trial_delta[w2] ^= (1u << b);
        }

        // Must have nonzero delta
        uint32_t any=0; for(int i=0;i<16;i++) any|=trial_delta[i];
        if(!any) continue;

        // Re-solve d[0],d[1] algebraically for W[16,17]
        uint32_t sig1_d15 = sig1(W[15]^trial_delta[15]) - sig1(W[15]);
        uint32_t sig0_d2 = sig0(W[2]^trial_delta[2]) - sig0(W[2]);
        trial_delta[1] = (uint32_t)(-(int32_t)(sig1_d15 + trial_delta[10] + sig0_d2));

        uint32_t sig1_d14 = sig1(W[14]^trial_delta[14]) - sig1(W[14]);
        uint32_t sig0_d1 = sig0(W[1]^trial_delta[1]) - sig0(W[1]);
        trial_delta[0] = (uint32_t)(-(int32_t)(sig1_d14 + trial_delta[9] + sig0_d1));

        // Evaluate
        int tcl, tsb, tsd;
        evaluate(W, trial_delta, target_round, &tcl, &tsb, &tsd);
        int ts = score(tcl, tsb, tsd);

        // Must have nonzero delta
        uint32_t any2=0; for(int i=0;i<16;i++) any2|=trial_delta[i];
        if(!any2) continue;

        // Accept if better (greedy)
        if(ts > cur_score) {
            cur_score = ts;
            for(int i=0;i<16;i++) delta[i] = trial_delta[i];
        }

        if(ts > best_local_score) {
            best_local_score = ts;
            for(int i=0;i<16;i++) best_local_delta[i] = trial_delta[i];
        }
    }

    // Update global best
    int old = atomicMax(best_score, best_local_score);
    if(best_local_score > old) {
        evaluate(W, best_local_delta, target_round, &cl, &sb, &sd);
        *best_clean = cl;
        *best_sched = sb;
        *best_state = sd;
        for(int i=0;i<16;i++){best_delta[i]=best_local_delta[i];best_msg[i]=W[i];}
    }
}

// ═══════════════════════════════════════════════════
// Meet-in-the-Middle on schedule
// Forward: fix d[8..15], compute W[16..23] partial
// Backward: fix d[0..7], compute required W[16..23]
// Match: find (d_left, d_right) where contributions cancel
// ═══════════════════════════════════════════════════

// For MITM: compute schedule contribution from high words only
__device__
void sched_contribution_high(const uint32_t W[16], const uint32_t delta_high[8],
                              uint32_t contrib[8]) {
    // W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16]
    // High words (8..15) contribute to:
    //   W[16]: W[9](high), sig1(W[14])(high), W[0]+sig0(W[1])(low)
    //   W[17]: W[10](high), sig1(W[15])(high), W[1]+sig0(W[2])(low)
    // Split: contrib_high[k] = delta in W[16+k] from d[8..15]

    for(int k=0;k<8;k++){
        uint32_t d=0;
        // W[16+k] = sig1(W[14+k]) + W[9+k] + sig0(W[1+k]) + W[k]
        // From high: sig1_delta(W[14+k]) if 14+k in [8..15], W[9+k] if in [8..15]
        if(14+k < 16 && 14+k >= 8)
            d += sig1(W[14+k]^delta_high[14+k-8]) - sig1(W[14+k]);
        if(9+k < 16 && 9+k >= 8)
            d += delta_high[9+k-8];
        contrib[k] = d;
    }
}

__global__
void mitm_search(
    uint64_t seed,
    int target_round,
    int* best_clean,
    int* best_sched,
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

    // Random delta in high words [8..15] — 1 bit each in 2-3 words
    uint32_t delta[16]={0};
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    delta[14] = 1u << ((int)(rng>>32) & 31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    delta[15] = 1u << ((int)(rng>>32) & 31);

    // Add 0-2 more in d[8..13]
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int extra = (int)(rng>>32) % 3;
    for(int e=0;e<extra;e++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        int w = 8+((int)(rng>>32)%6);
        delta[w] = 1u << ((int)((rng>>16)&31));
    }

    // Algebraically solve d[0..7] to cancel W[16..23]
    // Sequential: d[1] cancels W[17], d[0] cancels W[16]
    // Then d[2] cancels W[18] using actual computed values, etc.

    uint32_t w1[24],w2[24];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^delta[i];}
    for(int i=16;i<24;i++)
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];

    // Solve d[k] for k=0..7 to make w2[16+k] = w1[16+k]
    for(int k=0;k<8;k++){
        int i=16+k;
        // w2[i] = sig1(w2[i-2]) + w2[i-7] + sig0(w2[i-15]) + w2[i-16]
        // = sig1(w2[14+k]) + w2[9+k] + sig0(w2[1+k]) + w2[k]
        // Want = w1[i]
        // w2[k] = w1[i] - sig1(w2[14+k]) - w2[9+k] - sig0(w2[1+k])

        uint32_t v_m2 = (14+k < 16) ? w2[14+k] : w1[14+k]; // cancelled or known
        uint32_t v_m7 = (9+k < 16) ? w2[9+k] : w1[9+k];
        uint32_t v_m15 = w2[1+k]; // 1+k in 1..8

        uint32_t target = w1[i] - sig1(v_m2) - v_m7 - sig0(v_m15);
        delta[k] = W[k] ^ target;
        w2[k] = target;
        w2[i] = w1[i]; // mark as cancelled
    }

    // Refresh and evaluate
    for(int i=0;i<16;i++) w2[i] = W[i] ^ delta[i];
    for(int i=16;i<24;i++)
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];

    // Count clean in W[16..target]
    int ne=target_round-16;if(ne>32)ne=32;
    uint32_t ww1[48],ww2[48];
    for(int i=0;i<16;i++){ww1[i]=W[i];ww2[i]=W[i]^delta[i];}
    for(int i=16;i<16+ne;i++){
        ww1[i]=sig1(ww1[i-2])+ww1[i-7]+sig0(ww1[i-15])+ww1[i-16];
        ww2[i]=sig1(ww2[i-2])+ww2[i-7]+sig0(ww2[i-15])+ww2[i-16];
    }

    int clean=0,sched=0;
    for(int i=16;i<16+ne;i++){
        int b=popcnt(ww1[i]^ww2[i]);
        if(b==0) clean++;
        sched+=b;
    }

    int old=atomicMax(best_clean,clean);
    if(clean>old||(clean==old&&sched<*best_sched)){
        *best_sched=sched;
        for(int i=0;i<16;i++){best_delta[i]=delta[i];best_msg[i]=W[i];}
    }
}

int main() {
    printf("SHA-256 Hill Climbing + MITM\n");
    printf("═══════════════════════════\n\n");

    int *d_score,*d_clean,*d_sched,*d_state;
    uint32_t *d_delta,*d_msg,*d_seed_delta,*d_seed_msg;
    cudaMalloc(&d_score,4);cudaMalloc(&d_clean,4);cudaMalloc(&d_sched,4);cudaMalloc(&d_state,4);
    cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);cudaMalloc(&d_seed_delta,64);cudaMalloc(&d_seed_msg,64);

    int trials = 1 << 22; // 4M threads
    int mutations = 256;   // mutations per thread = 4M * 256 = 1B evaluations

    // ── MITM: algebraic solve d[0..7] for cancel W[16..23] ──
    printf("=== MITM: Algebraic d[0..7], random d[8..15] ===\n\n");

    for(int target=24;target<=40;target+=4){
        int h_clean=0,h_sched=9999;
        cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_sched,&h_sched,4,cudaMemcpyHostToDevice);

        for(int pass=0;pass<32;pass++){
            mitm_search<<<trials/256,256>>>(
                pass*6151ULL+target*43,target,
                d_clean,d_sched,d_delta,d_msg,trials);
            cudaDeviceSynchronize();
        }

        cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_sched,d_sched,4,cudaMemcpyDeviceToHost);

        uint32_t h_delta[16],h_msg[16];
        cudaMemcpy(h_delta,d_delta,64,cudaMemcpyDeviceToHost);
        cudaMemcpy(h_msg,d_msg,64,cudaMemcpyDeviceToHost);

        int dw=0,db=0;
        for(int i=0;i<16;i++)if(h_delta[i]){dw++;db+=popcnt(h_delta[i]);}

        printf("Round %2d: %2d clean | sched=%3d | %d words %d bits | ",
               target,h_clean,h_sched,dw,db);

        uint32_t w1[48],w2[48];
        for(int i=0;i<16;i++){w1[i]=h_msg[i];w2[i]=h_msg[i]^h_delta[i];}
        int ne=target-16;if(ne>32)ne=32;
        for(int i=16;i<16+ne;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }
        for(int i=16;i<16+ne;i++){
            int b=popcnt(w1[i]^w2[i]);
            if(b==0)printf("✓");else if(b<10)printf("%d",b);else printf("X");
        }
        printf("\n");

        if(h_clean>=10){
            printf("  *** BREAKTHROUGH! Delta:");
            for(int i=0;i<16;i++)if(h_delta[i])printf(" d[%d]=%08x",i,h_delta[i]);
            printf("\n");
        }
    }

    // ── Hill climb from MITM best ──
    printf("\n=== Hill Climbing from best MITM result ===\n\n");

    // Get best MITM delta for round 32
    int h_clean=0,h_sched=9999;
    cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);
    cudaMemcpy(d_sched,&h_sched,4,cudaMemcpyHostToDevice);
    for(int pass=0;pass<64;pass++){
        mitm_search<<<trials/256,256>>>(pass*8191ULL,32,d_clean,d_sched,d_delta,d_msg,trials);
        cudaDeviceSynchronize();
    }
    cudaMemcpy(d_seed_delta,d_delta,64,cudaMemcpyDeviceToDevice);
    cudaMemcpy(d_seed_msg,d_msg,64,cudaMemcpyDeviceToDevice);
    cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);
    printf("MITM seed at round 32: %d clean\n",h_clean);

    // Hill climb — extended iterations
    int mutations_per = 1024;
    for(int round=0;round<50;round++){
        int h_score=-999999;
        h_clean=0;h_sched=9999;int h_state=256;
        cudaMemcpy(d_score,&h_score,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_sched,&h_sched,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_state,&h_state,4,cudaMemcpyHostToDevice);

        hill_climb_kernel<<<trials/256,256>>>(
            d_seed_msg,d_seed_delta,48,mutations_per,round*12345ULL,
            d_score,d_clean,d_sched,d_state,d_delta,d_msg,trials);
        cudaDeviceSynchronize();

        cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_sched,d_sched,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_state,d_state,4,cudaMemcpyDeviceToHost);

        printf("  Round %d: %d clean | sched=%d | state=%d | ",round,h_clean,h_sched,h_state);

        uint32_t hd[16],hm[16];
        cudaMemcpy(hd,d_delta,64,cudaMemcpyDeviceToHost);
        cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);

        uint32_t w1[48],w2[48];
        for(int i=0;i<16;i++){w1[i]=hm[i];w2[i]=hm[i]^hd[i];}
        for(int i=16;i<48;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }
        for(int i=16;i<48;i++){int b=popcnt(w1[i]^w2[i]);if(b==0)printf("✓");else if(b<10)printf("%d",b);else printf("X");}
        printf("\n");

        // Use best as new seed
        cudaMemcpy(d_seed_delta,d_delta,64,cudaMemcpyDeviceToDevice);
        cudaMemcpy(d_seed_msg,d_msg,64,cudaMemcpyDeviceToDevice);

        if(h_clean >= 20) {
            printf("\n  *** BREAKTHROUGH: %d clean = %d controlled rounds! ***\n", h_clean, 15+h_clean);
            printf("  Delta:");
            for(int i=0;i<16;i++)if(hd[i])printf(" d[%d]=%08x",i,hd[i]);
            printf("\n");
            break;
        }
    }

    printf("\n=== Records ===\n");
    printf("Previous best: 8 clean (23 rounds)\n");
    printf("Academic record: ~31 rounds (collision), ~52 rounds (preimage with caveats)\n");
    printf("SHA-256 total: 64 rounds\n");

    cudaFree(d_score);cudaFree(d_clean);cudaFree(d_sched);cudaFree(d_state);
    cudaFree(d_delta);cudaFree(d_msg);cudaFree(d_seed_delta);cudaFree(d_seed_msg);
    return 0;
}

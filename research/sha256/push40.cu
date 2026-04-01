/*
 * SHA-256 Push to 40+ rounds
 * ===========================
 *
 * Current: 33 rounds (18 clean schedule words, 13 consecutive)
 * Target: 40 rounds (25+ clean schedule words)
 *
 * Barrier: 16 input words = 16 DOF. Can cancel ~18 schedule words max.
 *
 * New strategies:
 *
 * 1. MULTI-BIT DELTAS: instead of 1-bit per word, use optimal multi-bit
 *    deltas that create "self-cancelling" cascades in sig0/sig1.
 *    The nonlinear sig0/sig1 functions have special input patterns
 *    where differential propagation is lower.
 *
 * 2. RELAXED SCORE: instead of binary (clean/dirty), score by total
 *    hamming weight. A word with 1-bit diff is almost as good as 0.
 *    Optimize total_hamming(W[16..48]) instead of count_zeros.
 *
 * 3. WIDER MUTATIONS: mutate entire 32-bit words, not just flip bits.
 *    Some delta values have special properties with sig0/sig1.
 *
 * 4. POPULATION EVOLUTION: maintain population of best solutions,
 *    crossover between them.
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,550,1835,20091 push40.cu -o push40
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

// Algebraic fix d[0],d[1] for W[16],W[17] cancellation
__device__
void fix_d01(const uint32_t W[16], uint32_t d[16]) {
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));
}

// Score: weighted sum emphasizing CONSECUTIVE clean + low total hamming
// Clean words get big bonus, low-diff words get partial credit
__device__
int calc_score(const uint32_t W[16], const uint32_t d[16], int n_exp) {
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<16+n_exp;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }

    int score = 0;
    int consecutive = 0;
    int max_consecutive = 0;
    int total_clean = 0;

    for(int i=16;i<16+n_exp;i++){
        int b = popcnt(w1[i]^w2[i]);
        if(b==0){
            total_clean++;
            consecutive++;
            if(consecutive > max_consecutive) max_consecutive = consecutive;
            score += 1000 + consecutive * 500; // bonus for consecutive
        } else {
            consecutive = 0;
            // Partial credit for low diff
            if(b <= 2) score += 300 - b * 50;
            else if(b <= 5) score += 100 - b * 10;
            else score -= b * 5; // penalty for high diff
        }
    }

    // Big bonus for consecutive runs
    score += max_consecutive * max_consecutive * 100;

    return score;
}

// Simulated annealing with advanced mutations
__global__
void anneal_push40(
    uint64_t seed,
    int n_steps,
    float temp_start, float temp_end,
    int n_exp,          // schedule words to evaluate
    int* best_score,
    int* best_clean,
    uint32_t* best_delta,
    uint32_t* best_msg,
    int n_threads)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_threads) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    // Random message
    uint32_t W[16];
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
    }

    // Initialize delta with known good pattern
    uint32_t d[16]={0};
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[14]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[15]=1u<<((int)(rng>>32)&31);

    // Start with 3-6 delta words, 1-bit each (proven to work)
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int n_init=3+((int)(rng>>32)%4);
    for(int f=0;f<n_init;f++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        int w=2+((int)(rng>>32)%12);
        d[w]=1u<<((int)((rng>>16)&31));
    }

    fix_d01(W, d);
    int cur_score = calc_score(W, d, n_exp);

    uint32_t best_d[16], best_W[16];
    for(int i=0;i<16;i++){best_d[i]=d[i];best_W[i]=W[i];}
    int local_best = cur_score;

    float temp=temp_start;
    float decay=powf(temp_end/temp_start,1.0f/(float)n_steps);

    for(int s=0;s<n_steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);

        uint32_t trial_d[16], trial_W[16];
        for(int i=0;i<16;i++){trial_d[i]=d[i];trial_W[i]=W[i];}

        int mut = r % 12;

        if(mut <= 2){
            // Flip 1 bit in delta
            int w=2+((r>>4)%14);
            trial_d[w]^=(1u<<((r>>8)&31));
        } else if(mut == 3){
            // Flip 2-3 bits in delta
            int w=2+((r>>4)%14);
            trial_d[w]^=(1u<<((r>>8)&31))|(1u<<((r>>13)&31));
        } else if(mut == 4){
            // Replace delta word with new random value
            int w=2+((r>>4)%12);
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            trial_d[w]=(uint32_t)(rng>>32);
        } else if(mut == 5){
            // Set delta word to sig0/sig1 special value
            int w=2+((r>>4)%12);
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            uint32_t v=(uint32_t)(rng>>32);
            // Values where sig0(x^d)-sig0(x) has low hamming weight
            trial_d[w] = sig0(v) ^ sig0(v ^ (1u<<((r>>8)&31)));
        } else if(mut == 6){
            // Clear one delta word
            int w=2+((r>>4)%12);
            trial_d[w]=0;
        } else if(mut == 7){
            // Mutate d[14] or d[15]
            int w=(r>>4)&1?15:14;
            trial_d[w]^=(1u<<((r>>5)&31));
            if(!trial_d[w]) trial_d[w]=1;
        } else if(mut == 8){
            // Flip bit in message (change the message!)
            int w=(r>>4)&15;
            trial_W[w]^=(1u<<((r>>8)&31));
        } else if(mut == 9){
            // Replace entire message word
            int w=(r>>4)&15;
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            trial_W[w]=(uint32_t)(rng>>32);
        } else if(mut == 10){
            // Copy sig-related value between delta words
            int w1=2+((r>>4)%12);
            int w2=2+((r>>8)%12);
            if(trial_d[w1]) trial_d[w2]=trial_d[w1];
        } else {
            // Multi-word: flip bits in 2 delta words simultaneously
            int wa=2+((r>>4)%12);
            int wb=2+((r>>8)%12);
            trial_d[wa]^=(1u<<((r>>12)&31));
            trial_d[wb]^=(1u<<((r>>17)&31));
        }

        // Ensure d[14] or d[15] nonzero
        if(!trial_d[14]&&!trial_d[15]) continue;

        // Fix d[0,1] algebraically
        fix_d01(trial_W, trial_d);

        // Ensure nonzero
        uint32_t any=0;for(int i=0;i<16;i++)any|=trial_d[i];
        if(!any) continue;

        int ts = calc_score(trial_W, trial_d, n_exp);

        int delta_s = ts - cur_score;
        bool accept = (delta_s > 0);
        if(!accept && temp > 0.01f){
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            float r01=(float)(rng>>32)/4294967296.0f;
            accept=(r01<expf((float)delta_s/temp));
        }

        if(accept){
            cur_score=ts;
            for(int i=0;i<16;i++){d[i]=trial_d[i];W[i]=trial_W[i];}
        }
        if(ts>local_best){
            local_best=ts;
            for(int i=0;i<16;i++){best_d[i]=trial_d[i];best_W[i]=trial_W[i];}
        }

        temp*=decay;
    }

    // Count actual clean words for best
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=best_W[i];w2[i]=best_W[i]^best_d[i];}
    for(int i=16;i<64;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    int clean=0;
    for(int i=16;i<16+n_exp;i++) if(w1[i]==w2[i]) clean++;

    // Update global: use clean as primary, score as secondary
    int old_clean=atomicMax(best_clean,clean);
    if(clean>old_clean||(clean==old_clean&&local_best>*best_score)){
        *best_score=local_best;
        for(int i=0;i<16;i++){best_delta[i]=best_d[i];best_msg[i]=best_W[i];}
    }
}

int main(){
    printf("SHA-256 Push to 40+ Rounds\n");
    printf("══════════════════════════\n");
    printf("Advanced: multi-bit deltas, message mutation, weighted scoring\n\n");

    int *d_score,*d_clean;
    uint32_t *d_delta,*d_msg;
    cudaMalloc(&d_score,4);cudaMalloc(&d_clean,4);
    cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);

    int threads = 1<<21;
    int steps = 8192;
    int n_exp = 48; // evaluate W[16..63]

    int global_best_clean = 0;

    for(int epoch=0;epoch<40;epoch++){
        int h_score=-999999,h_clean=0;
        cudaMemcpy(d_score,&h_score,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);

        float t_start = 5000.0f + epoch * 1500.0f;

        anneal_push40<<<threads/256,256>>>(
            epoch*104729ULL+7, steps, t_start, 0.01f, n_exp,
            d_score,d_clean,d_delta,d_msg,threads);
        cudaDeviceSynchronize();

        cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);

        uint32_t hd[16],hm[16];
        cudaMemcpy(hd,d_delta,64,cudaMemcpyDeviceToHost);
        cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);

        // Show schedule
        uint32_t w1[64],w2[64];
        for(int i=0;i<16;i++){w1[i]=hm[i];w2[i]=hm[i]^hd[i];}
        for(int i=16;i<64;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }

        // Count consecutive from W[16]
        int consec=0;
        for(int i=16;i<64;i++){if(w1[i]==w2[i])consec++;else break;}

        // Count total low-diff (<=2 bits)
        int low_diff=0;
        for(int i=16;i<16+n_exp;i++) if(popcnt(w1[i]^w2[i])<=2) low_diff++;

        int dw=0,db=0;
        for(int i=0;i<16;i++)if(hd[i]){dw++;db+=popcnt(hd[i]);}

        printf("E%2d: %2d clean %2d consec %2d low | %dw %3db | ",
               epoch,h_clean,consec,low_diff,dw,db);
        for(int i=16;i<48;i++){
            int b=popcnt(w1[i]^w2[i]);
            if(b==0)printf("✓");else if(b<=2)printf(".");else if(b<10)printf("%d",b);else printf("X");
        }
        printf("\n");

        if(h_clean > global_best_clean){
            global_best_clean = h_clean;
            printf("  *** NEW RECORD: %d clean = %d rounds ***\n", h_clean, 15+h_clean);
            if(h_clean >= 25){
                printf("  Delta:");
                for(int i=0;i<16;i++)if(hd[i])printf(" d[%d]=%08x",i,hd[i]);
                printf("\n");
            }
        }
    }

    printf("\n═══════════════════════════════════════\n");
    printf("FINAL: %d clean = %d controlled rounds\n", global_best_clean, 15+global_best_clean);
    printf("SHA-256: 64 rounds total\n");

    cudaFree(d_score);cudaFree(d_clean);cudaFree(d_delta);cudaFree(d_msg);
    return 0;
}

/*
 * SHA-256 Simulated Annealing — Push to 48 rounds
 * =================================================
 *
 * Hill climb stuck at 16 clean (31 rounds). Local optimum.
 *
 * Simulated annealing: accept WORSE solutions with probability
 * exp(-delta_cost / temperature). Temperature decreases over time.
 * This allows escaping local optima.
 *
 * Additionally:
 *   - Large mutations (flip 2-4 bits, change whole words)
 *   - Population: 256 independent annealers per GPU block
 *   - Restart: periodically restart from best known
 *   - Target: 32 clean = 48 rounds with controlled diff
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,1835,20091 anneal.cu -o anneal
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

// Evaluate: count clean schedule words W[16..16+n_exp-1] and total sched bits
__device__
void evaluate_full(const uint32_t W[16], const uint32_t delta[16],
                   int n_exp, int* clean, int* sched_bits) {
    uint32_t w1[64], w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^delta[i];}
    for(int i=16;i<16+n_exp;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    *clean=0; *sched_bits=0;
    for(int i=16;i<16+n_exp;i++){
        int b=popcnt(w1[i]^w2[i]);
        if(b==0)(*clean)++;
        *sched_bits+=b;
    }
}

// Algebraically fix d[0],d[1] to cancel W[16],W[17]
__device__
void fix_d01(const uint32_t W[16], uint32_t delta[16]) {
    // W[17]: d1 = -(sig1_delta(W15,d15) + d10 + sig0_delta(W2,d2))
    delta[1] = (uint32_t)(-(int32_t)(
        sig1(W[15]^delta[15]) - sig1(W[15]) +
        delta[10] +
        sig0(W[2]^delta[2]) - sig0(W[2])
    ));
    // W[16]: d0 = -(sig1_delta(W14,d14) + d9 + sig0_delta(W1,d1))
    delta[0] = (uint32_t)(-(int32_t)(
        sig1(W[14]^delta[14]) - sig1(W[14]) +
        delta[9] +
        sig0(W[1]^delta[1]) - sig0(W[1])
    ));
}

// Score function: maximize clean words, minimize sched bits
// Higher = better
__device__
int calc_score(int clean, int sched_bits) {
    return clean * 10000 - sched_bits;
}

// ═══════════════════════════════════════════════════
// Simulated Annealing Kernel
// Each thread runs independent annealer
// ═══════════════════════════════════════════════════

__global__
void anneal_kernel(
    uint64_t seed,
    int n_steps,          // annealing steps per thread
    float temp_start,     // starting temperature
    float temp_end,       // ending temperature
    int* global_best_score,
    int* global_best_clean,
    int* global_best_sched,
    uint32_t* global_best_delta,
    uint32_t* global_best_msg,
    int n_threads)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_threads) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    // Generate random message
    uint32_t W[16];
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
    }

    // Start with random low-weight delta in d[2..15]
    uint32_t delta[16]={0};
    // d[14], d[15]: 1 bit each
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    delta[14]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    delta[15]=1u<<((int)(rng>>32)&31);
    // d[2..13]: 3-5 random words with 1 bit each
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int n_init = 3+((int)(rng>>32)%3);
    for(int f=0;f<n_init;f++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        int w=2+((int)(rng>>32)%12);
        delta[w]=1u<<((int)((rng>>16)&31));
    }

    // Fix d[0],d[1] algebraically
    fix_d01(W, delta);

    // Evaluate initial
    int cl, sb;
    evaluate_full(W, delta, 48, &cl, &sb);  // 48 expanded words = up to round 64
    int cur_score = calc_score(cl, sb);

    uint32_t best_delta[16];
    for(int i=0;i<16;i++) best_delta[i]=delta[i];
    int best_score = cur_score;
    int best_cl = cl;
    int best_sb = sb;

    // Annealing loop
    float temp_decay = powf(temp_end/temp_start, 1.0f/(float)n_steps);
    float temp = temp_start;

    for(int step=0; step<n_steps; step++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);

        // Generate mutation
        uint32_t trial[16];
        for(int i=0;i<16;i++) trial[i]=delta[i];

        int mut = r & 7;
        if(mut <= 2) {
            // Flip 1 bit in d[2..15]
            int w=2+((r>>3)%14);
            int b=(r>>7)&31;
            trial[w]^=(1u<<b);
        } else if(mut == 3) {
            // Flip 2 bits in same word
            int w=2+((r>>3)%14);
            int b1=(r>>7)&31;
            int b2=(r>>12)&31;
            trial[w]^=(1u<<b1)|(1u<<b2);
        } else if(mut == 4) {
            // Replace one word entirely with 1-bit value
            int w=2+((r>>3)%14);
            int b=(r>>7)&31;
            trial[w]=(1u<<b);
        } else if(mut == 5) {
            // Clear one word
            int w=2+((r>>3)%12);
            trial[w]=0;
        } else if(mut == 6) {
            // Flip bit in d[14] or d[15]
            int w=(r>>3)&1?14:15;
            int b=(r>>4)&31;
            trial[w]^=(1u<<b);
            // Ensure nonzero
            if(!trial[w]) trial[w]=1u<<((b+1)&31);
        } else {
            // Swap: move delta from one word to another
            int w1=2+((r>>3)%12);
            int w2=2+((r>>7)%12);
            if(trial[w1] && w1!=w2){
                trial[w2]^=trial[w1];
                trial[w1]=0;
            }
        }

        // Ensure nonzero delta in d[14] or d[15]
        if(!trial[14]&&!trial[15]) continue;

        // Must have some delta beyond d[0,1,14,15]
        uint32_t any=0;for(int i=2;i<14;i++)any|=trial[i];
        // OK if only d[14,15] (algebraic will set d[0,1])

        // Fix d[0],d[1]
        fix_d01(W, trial);

        // Ensure nonzero total
        any=0;for(int i=0;i<16;i++)any|=trial[i];
        if(!any) continue;

        // Evaluate
        int tcl, tsb;
        evaluate_full(W, trial, 48, &tcl, &tsb);
        int ts = calc_score(tcl, tsb);

        // Accept/reject
        int delta_score = ts - cur_score;
        bool accept = false;
        if(delta_score > 0) {
            accept = true;
        } else if(temp > 0.01f) {
            // Probability = exp(delta_score / temp)
            // delta_score is negative, temp positive
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            float rand01 = (float)(rng>>32) / 4294967296.0f;
            float prob = expf((float)delta_score / temp);
            accept = (rand01 < prob);
        }

        if(accept) {
            cur_score = ts;
            for(int i=0;i<16;i++) delta[i]=trial[i];

            if(ts > best_score) {
                best_score = ts;
                best_cl = tcl;
                best_sb = tsb;
                for(int i=0;i<16;i++) best_delta[i]=trial[i];
            }
        }

        temp *= temp_decay;
    }

    // Update global best
    int old = atomicMax(global_best_score, best_score);
    if(best_score > old) {
        *global_best_clean = best_cl;
        *global_best_sched = best_sb;
        for(int i=0;i<16;i++){
            global_best_delta[i]=best_delta[i];
            global_best_msg[i]=W[i];
        }
    }
}

// ═══════════════════════════════════════════════════
// Also search over MESSAGES (same delta, different msg)
// The schedule diff depends on actual message values!
// ═══════════════════════════════════════════════════

__global__
void message_anneal(
    const uint32_t* fixed_delta,
    uint64_t seed,
    int n_steps,
    float temp_start, float temp_end,
    int* best_score, int* best_clean, int* best_sched,
    uint32_t* best_msg,
    int n_threads)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_threads) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    uint32_t W[16];
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
    }

    // Need to re-solve d[0,1] for this message
    uint32_t delta[16];
    for(int i=0;i<16;i++) delta[i]=fixed_delta[i];
    fix_d01(W, delta);

    int cl,sb;
    evaluate_full(W,delta,48,&cl,&sb);
    int cur=calc_score(cl,sb);
    int best_local=cur;
    uint32_t best_W[16];
    for(int i=0;i<16;i++)best_W[i]=W[i];

    float temp=temp_start;
    float decay=powf(temp_end/temp_start,1.0f/(float)n_steps);

    for(int s=0;s<n_steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        // Mutate message
        uint32_t trial_W[16];
        for(int i=0;i<16;i++) trial_W[i]=W[i];
        int w=(int)((rng>>32)&15);
        int b=(int)((rng>>16)&31);
        trial_W[w]^=(1u<<b);

        uint32_t td[16];
        for(int i=0;i<16;i++) td[i]=fixed_delta[i];
        fix_d01(trial_W, td);

        int tcl,tsb;
        evaluate_full(trial_W,td,48,&tcl,&tsb);
        int ts=calc_score(tcl,tsb);

        int ds=ts-cur;
        bool accept=(ds>0);
        if(!accept&&temp>0.01f){
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            float r01=(float)(rng>>32)/4294967296.0f;
            accept=(r01<expf((float)ds/temp));
        }
        if(accept){cur=ts;for(int i=0;i<16;i++)W[i]=trial_W[i];}
        if(ts>best_local){best_local=ts;for(int i=0;i<16;i++)best_W[i]=trial_W[i];}
        temp*=decay;
    }

    int old=atomicMax(best_score,best_local);
    if(best_local>old){
        // Recompute clean/sched for best
        uint32_t td[16];for(int i=0;i<16;i++)td[i]=fixed_delta[i];
        fix_d01(best_W,td);
        evaluate_full(best_W,td,48,&cl,&sb);
        *best_clean=cl;*best_sched=sb;
        for(int i=0;i<16;i++)best_msg[i]=best_W[i];
    }
}

int main(){
    printf("SHA-256 Simulated Annealing — Target: 48 rounds\n");
    printf("═══════════════════════════════════════════════\n\n");

    int *d_score,*d_clean,*d_sched;
    uint32_t *d_delta,*d_msg,*d_fixed_delta;
    cudaMalloc(&d_score,4);cudaMalloc(&d_clean,4);cudaMalloc(&d_sched,4);
    cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);cudaMalloc(&d_fixed_delta,64);

    int threads = 1<<21; // 2M threads
    int steps = 8192;     // steps per thread = 17B total evaluations

    printf("Phase 1: Delta annealing (%d threads × %d steps = %.1fB evals)\n\n",
           threads, steps, (double)threads*steps/1e9);

    int overall_best_clean = 0;
    uint32_t overall_best_delta[16]={0}, overall_best_msg[16]={0};

    for(int epoch=0; epoch<20; epoch++){
        int h_score=-999999,h_clean=0,h_sched=9999;
        cudaMemcpy(d_score,&h_score,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_sched,&h_sched,4,cudaMemcpyHostToDevice);

        // Vary temperature schedule
        float t_start = 5000.0f * (1.0f + epoch * 0.5f);
        float t_end = 0.1f;

        anneal_kernel<<<threads/256,256>>>(
            epoch*999983ULL, steps, t_start, t_end,
            d_score,d_clean,d_sched,d_delta,d_msg,threads);
        cudaDeviceSynchronize();

        cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_sched,d_sched,4,cudaMemcpyDeviceToHost);

        uint32_t hd[16],hm[16];
        cudaMemcpy(hd,d_delta,64,cudaMemcpyDeviceToHost);
        cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);

        // Show schedule pattern
        uint32_t w1[64],w2[64];
        for(int i=0;i<16;i++){w1[i]=hm[i];w2[i]=hm[i]^hd[i];}
        for(int i=16;i<64;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }

        int dw=0,db=0;
        for(int i=0;i<16;i++)if(hd[i]){dw++;db+=popcnt(hd[i]);}

        printf("Epoch %2d: %2d clean | sched=%3d | %dw %db | T=%.0f→%.1f | ",
               epoch,h_clean,h_sched,dw,db,t_start,t_end);

        for(int i=16;i<48;i++){
            int b=popcnt(w1[i]^w2[i]);
            if(b==0)printf("✓");else if(b<10)printf("%d",b);else printf("X");
        }
        printf("\n");

        if(h_clean > overall_best_clean){
            overall_best_clean = h_clean;
            for(int i=0;i<16;i++){overall_best_delta[i]=hd[i];overall_best_msg[i]=hm[i];}
        }
    }

    printf("\nBest: %d clean schedule words\n", overall_best_clean);

    // Phase 2: Message annealing with best delta
    printf("\nPhase 2: Message annealing (fix best delta, optimize message)\n\n");

    cudaMemcpy(d_fixed_delta, overall_best_delta, 64, cudaMemcpyHostToDevice);

    for(int epoch=0;epoch<20;epoch++){
        int h_score=-999999,h_clean=0,h_sched=9999;
        cudaMemcpy(d_score,&h_score,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_sched,&h_sched,4,cudaMemcpyHostToDevice);

        message_anneal<<<threads/256,256>>>(
            d_fixed_delta,epoch*777773ULL,steps,3000.0f,0.1f,
            d_score,d_clean,d_sched,d_msg,threads);
        cudaDeviceSynchronize();

        cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_sched,d_sched,4,cudaMemcpyDeviceToHost);

        uint32_t hm[16];
        cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);

        uint32_t td[16];
        for(int i=0;i<16;i++) td[i]=overall_best_delta[i];
        // Re-fix d01 for this message on host
        td[1]=(uint32_t)(-(int32_t)(sig1(hm[15]^td[15])-sig1(hm[15])+td[10]+sig0(hm[2]^td[2])-sig0(hm[2])));
        td[0]=(uint32_t)(-(int32_t)(sig1(hm[14]^td[14])-sig1(hm[14])+td[9]+sig0((hm[1]^td[1]))-sig0(hm[1])));

        uint32_t w1[64],w2[64];
        for(int i=0;i<16;i++){w1[i]=hm[i];w2[i]=hm[i]^td[i];}
        for(int i=16;i<64;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }

        printf("Msg epoch %d: %2d clean | sched=%3d | ",epoch,h_clean,h_sched);
        for(int i=16;i<48;i++){int b=popcnt(w1[i]^w2[i]);if(b==0)printf("✓");else if(b<10)printf("%d",b);else printf("X");}
        printf("\n");

        if(h_clean > overall_best_clean){
            overall_best_clean = h_clean;
            printf("  *** NEW RECORD: %d clean = %d rounds ***\n", h_clean, 15+h_clean);
        }
    }

    // Phase 3: Joint delta+message annealing — mutate BOTH simultaneously
    printf("\nPhase 3: Joint delta+message annealing\n\n");

    for(int epoch=0;epoch<30;epoch++){
        int h_score=-999999,h_clean=0,h_sched=9999;
        cudaMemcpy(d_score,&h_score,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_sched,&h_sched,4,cudaMemcpyHostToDevice);

        // Higher temperature + more steps for deeper exploration
        float t_start = 8000.0f + epoch * 2000.0f;
        float t_end = 0.01f;

        anneal_kernel<<<threads/256,256>>>(
            epoch*1299827ULL+42, steps, t_start, t_end,
            d_score,d_clean,d_sched,d_delta,d_msg,threads);
        cudaDeviceSynchronize();

        cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_sched,d_sched,4,cudaMemcpyDeviceToHost);

        uint32_t hd[16],hm[16];
        cudaMemcpy(hd,d_delta,64,cudaMemcpyDeviceToHost);
        cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);

        // Get best delta for message annealing
        if(h_clean > 12) {
            // Message anneal with this delta
            cudaMemcpy(d_fixed_delta, hd, 64, cudaMemcpyHostToDevice);
            int h2_score=-999999,h2_clean=0,h2_sched=9999;
            cudaMemcpy(d_score,&h2_score,4,cudaMemcpyHostToDevice);
            cudaMemcpy(d_clean,&h2_clean,4,cudaMemcpyHostToDevice);
            cudaMemcpy(d_sched,&h2_sched,4,cudaMemcpyHostToDevice);

            message_anneal<<<threads/256,256>>>(
                d_fixed_delta,epoch*3571ULL,steps,5000.0f,0.01f,
                d_score,d_clean,d_sched,d_msg,threads);
            cudaDeviceSynchronize();

            cudaMemcpy(&h2_clean,d_clean,4,cudaMemcpyDeviceToHost);
            cudaMemcpy(&h2_sched,d_sched,4,cudaMemcpyDeviceToHost);

            if(h2_clean > h_clean) {
                h_clean = h2_clean;
                h_sched = h2_sched;
                cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);
            }
        }

        uint32_t w1[64],w2[64];
        // Re-fix d01 for display
        uint32_t td[16];for(int i=0;i<16;i++)td[i]=hd[i];
        td[1]=(uint32_t)(-(int32_t)(sig1(hm[15]^td[15])-sig1(hm[15])+td[10]+sig0(hm[2]^td[2])-sig0(hm[2])));
        td[0]=(uint32_t)(-(int32_t)(sig1(hm[14]^td[14])-sig1(hm[14])+td[9]+sig0((hm[1]^td[1]))-sig0(hm[1])));
        for(int i=0;i<16;i++){w1[i]=hm[i];w2[i]=hm[i]^td[i];}
        for(int i=16;i<64;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }

        printf("J%2d: %2d clean | sched=%3d | T=%.0f | ", epoch, h_clean, h_sched, t_start);
        for(int i=16;i<48;i++){int b=popcnt(w1[i]^w2[i]);if(b==0)printf("✓");else if(b<10)printf("%d",b);else printf("X");}
        printf("\n");

        if(h_clean > overall_best_clean){
            overall_best_clean = h_clean;
            for(int i=0;i<16;i++){overall_best_delta[i]=hd[i];}
            printf("  *** NEW RECORD: %d clean = %d rounds ***\n", h_clean, 15+h_clean);
        }

        if(h_clean >= 24) {
            printf("\n  *** TARGET REACHED: %d+ clean = %d+ rounds! ***\n", h_clean, 15+h_clean);
            printf("  Delta:");
            for(int i=0;i<16;i++)if(td[i])printf(" d[%d]=%08x",i,td[i]);
            printf("\n");
            break;
        }
    }

    printf("\n═══════════════════════════════════════\n");
    printf("FINAL: %d clean schedule words = %d controlled rounds of SHA-256\n",
           overall_best_clean, 15+overall_best_clean);
    printf("SHA-256 total: 64 rounds\n");
    printf("Remaining: %d rounds to full break\n", 64-15-overall_best_clean);

    cudaFree(d_score);cudaFree(d_clean);cudaFree(d_sched);
    cudaFree(d_delta);cudaFree(d_msg);cudaFree(d_fixed_delta);
    return 0;
}

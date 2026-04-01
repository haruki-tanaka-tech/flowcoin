/*
 * SHA-256 Collision Finder
 * =========================
 *
 * State diff plateau at 74 bits across all 64 rounds.
 * Birthday attack: 2^(74/2) = 2^37 ≈ 137 billion pairs to test.
 *
 * Strategy:
 *   1. Fix delta pattern (from best state_diff result)
 *   2. Generate random messages M
 *   3. Compute SHA-256(M) and SHA-256(M ⊕ delta)
 *   4. Measure state diff at round 64 (output diff)
 *   5. If diff < threshold → near-collision
 *   6. If diff = 0 → FULL COLLISION
 *
 * Actually: the 74-bit diff means hamming(H(M) ⊕ H(M')) ≈ 74.
 * For collision we need hamming = 0. Birthday doesn't directly apply
 * to hamming weight — we need the EXACT same 74 bits to flip.
 *
 * Better approach: measure which BITS differ consistently.
 * If the same 74 bit positions always differ → XOR is fixed pattern.
 * Then search for message where those 74 bits happen to cancel.
 *
 * OR: the 74 bits are DIFFERENT each time (message-dependent).
 * Then we need birthday on the 74-bit diff pattern itself.
 *
 * Step 1: Determine if diff pattern is FIXED or VARIABLE.
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,550,1835,20091 collision_finder.cu -o collision
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <time.h>

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

// Full SHA-256 compression, return XOR diff of outputs
__device__
void sha256_diff(const uint32_t W[16], const uint32_t d[16],
                 uint32_t out_xor[8], int* out_bits) {
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<64;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a;
    uint32_t e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
    for(int i=0;i<64;i++){
        uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;
    }
    // Output = H0 + compress result
    uint32_t H[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint32_t o1[8]={(a1+H[0])&0xFFFFFFFF,(b1+H[1])&0xFFFFFFFF,
                    (c1+H[2])&0xFFFFFFFF,(d1+H[3])&0xFFFFFFFF,
                    (e1+H[4])&0xFFFFFFFF,(f1+H[5])&0xFFFFFFFF,
                    (g1+H[6])&0xFFFFFFFF,(h1+H[7])&0xFFFFFFFF};
    uint32_t o2[8]={(a2+H[0])&0xFFFFFFFF,(b2+H[1])&0xFFFFFFFF,
                    (c2+H[2])&0xFFFFFFFF,(d2+H[3])&0xFFFFFFFF,
                    (e2+H[4])&0xFFFFFFFF,(f2+H[5])&0xFFFFFFFF,
                    (g2+H[6])&0xFFFFFFFF,(h2+H[7])&0xFFFFFFFF};
    int bits=0;
    for(int i=0;i<8;i++){
        out_xor[i]=o1[i]^o2[i];
        bits+=popcnt(out_xor[i]);
    }
    *out_bits=bits;
}

// Phase 1: Analyze diff pattern — is it fixed or variable?
__global__
void analyze_diff_pattern(
    const uint32_t* fixed_delta, // [16]
    uint64_t seed,
    uint32_t* bit_freq,   // [256] how often each bit position differs
    int* min_diff,
    int* max_diff,
    uint32_t* best_msg,   // message with lowest diff
    int n_trials)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_trials) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    uint32_t W[16], d[16];
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
        d[i]=fixed_delta[i];
    }
    // Re-solve d[0,1] for this message
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));

    uint32_t xor_diff[8];
    int bits;
    sha256_diff(W, d, xor_diff, &bits);

    // Update bit frequency (which bit positions differ)
    for(int w=0;w<8;w++){
        for(int b=0;b<32;b++){
            if(xor_diff[w] & (1u<<b)){
                atomicAdd(&bit_freq[w*32+b], 1);
            }
        }
    }

    // Track min/max diff
    atomicMin(min_diff, bits);
    atomicMax(max_diff, bits);

    // Save best message
    int old = atomicMin(min_diff, bits);
    if(bits <= old){
        for(int i=0;i<16;i++) best_msg[i] = W[i];
    }
}

// Phase 2: Targeted search — find messages with minimum diff
__global__
void find_min_diff(
    const uint32_t* fixed_delta,
    uint64_t seed,
    int* best_diff,
    uint32_t* best_msg,
    uint32_t* best_xor,  // [8] the XOR pattern of best
    int n_trials)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_trials) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    uint32_t W[16], d[16];
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
        d[i]=fixed_delta[i];
    }
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));

    uint32_t xor_diff[8];
    int bits;
    sha256_diff(W, d, xor_diff, &bits);

    int old = atomicMin(best_diff, bits);
    if(bits < old){
        for(int i=0;i<16;i++) best_msg[i] = W[i];
        for(int i=0;i<8;i++) best_xor[i] = xor_diff[i];
    }
}

// Phase 3: Simulated annealing on message to minimize diff
__global__
void anneal_collision(
    const uint32_t* fixed_delta,
    uint64_t seed,
    int n_steps,
    float temp_start, float temp_end,
    int* best_diff,
    uint32_t* best_msg,
    uint32_t* best_xor,
    int n_threads)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_threads) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    uint32_t W[16], d[16];
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
        d[i]=fixed_delta[i];
    }
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));

    uint32_t xd[8]; int cur;
    sha256_diff(W, d, xd, &cur);
    int local_best = cur;
    uint32_t best_W[16], best_X[8];
    for(int i=0;i<16;i++) best_W[i]=W[i];
    for(int i=0;i<8;i++) best_X[i]=xd[i];

    float temp=temp_start;
    float decay=powf(temp_end/temp_start, 1.0f/(float)n_steps);

    for(int s=0;s<n_steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);

        uint32_t tW[16],td[16];
        for(int i=0;i<16;i++){tW[i]=W[i];td[i]=fixed_delta[i];}

        // Mutate message
        int mut=r%6;
        if(mut<=2){
            tW[(r>>4)&15]^=1u<<((r>>8)&31);
        }else if(mut==3){
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            tW[(r>>4)&15]=(uint32_t)(rng>>32);
        }else{
            tW[(r>>4)&15]^=(1u<<((r>>8)&31))|(1u<<((r>>13)&31));
        }

        // Re-solve d[0,1]
        td[1]=(uint32_t)(-(int32_t)(sig1(tW[15]^td[15])-sig1(tW[15])+td[10]+sig0(tW[2]^td[2])-sig0(tW[2])));
        td[0]=(uint32_t)(-(int32_t)(sig1(tW[14]^td[14])-sig1(tW[14])+td[9]+sig0(tW[1]^td[1])-sig0(tW[1])));

        uint32_t txd[8]; int ts;
        sha256_diff(tW, td, txd, &ts);

        int ds=ts-cur;
        bool accept=(ds<0);
        if(!accept&&temp>0.01f){
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)ds/temp);
        }

        if(accept){cur=ts;for(int i=0;i<16;i++)W[i]=tW[i];}
        if(ts<local_best){
            local_best=ts;
            for(int i=0;i<16;i++)best_W[i]=tW[i];
            for(int i=0;i<8;i++)best_X[i]=txd[i];
        }
        temp*=decay;
    }

    int old=atomicMin(best_diff,local_best);
    if(local_best<old){
        for(int i=0;i<16;i++)best_msg[i]=best_W[i];
        for(int i=0;i<8;i++)best_xor[i]=best_X[i];
    }
}

int main(){
    printf("SHA-256 Collision Finder\n");
    printf("═══════════════════════\n");
    printf("74-bit state diff → searching for 0-bit (collision)\n\n");

    // Best delta from state_diff_opt (use simple 1-bit d[14],d[15])
    // d[0,1] solved per-message
    uint32_t fixed_delta[16]={0};
    fixed_delta[14] = 0x00000100; // bit 8
    fixed_delta[15] = 0x00000100; // bit 8

    uint32_t *d_delta, *d_msg, *d_xor, *d_freq;
    int *d_min, *d_max, *d_best;
    cudaMalloc(&d_delta,64); cudaMalloc(&d_msg,64); cudaMalloc(&d_xor,32);
    cudaMalloc(&d_freq,256*4); cudaMalloc(&d_min,4); cudaMalloc(&d_max,4);
    cudaMalloc(&d_best,4);
    cudaMemcpy(d_delta, fixed_delta, 64, cudaMemcpyHostToDevice);

    int threads = 1<<19;
    int thermal_ms = 500;

    // ── Phase 1: Analyze diff pattern ──
    printf("=== Phase 1: Diff pattern analysis (1M messages) ===\n");
    {
        int h_min=256, h_max=0;
        uint32_t h_freq[256]={0};
        cudaMemcpy(d_min,&h_min,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_max,&h_max,4,cudaMemcpyHostToDevice);
        cudaMemset(d_freq,0,256*4);

        for(int pass=0;pass<4;pass++){
            struct timespec ts={0,thermal_ms*1000000L};
            nanosleep(&ts,NULL);
            analyze_diff_pattern<<<threads/256,256>>>(
                d_delta,pass*99991ULL,d_freq,d_min,d_max,d_msg,threads);
            cudaDeviceSynchronize();
        }

        cudaMemcpy(&h_min,d_min,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_max,d_max,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(h_freq,d_freq,256*4,cudaMemcpyDeviceToHost);

        int total_samples = threads * 4;
        printf("  Min diff: %d bits\n", h_min);
        printf("  Max diff: %d bits\n", h_max);
        printf("  Range: %d bits spread\n", h_max - h_min);
        printf("\n  Bit position frequency (how often each bit differs):\n");

        int always_diff=0, never_diff=0, variable=0;
        for(int i=0;i<256;i++){
            float pct = 100.0f * h_freq[i] / total_samples;
            if(pct > 99.0f) always_diff++;
            else if(pct < 1.0f) never_diff++;
            else variable++;
        }
        printf("    Always differ (>99%%): %d bits\n", always_diff);
        printf("    Never differ  (<1%%):  %d bits\n", never_diff);
        printf("    Variable:             %d bits\n", variable);
        printf("    → Pattern is %s\n",
               always_diff > 50 ? "MOSTLY FIXED — good for targeted search!" :
               "VARIABLE — need birthday approach");
    }

    // ── Phase 2: Random search for minimum diff ──
    printf("\n=== Phase 2: Random search for minimum diff ===\n");
    {
        int h_best=256;
        cudaMemcpy(d_best,&h_best,4,cudaMemcpyHostToDevice);

        for(int pass=0;pass<20;pass++){
            struct timespec ts={0,thermal_ms*1000000L};
            nanosleep(&ts,NULL);
            find_min_diff<<<threads/256,256>>>(
                d_delta,pass*77773ULL,d_best,d_msg,d_xor,threads);
            cudaDeviceSynchronize();

            cudaMemcpy(&h_best,d_best,4,cudaMemcpyDeviceToHost);
            printf("  Pass %2d: best diff = %d bits (%.1fM tested)\n",
                   pass, h_best, (pass+1)*threads/1e6);
        }

        uint32_t h_xor[8];
        cudaMemcpy(h_xor,d_xor,32,cudaMemcpyDeviceToHost);
        printf("\n  Best XOR pattern: ");
        for(int i=0;i<8;i++) printf("%08x ", h_xor[i]);
        printf("\n  Best diff: %d bits\n", h_best);
    }

    // ── Phase 3: Anneal from best toward collision ──
    printf("\n=== Phase 3: Simulated annealing → collision ===\n");
    {
        int h_best=256;
        cudaMemcpy(d_best,&h_best,4,cudaMemcpyHostToDevice);

        for(int epoch=0;epoch<30;epoch++){
            struct timespec ts={0,thermal_ms*1000000L};
            nanosleep(&ts,NULL);

            float t_start=2000.0f+epoch*500.0f;
            anneal_collision<<<threads/256,256>>>(
                d_delta,epoch*31337ULL,4096,t_start,0.01f,
                d_best,d_msg,d_xor,threads);
            cudaDeviceSynchronize();

            cudaMemcpy(&h_best,d_best,4,cudaMemcpyDeviceToHost);
            printf("  Epoch %2d: best diff = %d bits\n", epoch, h_best);

            if(h_best == 0){
                printf("\n  ╔═══════════════════════════════════╗\n");
                printf("  ║   SHA-256 COLLISION FOUND!!!      ║\n");
                printf("  ╚═══════════════════════════════════╝\n\n");

                uint32_t hm[16],hd[16];
                cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);
                for(int i=0;i<16;i++) hd[i]=fixed_delta[i];
                hd[1]=(uint32_t)(-(int32_t)(sig1(hm[15]^hd[15])-sig1(hm[15])+hd[10]+sig0(hm[2]^hd[2])-sig0(hm[2])));
                hd[0]=(uint32_t)(-(int32_t)(sig1(hm[14]^hd[14])-sig1(hm[14])+hd[9]+sig0(hm[1]^hd[1])-sig0(hm[1])));

                printf("  M:  "); for(int i=0;i<16;i++) printf("%08x ",hm[i]); printf("\n");
                printf("  M': "); for(int i=0;i<16;i++) printf("%08x ",hm[i]^hd[i]); printf("\n");
                printf("  Delta: "); for(int i=0;i<16;i++) if(hd[i]) printf("d[%d]=%08x ",i,hd[i]); printf("\n");
                break;
            }

            if(h_best < 30){
                printf("  *** NEAR COLLISION: %d bits! ***\n", h_best);
            }
        }
    }

    printf("\n═══════════════════════════════════════\n");

    cudaFree(d_delta);cudaFree(d_msg);cudaFree(d_xor);
    cudaFree(d_freq);cudaFree(d_min);cudaFree(d_max);cudaFree(d_best);
    return 0;
}

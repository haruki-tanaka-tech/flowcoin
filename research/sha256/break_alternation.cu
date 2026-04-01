/*
 * SHA-256 Break Alternation Barrier
 * ===================================
 *
 * Key insight: d[14] can be COMPUTED (not free) to cancel W[30].
 *   d[14] = -sig0_delta(W[15], d[15])  → cancels W[30]
 *   d[13] = -sig0_delta(W[14], d[14])  → cancels W[29]
 *   d[0,1] algebraic from d[14,15]     → cancels W[16,17]
 *   d[15] = only free parameter (1 bit)
 *
 * Chain: d[15] → d[14] → d[13] → d[0,1] → W[16..30] = 0
 * Expected: 15 consecutive clean schedule words!
 *
 * Then continue: d[12] for W[28]? d[11] for W[27]?
 * Cascade BACKWARDS from W[30] → W[16], using all d[0..15].
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,550,1835,20091 break_alternation.cu -o break_alt
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

/*
 * New algebraic cascade: solve d[14], d[13], d[0], d[1] from d[15]
 *
 * Given message W and d[15] (single free param), plus optional d[2..12]:
 *
 * Step 1: d[14] = -sig0_delta(W[15], d[15]) - delta_W[23]
 *         Wait — need to account for delta_W[23] contribution to W[30]
 *
 * Actually W[30] = sig1(W[28]) + W[23] + sig0(W[15]) + W[14]
 * delta_W[30] = sig1_delta(W[28], dW28) + dW23 + sig0_delta(W[15],d15) + d14
 *
 * If W[16..28] are clean (dW28=0, dW23=0):
 *   delta_W[30] = sig0_delta(W[15],d15) + d14
 *   For zero: d14 = -sig0_delta(W[15],d15)
 *
 * Similarly W[29] = sig1(W[27]) + W[22] + sig0(W[14]) + W[13]
 * If W[22]=0, W[27]=0:
 *   delta_W[29] = sig0_delta(W[14],d14) + d13
 *   For zero: d13 = -sig0_delta(W[14],d14)
 *
 * Then W[17]: d1 = -(sig1_delta(W15,d15) + d10 + sig0_delta(W2,d2))
 * And  W[16]: d0 = -(sig1_delta(W14,d14) + d9 + sig0_delta(W1,d1))
 *
 * BUT: this only works if W[16..28] ARE clean.
 * The cascade is: d15 → d14 → d13 → d1 → d0
 * And then W[16..17] cancelled by d0,d1.
 * W[18..28]: need the SAME cascade as before (from d[2..12] + effects of d13,d14)
 *
 * The question: does setting d13,d14 as multi-bit values
 * (instead of 1-bit) break W[18..28] cleanliness?
 */

__global__
void search_extended_cascade(
    uint64_t seed,
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

    uint32_t d[16] = {0};

    // d[15] = free parameter (1 bit)
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int b15 = (int)(rng>>32) & 31;
    d[15] = 1u << b15;

    // d[14] = -sig0_delta(W[15], d[15])  → cancel W[30]
    d[14] = (uint32_t)(-(int32_t)(sig0(W[15] ^ d[15]) - sig0(W[15])));

    // d[13] = -sig0_delta(W[14], d[14])  → cancel W[29]
    d[13] = (uint32_t)(-(int32_t)(sig0(W[14] ^ d[14]) - sig0(W[14])));

    // Optionally add d[2..12] for additional schedule control
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int n_extra = (int)(rng>>32) % 4; // 0-3 extra words
    for(int f=0; f<n_extra; f++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        int w = 2+((int)(rng>>32)%11); // d[2..12]
        d[w] = 1u<<((int)((rng>>16)&31));
    }

    // d[1] cancel W[17]
    d[1] = (uint32_t)(-(int32_t)(
        sig1(W[15]^d[15]) - sig1(W[15]) + d[10] +
        sig0(W[2]^d[2]) - sig0(W[2])
    ));

    // d[0] cancel W[16]
    d[0] = (uint32_t)(-(int32_t)(
        sig1(W[14]^d[14]) - sig1(W[14]) + d[9] +
        sig0(W[1]^d[1]) - sig0(W[1])
    ));

    // Evaluate
    uint32_t w1[64], w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<48;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }

    int clean=0, sched=0;
    for(int i=16;i<48;i++){
        int b=popcnt(w1[i]^w2[i]);
        if(b==0) clean++;
        sched += b;
    }

    int old = atomicMax(best_clean, clean);
    if(clean > old || (clean == old && sched < *best_sched)){
        *best_sched = sched;
        for(int i=0;i<16;i++){best_delta[i]=d[i];best_msg[i]=W[i];}
    }
}

// Also try: cascade d12→W[28], d11→W[27], etc.
__global__
void search_deep_cascade(
    uint64_t seed,
    int cascade_depth, // how many extra W to cancel: 2=W[29,30], 4=W[27..30], etc.
    int* best_clean,
    int* best_sched,
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

    uint32_t d[16] = {0};

    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int b15 = (int)(rng>>32) & 31;
    d[15] = 1u << b15;

    // Backward cascade from W[30] → W[30-cascade_depth+1]
    // W[30]: d14 = -sig0_delta(W15,d15)
    // W[29]: d13 = -sig0_delta(W14,d14)
    // W[28]: d12 = -sig0_delta(W13,d13) - sig1_delta(W26,dW26)
    //   But dW26 depends on everything... only clean if W[16..25] clean
    //   For now assume clean and correct later

    // Step 1: d14 from W[30]
    d[14] = (uint32_t)(-(int32_t)(sig0(W[15]^d[15]) - sig0(W[15])));

    // Step 2: d13 from W[29]
    d[13] = (uint32_t)(-(int32_t)(sig0(W[14]^d[14]) - sig0(W[14])));

    if(cascade_depth >= 4){
        // Step 3: d12 from W[28]
        // W[28] = sig1(W[26]) + W[21] + sig0(W[13]) + W[12]
        // Assume W[26],W[21] clean → delta=0
        // delta_W[28] = sig0_delta(W13,d13) + d12
        d[12] = (uint32_t)(-(int32_t)(sig0(W[13]^d[13]) - sig0(W[13])));

        // Step 4: d11 from W[27]
        // W[27] = sig1(W[25]) + W[20] + sig0(W[12]) + W[11]
        d[11] = (uint32_t)(-(int32_t)(sig0(W[12]^d[12]) - sig0(W[12])));
    }

    if(cascade_depth >= 6){
        d[10] = (uint32_t)(-(int32_t)(sig0(W[11]^d[11]) - sig0(W[11])));
        d[9]  = (uint32_t)(-(int32_t)(sig0(W[10]^d[10]) - sig0(W[10])));
    }

    if(cascade_depth >= 8){
        d[8] = (uint32_t)(-(int32_t)(sig0(W[9]^d[9]) - sig0(W[9])));
        d[7] = (uint32_t)(-(int32_t)(sig0(W[8]^d[8]) - sig0(W[8])));
    }

    if(cascade_depth >= 10){
        d[6] = (uint32_t)(-(int32_t)(sig0(W[7]^d[7]) - sig0(W[7])));
        d[5] = (uint32_t)(-(int32_t)(sig0(W[6]^d[6]) - sig0(W[6])));
    }

    if(cascade_depth >= 12){
        d[4] = (uint32_t)(-(int32_t)(sig0(W[5]^d[5]) - sig0(W[5])));
        d[3] = (uint32_t)(-(int32_t)(sig0(W[4]^d[4]) - sig0(W[4])));
    }

    // Algebraic d[1], d[0] (always)
    d[1] = (uint32_t)(-(int32_t)(
        sig1(W[15]^d[15]) - sig1(W[15]) + d[10] +
        sig0(W[2]^d[2]) - sig0(W[2])
    ));
    d[0] = (uint32_t)(-(int32_t)(
        sig1(W[14]^d[14]) - sig1(W[14]) + d[9] +
        sig0(W[1]^d[1]) - sig0(W[1])
    ));

    // Evaluate
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<48;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }

    int clean=0,sched=0;
    for(int i=16;i<48;i++){
        int b=popcnt(w1[i]^w2[i]);
        if(b==0)clean++;
        sched+=b;
    }

    int old=atomicMax(best_clean,clean);
    if(clean>old||(clean==old&&sched<*best_sched)){
        *best_sched=sched;
        for(int i=0;i<16;i++){best_delta[i]=d[i];best_msg[i]=W[i];}
    }
}

int main(){
    printf("SHA-256 Break Alternation Barrier\n");
    printf("═════════════════════════════════\n");
    printf("d[15]→d[14]→d[13]→d[0,1] cascade: cancel W[16..30]\n\n");

    int *d_clean,*d_sched;
    uint32_t *d_delta,*d_msg;
    cudaMalloc(&d_clean,4);cudaMalloc(&d_sched,4);
    cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);

    int threads = 1<<19; // 512K
    int thermal_ms = 500;

    // ── Test 1: Basic d15→d14→d13 cascade ──
    printf("=== Test 1: d15→d14→d13 (cancel W[29,30]) ===\n\n");

    for(int pass=0;pass<20;pass++){
        struct timespec ts={0,thermal_ms*1000000L};
        nanosleep(&ts,NULL);

        int h_clean=0,h_sched=9999;
        cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_sched,&h_sched,4,cudaMemcpyHostToDevice);

        search_extended_cascade<<<threads/256,256>>>(
            pass*104729ULL,d_clean,d_sched,d_delta,d_msg,threads);
        cudaDeviceSynchronize();

        cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_sched,d_sched,4,cudaMemcpyDeviceToHost);

        uint32_t hd[16],hm[16];
        cudaMemcpy(hd,d_delta,64,cudaMemcpyDeviceToHost);
        cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);

        uint32_t w1[48],w2[48];
        for(int i=0;i<16;i++){w1[i]=hm[i];w2[i]=hm[i]^hd[i];}
        for(int i=16;i<48;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }

        int dw=0,db=0;
        for(int i=0;i<16;i++)if(hd[i]){dw++;db+=popcnt(hd[i]);}

        printf("P%2d: %2d clean | sched=%3d | %dw %3db | ",pass,h_clean,h_sched,dw,db);
        for(int i=16;i<48;i++){int b=popcnt(w1[i]^w2[i]);if(b==0)printf("✓");else if(b<10)printf("%d",b);else printf("X");}
        printf("\n");
    }

    // ── Test 2: Deep cascade (varying depth) ──
    printf("\n=== Test 2: Deep backward cascade ===\n\n");

    for(int depth=2;depth<=14;depth+=2){
        struct timespec ts={0,thermal_ms*1000000L};
        nanosleep(&ts,NULL);

        int h_clean=0,h_sched=9999;
        cudaMemcpy(d_clean,&h_clean,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_sched,&h_sched,4,cudaMemcpyHostToDevice);

        for(int pass=0;pass<10;pass++){
            search_deep_cascade<<<threads/256,256>>>(
                pass*7919ULL+depth*131,depth,
                d_clean,d_sched,d_delta,d_msg,threads);
            cudaDeviceSynchronize();
            struct timespec ts2={0,300*1000000L};
            nanosleep(&ts2,NULL);
        }

        cudaMemcpy(&h_clean,d_clean,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_sched,d_sched,4,cudaMemcpyDeviceToHost);

        uint32_t hd[16],hm[16];
        cudaMemcpy(hd,d_delta,64,cudaMemcpyDeviceToHost);
        cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);

        uint32_t w1[48],w2[48];
        for(int i=0;i<16;i++){w1[i]=hm[i];w2[i]=hm[i]^hd[i];}
        for(int i=16;i<48;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }

        int dw=0,db=0;
        for(int i=0;i<16;i++)if(hd[i]){dw++;db+=popcnt(hd[i]);}

        printf("Depth %2d: %2d clean | sched=%3d | %dw %3db | ",depth,h_clean,h_sched,dw,db);
        for(int i=16;i<48;i++){int b=popcnt(w1[i]^w2[i]);if(b==0)printf("✓");else if(b<10)printf("%d",b);else printf("X");}
        printf("\n");
    }

    cudaFree(d_clean);cudaFree(d_sched);cudaFree(d_delta);cudaFree(d_msg);
    return 0;
}

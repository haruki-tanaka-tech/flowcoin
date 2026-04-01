/*
 * SHA-256 Birthday Collision Finder
 * ===================================
 *
 * State diff plateau at 74 bits. Birthday attack: 2^(74/2) = 2^37.
 *
 * Approach:
 *   1. Fix optimal delta pattern (from state_diff_opt)
 *   2. Generate 2^37 random messages
 *   3. For each: compute state diff XOR pattern at round 64
 *   4. Store (xor_pattern_hash, message) in hash table
 *   5. Find two messages with SAME xor_pattern → their diffs cancel
 *      If diff(M1) == diff(M2), then M1⊕delta and M2⊕delta give
 *      same output diff pattern. This is a collision on the diff.
 *
 * Wait — this doesn't directly give collision. Let me reconsider.
 *
 * Actually: for birthday we need two DIFFERENT deltas d1, d2 where:
 *   SHA256(M) ⊕ SHA256(M⊕d1) = SHA256(M) ⊕ SHA256(M⊕d2)
 *   → SHA256(M⊕d1) = SHA256(M⊕d2)
 *   → collision between M⊕d1 and M⊕d2!
 *
 * Simpler approach: fix delta, vary message.
 * For each message M: output_diff(M) = SHA256(M) ⊕ SHA256(M⊕d)
 * If output_diff(M1) = output_diff(M2) AND output_diff = 0 for some M
 * → collision.
 *
 * But output_diff is ~74 bits hamming weight, NOT a fixed pattern.
 * The 74 bits are in DIFFERENT positions for different messages.
 *
 * CORRECT birthday: among 2^37 messages, find one where diff = 0.
 * Probability per message: ~2^(-74) (74 bit positions must all be 0)
 * Expected: 2^74 trials. Birthday doesn't help directly.
 *
 * UNLESS: we find near-collisions and combine them.
 *
 * PRACTICAL approach: just brute force 2^54 messages with annealing
 * to find diff < 74, then intensify around those.
 *
 * OR: differential-birthday hybrid:
 *   - Compute partial hash (rounds 0-48) for many messages
 *   - Find pairs where round-48 state is CLOSE
 *   - For close pairs: check if rounds 48-64 converge to 0
 *   - Birthday on partial state: 2^37 in VRAM
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,550,1835,20091 birthday_collision.cu -o birthday
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

// Full SHA-256 compression: returns internal state diff (8 XOR words)
__device__
void compress_diff(const uint32_t W[16], const uint32_t d[16],
                   uint32_t xor_out[8], int* hamming) {
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
    xor_out[0]=a1^a2;xor_out[1]=b1^b2;xor_out[2]=c1^c2;xor_out[3]=d1^d2;
    xor_out[4]=e1^e2;xor_out[5]=f1^f2;xor_out[6]=g1^g2;xor_out[7]=h1^h2;
    *hamming=0;
    for(int i=0;i<8;i++) *hamming+=popcnt(xor_out[i]);
}

// Phase 1: Massive scan — find messages with lowest diff
// Each thread tests one message, reports if diff < threshold
__global__
void massive_scan(const uint32_t* fixed_delta,
                  uint64_t seed_base,
                  int* global_min_diff,
                  uint32_t* best_msg,
                  uint32_t* best_xor,
                  int n_per_thread,  // messages per thread
                  int n_threads) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_threads) return;

    uint64_t rng = seed_base + (uint64_t)tid * n_per_thread * 6364136223846793005ULL + 1;

    uint32_t d[16];
    for(int i=0;i<16;i++) d[i] = fixed_delta[i];

    int local_min = 256;
    uint32_t local_best_W[16], local_best_xor[8];

    for(int trial=0; trial<n_per_thread; trial++){
        uint32_t W[16];
        for(int i=0;i<16;i++){
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            W[i]=(uint32_t)(rng>>32);
        }

        // Fix d[0,1] for this message
        uint32_t td[16];
        for(int i=0;i<16;i++) td[i]=d[i];
        td[1]=(uint32_t)(-(int32_t)(sig1(W[15]^td[15])-sig1(W[15])+td[10]+sig0(W[2]^td[2])-sig0(W[2])));
        td[0]=(uint32_t)(-(int32_t)(sig1(W[14]^td[14])-sig1(W[14])+td[9]+sig0(W[1]^td[1])-sig0(W[1])));

        uint32_t xor_diff[8];
        int hw;
        compress_diff(W, td, xor_diff, &hw);

        if(hw < local_min) {
            local_min = hw;
            for(int i=0;i<16;i++) local_best_W[i] = W[i];
            for(int i=0;i<8;i++) local_best_xor[i] = xor_diff[i];
        }
    }

    int old = atomicMin(global_min_diff, local_min);
    if(local_min < old) {
        for(int i=0;i<16;i++) best_msg[i] = local_best_W[i];
        for(int i=0;i<8;i++) best_xor[i] = local_best_xor[i];
    }
}

// Phase 2: Anneal from best message found in Phase 1
__global__
void deep_anneal(const uint32_t* fixed_delta,
                 const uint32_t* seed_msg,
                 uint64_t seed,
                 int n_steps,
                 float temp_start, float temp_end,
                 int* best_diff,
                 uint32_t* best_msg,
                 uint32_t* best_xor,
                 int n_threads) {
    int tid=blockIdx.x*blockDim.x+threadIdx.x;
    if(tid>=n_threads) return;
    uint64_t rng=seed+tid*6364136223846793005ULL+1;

    uint32_t W[16],d[16];
    for(int i=0;i<16;i++){W[i]=seed_msg[i];d[i]=fixed_delta[i];}
    // Perturb start
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    W[(rng>>32)&15]^=(uint32_t)(rng&0xFFFFFFFF);

    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));

    uint32_t xd[8];int hw;
    compress_diff(W,d,xd,&hw);
    int cur=hw,lb=hw;
    uint32_t bW[16],bX[8];
    for(int i=0;i<16;i++)bW[i]=W[i];
    for(int i=0;i<8;i++)bX[i]=xd[i];

    float temp=temp_start,decay=powf(temp_end/temp_start,1.0f/(float)n_steps);
    for(int s=0;s<n_steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);
        uint32_t tW[16],td[16];
        for(int i=0;i<16;i++){tW[i]=W[i];td[i]=fixed_delta[i];}

        // Message mutation
        if(r&1) tW[(r>>1)&15]^=1u<<((r>>5)&31);
        else tW[(r>>1)&15]^=(1u<<((r>>5)&31))|(1u<<((r>>10)&31));

        td[1]=(uint32_t)(-(int32_t)(sig1(tW[15]^td[15])-sig1(tW[15])+td[10]+sig0(tW[2]^td[2])-sig0(tW[2])));
        td[0]=(uint32_t)(-(int32_t)(sig1(tW[14]^td[14])-sig1(tW[14])+td[9]+sig0(tW[1]^td[1])-sig0(tW[1])));

        uint32_t txd[8];int thw;
        compress_diff(tW,td,txd,&thw);

        bool accept=(thw<cur);
        if(!accept&&temp>0.01f){
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)(thw-cur)/temp);
        }
        if(accept){cur=thw;for(int i=0;i<16;i++)W[i]=tW[i];}
        if(thw<lb){lb=thw;for(int i=0;i<16;i++)bW[i]=tW[i];for(int i=0;i<8;i++)bX[i]=txd[i];}
        temp*=decay;
    }

    int old=atomicMin(best_diff,lb);
    if(lb<old){
        for(int i=0;i<16;i++)best_msg[i]=bW[i];
        for(int i=0;i<8;i++)best_xor[i]=bX[i];
    }
}

int main(){
    printf("SHA-256 Birthday/Brute-force Collision Finder\n");
    printf("═════════════════════════════════════════════\n\n");

    // Best known delta: simple 1-bit d[14], d[15] + algebraic d[0,1]
    // Try multiple delta patterns
    uint32_t deltas[][16] = {
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x100, 0x100},          // bit 8,8
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x80000000, 0x100},     // bit 31,8
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x200, 0x200},          // bit 9,9
        {0,0,0,0,0,0,1,0,0,0,0,0,0,0, 0x100, 0x100},          // +d[6]=1
        {0,0,0,0,0,0,0,1,0,0,0,0,0,0, 0x100, 0x100},          // +d[7]=1
        {0,0,0,1,0,0,0,0,0,0,0,0,0,0, 0x100, 0x100},          // +d[3]=1
    };
    int n_deltas = 6;

    int *d_diff;
    uint32_t *d_delta,*d_msg,*d_xor,*d_seed_msg;
    cudaMalloc(&d_diff,4);cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);
    cudaMalloc(&d_xor,32);cudaMalloc(&d_seed_msg,64);

    int threads = 1<<18; // 256K
    int msgs_per_thread = 64; // each thread tests 64 messages
    int thermal_ms = 500;
    int overall_best = 256;

    printf("Phase 1: Massive scan — %d delta patterns × %.0fM messages each\n\n",
           n_deltas, threads*msgs_per_thread/1e6);

    for(int di=0; di<n_deltas; di++){
        cudaMemcpy(d_delta, deltas[di], 64, cudaMemcpyHostToDevice);
        int h_diff = 256;

        for(int pass=0; pass<10; pass++){
            struct timespec ts={0,thermal_ms*1000000L};nanosleep(&ts,NULL);
            cudaMemcpy(d_diff,&h_diff,4,cudaMemcpyHostToDevice);

            massive_scan<<<threads/256,256>>>(d_delta, pass*999979ULL+di*7,
                d_diff, d_msg, d_xor, msgs_per_thread, threads);
            cudaDeviceSynchronize();
            cudaMemcpy(&h_diff,d_diff,4,cudaMemcpyDeviceToHost);
        }

        printf("  Delta %d: min diff = %d bits (%.0fM messages)\n",
               di, h_diff, 10.0*threads*msgs_per_thread/1e6);

        if(h_diff < overall_best){
            overall_best = h_diff;
            cudaMemcpy(d_seed_msg, d_msg, 64, cudaMemcpyDeviceToDevice);
            // Save this delta for Phase 2
            cudaMemcpy(d_delta, deltas[di], 64, cudaMemcpyHostToDevice);
        }
    }

    printf("\nBest from scan: %d bits\n", overall_best);

    // Phase 2: Deep anneal from best
    printf("\nPhase 2: Deep annealing from best message\n\n");

    for(int epoch=0;epoch<40;epoch++){
        struct timespec ts={0,thermal_ms*1000000L};nanosleep(&ts,NULL);
        // Don't reset d_diff — keep running minimum
        deep_anneal<<<threads/256,256>>>(d_delta,d_seed_msg,
            epoch*31337ULL, 8192, 5000.0f+epoch*1000.0f, 0.001f,
            d_diff, d_msg, d_xor, threads);
        cudaDeviceSynchronize();

        int h; cudaMemcpy(&h,d_diff,4,cudaMemcpyDeviceToHost);
        if(h < overall_best){
            overall_best = h;
            cudaMemcpy(d_seed_msg, d_msg, 64, cudaMemcpyDeviceToDevice);
            printf("  A%2d: %d bits ***\n",epoch,h);
        } else if(epoch%10==0){
            printf("  A%2d: best=%d\n",epoch,overall_best);
        }

        if(overall_best == 0){
            printf("\n  ╔══════════════════════════════╗\n");
            printf("  ║  SHA-256 COLLISION FOUND!!!   ║\n");
            printf("  ╚══════════════════════════════╝\n");
            uint32_t hm[16],hx[8];
            cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);
            cudaMemcpy(hx,d_xor,32,cudaMemcpyDeviceToHost);
            printf("  M: ");for(int i=0;i<16;i++)printf("%08x ",hm[i]);printf("\n");
            printf("  XOR: ");for(int i=0;i<8;i++)printf("%08x ",hx[i]);printf("\n");
            break;
        }
        if(overall_best < 40) printf("  *** NEAR: %d bits ***\n", overall_best);
    }

    printf("\n═══════════════════════════════════════\n");
    printf("FINAL: %d bits internal state diff\n", overall_best);
    printf("Random: 128. Advantage: 2^%d\n", 128-overall_best);
    printf("Total messages tested: ~%.0fM + annealing\n",
           n_deltas*10.0*threads*msgs_per_thread/1e6);

    cudaFree(d_diff);cudaFree(d_delta);cudaFree(d_msg);
    cudaFree(d_xor);cudaFree(d_seed_msg);
    return 0;
}

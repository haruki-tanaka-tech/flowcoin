/*
 * SHA-256 Diverse Delta Search — Escape 74-bit basin
 * ====================================================
 *
 * All previous runs converge to 74 bits with similar delta patterns.
 * Need fundamentally different delta structures.
 *
 * Strategies:
 *   1. NO algebraic d[0,1] — let ALL 16 words be free
 *   2. High hamming weight deltas (many bits, not 1-bit)
 *   3. Structured deltas: all-ones, alternating, shifted
 *   4. Single-word delta (only 1 word differs)
 *   5. Two-word delta with large values
 *
 * Measure internal STATE diff at round 64 (not output with IV add).
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,550,1835,20091 diverse_search.cu -o diverse
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

// Internal state diff at round 64 (NO IV addition — pure compression diff)
__device__
int state_diff_r64(const uint32_t W[16], const uint32_t d[16]) {
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
    return popcnt(a1^a2)+popcnt(b1^b2)+popcnt(c1^c2)+popcnt(d1^d2)+
           popcnt(e1^e2)+popcnt(f1^f2)+popcnt(g1^g2)+popcnt(h1^h2);
}

// Strategy 1: Single-word delta (only d[k] nonzero, no algebraic constraints)
__global__
void search_single_word(uint64_t seed, int delta_word,
                        int* best_diff, uint32_t* best_delta, uint32_t* best_msg,
                        int n_trials) {
    int tid=blockIdx.x*blockDim.x+threadIdx.x;
    if(tid>=n_trials) return;
    uint64_t rng=seed+tid*6364136223846793005ULL+1;

    uint32_t W[16],d[16]={0};
    for(int i=0;i<16;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;W[i]=(uint32_t)(rng>>32);}
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[delta_word]=(uint32_t)(rng>>32); // full random 32-bit delta
    if(!d[delta_word]) d[delta_word]=1;

    int bits=state_diff_r64(W,d);
    int old=atomicMin(best_diff,bits);
    if(bits<old){for(int i=0;i<16;i++){best_delta[i]=d[i];best_msg[i]=W[i];}}
}

// Strategy 2: Two-word delta with annealing
__global__
void search_two_word(uint64_t seed, int w1_idx, int w2_idx,
                     int n_steps, float temp_start, float temp_end,
                     int* best_diff, uint32_t* best_delta, uint32_t* best_msg,
                     int n_threads) {
    int tid=blockIdx.x*blockDim.x+threadIdx.x;
    if(tid>=n_threads) return;
    uint64_t rng=seed+tid*6364136223846793005ULL+1;

    uint32_t W[16],d[16]={0};
    for(int i=0;i<16;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;W[i]=(uint32_t)(rng>>32);}
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[w1_idx]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[w2_idx]=1u<<((int)(rng>>32)&31);

    int cur=state_diff_r64(W,d);
    int local_best=cur;
    uint32_t bd[16],bW[16];
    for(int i=0;i<16;i++){bd[i]=d[i];bW[i]=W[i];}

    float temp=temp_start,decay=powf(temp_end/temp_start,1.0f/(float)n_steps);
    for(int s=0;s<n_steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);
        uint32_t td[16],tW[16];
        for(int i=0;i<16;i++){td[i]=d[i];tW[i]=W[i];}

        int mut=r%6;
        if(mut==0) td[w1_idx]^=1u<<((r>>4)&31);
        else if(mut==1) td[w2_idx]^=1u<<((r>>4)&31);
        else if(mut==2) tW[(r>>4)&15]^=1u<<((r>>8)&31);
        else if(mut==3){rng=rng*6364136223846793005ULL+1442695040888963407ULL;tW[(r>>4)&15]=(uint32_t)(rng>>32);}
        else if(mut==4){td[w1_idx]=1u<<((r>>4)&31);}
        else{td[w2_idx]=1u<<((r>>4)&31);}

        if(!td[w1_idx]&&!td[w2_idx]) continue;
        int ts=state_diff_r64(tW,td);

        bool accept=(ts<cur);
        if(!accept&&temp>0.01f){
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)(ts-cur)/temp);
        }
        if(accept){cur=ts;for(int i=0;i<16;i++){d[i]=td[i];W[i]=tW[i];}}
        if(ts<local_best){local_best=ts;for(int i=0;i<16;i++){bd[i]=td[i];bW[i]=tW[i];}}
        temp*=decay;
    }
    int old=atomicMin(best_diff,local_best);
    if(local_best<old){for(int i=0;i<16;i++){best_delta[i]=bd[i];best_msg[i]=bW[i];}}
}

// Strategy 3: Free-form delta annealing (ALL words free, no algebraic)
__global__
void search_freeform(uint64_t seed, int n_steps,
                     float temp_start, float temp_end,
                     int* best_diff, uint32_t* best_delta, uint32_t* best_msg,
                     int n_threads) {
    int tid=blockIdx.x*blockDim.x+threadIdx.x;
    if(tid>=n_threads) return;
    uint64_t rng=seed+tid*6364136223846793005ULL+1;

    uint32_t W[16],d[16]={0};
    for(int i=0;i<16;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;W[i]=(uint32_t)(rng>>32);}

    // Random sparse delta: 2-4 words, 1-2 bits each
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int nw=2+((int)(rng>>32)%3);
    for(int f=0;f<nw;f++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        d[(int)(rng>>32)&15]=1u<<((int)((rng>>16)&31));
    }

    int cur=state_diff_r64(W,d);
    int local_best=cur;
    uint32_t bd[16],bW[16];
    for(int i=0;i<16;i++){bd[i]=d[i];bW[i]=W[i];}

    float temp=temp_start,decay=powf(temp_end/temp_start,1.0f/(float)n_steps);
    for(int s=0;s<n_steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);
        uint32_t td[16],tW[16];
        for(int i=0;i<16;i++){td[i]=d[i];tW[i]=W[i];}

        int mut=r%8;
        if(mut<=2) td[(r>>4)&15]^=1u<<((r>>8)&31);
        else if(mut==3) td[(r>>4)&15]=0;
        else if(mut==4) td[(r>>4)&15]=1u<<((r>>8)&31);
        else if(mut<=6) tW[(r>>4)&15]^=1u<<((r>>8)&31);
        else{rng=rng*6364136223846793005ULL+1442695040888963407ULL;tW[(r>>4)&15]=(uint32_t)(rng>>32);}

        uint32_t any=0;for(int i=0;i<16;i++)any|=td[i];if(!any)continue;
        int ts=state_diff_r64(tW,td);

        bool accept=(ts<cur);
        if(!accept&&temp>0.01f){
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)(ts-cur)/temp);
        }
        if(accept){cur=ts;for(int i=0;i<16;i++){d[i]=td[i];W[i]=tW[i];}}
        if(ts<local_best){local_best=ts;for(int i=0;i<16;i++){bd[i]=td[i];bW[i]=tW[i];}}
        temp*=decay;
    }
    int old=atomicMin(best_diff,local_best);
    if(local_best<old){for(int i=0;i<16;i++){best_delta[i]=bd[i];best_msg[i]=bW[i];}}
}

int main(){
    printf("SHA-256 Diverse Delta Search — Escape 74-bit basin\n");
    printf("═══════════════════════════════════════════════════\n");
    printf("Internal state diff (no IV add). Multiple strategies.\n\n");

    int *d_diff;
    uint32_t *d_delta,*d_msg;
    cudaMalloc(&d_diff,4);cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);

    int threads=1<<19;
    int thermal_ms=500;

    // ── Strategy 1: Single-word delta ──
    printf("=== Strategy 1: Single word delta (d[k] only) ===\n");
    for(int w=0;w<16;w++){
        struct timespec ts={0,thermal_ms*1000000L};nanosleep(&ts,NULL);
        int h=256;cudaMemcpy(d_diff,&h,4,cudaMemcpyHostToDevice);
        search_single_word<<<threads/256,256>>>(w*99991ULL,w,d_diff,d_delta,d_msg,threads);
        cudaDeviceSynchronize();
        cudaMemcpy(&h,d_diff,4,cudaMemcpyDeviceToHost);
        printf("  d[%2d] only: min diff = %d bits\n",w,h);
    }

    // ── Strategy 2: Best two-word pairs ──
    printf("\n=== Strategy 2: Two-word delta (anneal) ===\n");
    int global_best=256;
    int best_w1=-1,best_w2=-1;
    for(int w1=0;w1<16;w1+=2){
        for(int w2=w1+1;w2<16;w2+=2){
            struct timespec ts={0,200*1000000L};nanosleep(&ts,NULL);
            int h=256;cudaMemcpy(d_diff,&h,4,cudaMemcpyHostToDevice);
            search_two_word<<<threads/256,256>>>(w1*1000+w2,w1,w2,
                2048,3000.0f,0.01f,d_diff,d_delta,d_msg,threads);
            cudaDeviceSynchronize();
            cudaMemcpy(&h,d_diff,4,cudaMemcpyDeviceToHost);
            if(h<global_best){
                global_best=h;best_w1=w1;best_w2=w2;
                printf("  d[%d]+d[%d]: %d bits *** best ***\n",w1,w2,h);
            }
        }
    }
    printf("  Best pair: d[%d]+d[%d] = %d bits\n",best_w1,best_w2,global_best);

    // ── Strategy 3: Free-form (no algebraic constraints) ──
    printf("\n=== Strategy 3: Free-form annealing (no constraints) ===\n");
    int ff_best=256;
    for(int epoch=0;epoch<30;epoch++){
        struct timespec ts={0,thermal_ms*1000000L};nanosleep(&ts,NULL);
        int h=256;cudaMemcpy(d_diff,&h,4,cudaMemcpyHostToDevice);
        search_freeform<<<threads/256,256>>>(epoch*77713ULL,4096,
            3000.0f+epoch*500.0f,0.01f,d_diff,d_delta,d_msg,threads);
        cudaDeviceSynchronize();
        cudaMemcpy(&h,d_diff,4,cudaMemcpyDeviceToHost);
        if(h<ff_best){
            ff_best=h;
            uint32_t hd[16],hm[16];
            cudaMemcpy(hd,d_delta,64,cudaMemcpyDeviceToHost);
            cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);
            int dw=0,db=0;
            for(int i=0;i<16;i++)if(hd[i]){dw++;db+=popcnt(hd[i]);}
            printf("  E%2d: %d bits (%dw %db)\n",epoch,h,dw,db);

            if(h==0){
                printf("\n  *** ZERO DIFF FOUND — VERIFYING ***\n");
                printf("  M:     ");for(int i=0;i<16;i++)printf("%08x ",hm[i]);printf("\n");
                printf("  Delta: ");for(int i=0;i<16;i++)printf("%08x ",hd[i]);printf("\n");
                printf("  M':    ");for(int i=0;i<16;i++)printf("%08x ",hm[i]^hd[i]);printf("\n");
                // Check delta is truly nonzero
                uint32_t any=0;for(int i=0;i<16;i++)any|=hd[i];
                printf("  Delta nonzero: %s\n", any?"YES":"NO (BUG!)");
                if(!any) printf("  FALSE ALARM: delta converged to zero\n");
            }
        } else if(epoch%10==0){
            printf("  E%2d: best=%d\n",epoch,ff_best);
        }
    }

    printf("\n═══════════════════════════════════════\n");
    printf("RESULTS:\n");
    printf("  Single-word: see above\n");
    printf("  Two-word:    %d bits (d[%d]+d[%d])\n",global_best,best_w1,best_w2);
    printf("  Free-form:   %d bits\n",ff_best);
    printf("  Previous:    74 bits (with algebraic d[0,1])\n");

    cudaFree(d_diff);cudaFree(d_delta);cudaFree(d_msg);
    return 0;
}

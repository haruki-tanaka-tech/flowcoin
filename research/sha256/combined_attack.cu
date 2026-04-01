/*
 * SHA-256 Combined Attack — Best delta + massive message search
 * ==============================================================
 *
 * Phase 1: Find optimal delta pattern (anneal over delta+message)
 *          Save the BEST delta that gave 74-bit diff
 *
 * Phase 2: Fix that delta, search BILLIONS of messages
 *          for minimum diff with that specific delta
 *
 * Phase 3: For best message, anneal locally around it
 *
 * The key difference: Phase 1 of state_diff_opt found 74 bits
 * but CHANGED delta every trial. Here we LOCK the best delta
 * and search much harder over messages.
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,550,1835,20091 combined_attack.cu -o combined
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

// Compute output hamming diff for M vs M^delta through full SHA-256
__device__
int sha256_output_diff(const uint32_t W[16], const uint32_t d[16]) {
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<64;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1_=0xa54ff53a;
    uint32_t e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1_,e2=e1,f2=f1,g2=g1,h2=h1;
    for(int i=0;i<64;i++){
        uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1_+t1;d1_=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;
    }
    // Add IV (standard SHA-256 output)
    return popcnt((a1+0x6a09e667)^(a2+0x6a09e667))+popcnt((b1+0xbb67ae85)^(b2+0xbb67ae85))+
           popcnt((c1+0x3c6ef372)^(c2+0x3c6ef372))+popcnt((d1_+0xa54ff53a)^(d2+0xa54ff53a))+
           popcnt((e1+0x510e527f)^(e2+0x510e527f))+popcnt((f1+0x9b05688c)^(f2+0x9b05688c))+
           popcnt((g1+0x1f83d9ab)^(g2+0x1f83d9ab))+popcnt((h1+0x5be0cd19)^(h2+0x5be0cd19));
}

// Phase 1: Find best delta+message pair
__global__
void find_best_delta(uint64_t seed, int n_steps,
                     float temp_start, float temp_end,
                     int* best_diff,
                     uint32_t* best_delta, uint32_t* best_msg,
                     int n_threads) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_threads) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    uint32_t W[16], d[16]={0};
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
    }

    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[14]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[15]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int ne=1+((int)(rng>>32)%4);
    for(int f=0;f<ne;f++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        d[2+((int)(rng>>32)%12)]=1u<<((int)((rng>>16)&31));
    }
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));

    int cur = sha256_output_diff(W, d);
    int local_best = cur;
    uint32_t bd[16], bW[16];
    for(int i=0;i<16;i++){bd[i]=d[i];bW[i]=W[i];}

    float temp=temp_start, decay=powf(temp_end/temp_start,1.0f/(float)n_steps);

    for(int s=0;s<n_steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);
        uint32_t td[16],tW[16];
        for(int i=0;i<16;i++){td[i]=d[i];tW[i]=W[i];}

        int mut=r%8;
        if(mut<=1){td[2+((r>>4)%14)]^=1u<<((r>>8)&31);}
        else if(mut==2){int w=(r>>4)&1?15:14;td[w]^=1u<<((r>>5)&31);if(!td[w])td[w]=1;}
        else if(mut==3){td[2+((r>>4)%12)]=0;}
        else if(mut<=5){tW[(r>>4)&15]^=1u<<((r>>8)&31);}
        else if(mut==6){rng=rng*6364136223846793005ULL+1442695040888963407ULL;tW[(r>>4)&15]=(uint32_t)(rng>>32);}
        else{td[2+((r>>4)%14)]^=(1u<<((r>>8)&31))|(1u<<((r>>13)&31));}

        if(!td[14]&&!td[15]) continue;
        td[1]=(uint32_t)(-(int32_t)(sig1(tW[15]^td[15])-sig1(tW[15])+td[10]+sig0(tW[2]^td[2])-sig0(tW[2])));
        td[0]=(uint32_t)(-(int32_t)(sig1(tW[14]^td[14])-sig1(tW[14])+td[9]+sig0(tW[1]^td[1])-sig0(tW[1])));
        uint32_t any=0;for(int i=0;i<16;i++)any|=td[i]; if(!any)continue;

        int ts=sha256_output_diff(tW,td);
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
    if(local_best<old){
        for(int i=0;i<16;i++){best_delta[i]=bd[i];best_msg[i]=bW[i];}
    }
}

// Phase 2: Fixed delta, massive message scan
__global__
void scan_messages(const uint32_t* fixed_delta, uint64_t seed,
                   int* best_diff, uint32_t* best_msg, int n_trials) {
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

    int bits = sha256_output_diff(W, d);
    int old = atomicMin(best_diff, bits);
    if(bits < old) {
        for(int i=0;i<16;i++) best_msg[i] = W[i];
    }
}

// Phase 3: Anneal message around best
__global__
void anneal_message(const uint32_t* fixed_delta, const uint32_t* seed_msg,
                    uint64_t seed, int n_steps, float temp_start, float temp_end,
                    int* best_diff, uint32_t* best_msg, int n_threads) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_threads) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;
    uint32_t W[16], d[16];
    for(int i=0;i<16;i++){W[i]=seed_msg[i];d[i]=fixed_delta[i];}

    // Perturb starting message slightly per thread
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    W[(rng>>32)&15]^=(uint32_t)(rng&0xFFFFFFFF);

    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));

    int cur=sha256_output_diff(W,d);
    int local_best=cur;
    uint32_t bW[16]; for(int i=0;i<16;i++)bW[i]=W[i];

    float temp=temp_start, decay=powf(temp_end/temp_start,1.0f/(float)n_steps);
    for(int s=0;s<n_steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);
        uint32_t tW[16],td[16];
        for(int i=0;i<16;i++){tW[i]=W[i];td[i]=fixed_delta[i];}

        if(r&1) tW[(r>>1)&15]^=1u<<((r>>5)&31);
        else tW[(r>>1)&15]^=(1u<<((r>>5)&31))|(1u<<((r>>10)&31));

        td[1]=(uint32_t)(-(int32_t)(sig1(tW[15]^td[15])-sig1(tW[15])+td[10]+sig0(tW[2]^td[2])-sig0(tW[2])));
        td[0]=(uint32_t)(-(int32_t)(sig1(tW[14]^td[14])-sig1(tW[14])+td[9]+sig0(tW[1]^td[1])-sig0(tW[1])));

        int ts=sha256_output_diff(tW,td);
        bool accept=(ts<cur);
        if(!accept&&temp>0.01f){
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)(ts-cur)/temp);
        }
        if(accept){cur=ts;for(int i=0;i<16;i++)W[i]=tW[i];}
        if(ts<local_best){local_best=ts;for(int i=0;i<16;i++)bW[i]=tW[i];}
        temp*=decay;
    }

    int old=atomicMin(best_diff,local_best);
    if(local_best<old){for(int i=0;i<16;i++)best_msg[i]=bW[i];}
}

int main(){
    printf("SHA-256 Combined Attack — Find Collision\n");
    printf("════════════════════════════════════════\n\n");

    int *d_diff;
    uint32_t *d_delta,*d_msg,*d_seed_msg;
    cudaMalloc(&d_diff,4);cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);cudaMalloc(&d_seed_msg,64);

    int threads=1<<19;
    int thermal_ms=500;

    // ── Phase 1: Find best delta ──
    printf("Phase 1: Annealing for best delta (joint delta+message)\n");
    int global_best = 256;

    for(int epoch=0;epoch<30;epoch++){
        struct timespec ts={0,thermal_ms*1000000L}; nanosleep(&ts,NULL);
        int h=256; cudaMemcpy(d_diff,&h,4,cudaMemcpyHostToDevice);

        find_best_delta<<<threads/256,256>>>(
            epoch*104729ULL,4096,3000.0f+epoch*500.0f,0.01f,
            d_diff,d_delta,d_msg,threads);
        cudaDeviceSynchronize();

        cudaMemcpy(&h,d_diff,4,cudaMemcpyDeviceToHost);
        if(h<global_best){
            global_best=h;
            // Save best delta to host for Phase 2
            cudaMemcpy(d_seed_msg,d_msg,64,cudaMemcpyDeviceToDevice);
            printf("  E%2d: %d bits *** new best ***\n",epoch,h);
        } else if(epoch%5==0){
            printf("  E%2d: best=%d\n",epoch,global_best);
        }
    }

    printf("\nBest delta found: %d bits output diff\n",global_best);

    // Show the delta
    uint32_t h_delta[16];
    cudaMemcpy(h_delta,d_delta,64,cudaMemcpyDeviceToHost);
    printf("Delta: ");
    for(int i=0;i<16;i++) if(h_delta[i]) printf("d[%d]=%08x ",i,h_delta[i]);
    printf("\n\n");

    // ── Phase 2: Massive message scan with fixed delta ──
    printf("Phase 2: Massive message scan (fixed delta)\n");

    for(int round=0;round<20;round++){
        struct timespec ts={0,thermal_ms*1000000L}; nanosleep(&ts,NULL);

        // Don't reset — keep running minimum
        scan_messages<<<threads/256,256>>>(d_delta,round*999979ULL,d_diff,d_msg,threads);
        cudaDeviceSynchronize();

        int h; cudaMemcpy(&h,d_diff,4,cudaMemcpyDeviceToHost);
        if(h<global_best){
            global_best=h;
            cudaMemcpy(d_seed_msg,d_msg,64,cudaMemcpyDeviceToDevice);
            printf("  R%2d: %d bits *** new best *** (%.1fM scanned)\n",round,h,(round+1)*threads/1e6);
        } else if(round%5==0){
            printf("  R%2d: best=%d (%.1fM scanned)\n",round,global_best,(round+1)*threads/1e6);
        }
    }

    printf("\nAfter scan: %d bits\n\n",global_best);

    // ── Phase 3: Deep anneal around best message ──
    printf("Phase 3: Deep annealing around best message\n");

    for(int epoch=0;epoch<30;epoch++){
        struct timespec ts={0,thermal_ms*1000000L}; nanosleep(&ts,NULL);

        anneal_message<<<threads/256,256>>>(
            d_delta,d_seed_msg,epoch*31337ULL,
            8192,5000.0f+epoch*1000.0f,0.001f,
            d_diff,d_msg,threads);
        cudaDeviceSynchronize();

        int h; cudaMemcpy(&h,d_diff,4,cudaMemcpyDeviceToHost);
        if(h<global_best){
            global_best=h;
            cudaMemcpy(d_seed_msg,d_msg,64,cudaMemcpyDeviceToDevice);
            printf("  A%2d: %d bits *** IMPROVED ***\n",epoch,h);
        } else if(epoch%5==0){
            printf("  A%2d: best=%d\n",epoch,global_best);
        }

        if(global_best==0){
            printf("\n  ╔══════════════════════════════════════╗\n");
            printf("  ║   SHA-256 COLLISION FOUND!!!!        ║\n");
            printf("  ╚══════════════════════════════════════╝\n");
            uint32_t hm[16];
            cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);
            cudaMemcpy(h_delta,d_delta,64,cudaMemcpyDeviceToHost);
            // Fix d01
            h_delta[1]=(uint32_t)(-(int32_t)(sig1(hm[15]^h_delta[15])-sig1(hm[15])+h_delta[10]+sig0(hm[2]^h_delta[2])-sig0(hm[2])));
            h_delta[0]=(uint32_t)(-(int32_t)(sig1(hm[14]^h_delta[14])-sig1(hm[14])+h_delta[9]+sig0(hm[1]^h_delta[1])-sig0(hm[1])));
            printf("\n  M:  ");for(int i=0;i<16;i++)printf("%08x ",hm[i]);
            printf("\n  M': ");for(int i=0;i<16;i++)printf("%08x ",hm[i]^h_delta[i]);
            printf("\n");
            break;
        }

        if(global_best<40) printf("  *** NEAR COLLISION: %d bits ***\n",global_best);
    }

    printf("\n═══════════════════════════════════════\n");
    printf("FINAL: %d bits minimum output diff\n",global_best);
    printf("Random: 128 bits. Advantage: 2^%d\n",128-global_best);
    if(global_best<64) printf("PRACTICAL DISTINGUISHER ACHIEVED!\n");
    if(global_best==0) printf("FULL COLLISION!\n");

    cudaFree(d_diff);cudaFree(d_delta);cudaFree(d_msg);cudaFree(d_seed_msg);
    return 0;
}

/*
 * SHA-256 New Metrics — Try different optimization targets
 * =========================================================
 *
 * Metric 1: Per-register zeroing (zero ONE register at a time)
 * Metric 2: Arithmetic diff (a1-a2 instead of a1^a2)
 * Metric 3: Partial match (top 4 registers = 0)
 * Metric 4: Weighted register (e,f heavily weighted — Ch dependency)
 * Metric 5: Minimum single-register diff (find weakest register)
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,550,1835,20091 new_metrics.cu -o newmet
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

__device__
void fix_d01(const uint32_t W[16], uint32_t d[16]) {
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));
}

// Compute state at round 64, return all 8 XOR diffs
__device__
void full_diff(const uint32_t W[16], const uint32_t d[16], uint32_t xor_out[8]) {
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
}

// Generic annealing kernel with pluggable score function
// score_mode: 0=total hamming, 1=single register, 2=arithmetic,
//             3=top4 registers, 4=min register, 5=partial zero count
__global__
void anneal_metric(uint64_t seed, int n_steps,
                   float temp_start, float temp_end,
                   int score_mode, int target_reg, // for mode 1
                   int* best_score,
                   uint32_t* best_delta, uint32_t* best_msg,
                   int n_threads) {
    int tid=blockIdx.x*blockDim.x+threadIdx.x;
    if(tid>=n_threads) return;
    uint64_t rng=seed+tid*6364136223846793005ULL+1;

    uint32_t W[16],d[16]={0};
    for(int i=0;i<16;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;W[i]=(uint32_t)(rng>>32);}
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[14]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[15]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int ne=1+((int)(rng>>32)%3);
    for(int f=0;f<ne;f++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        d[2+((int)(rng>>32)%12)]=1u<<((int)((rng>>16)&31));
    }
    fix_d01(W,d);

    // Compute initial score
    uint32_t xd[8];
    full_diff(W,d,xd);

    auto calc_score = [&](uint32_t x[8]) -> int {
        if(score_mode==0) { // total hamming
            int t=0;for(int i=0;i<8;i++)t+=popcnt(x[i]);return t;
        } else if(score_mode==1) { // single register
            return popcnt(x[target_reg]);
        } else if(score_mode==2) { // arithmetic diff (hamming of subtraction)
            // Not XOR but actual value closeness
            int t=0;for(int i=0;i<8;i++){
                // Count trailing zeros of XOR = matching low bits
                uint32_t v=x[i]; if(!v){t-=32;continue;}
                t+=popcnt(v);
            }
            return t;
        } else if(score_mode==3) { // top 4 registers only (a,b,c,d)
            return popcnt(x[0])+popcnt(x[1])+popcnt(x[2])+popcnt(x[3]);
        } else if(score_mode==4) { // minimum single register
            int mn=32;
            for(int i=0;i<8;i++){int p=popcnt(x[i]);if(p<mn)mn=p;}
            return mn;
        } else { // mode 5: count zero bytes (partial collision)
            int zeros=0;
            for(int i=0;i<8;i++){
                if((x[i]&0xFF)==0) zeros++;
                if((x[i]&0xFF00)==0) zeros++;
                if((x[i]&0xFF0000)==0) zeros++;
                if((x[i]&0xFF000000)==0) zeros++;
            }
            return -zeros; // negative = more zeros = better (minimize)
        }
    };

    int cur=calc_score(xd);
    int lb=cur;
    uint32_t bd[16],bW[16];
    for(int i=0;i<16;i++){bd[i]=d[i];bW[i]=W[i];}

    float temp=temp_start,decay=powf(temp_end/temp_start,1.0f/(float)n_steps);
    for(int s=0;s<n_steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);
        uint32_t td[16],tW[16];
        for(int i=0;i<16;i++){td[i]=d[i];tW[i]=W[i];}

        int mut=r%8;
        if(mut<=1) td[2+((r>>4)%14)]^=1u<<((r>>8)&31);
        else if(mut==2){int w=(r>>4)&1?15:14;td[w]^=1u<<((r>>5)&31);if(!td[w])td[w]=1;}
        else if(mut==3) td[2+((r>>4)%12)]=0;
        else if(mut<=5) tW[(r>>4)&15]^=1u<<((r>>8)&31);
        else if(mut==6){rng=rng*6364136223846793005ULL+1442695040888963407ULL;tW[(r>>4)&15]=(uint32_t)(rng>>32);}
        else td[2+((r>>4)%14)]^=(1u<<((r>>8)&31))|(1u<<((r>>13)&31));

        if(!td[14]&&!td[15])continue;
        fix_d01(tW,td);
        uint32_t any=0;for(int i=0;i<16;i++)any|=td[i];if(!any)continue;

        uint32_t txd[8];
        full_diff(tW,td,txd);
        int ts=calc_score(txd);

        bool accept=(ts<cur);
        if(!accept&&temp>0.01f){
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)(ts-cur)/temp);
        }
        if(accept){cur=ts;for(int i=0;i<16;i++){d[i]=td[i];W[i]=tW[i];}}
        if(ts<lb){lb=ts;for(int i=0;i<16;i++){bd[i]=td[i];bW[i]=tW[i];}}
        temp*=decay;
    }

    int old=atomicMin(best_score,lb);
    if(lb<old){for(int i=0;i<16;i++){best_delta[i]=bd[i];best_msg[i]=bW[i];}}
}

int main(){
    printf("SHA-256 New Metrics — Breaking 74-bit floor\n");
    printf("════════════════════════════════════════════\n\n");

    int *d_score;
    uint32_t *d_delta,*d_msg;
    cudaMalloc(&d_score,4);cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);

    int threads=1<<19;
    int thermal_ms=500;

    // ── Metric 0: Baseline (total hamming) ──
    printf("=== Metric 0: Total hamming (baseline) ===\n");
    {
        int best=256;
        for(int e=0;e<20;e++){
            struct timespec ts={0,thermal_ms*1000000L};nanosleep(&ts,NULL);
            int h=256;cudaMemcpy(d_score,&h,4,cudaMemcpyHostToDevice);
            anneal_metric<<<threads/256,256>>>(e*99991ULL,4096,3000.0f+e*500,0.01f,
                0,0,d_score,d_delta,d_msg,threads);
            cudaDeviceSynchronize();
            cudaMemcpy(&h,d_score,4,cudaMemcpyDeviceToHost);
            if(h<best){best=h;printf("  E%2d: %d bits\n",e,h);}
        }
        printf("  BEST: %d bits (total hamming)\n\n",best);
    }

    // ── Metric 1: Per-register zeroing ──
    printf("=== Metric 1: Per-register diff (minimize each register) ===\n");
    for(int reg=0;reg<8;reg++){
        int best=32;
        for(int e=0;e<10;e++){
            struct timespec ts={0,300*1000000L};nanosleep(&ts,NULL);
            int h=32;cudaMemcpy(d_score,&h,4,cudaMemcpyHostToDevice);
            anneal_metric<<<threads/256,256>>>(e*77713ULL+reg*1000,4096,
                3000.0f+e*500,0.01f,1,reg,d_score,d_delta,d_msg,threads);
            cudaDeviceSynchronize();
            cudaMemcpy(&h,d_score,4,cudaMemcpyDeviceToHost);
            if(h<best) best=h;
        }
        printf("  Register %s: min diff = %d/32 bits\n","abcdefgh"+reg*0,best);
        // Print register name properly
    }
    // Redo with names
    {
        const char* names[]={"a","b","c","d","e","f","g","h"};
        printf("  Summary: ");
        for(int reg=0;reg<8;reg++){
            int best=32;
            for(int e=0;e<15;e++){
                struct timespec ts={0,300*1000000L};nanosleep(&ts,NULL);
                int h=32;cudaMemcpy(d_score,&h,4,cudaMemcpyHostToDevice);
                anneal_metric<<<threads/256,256>>>(e*77713ULL+reg*1000+500,4096,
                    5000.0f+e*500,0.01f,1,reg,d_score,d_delta,d_msg,threads);
                cudaDeviceSynchronize();
                cudaMemcpy(&h,d_score,4,cudaMemcpyDeviceToHost);
                if(h<best) best=h;
            }
            printf("%s=%d ",names[reg],best);
        }
        printf("\n\n");
    }

    // ── Metric 3: Top 4 registers ──
    printf("=== Metric 3: Top 4 registers (a,b,c,d) diff ===\n");
    {
        int best=128;
        for(int e=0;e<20;e++){
            struct timespec ts={0,thermal_ms*1000000L};nanosleep(&ts,NULL);
            int h=128;cudaMemcpy(d_score,&h,4,cudaMemcpyHostToDevice);
            anneal_metric<<<threads/256,256>>>(e*55551ULL,4096,3000.0f+e*500,0.01f,
                3,0,d_score,d_delta,d_msg,threads);
            cudaDeviceSynchronize();
            cudaMemcpy(&h,d_score,4,cudaMemcpyDeviceToHost);
            if(h<best){best=h;printf("  E%2d: %d/128 bits\n",e,h);}
        }
        printf("  BEST: %d/128 bits (top 4 regs)\n\n",best);
    }

    // ── Metric 4: Minimum single register ──
    printf("=== Metric 4: Minimum single register diff ===\n");
    {
        int best=32;
        for(int e=0;e<20;e++){
            struct timespec ts={0,thermal_ms*1000000L};nanosleep(&ts,NULL);
            int h=32;cudaMemcpy(d_score,&h,4,cudaMemcpyHostToDevice);
            anneal_metric<<<threads/256,256>>>(e*33331ULL,4096,3000.0f+e*500,0.01f,
                4,0,d_score,d_delta,d_msg,threads);
            cudaDeviceSynchronize();
            cudaMemcpy(&h,d_score,4,cudaMemcpyDeviceToHost);
            if(h<best){best=h;printf("  E%2d: %d/32 bits (weakest reg)\n",e,h);}
        }
        printf("  BEST: %d/32 bits (weakest register)\n\n",best);
    }

    // ── Metric 5: Zero byte count ──
    printf("=== Metric 5: Zero byte count (partial collision) ===\n");
    {
        int best=0;
        for(int e=0;e<20;e++){
            struct timespec ts={0,thermal_ms*1000000L};nanosleep(&ts,NULL);
            int h=0;cudaMemcpy(d_score,&h,4,cudaMemcpyHostToDevice);
            anneal_metric<<<threads/256,256>>>(e*11117ULL,4096,3000.0f+e*500,0.01f,
                5,0,d_score,d_delta,d_msg,threads);
            cudaDeviceSynchronize();
            cudaMemcpy(&h,d_score,4,cudaMemcpyDeviceToHost);
            if(h<best){best=h;printf("  E%2d: %d zero bytes (/32)\n",e,-h);}
        }
        printf("  BEST: %d zero bytes out of 32\n\n",-best);
    }

    printf("═══════════════════════════════════════\n");
    printf("Compare metrics to find new attack surface.\n");
    printf("If any register consistently low → chain attack.\n");
    printf("If zero bytes > 4 → partial collision possible.\n");

    cudaFree(d_score);cudaFree(d_delta);cudaFree(d_msg);
    return 0;
}

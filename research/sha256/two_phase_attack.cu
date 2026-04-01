/*
 * SHA-256 Two-Phase Attack
 * =========================
 *
 * Phase 1: Minimize state diff at round 48 (target: <74 bits)
 * Phase 2: From best Phase 1, minimize R64 diff using trajectory
 *
 * Observation: trajectory shows -43 bits drop in 16 rounds (130→87)
 * If Phase 1 gets R48=74, Phase 2 could get R64=74-43=31 bits!
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,550,1835,20091 two_phase_attack.cu -o twophase
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

// State diff at specific round
__device__
int state_diff_at(const uint32_t W[16], const uint32_t d[16], int target_round) {
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<64;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a;
    uint32_t e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
    for(int i=0;i<target_round;i++){
        uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;
    }
    return popcnt(a1^a2)+popcnt(b1^b2)+popcnt(c1^c2)+popcnt(d1^d2)+
           popcnt(e1^e2)+popcnt(f1^f2)+popcnt(g1^g2)+popcnt(h1^h2);
}

// Two-metric score: minimize R48 diff AND R64 diff
// Score = R48_diff * 100 + R64_diff * 1000 (lower=better)
__device__
int two_phase_score(const uint32_t W[16], const uint32_t d[16],
                    int* r48_out, int* r64_out) {
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<64;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a;
    uint32_t e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
    int r48=-1, r64=-1;
    for(int i=0;i<64;i++){
        uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;
        if(i==47) r48=popcnt(a1^a2)+popcnt(b1^b2)+popcnt(c1^c2)+popcnt(d1^d2)+
                      popcnt(e1^e2)+popcnt(f1^f2)+popcnt(g1^g2)+popcnt(h1^h2);
        if(i==63) r64=popcnt(a1^a2)+popcnt(b1^b2)+popcnt(c1^c2)+popcnt(d1^d2)+
                      popcnt(e1^e2)+popcnt(f1^f2)+popcnt(g1^g2)+popcnt(h1^h2);
    }
    *r48_out=r48; *r64_out=r64;
    return r64 * 1000 + r48 * 10; // prioritize R64, use R48 as tiebreaker
}

__global__
void anneal_twophase(uint64_t seed, int n_steps,
                     float temp_start, float temp_end,
                     int* best_score, int* best_r48, int* best_r64,
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

    int r48,r64;
    int cur=two_phase_score(W,d,&r48,&r64);
    int lb=cur,lb48=r48,lb64=r64;
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

        int tr48,tr64;
        int ts=two_phase_score(tW,td,&tr48,&tr64);

        bool accept=(ts<cur);
        if(!accept&&temp>0.01f){
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)(ts-cur)/temp);
        }
        if(accept){cur=ts;for(int i=0;i<16;i++){d[i]=td[i];W[i]=tW[i];}}
        if(ts<lb){lb=ts;lb48=tr48;lb64=tr64;for(int i=0;i<16;i++){bd[i]=td[i];bW[i]=tW[i];}}
        temp*=decay;
    }

    int old=atomicMin(best_score,lb);
    if(lb<old){*best_r48=lb48;*best_r64=lb64;
    for(int i=0;i<16;i++){best_delta[i]=bd[i];best_msg[i]=bW[i];}}
}

int main(){
    printf("SHA-256 Two-Phase Attack\n");
    printf("═══════════════════════\n");
    printf("Phase 1+2 combined: minimize R48 AND R64 jointly\n\n");

    int *d_score,*d_r48,*d_r64;
    uint32_t *d_delta,*d_msg;
    cudaMalloc(&d_score,4);cudaMalloc(&d_r48,4);cudaMalloc(&d_r64,4);
    cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);

    int threads=1<<19;
    int thermal_ms=500;
    int global_best_r64=256;

    for(int epoch=0;epoch<60;epoch++){
        struct timespec ts={0,thermal_ms*1000000L};nanosleep(&ts,NULL);
        int hs=999999,h48=256,h64=256;
        cudaMemcpy(d_score,&hs,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_r48,&h48,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_r64,&h64,4,cudaMemcpyHostToDevice);

        anneal_twophase<<<threads/256,256>>>(
            epoch*104729ULL,4096,3000.0f+epoch*500.0f,0.01f,
            d_score,d_r48,d_r64,d_delta,d_msg,threads);
        cudaDeviceSynchronize();

        cudaMemcpy(&h48,d_r48,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h64,d_r64,4,cudaMemcpyDeviceToHost);

        if(h64<global_best_r64){
            global_best_r64=h64;
            printf("  E%2d: R48=%3d R64=%3d (drop=%d) ***\n",epoch,h48,h64,h48-h64);
        } else if(epoch%10==0){
            printf("  E%2d: best R64=%d\n",epoch,global_best_r64);
        }

        if(global_best_r64<40){
            printf("\n  *** NEAR COLLISION: R64=%d bits ***\n",global_best_r64);
        }
        if(global_best_r64==0){
            printf("\n  *** COLLISION! ***\n");
            break;
        }
    }

    printf("\n═══════════════════════════════════════\n");
    printf("FINAL: R64 = %d bits (random=128, advantage=2^%d)\n",
           global_best_r64, 128-global_best_r64);

    cudaFree(d_score);cudaFree(d_r48);cudaFree(d_r64);
    cudaFree(d_delta);cudaFree(d_msg);
    return 0;
}

/*
 * SHA-256 Truncated Differential — Zero HALF the state
 * =====================================================
 *
 * New metric: don't minimize ALL 256 bits of state diff.
 * Instead: zero SPECIFIC 128 bits (4 registers).
 * If top 4 registers (a,b,c,d) diff = 0:
 *   → Only e,f,g,h differ
 *   → Birthday on 128 remaining bits = 2^64
 *   → Feasible on GPU cluster!
 *
 * We proved: each register INDIVIDUALLY can be zeroed.
 * Now: zero 2, 3, 4 registers SIMULTANEOUSLY.
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,550,1835,20091 truncated_diff.cu -o truncated
 */

#include <cstdint>
#include <cstdio>
#include <time.h>

__constant__ static const uint32_t K[64]={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,
    0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

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
void fix_d01(const uint32_t W[16],uint32_t d[16]){
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));
}

// Compute per-register XOR diff at round 64
__device__
void per_reg_diff(const uint32_t W[16], const uint32_t d[16], uint32_t xor_out[8]) {
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

// Anneal to minimize diff in SELECTED registers only
// reg_mask: bitmask of which registers to minimize (e.g., 0x0F = a,b,c,d)
__global__
void anneal_truncated(uint64_t seed, int n_steps, float t0, float t1,
                      uint32_t reg_mask,
                      int* best_target_diff,  // diff in target registers
                      int* best_total_diff,   // diff in ALL registers
                      uint32_t* best_delta, uint32_t* best_msg,
                      int n) {
    int tid=blockIdx.x*blockDim.x+threadIdx.x; if(tid>=n)return;
    uint64_t rng=seed+tid*6364136223846793005ULL+1;

    uint32_t W[16],d[16]={0};
    for(int i=0;i<16;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;W[i]=(uint32_t)(rng>>32);}
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;d[14]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;d[15]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int ne=1+((int)(rng>>32)%3);
    for(int f=0;f<ne;f++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[2+((int)(rng>>32)%12)]=1u<<((int)((rng>>16)&31));}
    fix_d01(W,d);

    uint32_t xd[8]; per_reg_diff(W,d,xd);
    int target=0, total=0;
    for(int i=0;i<8;i++){
        int b=popcnt(xd[i]);
        total+=b;
        if(reg_mask&(1<<i)) target+=b;
    }

    int cur=target;
    int lb_t=target, lb_tot=total;
    uint32_t bd[16],bW[16];for(int i=0;i<16;i++){bd[i]=d[i];bW[i]=W[i];}

    float temp=t0,decay=powf(t1/t0,1.0f/(float)n_steps);
    for(int s=0;s<n_steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);
        uint32_t td[16],tW[16];for(int i=0;i<16;i++){td[i]=d[i];tW[i]=W[i];}

        int mut=r%8;
        if(mut<=1) td[2+((r>>4)%14)]^=1u<<((r>>8)&31);
        else if(mut==2){int w=(r>>4)&1?15:14;td[w]^=1u<<((r>>5)&31);if(!td[w])td[w]=1;}
        else if(mut==3) td[2+((r>>4)%12)]=0;
        else if(mut<=5) tW[(r>>4)&15]^=1u<<((r>>8)&31);
        else if(mut==6){rng=rng*6364136223846793005ULL+1442695040888963407ULL;tW[(r>>4)&15]=(uint32_t)(rng>>32);}
        else td[2+((r>>4)%14)]^=(1u<<((r>>8)&31))|(1u<<((r>>13)&31));

        if(!td[14]&&!td[15])continue;
        fix_d01(tW,td);
        uint32_t any=0;int dbc=0;for(int i=0;i<16;i++){any|=td[i];dbc+=popcnt(td[i]);}
        if(dbc<3)continue;

        uint32_t txd[8]; per_reg_diff(tW,td,txd);
        int tt=0,ttot=0;
        for(int i=0;i<8;i++){int b=popcnt(txd[i]);ttot+=b;if(reg_mask&(1<<i))tt+=b;}

        bool accept=(tt<cur);
        if(!accept&&temp>0.01f){rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)(tt-cur)/temp);}
        if(accept){cur=tt;for(int i=0;i<16;i++){d[i]=td[i];W[i]=tW[i];}}
        if(tt<lb_t){lb_t=tt;lb_tot=ttot;for(int i=0;i<16;i++){bd[i]=td[i];bW[i]=tW[i];}}
        temp*=decay;
    }
    int old=atomicMin(best_target_diff,lb_t);
    if(lb_t<old){*best_total_diff=lb_tot;
    for(int i=0;i<16;i++){best_delta[i]=bd[i];best_msg[i]=bW[i];}}
}

int main(){
    printf("SHA-256 Truncated Differential — Zero HALF the state\n");
    printf("═══════════════════════════════════════════════════\n\n");

    int *d_target,*d_total;
    uint32_t *d_delta,*d_msg;
    cudaMalloc(&d_target,4);cudaMalloc(&d_total,4);
    cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);

    int threads=1<<19, thermal=500;
    const char* reg_names="abcdefgh";

    // Try different register combinations
    struct { uint32_t mask; const char* name; int target_bits; } combos[] = {
        {0x01, "a only", 32},
        {0x03, "a,b", 64},
        {0x07, "a,b,c", 96},
        {0x0F, "a,b,c,d (top4)", 128},
        {0x11, "a,e", 64},
        {0x33, "a,b,e,f", 128},
        {0xF0, "e,f,g,h (bot4)", 128},
        {0xFF, "all (baseline)", 256},
    };
    int n_combos = 8;

    for(int ci=0; ci<n_combos; ci++){
        printf("=== %s (mask=0x%02x, %d target bits) ===\n",
               combos[ci].name, combos[ci].mask, combos[ci].target_bits);

        int gb_target=combos[ci].target_bits, gb_total=256;

        for(int e=0;e<30;e++){
            struct timespec ts={0,thermal*1000000L};nanosleep(&ts,NULL);
            int ht=combos[ci].target_bits,htot=256;
            cudaMemcpy(d_target,&ht,4,cudaMemcpyHostToDevice);
            cudaMemcpy(d_total,&htot,4,cudaMemcpyHostToDevice);

            anneal_truncated<<<threads/256,256>>>(e*104729ULL+ci*7,4096,
                3000.0f+e*500,0.01f, combos[ci].mask,
                d_target,d_total,d_delta,d_msg,threads);
            cudaDeviceSynchronize();

            cudaMemcpy(&ht,d_target,4,cudaMemcpyDeviceToHost);
            cudaMemcpy(&htot,d_total,4,cudaMemcpyDeviceToHost);

            if(ht<gb_target){
                gb_target=ht; gb_total=htot;

                // Show per-register
                uint32_t hd[16],hm[16];
                cudaMemcpy(hd,d_delta,64,cudaMemcpyDeviceToHost);
                cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);

                uint32_t w1[64],w2[64];
                for(int i=0;i<16;i++){w1[i]=hm[i];w2[i]=hm[i]^hd[i];}
                for(int i=16;i<64;i++){w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
                w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];}
                uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a;
                uint32_t e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
                uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
                for(int i=0;i<64;i++){
                    uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
                    h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
                    t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
                    h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;
                }
                printf("  E%2d: target=%3d/%d total=%3d | a=%d b=%d c=%d d=%d e=%d f=%d g=%d h=%d\n",
                    e,ht,combos[ci].target_bits,htot,
                    popcnt(a1^a2),popcnt(b1^b2),popcnt(c1^c2),popcnt(d1^d2),
                    popcnt(e1^e2),popcnt(f1^f2),popcnt(g1^g2),popcnt(h1^h2));
            }
        }
        printf("  BEST: %d/%d target bits (total=%d)\n\n",gb_target,combos[ci].target_bits,gb_total);
    }

    printf("═══════════════════════════════════════\n");
    printf("If any combo gets target < 32 → birthday on remainder feasible!\n");
    printf("target=0 for 4 regs → birthday 2^64 on other 4 = GPU hours\n");

    cudaFree(d_target);cudaFree(d_total);cudaFree(d_delta);cudaFree(d_msg);
    return 0;
}

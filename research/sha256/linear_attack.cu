/*
 * SHA-256 Linear Approximation Attack
 * =====================================
 *
 * KEY INSIGHT: SHA-256 round = LINEAR(S0,S1) + MASKED(Ch,Maj)
 *   delta_Maj = delta_a & (b^c)  — mask = b^c
 *   delta_Ch  = delta_e & (f^g)  — mask = f^g
 *   If masks ≈ 0: round is LINEAR → diff predictable/controllable
 *
 * Strategy: optimize MESSAGE to minimize masks (b^c, f^g)
 * at rounds 28-40, THEN use linear system to find delta
 * that passes through these nearly-linear rounds.
 *
 * Score = sum of popcount(b^c) + popcount(f^g) at target rounds
 * Lower = more linear = easier to control differential
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,550,1835,20091 linear_attack.cu -o linear
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

// Compute nonlinearity masks at each round
// Returns total mask weight for rounds [from..to)
__device__
int mask_weight(const uint32_t W[16], int from, int to) {
    uint32_t w[64];
    for(int i=0;i<16;i++) w[i]=W[i];
    for(int i=16;i<64;i++) w[i]=sig1(w[i-2])+w[i-7]+sig0(w[i-15])+w[i-16];

    uint32_t a=0x6a09e667,b=0xbb67ae85,c=0x3c6ef372,d=0xa54ff53a;
    uint32_t e=0x510e527f,f=0x9b05688c,g=0x1f83d9ab,h=0x5be0cd19;

    int total = 0;
    for(int i=0;i<to;i++){
        uint32_t t1=h+S1(e)+CH(e,f,g)+K[i]+w[i];
        uint32_t t2=S0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;

        if(i >= from) {
            total += popcnt(b^c);  // Maj mask
            total += popcnt(f^g);  // Ch mask
        }
    }
    return total;
}

// Combined: minimize masks AND state diff
__device__
void combined_eval(const uint32_t W[16], const uint32_t delta[16],
                   int mask_from, int mask_to,
                   int* mask_out, int* diff_out) {
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^delta[i];}
    for(int i=16;i<64;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a;
    uint32_t e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
    int mask=0;
    for(int i=0;i<64;i++){
        uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;
        // Use the FIRST message's state for mask computation
        if(i>=mask_from && i<mask_to){
            mask+=popcnt(b1^c1)+popcnt(f1^g1);
        }
    }
    *mask_out=mask;
    *diff_out=popcnt(a1^a2)+popcnt(b1^b2)+popcnt(c1^c2)+popcnt(d1^d2)+
              popcnt(e1^e2)+popcnt(f1^f2)+popcnt(g1^g2)+popcnt(h1^h2);
}

// Phase 1: Find messages with minimum nonlinearity masks
__global__
void find_low_mask(uint64_t seed, int from, int to,
                   int* best_mask, uint32_t* best_msg, int n) {
    int tid=blockIdx.x*blockDim.x+threadIdx.x; if(tid>=n) return;
    uint64_t rng=seed+tid*6364136223846793005ULL+1;
    uint32_t W[16];
    for(int i=0;i<16;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;W[i]=(uint32_t)(rng>>32);}
    int m = mask_weight(W, from, to);
    int old=atomicMin(best_mask,m);
    if(m<old){for(int i=0;i<16;i++)best_msg[i]=W[i];}
}

// Phase 2: Anneal message for low masks, then find delta with low diff
__global__
void anneal_linear(uint64_t seed, int n_steps, float t0, float t1,
                   int mask_from, int mask_to,
                   int* best_combined, int* best_mask, int* best_diff,
                   uint32_t* best_delta, uint32_t* best_msg, int n) {
    int tid=blockIdx.x*blockDim.x+threadIdx.x; if(tid>=n) return;
    uint64_t rng=seed+tid*6364136223846793005ULL+1;

    uint32_t W[16],d[16]={0};
    for(int i=0;i<16;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;W[i]=(uint32_t)(rng>>32);}
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[14]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[15]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int ne=1+((int)(rng>>32)%2);
    for(int f=0;f<ne;f++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[2+((int)(rng>>32)%12)]=1u<<((int)((rng>>16)&31));}
    // Fix d01
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));

    int mk,df;
    combined_eval(W,d,mask_from,mask_to,&mk,&df);
    // Score: low mask + low diff. Weight mask more heavily for linearity
    int cur=mk*10+df;
    int lb=cur,lb_mk=mk,lb_df=df;
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
        td[1]=(uint32_t)(-(int32_t)(sig1(tW[15]^td[15])-sig1(tW[15])+td[10]+sig0(tW[2]^td[2])-sig0(tW[2])));
        td[0]=(uint32_t)(-(int32_t)(sig1(tW[14]^td[14])-sig1(tW[14])+td[9]+sig0(tW[1]^td[1])-sig0(tW[1])));
        uint32_t any=0;for(int i=0;i<16;i++)any|=td[i];if(!any)continue;

        int tmk,tdf;
        combined_eval(tW,td,mask_from,mask_to,&tmk,&tdf);
        int ts=tmk*10+tdf;

        bool accept=(ts<cur);
        if(!accept&&temp>0.01f){rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)(ts-cur)/temp);}
        if(accept){cur=ts;for(int i=0;i<16;i++){d[i]=td[i];W[i]=tW[i];}}
        if(ts<lb){lb=ts;lb_mk=tmk;lb_df=tdf;for(int i=0;i<16;i++){bd[i]=td[i];bW[i]=tW[i];}}
        temp*=decay;
    }

    int old=atomicMin(best_combined,lb);
    if(lb<old){*best_mask=lb_mk;*best_diff=lb_df;
    for(int i=0;i<16;i++){best_delta[i]=bd[i];best_msg[i]=bW[i];}}
}

int main(){
    printf("SHA-256 Linear Approximation Attack\n");
    printf("═══════════════════════════════════\n");
    printf("Minimize nonlinearity masks (b^c, f^g) at key rounds\n\n");

    int *d_mask,*d_combined,*d_diff;
    uint32_t *d_delta,*d_msg;
    cudaMalloc(&d_mask,4);cudaMalloc(&d_combined,4);cudaMalloc(&d_diff,4);
    cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);

    int threads=1<<19, thermal=500;

    // Phase 1: minimum masks at different round ranges
    printf("=== Phase 1: Minimum nonlinearity masks ===\n");
    int ranges[][2] = {{28,36},{30,38},{32,40},{28,40},{0,64}};
    for(int r=0;r<5;r++){
        int h=99999;cudaMemcpy(d_mask,&h,4,cudaMemcpyHostToDevice);
        for(int p=0;p<5;p++){
            struct timespec ts={0,thermal*1000000L};nanosleep(&ts,NULL);
            find_low_mask<<<threads/256,256>>>(p*99991ULL+r*7,ranges[r][0],ranges[r][1],
                d_mask,d_msg,threads);cudaDeviceSynchronize();}
        cudaMemcpy(&h,d_mask,4,cudaMemcpyDeviceToHost);
        int n_rounds=ranges[r][1]-ranges[r][0];
        printf("  Rounds %d-%d: min mask = %d/%d (%.1f per round, ideal=0, random=%d)\n",
            ranges[r][0],ranges[r][1]-1,h,n_rounds*64,
            (float)h/n_rounds,n_rounds*32);
    }

    // Phase 2: Combined mask+diff optimization at rounds 28-36
    printf("\n=== Phase 2: Combined mask+diff optimization (R28-36) ===\n\n");
    int gb_comb=999999,gb_mask=0,gb_diff=256;
    for(int e=0;e<40;e++){
        struct timespec ts={0,thermal*1000000L};nanosleep(&ts,NULL);
        int hc=999999,hm=99999,hd=256;
        cudaMemcpy(d_combined,&hc,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_mask,&hm,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_diff,&hd,4,cudaMemcpyHostToDevice);

        anneal_linear<<<threads/256,256>>>(e*104729ULL,4096,3000.0f+e*500,0.01f,
            28,36, d_combined,d_mask,d_diff,d_delta,d_msg,threads);
        cudaDeviceSynchronize();

        cudaMemcpy(&hc,d_combined,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&hm,d_mask,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&hd,d_diff,4,cudaMemcpyDeviceToHost);

        if(hc<gb_comb){
            gb_comb=hc;gb_mask=hm;gb_diff=hd;
            printf("  E%2d: mask=%3d diff=%3d (combined=%d)\n",e,hm,hd,hc);
        } else if(e%10==0){
            printf("  E%2d: best mask=%d diff=%d\n",e,gb_mask,gb_diff);
        }
    }

    printf("\n═══════════════════════════════════\n");
    printf("Best: mask=%d/512 diff=%d/256 at R28-36\n",gb_mask,gb_diff);
    printf("Low mask = more linear = diff more controllable\n");
    printf("If mask < 64 (8 rounds × 8 bits nonlinear): near-linear!\n");

    cudaFree(d_mask);cudaFree(d_combined);cudaFree(d_diff);
    cudaFree(d_delta);cudaFree(d_msg);
    return 0;
}

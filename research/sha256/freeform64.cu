/*
 * SHA-256 Freeform — NO algebraic constraints
 * ALL 512 bits (16 words delta + 16 words message) are optimization variables.
 * No d[0,1] fix. No schedule cancel. Pure state diff minimization.
 *
 * 1024 total bits of freedom vs 74-bit target.
 * This should be EASIER than constrained search.
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
int state_diff_full(const uint32_t W[16],const uint32_t d[16]){
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<64;i++){w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
    w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];}
    uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a;
    uint32_t e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
    for(int i=0;i<64;i++){
        uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;}
    return popcnt(a1^a2)+popcnt(b1^b2)+popcnt(c1^c2)+popcnt(d1^d2)+
           popcnt(e1^e2)+popcnt(f1^f2)+popcnt(g1^g2)+popcnt(h1^h2);
}

__global__
void anneal_free(uint64_t seed,int n_steps,float t0,float t1,
    int* best_diff,uint32_t* best_delta,uint32_t* best_msg,int n){
    int tid=blockIdx.x*blockDim.x+threadIdx.x;if(tid>=n)return;
    uint64_t rng=seed+tid*6364136223846793005ULL+1;
    uint32_t W[16],d[16];
    for(int i=0;i<16;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;W[i]=(uint32_t)(rng>>32);}
    // Start with 1-3 bit sparse delta
    for(int i=0;i<16;i++)d[i]=0;
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int nw=1+((int)(rng>>32)%3);
    for(int f=0;f<nw;f++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[(int)(rng>>32)&15]=1u<<((int)((rng>>16)&31));}

    int cur=state_diff_full(W,d);
    int lb=cur;uint32_t bd[16],bW[16];
    for(int i=0;i<16;i++){bd[i]=d[i];bW[i]=W[i];}

    float temp=t0,decay=powf(t1/t0,1.0f/(float)n_steps);
    for(int s=0;s<n_steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);
        uint32_t td[16],tW[16];
        for(int i=0;i<16;i++){td[i]=d[i];tW[i]=W[i];}

        // 50% mutate delta, 50% mutate message
        if(r&1){
            int mut=(r>>1)%5;
            if(mut<=1) td[(r>>4)&15]^=1u<<((r>>8)&31);
            else if(mut==2) td[(r>>4)&15]=1u<<((r>>8)&31);
            else if(mut==3) td[(r>>4)&15]=0;
            else td[(r>>4)&15]^=(1u<<((r>>8)&31))|(1u<<((r>>13)&31));
        } else {
            int mut=(r>>1)%4;
            if(mut<=1) tW[(r>>4)&15]^=1u<<((r>>8)&31);
            else if(mut==2){rng=rng*6364136223846793005ULL+1442695040888963407ULL;tW[(r>>4)&15]=(uint32_t)(rng>>32);}
            else tW[(r>>4)&15]^=(1u<<((r>>8)&31))|(1u<<((r>>13)&31));
        }
        uint32_t any=0;int dbc=0;for(int i=0;i<16;i++){any|=td[i];dbc+=popcnt(td[i]);}if(dbc<3)continue;

        int ts=state_diff_full(tW,td);
        bool accept=(ts<cur);
        if(!accept&&temp>0.01f){rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)(ts-cur)/temp);}
        if(accept){cur=ts;for(int i=0;i<16;i++){d[i]=td[i];W[i]=tW[i];}}
        if(ts<lb){lb=ts;for(int i=0;i<16;i++){bd[i]=td[i];bW[i]=tW[i];}}
        temp*=decay;
    }
    int old=atomicMin(best_diff,lb);
    if(lb<old){for(int i=0;i<16;i++){best_delta[i]=bd[i];best_msg[i]=bW[i];}}
}

int main(){
    printf("SHA-256 Freeform — NO constraints, 1024 bits of freedom\n");
    printf("═══════════════════════════════════════════════════════\n\n");
    int *d_diff;uint32_t *d_d,*d_m;
    cudaMalloc(&d_diff,4);cudaMalloc(&d_d,64);cudaMalloc(&d_m,64);
    int threads=1<<19,thermal=500;
    int gb=256;
    for(int e=0;e<60;e++){
        struct timespec ts={0,thermal*1000000L};nanosleep(&ts,NULL);
        int h=256;cudaMemcpy(d_diff,&h,4,cudaMemcpyHostToDevice);
        anneal_free<<<threads/256,256>>>(e*104729ULL,4096,3000.0f+e*500,0.01f,
            d_diff,d_d,d_m,threads);
        cudaDeviceSynchronize();
        cudaMemcpy(&h,d_diff,4,cudaMemcpyDeviceToHost);
        if(h<gb){gb=h;
            uint32_t hd[16];cudaMemcpy(hd,d_d,64,cudaMemcpyDeviceToHost);
            int dw=0,db=0;for(int i=0;i<16;i++)if(hd[i]){dw++;db+=popcnt(hd[i]);}
            printf("  E%2d: %d bits (%dw %db) ***\n",e,h,dw,db);
        } else if(e%10==0) printf("  E%2d: best=%d\n",e,gb);
    }
    printf("\nFINAL: %d bits (random=128, advantage=2^%d)\n",gb,128-gb);
    printf("Previous with d[0,1] algebraic: 74 bits\n");
    printf("Difference: %d bits\n",74-gb);
    cudaFree(d_diff);cudaFree(d_d);cudaFree(d_m);return 0;
}

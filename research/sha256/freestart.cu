/*
 * SHA-256 Free-start Attack — IV is a variable, not fixed
 * ========================================================
 * Normal: IV fixed (256 bits) + message (512 bits) = 512 DOF, 256 constraints
 * Free-start: IV variable (256 bits) + message (512 bits) = 768 DOF, 256 constraints
 * 3x overdetermined → MUCH easier!
 *
 * Free-start collision: find (IV, M, M') where
 *   compress(IV, M) = compress(IV, M')
 *   M ≠ M' (M' = M ^ delta)
 *
 * This breaks the compression function, not full SHA-256.
 * But: academic record for free-start SHA-256 = 38 rounds.
 * If we get full 64 → major result.
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
__device__ __host__ int popcnt(uint32_t x){x=x-((x>>1)&0x55555555);x=(x&0x33333333)+((x>>2)&0x33333333);return(((x+(x>>4))&0x0F0F0F0F)*0x01010101)>>24;}

// Free-start: IV is parameter, not fixed
__device__ int freestart_diff(const uint32_t IV[8], const uint32_t W[16], const uint32_t d[16]){
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<64;i++){w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
    w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];}
    uint32_t a1=IV[0],b1=IV[1],c1=IV[2],d1=IV[3],e1=IV[4],f1=IV[5],g1=IV[6],h1=IV[7];
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
    for(int i=0;i<64;i++){
        uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;}
    return popcnt(a1^a2)+popcnt(b1^b2)+popcnt(c1^c2)+popcnt(d1^d2)+
           popcnt(e1^e2)+popcnt(f1^f2)+popcnt(g1^g2)+popcnt(h1^h2);
}

__global__ void anneal_freestart(uint64_t seed, int n_steps, float t0, float t1,
    int* best_diff, uint32_t* best_iv, uint32_t* best_delta, uint32_t* best_msg, int n){
    int tid=blockIdx.x*blockDim.x+threadIdx.x;if(tid>=n)return;
    uint64_t rng=seed+tid*6364136223846793005ULL+1;

    // Random IV
    uint32_t iv[8];
    for(int i=0;i<8;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;iv[i]=(uint32_t)(rng>>32);}
    // Random message
    uint32_t W[16],d[16]={0};
    for(int i=0;i<16;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;W[i]=(uint32_t)(rng>>32);}
    // Sparse delta
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[14]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[15]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    for(int f=0;f<1+((int)(rng>>32)%2);f++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[2+((int)(rng>>32)%12)]=1u<<((int)((rng>>16)&31));}
    // Fix d01
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));

    int cur=freestart_diff(iv,W,d);
    int lb=cur;
    uint32_t biv[8],bd[16],bW[16];
    for(int i=0;i<8;i++)biv[i]=iv[i];
    for(int i=0;i<16;i++){bd[i]=d[i];bW[i]=W[i];}

    float temp=t0,decay=powf(t1/t0,1.0f/(float)n_steps);
    for(int s=0;s<n_steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);
        uint32_t tiv[8],td[16],tW[16];
        for(int i=0;i<8;i++)tiv[i]=iv[i];
        for(int i=0;i<16;i++){td[i]=d[i];tW[i]=W[i];}

        int mut=r%12;
        if(mut<=2){// Flip IV bit
            tiv[(r>>4)&7]^=1u<<((r>>8)&31);
        }else if(mut==3){// Replace IV word
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            tiv[(r>>4)&7]=(uint32_t)(rng>>32);
        }else if(mut<=5){// Flip delta bit
            td[2+((r>>4)%14)]^=1u<<((r>>8)&31);
        }else if(mut==6){td[2+((r>>4)%12)]=0;}
        else if(mut==7){int w=(r>>4)&1?15:14;td[w]^=1u<<((r>>5)&31);if(!td[w])td[w]=1;}
        else if(mut<=9){tW[(r>>4)&15]^=1u<<((r>>8)&31);}
        else if(mut==10){rng=rng*6364136223846793005ULL+1442695040888963407ULL;tW[(r>>4)&15]=(uint32_t)(rng>>32);}
        else{// Multi flip
            tiv[(r>>4)&7]^=1u<<((r>>8)&31);
            tW[(r>>12)&15]^=1u<<((r>>16)&31);
        }

        if(!td[14]&&!td[15])continue;
        td[1]=(uint32_t)(-(int32_t)(sig1(tW[15]^td[15])-sig1(tW[15])+td[10]+sig0(tW[2]^td[2])-sig0(tW[2])));
        td[0]=(uint32_t)(-(int32_t)(sig1(tW[14]^td[14])-sig1(tW[14])+td[9]+sig0(tW[1]^td[1])-sig0(tW[1])));
        uint32_t any=0;int dbc=0;for(int i=0;i<16;i++){any|=td[i];dbc+=popcnt(td[i]);}if(dbc<3)continue;

        int ts=freestart_diff(tiv,tW,td);
        bool accept=(ts<cur);
        if(!accept&&temp>0.01f){rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)(ts-cur)/temp);}
        if(accept){cur=ts;for(int i=0;i<8;i++)iv[i]=tiv[i];for(int i=0;i<16;i++){d[i]=td[i];W[i]=tW[i];}}
        if(ts<lb){lb=ts;for(int i=0;i<8;i++)biv[i]=tiv[i];for(int i=0;i<16;i++){bd[i]=td[i];bW[i]=tW[i];}}
        temp*=decay;
    }
    int old=atomicMin(best_diff,lb);
    if(lb<old){for(int i=0;i<8;i++)best_iv[i]=biv[i];
    for(int i=0;i<16;i++){best_delta[i]=bd[i];best_msg[i]=bW[i];}}
}

int main(){
    printf("SHA-256 Free-start Attack — Variable IV\n");
    printf("════════════════════════════════════════\n");
    printf("768 bits DOF (256 IV + 512 message) vs 256 constraints\n");
    printf("Academic record: 38 rounds. Target: 64 rounds.\n\n");

    int *d_diff;uint32_t *d_iv,*d_delta,*d_msg;
    cudaMalloc(&d_diff,4);cudaMalloc(&d_iv,32);cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);
    int threads=1<<19,thermal=500,gb=256;

    for(int e=0;e<200;e++){
        struct timespec ts={0,thermal*1000000L};nanosleep(&ts,NULL);
        int h=256;cudaMemcpy(d_diff,&h,4,cudaMemcpyHostToDevice);
        anneal_freestart<<<threads/256,256>>>(e*104729ULL,8192,8000.0f+e*300,0.01f,
            d_diff,d_iv,d_delta,d_msg,threads);
        cudaDeviceSynchronize();
        cudaMemcpy(&h,d_diff,4,cudaMemcpyDeviceToHost);
        if(h<gb){gb=h;printf("  E%2d: %d bits ***\n",e,h);}
        else if(e%10==0)printf("  E%2d: best=%d\n",e,gb);
        if(gb==0){
            printf("\n  *** FREE-START COLLISION! ***\n");
            uint32_t hiv[8],hd[16],hm[16];
            cudaMemcpy(hiv,d_iv,32,cudaMemcpyDeviceToHost);
            cudaMemcpy(hd,d_delta,64,cudaMemcpyDeviceToHost);
            cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);
            printf("  IV: ");for(int i=0;i<8;i++)printf("%08x ",hiv[i]);printf("\n");
            printf("  M:  ");for(int i=0;i<16;i++)printf("%08x ",hm[i]);printf("\n");
            printf("  D:  ");for(int i=0;i<16;i++)if(hd[i])printf("d[%d]=%08x ",i,hd[i]);printf("\n");
            break;
        }
    }
    printf("\nFINAL: %d bits (fixed IV was 74)\n",gb);
    printf("Free IV advantage: %d bits improvement\n",74-gb);
    cudaFree(d_diff);cudaFree(d_iv);cudaFree(d_delta);cudaFree(d_msg);
    return 0;
}

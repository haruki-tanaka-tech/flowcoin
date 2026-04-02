/* Dense delta: ALL 16 words nonzero, full 32-bit random values.
 * NO algebraic d[0,1]. NO schedule cancellation.
 * Pure annealing on (IV, message, delta) simultaneously.
 * 768 + 512 = 1280 bits total freedom. */
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

__device__ int fs_diff(const uint32_t IV[8],const uint32_t W[16],const uint32_t d[16]){
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

__global__ void anneal_dense(uint64_t seed,int steps,float t0,float t1,
    int* best,uint32_t* biv,uint32_t* bd,uint32_t* bm,int n){
    int tid=blockIdx.x*blockDim.x+threadIdx.x;if(tid>=n)return;
    uint64_t rng=seed+tid*6364136223846793005ULL+1;
    uint32_t iv[8],W[16],d[16];
    for(int i=0;i<8;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;iv[i]=(uint32_t)(rng>>32);}
    for(int i=0;i<16;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;W[i]=(uint32_t)(rng>>32);}
    // Dense delta: every word gets random value, then anneal down
    for(int i=0;i<16;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;d[i]=(uint32_t)(rng>>32);}

    int cur=fs_diff(iv,W,d);int lb=cur;
    uint32_t bi[8],bdd[16],bw[16];
    for(int i=0;i<8;i++)bi[i]=iv[i];
    for(int i=0;i<16;i++){bdd[i]=d[i];bw[i]=W[i];}

    float temp=t0,decay=powf(t1/t0,1.0f/(float)steps);
    for(int s=0;s<steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);
        uint32_t ti[8],td[16],tw[16];
        for(int i=0;i<8;i++)ti[i]=iv[i];
        for(int i=0;i<16;i++){td[i]=d[i];tw[i]=W[i];}

        int mut=r%9;
        if(mut<=1) ti[(r>>4)&7]^=1u<<((r>>8)&31);      // flip IV bit
        else if(mut<=3) td[(r>>4)&15]^=1u<<((r>>8)&31); // flip delta bit
        else if(mut<=5) tw[(r>>4)&15]^=1u<<((r>>8)&31); // flip msg bit
        else if(mut==6){rng=rng*6364136223846793005ULL+1442695040888963407ULL;ti[(r>>4)&7]=(uint32_t)(rng>>32);}
        else if(mut==7){rng=rng*6364136223846793005ULL+1442695040888963407ULL;td[(r>>4)&15]=(uint32_t)(rng>>32);}
        else{rng=rng*6364136223846793005ULL+1442695040888963407ULL;tw[(r>>4)&15]=(uint32_t)(rng>>32);}

        uint32_t any=0;for(int i=0;i<16;i++)any|=td[i];if(!any)continue;
        int ts=fs_diff(ti,tw,td);
        bool accept=(ts<cur);
        if(!accept&&temp>0.01f){rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)(ts-cur)/temp);}
        if(accept){cur=ts;for(int i=0;i<8;i++)iv[i]=ti[i];for(int i=0;i<16;i++){d[i]=td[i];W[i]=tw[i];}}
        if(ts<lb){lb=ts;for(int i=0;i<8;i++)bi[i]=ti[i];for(int i=0;i<16;i++){bdd[i]=td[i];bw[i]=tw[i];}}
        temp*=decay;
    }
    int old=atomicMin(best,lb);
    if(lb<old){for(int i=0;i<8;i++)biv[i]=bi[i];for(int i=0;i<16;i++){bd[i]=bdd[i];bm[i]=bw[i];}}
}

int main(){
    printf("SHA-256 Dense Delta + Free IV\n");
    printf("═════════════════════════════\n");
    printf("ALL 16 delta words random. No algebraic. No schedule cancel.\n");
    printf("1280 bits total freedom (256 IV + 512 msg + 512 delta)\n\n");

    int *d_best;uint32_t *d_iv,*d_d,*d_m;
    cudaMalloc(&d_best,4);cudaMalloc(&d_iv,32);cudaMalloc(&d_d,64);cudaMalloc(&d_m,64);
    int threads=1<<19,thermal=500,gb=256;

    for(int e=0;e<100;e++){
        struct timespec ts={0,thermal*1000000L};nanosleep(&ts,NULL);
        int h=256;cudaMemcpy(d_best,&h,4,cudaMemcpyHostToDevice);
        anneal_dense<<<threads/256,256>>>(e*104729ULL,8192,8000.0f+e*300,0.01f,
            d_best,d_iv,d_d,d_m,threads);
        cudaDeviceSynchronize();
        cudaMemcpy(&h,d_best,4,cudaMemcpyDeviceToHost);
        if(h<gb){gb=h;printf("  E%2d: %d bits ***\n",e,h);}
        else if(e%20==0)printf("  E%2d: best=%d\n",e,gb);
        if(gb<64){printf("\n  *** BELOW 64 BITS! ***\n");break;}
        if(gb==0){printf("\n  *** COLLISION! ***\n");break;}
    }
    printf("\nFINAL: %d bits\n",gb);
    cudaFree(d_best);cudaFree(d_iv);cudaFree(d_d);cudaFree(d_m);
    return 0;
}

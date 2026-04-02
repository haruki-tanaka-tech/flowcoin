#include <cstdint>
#include <cstdio>
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

__global__ void find_and_print(uint64_t seed, int n){
    int tid=blockIdx.x*blockDim.x+threadIdx.x; if(tid>=n)return;
    uint64_t rng=seed+tid*6364136223846793005ULL+1;
    uint32_t W[16],d[16];
    for(int i=0;i<16;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;W[i]=(uint32_t)(rng>>32);}
    for(int i=0;i<16;i++)d[i]=0;
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int nw=1+((int)(rng>>32)%3);
    for(int f=0;f<nw;f++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[(int)(rng>>32)&15]=1u<<((int)((rng>>16)&31));}

    // Anneal
    uint32_t w1[64],w2[64];
    float temp=3000.0f,decay=powf(0.01f/3000.0f,1.0f/4096.0f);
    int cur=256;
    // Quick eval
    {for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<64;i++){w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
    w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];}
    uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a,e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
    for(int i=0;i<64;i++){uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
    h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
    t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
    h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;}
    cur=popcnt(a1^a2)+popcnt(b1^b2)+popcnt(c1^c2)+popcnt(d1^d2)+popcnt(e1^e2)+popcnt(f1^f2)+popcnt(g1^g2)+popcnt(h1^h2);}

    for(int s=0;s<4096;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);
        uint32_t td[16],tW[16];for(int i=0;i<16;i++){td[i]=d[i];tW[i]=W[i];}
        if(r&1){td[(r>>4)&15]^=1u<<((r>>8)&31);}
        else{tW[(r>>4)&15]^=1u<<((r>>8)&31);}
        uint32_t any=0;for(int i=0;i<16;i++)any|=td[i];if(!any)continue;

        for(int i=0;i<16;i++){w1[i]=tW[i];w2[i]=tW[i]^td[i];}
        for(int i=16;i<64;i++){w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];}
        uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1_=0xa54ff53a,e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
        uint32_t a2=a1,b2=b1,c2=c1,d2=d1_,e2=e1,f2=f1,g2=g1,h2=h1;
        for(int i=0;i<64;i++){uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1_+t1;d1_=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;}
        int ts=popcnt(a1^a2)+popcnt(b1^b2)+popcnt(c1^c2)+popcnt(d1_^d2)+popcnt(e1^e2)+popcnt(f1^f2)+popcnt(g1^g2)+popcnt(h1^h2);

        bool accept=(ts<cur);
        if(!accept&&temp>0.01f){rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)(ts-cur)/temp);}
        if(accept){cur=ts;for(int i=0;i<16;i++){d[i]=td[i];W[i]=tW[i];}}
        temp*=decay;

        if(cur==0){
            // PRINT IT
            printf("ZERO DIFF FOUND by thread %d!\n",tid);
            printf("M:     ");for(int i=0;i<16;i++)printf("%08x ",W[i]);printf("\n");
            printf("Delta: ");for(int i=0;i<16;i++)printf("%08x ",d[i]);printf("\n");
            printf("M':    ");for(int i=0;i<16;i++)printf("%08x ",W[i]^d[i]);printf("\n");
            // Verify nonzero delta
            uint32_t a=0;for(int i=0;i<16;i++)a|=d[i];
            printf("Delta nonzero: %s\n",a?"YES":"NO");
            return;
        }
    }
}
int main(){
    printf("Searching for 0-bit diff with output...\n");
    find_and_print<<<512,256>>>(42ULL,131072);
    cudaDeviceSynchronize();
    printf("Done.\n");
    return 0;
}

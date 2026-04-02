/*
 * Chain round-by-round: find message where diff DROPS each round
 * For each round R: try messages, keep one where diff(R) < diff(R-1)
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

// State diff at specific round
__device__ int diff_at(const uint32_t W[16],const uint32_t d[16],int r){
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<64;i++){w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
    w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];}
    uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a,e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
    for(int i=0;i<r;i++){
        uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;}
    return popcnt(a1^a2)+popcnt(b1^b2)+popcnt(c1^c2)+popcnt(d1^d2)+
           popcnt(e1^e2)+popcnt(f1^f2)+popcnt(g1^g2)+popcnt(h1^h2);
}

// Find message minimizing diff at target_round
__global__ void find_best_msg(const uint32_t* fixed_delta, int target_round,
    uint64_t seed, int* best_diff, uint32_t* best_msg, int n){
    int tid=blockIdx.x*blockDim.x+threadIdx.x;if(tid>=n)return;
    uint64_t rng=seed+tid*6364136223846793005ULL+1;
    uint32_t W[16],d[16];
    for(int i=0;i<16;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;W[i]=(uint32_t)(rng>>32);d[i]=fixed_delta[i];}
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));
    int df=diff_at(W,d,target_round);
    int old=atomicMin(best_diff,df);
    if(df<old){for(int i=0;i<16;i++)best_msg[i]=W[i];}
}

int main(){
    printf("SHA-256 Chain Round-by-Round Brute Force\n");
    printf("════════════════════════════════════════\n\n");

    uint32_t h_delta[16]={0};
    h_delta[14]=1<<8; h_delta[15]=1<<8;

    uint32_t *d_delta,*d_msg;int *d_diff;
    cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);cudaMalloc(&d_diff,4);
    cudaMemcpy(d_delta,h_delta,64,cudaMemcpyHostToDevice);

    int threads=1<<19, thermal=300;

    printf("Scanning messages for minimum diff at each round:\n\n");

    for(int target=34;target<=34;target++){
        int h_diff=256;
        cudaMemcpy(d_diff,&h_diff,4,cudaMemcpyHostToDevice);

        // Multiple passes for more coverage
        for(int pass=0;pass<200;pass++){
            struct timespec ts={0,thermal*1000000L};nanosleep(&ts,NULL);
            find_best_msg<<<threads/256,256>>>(d_delta,target,
                (uint64_t)pass*999983+target*7,d_diff,d_msg,threads);
            cudaDeviceSynchronize();
        }
        cudaMemcpy(&h_diff,d_diff,4,cudaMemcpyDeviceToHost);

        printf("  R%2d: min diff = %3d bits (from %.0fM messages)\n",target,h_diff,10.0*threads/1e6);

        if(h_diff==0){
            printf("\n  *** COLLISION AT ROUND %d! ***\n",target);
            break;
        }
    }

    printf("\n");
    cudaFree(d_delta);cudaFree(d_msg);cudaFree(d_diff);
    return 0;
}

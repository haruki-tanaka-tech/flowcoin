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

__device__ void fix_d01(const uint32_t W[16],uint32_t d[16]){
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));
}

// Returns per-register diffs at target round
__device__ void reg_diff_at(const uint32_t W[16],const uint32_t d[16],int target,int out[8]){
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<64;i++){w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
    w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];}
    uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a;
    uint32_t e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
    for(int i=0;i<target;i++){
        uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;
    }
    out[0]=popcnt(a1^a2);out[1]=popcnt(b1^b2);out[2]=popcnt(c1^c2);out[3]=popcnt(d1^d2);
    out[4]=popcnt(e1^e2);out[5]=popcnt(f1^f2);out[6]=popcnt(g1^g2);out[7]=popcnt(h1^h2);
}

// Score: minimize top4 registers at round 40
__global__ void anneal_top4_r40(uint64_t seed,int n_steps,float t0,float t1,
    int* best_top4,int* best_total,uint32_t* best_delta,uint32_t* best_msg,int nthreads){
    int tid=blockIdx.x*blockDim.x+threadIdx.x;if(tid>=nthreads)return;
    uint64_t rng=seed+tid*6364136223846793005ULL+1;
    uint32_t W[16],d[16]={0};
    for(int i=0;i<16;i++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;W[i]=(uint32_t)(rng>>32);}
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;d[14]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;d[15]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int ne=1+((int)(rng>>32)%3);
    for(int f=0;f<ne;f++){rng=rng*6364136223846793005ULL+1442695040888963407ULL;d[2+((int)(rng>>32)%12)]=1u<<((int)((rng>>16)&31));}
    fix_d01(W,d);

    int rd[8];reg_diff_at(W,d,40,rd);
    int cur_top4=rd[0]+rd[1]+rd[2]+rd[3];
    int cur_total=cur_top4+rd[4]+rd[5]+rd[6]+rd[7];
    int lb_t4=cur_top4,lb_tot=cur_total;
    uint32_t bd[16],bW[16];for(int i=0;i<16;i++){bd[i]=d[i];bW[i]=W[i];}

    float temp=t0,decay=powf(t1/t0,1.0f/(float)n_steps);
    for(int s=0;s<n_steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;uint32_t r=(uint32_t)(rng>>32);
        uint32_t td[16],tW[16];for(int i=0;i<16;i++){td[i]=d[i];tW[i]=W[i];}
        int mut=r%8;
        if(mut<=1)td[2+((r>>4)%14)]^=1u<<((r>>8)&31);
        else if(mut==2){int w=(r>>4)&1?15:14;td[w]^=1u<<((r>>5)&31);if(!td[w])td[w]=1;}
        else if(mut==3)td[2+((r>>4)%12)]=0;
        else if(mut<=5)tW[(r>>4)&15]^=1u<<((r>>8)&31);
        else if(mut==6){rng=rng*6364136223846793005ULL+1442695040888963407ULL;tW[(r>>4)&15]=(uint32_t)(rng>>32);}
        else td[2+((r>>4)%14)]^=(1u<<((r>>8)&31))|(1u<<((r>>13)&31));
        if(!td[14]&&!td[15])continue;
        fix_d01(tW,td);uint32_t any=0;for(int i=0;i<16;i++)any|=td[i];if(!any)continue;

        int trd[8];reg_diff_at(tW,td,40,trd);
        int tt4=trd[0]+trd[1]+trd[2]+trd[3];
        int ttot=tt4+trd[4]+trd[5]+trd[6]+trd[7];
        // Score: minimize top4 primarily
        int ts=ttot;int cs=cur_total;
        bool accept=(ts<cs);
        if(!accept&&temp>0.01f){rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)(ts-cs)/temp);}
        if(accept){cur_top4=tt4;cur_total=ttot;for(int i=0;i<16;i++){d[i]=td[i];W[i]=tW[i];}}
        if(tt4<lb_t4||(tt4==lb_t4&&ttot<lb_tot)){lb_t4=tt4;lb_tot=ttot;for(int i=0;i<16;i++){bd[i]=td[i];bW[i]=tW[i];}}
        temp*=decay;
    }
    int old=atomicMin(best_top4,lb_t4);
    if(lb_t4<old){*best_total=lb_tot;for(int i=0;i<16;i++){best_delta[i]=bd[i];best_msg[i]=bW[i];}}
}

int main(){
    printf("SHA-256 Target Round 40 — Per-register optimization\n");
    printf("═══════════════════════════════════════════════════\n\n");
    int *d_t4,*d_tot;uint32_t *d_d,*d_m;
    cudaMalloc(&d_t4,4);cudaMalloc(&d_tot,4);cudaMalloc(&d_d,64);cudaMalloc(&d_m,64);
    int threads=1<<19,thermal=500;
    int gb_t4=128;

    for(int e=0;e<40;e++){
        struct timespec ts={0,thermal*1000000L};nanosleep(&ts,NULL);
        int h4=128,ht=256;
        cudaMemcpy(d_t4,&h4,4,cudaMemcpyHostToDevice);cudaMemcpy(d_tot,&ht,4,cudaMemcpyHostToDevice);
        anneal_top4_r40<<<threads/256,256>>>(e*104729ULL,4096,3000.0f+e*500,0.01f,
            d_t4,d_tot,d_d,d_m,threads);
        cudaDeviceSynchronize();
        cudaMemcpy(&h4,d_t4,4,cudaMemcpyDeviceToHost);cudaMemcpy(&ht,d_tot,4,cudaMemcpyDeviceToHost);
        if(h4<gb_t4){
            gb_t4=h4;
            uint32_t hd[16],hm[16];
            cudaMemcpy(hd,d_d,64,cudaMemcpyDeviceToHost);cudaMemcpy(hm,d_m,64,cudaMemcpyDeviceToHost);
            int rd[8];
            // Host recompute
            uint32_t w1[64],w2[64];
            for(int i=0;i<16;i++){w1[i]=hm[i];w2[i]=hm[i]^hd[i];}
            for(int i=16;i<64;i++){w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];}
            uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a;
            uint32_t e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
            uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
            for(int i=0;i<40;i++){
                uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
                h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
                t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
                h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;
            }
            printf("  E%2d R40: top4=%d total=%d | a=%d b=%d c=%d d=%d | e=%d f=%d g=%d h=%d\n",
                e,h4,ht,popcnt(a1^a2),popcnt(b1^b2),popcnt(c1^c2),popcnt(d1^d2),
                popcnt(e1^e2),popcnt(f1^f2),popcnt(g1^g2),popcnt(h1^h2));
        } else if(e%10==0) printf("  E%2d: best top4=%d\n",e,gb_t4);
    }
    printf("\nFINAL R40: top4(a,b,c,d) = %d/128 bits\n",gb_t4);
    printf("If top4<16: only 4 registers differ → 40-round partial collision!\n");
    cudaFree(d_t4);cudaFree(d_tot);cudaFree(d_d);cudaFree(d_m);
    return 0;
}

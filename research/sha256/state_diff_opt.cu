/*
 * SHA-256 State Diff Direct Optimization
 * ========================================
 *
 * New approach: optimize STATE DIFF directly, not schedule cleanness.
 *
 * Old metric: count zero-delta W[i] (clean schedule words)
 * New metric: minimize hamming(state_diff) at target round
 *
 * Strategy: use delta_W[i] as CORRECTIVE INJECTIONS
 * to reduce state diff, not just set them to zero.
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,550,1835,20091 state_diff_opt.cu -o statediff
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

// Run N rounds, return state diff in bits
__device__
int run_and_diff(const uint32_t W[16], const uint32_t d[16], int n_rounds) {
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<64;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a;
    uint32_t e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
    for(int i=0;i<n_rounds;i++){
        uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;
    }
    return popcnt(a1^a2)+popcnt(b1^b2)+popcnt(c1^c2)+popcnt(d1^d2)+
           popcnt(e1^e2)+popcnt(f1^f2)+popcnt(g1^g2)+popcnt(h1^h2);
}

// Simulated annealing: optimize STATE DIFF at target round
__global__
void anneal_state_diff(
    uint64_t seed,
    int target_round,
    int n_steps,
    float temp_start, float temp_end,
    int* best_diff,
    uint32_t* best_delta,
    uint32_t* best_msg,
    int n_threads)
{
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_threads) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    // Random message
    uint32_t W[16];
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
    }

    // Initialize delta: start with algebraic cancel W[16,17]
    uint32_t d[16]={0};
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[14]=1u<<((int)(rng>>32)&31);
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    d[15]=1u<<((int)(rng>>32)&31);
    // Add 1-3 extra
    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int ne=1+((int)(rng>>32)%3);
    for(int f=0;f<ne;f++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        d[2+((int)(rng>>32)%12)]=1u<<((int)((rng>>16)&31));
    }
    // Fix d[0,1]
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));

    int cur = run_and_diff(W, d, target_round);
    int local_best = cur;
    uint32_t best_d[16], best_W[16];
    for(int i=0;i<16;i++){best_d[i]=d[i];best_W[i]=W[i];}

    float temp=temp_start;
    float decay=powf(temp_end/temp_start,1.0f/(float)n_steps);

    for(int s=0;s<n_steps;s++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        uint32_t r=(uint32_t)(rng>>32);

        uint32_t td[16],tW[16];
        for(int i=0;i<16;i++){td[i]=d[i];tW[i]=W[i];}

        int mut=r%10;
        if(mut<=2){
            // Flip bit in delta
            int w=2+((r>>4)%14); td[w]^=1u<<((r>>8)&31);
        }else if(mut==3){
            // Replace delta word
            int w=2+((r>>4)%12);
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            td[w]=1u<<((int)(rng>>32)&31);
        }else if(mut==4){
            td[2+((r>>4)%12)]=0; // clear word
        }else if(mut==5){
            // Mutate d14 or d15
            int w=(r>>4)&1?15:14;
            td[w]^=1u<<((r>>5)&31);
            if(!td[w])td[w]=1;
        }else if(mut==6){
            // Flip message bit
            tW[(r>>4)&15]^=1u<<((r>>8)&31);
        }else if(mut==7){
            // Replace message word
            int w=(r>>4)&15;
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            tW[w]=(uint32_t)(rng>>32);
        }else{
            // Multi-bit delta flip
            int w=2+((r>>4)%14);
            td[w]^=(1u<<((r>>8)&31))|(1u<<((r>>13)&31));
        }

        if(!td[14]&&!td[15]) continue;

        // Fix d[0,1]
        td[1]=(uint32_t)(-(int32_t)(sig1(tW[15]^td[15])-sig1(tW[15])+td[10]+sig0(tW[2]^td[2])-sig0(tW[2])));
        td[0]=(uint32_t)(-(int32_t)(sig1(tW[14]^td[14])-sig1(tW[14])+td[9]+sig0(tW[1]^td[1])-sig0(tW[1])));

        uint32_t any=0;for(int i=0;i<16;i++)any|=td[i];
        if(!any)continue;

        int ts=run_and_diff(tW,td,target_round);
        int ds=ts-cur;

        bool accept=(ds<0); // minimize!
        if(!accept&&temp>0.01f){
            rng=rng*6364136223846793005ULL+1442695040888963407ULL;
            accept=((float)(rng>>32)/4294967296.0f)<expf(-(float)ds/temp);
        }

        if(accept){cur=ts;for(int i=0;i<16;i++){d[i]=td[i];W[i]=tW[i];}}
        if(ts<local_best){local_best=ts;for(int i=0;i<16;i++){best_d[i]=td[i];best_W[i]=tW[i];}}
        temp*=decay;
    }

    // Global best (minimize)
    int old=atomicMin(best_diff,local_best);
    if(local_best<old){
        for(int i=0;i<16;i++){best_delta[i]=best_d[i];best_msg[i]=best_W[i];}
    }
}

int main(){
    printf("SHA-256 State Diff Direct Optimization\n");
    printf("═══════════════════════════════════════\n");
    printf("NEW: minimize STATE DIFF, not schedule cleanness\n\n");

    int *d_diff;
    uint32_t *d_delta,*d_msg;
    cudaMalloc(&d_diff,4);cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);

    int threads=1<<19;
    int steps=4096;
    int thermal_ms=500;

    for(int target=48;target<=64;target+=4){
        printf("=== Target: Round %d ===\n",target);

        int global_best=256;
        for(int epoch=0;epoch<50;epoch++){
            struct timespec ts={0,thermal_ms*1000000L};
            nanosleep(&ts,NULL);

            int h_diff=256;
            cudaMemcpy(d_diff,&h_diff,4,cudaMemcpyHostToDevice);

            float t_start=3000.0f+epoch*500.0f;

            anneal_state_diff<<<threads/256,256>>>(
                epoch*104729ULL+target*37,target,steps,t_start,0.01f,
                d_diff,d_delta,d_msg,threads);
            cudaDeviceSynchronize();

            cudaMemcpy(&h_diff,d_diff,4,cudaMemcpyDeviceToHost);

            if(h_diff<global_best){
                global_best=h_diff;

                uint32_t hd[16],hm[16];
                cudaMemcpy(hd,d_delta,64,cudaMemcpyDeviceToHost);
                cudaMemcpy(hm,d_msg,64,cudaMemcpyDeviceToHost);

                // Show schedule pattern
                uint32_t w1[64],w2[64];
                for(int i=0;i<16;i++){w1[i]=hm[i];w2[i]=hm[i]^hd[i];}
                for(int i=16;i<64;i++){
                    w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
                    w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
                }

                int dw=0,db=0;
                for(int i=0;i<16;i++)if(hd[i]){dw++;db+=popcnt(hd[i]);}

                printf("  E%2d: state_diff=%3d bits @ R%d | %dw %3db | sched: ",
                       epoch,h_diff,target,dw,db);
                for(int i=16;i<target&&i<48;i++){
                    int b=popcnt(w1[i]^w2[i]);
                    if(b==0)printf("✓");else if(b<10)printf("%d",b);else printf("X");
                }
                printf("\n");
            }
        }
        printf("  BEST R%d: %d bits state diff (random=128)\n\n",target,global_best);
    }

    cudaFree(d_diff);cudaFree(d_delta);cudaFree(d_msg);
    return 0;
}

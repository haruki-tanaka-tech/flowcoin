/*
 * SHA-256 GPU Gradient Descent — 512 parallel bit flips
 * Each iteration: try ALL 512 message bits, keep best flip.
 * O(512) evaluations per step, fully parallel.
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

__device__ int eval(const uint32_t W[16], const uint32_t d[16]){
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^d[i];}
    for(int i=16;i<64;i++){w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
    w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];}
    uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a,e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
    for(int i=0;i<64;i++){
        uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;}
    return popcnt(a1^a2)+popcnt(b1^b2)+popcnt(c1^c2)+popcnt(d1^d2)+
           popcnt(e1^e2)+popcnt(f1^f2)+popcnt(g1^g2)+popcnt(h1^h2);
}

// Each thread flips one of 512 message bits, reports resulting diff
__global__ void try_all_flips(const uint32_t* msg, const uint32_t* delta,
                               int* diffs) { // [512] output
    int tid = threadIdx.x; // 0..511
    if(tid >= 512) return;
    int word = tid >> 5;  // 0..15
    int bit = tid & 31;   // 0..31

    uint32_t W[16], d[16];
    for(int i=0;i<16;i++){W[i]=msg[i];d[i]=delta[i];}
    W[word] ^= (1u << bit); // flip this bit
    // Re-fix d[0,1]
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));
    diffs[tid] = eval(W, d);
}

// Multiple starting points — each block is independent gradient descent
__global__ void multi_gradient(uint64_t seed, const uint32_t* base_delta,
                                int n_steps,
                                int* global_best, uint32_t* global_best_msg) {
    // Each block: one independent gradient search
    int bid = blockIdx.x;
    __shared__ uint32_t msg[16];
    __shared__ uint32_t delta[16];
    __shared__ int diffs[512];
    __shared__ int current_diff;
    __shared__ int best_local;

    int tid = threadIdx.x; // 0..511

    // Initialize message from seed
    if(tid < 16) {
        uint64_t rng = seed + bid * 16 + tid;
        rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
        msg[tid] = (uint32_t)(rng >> 32);
        delta[tid] = base_delta[tid];
    }
    __syncthreads();

    // Fix d[0,1] and eval initial
    if(tid == 0) {
        delta[1]=(uint32_t)(-(int32_t)(sig1(msg[15]^delta[15])-sig1(msg[15])+delta[10]+sig0(msg[2]^delta[2])-sig0(msg[2])));
        delta[0]=(uint32_t)(-(int32_t)(sig1(msg[14]^delta[14])-sig1(msg[14])+delta[9]+sig0(msg[1]^delta[1])-sig0(msg[1])));
        current_diff = eval(msg, delta);
        best_local = current_diff;
    }
    __syncthreads();

    for(int step = 0; step < n_steps; step++) {
        // Each thread tries flipping one bit
        if(tid < 512) {
            int word = tid >> 5;
            int bit = tid & 31;
            uint32_t W[16], d[16];
            for(int i=0;i<16;i++){W[i]=msg[i];d[i]=delta[i];}
            W[word] ^= (1u << bit);
            d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
            d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));
            diffs[tid] = eval(W, d);
        }
        __syncthreads();

        // Thread 0: find minimum and apply
        if(tid == 0) {
            int best_flip = -1;
            int best_val = current_diff;
            for(int i=0;i<512;i++){
                if(diffs[i] < best_val){
                    best_val = diffs[i];
                    best_flip = i;
                }
            }
            if(best_flip >= 0) {
                msg[best_flip >> 5] ^= (1u << (best_flip & 31));
                delta[1]=(uint32_t)(-(int32_t)(sig1(msg[15]^delta[15])-sig1(msg[15])+delta[10]+sig0(msg[2]^delta[2])-sig0(msg[2])));
                delta[0]=(uint32_t)(-(int32_t)(sig1(msg[14]^delta[14])-sig1(msg[14])+delta[9]+sig0(msg[1]^delta[1])-sig0(msg[1])));
                current_diff = best_val;
                if(best_val < best_local) best_local = best_val;
            }
        }
        __syncthreads();

        if(current_diff == 0) break;
    }

    // Update global best
    if(tid == 0) {
        int old = atomicMin(global_best, best_local);
        if(best_local < old) {
            for(int i=0;i<16;i++) global_best_msg[i] = msg[i];
        }
    }
}

int main(){
    printf("SHA-256 GPU Gradient Descent\n");
    printf("═══════════════════════════\n");
    printf("512 parallel bit flips per step, greedy descent\n\n");

    uint32_t h_delta[16]={0};
    h_delta[14]=1<<8; h_delta[15]=1<<8;

    uint32_t *d_delta, *d_msg;
    int *d_best;
    cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);cudaMalloc(&d_best,4);
    cudaMemcpy(d_delta,h_delta,64,cudaMemcpyHostToDevice);

    int n_blocks = 512;   // 256 independent gradient searches
    int n_steps = 2000;    // 500 gradient steps each
    int thermal = 500;
    int gb = 256;

    printf("Blocks: %d, Steps: %d, Total: %d bit-flip evaluations\n\n",
           n_blocks, n_steps, n_blocks * n_steps * 512);

    for(int epoch=0; epoch<20; epoch++){
        struct timespec ts={0,thermal*1000000L};nanosleep(&ts,NULL);
        int h=256;cudaMemcpy(d_best,&h,4,cudaMemcpyHostToDevice);

        multi_gradient<<<n_blocks, 512>>>(
            (uint64_t)epoch * 999983 + 42, d_delta, n_steps,
            d_best, d_msg);
        cudaDeviceSynchronize();

        cudaError_t err = cudaGetLastError();
        if(err != cudaSuccess){printf("CUDA error: %s\n",cudaGetErrorString(err));break;}

        cudaMemcpy(&h,d_best,4,cudaMemcpyDeviceToHost);
        if(h<gb){
            gb=h;
            printf("  E%2d: %d bits ***\n",epoch,h);
        } else if(epoch%5==0){
            printf("  E%2d: best=%d\n",epoch,gb);
        }
        if(gb==0){printf("\n  *** COLLISION! ***\n");break;}
    }

    printf("\nFINAL: %d bits\n",gb);
    printf("Previous annealing: 74 bits\n");

    cudaFree(d_delta);cudaFree(d_msg);cudaFree(d_best);
    return 0;
}

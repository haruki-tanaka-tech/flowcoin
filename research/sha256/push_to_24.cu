/*
 * SHA-256 Push Beyond Round 20 — Two-sided cascade
 * ==================================================
 *
 * Finding from cascade_cancel:
 *   - Cancel W[16..17] → W[16..20] = 0 for FREE (5 clean rounds)
 *   - But W[21..23] leak 1,1,2 bits
 *   - Trying to cancel W[21+] breaks W[20]
 *
 * New strategy: use ALL 16 delta words
 *   d[14], d[15] = free parameters (1 bit each)
 *   d[0..7] = computed to cancel W[16..23]
 *   d[8..13] = FREE — use to cancel W[24..29]!
 *
 * W[24] = sig1(W[22]) + W[17] + sig0(W[9])  + W[8]
 * W[25] = sig1(W[23]) + W[18] + sig0(W[10]) + W[9]
 * W[26] = sig1(W[24]) + W[19] + sig0(W[11]) + W[10]
 * W[27] = sig1(W[25]) + W[20] + sig0(W[12]) + W[11]
 * W[28] = sig1(W[26]) + W[21] + sig0(W[13]) + W[12]
 * W[29] = sig1(W[27]) + W[22] + sig0(W[14]) + W[13]
 *
 * If W[16..23] are cancelled (delta=0), then W[24..29] depend only on d[8..13]:
 *   d[8] cancels W[24], d[9] cancels W[25], etc.
 *
 * Total: d[0..15] control W[16..29] = 14 clean schedule rounds!
 * That means 29 SHA-256 rounds with zero schedule delta!
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,1835,20091 push_to_24.cu -o push24
 */

#include <cstdint>
#include <cstdio>
#include <cstring>

__constant__ static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,
    0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(e,f,g) (((e)&(f))^((~(e))&(g)))
#define MAJ(a,b,c) (((a)&(b))^((a)&(c))^((b)&(c)))
#define S0(a) (ROTR(a,2)^ROTR(a,13)^ROTR(a,22))
#define S1(e) (ROTR(e,6)^ROTR(e,11)^ROTR(e,25))
#define sig0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define sig1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

__device__ __host__
int popcnt(uint32_t x) {
    x=x-((x>>1)&0x55555555);x=(x&0x33333333)+((x>>2)&0x33333333);
    return(((x+(x>>4))&0x0F0F0F0F)*0x01010101)>>24;
}

__device__ __host__
void sha256_n(const uint32_t W[16], int n, uint32_t out[8]) {
    out[0]=0x6a09e667;out[1]=0xbb67ae85;out[2]=0x3c6ef372;out[3]=0xa54ff53a;
    out[4]=0x510e527f;out[5]=0x9b05688c;out[6]=0x1f83d9ab;out[7]=0x5be0cd19;
    uint32_t w[64];
    for(int i=0;i<16;i++)w[i]=W[i];
    for(int i=16;i<64;i++)w[i]=sig1(w[i-2])+w[i-7]+sig0(w[i-15])+w[i-16];
    uint32_t a=out[0],b=out[1],c=out[2],d=out[3],e=out[4],f=out[5],g=out[6],h=out[7];
    for(int i=0;i<n&&i<64;i++){
        uint32_t t1=h+S1(e)+CH(e,f,g)+K[i]+w[i];uint32_t t2=S0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    out[0]=a;out[1]=b;out[2]=c;out[3]=d;out[4]=e;out[5]=f;out[6]=g;out[7]=h;
}

__device__ __host__
int sdiff(const uint32_t a[8], const uint32_t b[8]) {
    int t=0;for(int i=0;i<8;i++)t+=popcnt(a[i]^b[i]);return t;
}

// Full 16-word cascade solver
// Free params: bit14, bit15 (1 bit each in W[14], W[15])
// Solves d[0..13] to cancel W[16..29]
//
// Key: solve d[k] iteratively, maintaining w2[] array fully updated
__device__ __host__
void solve_full_cascade(const uint32_t W[16], int bit14, int bit15,
                        uint32_t delta[16]) {
    for(int i=0;i<16;i++) delta[i] = 0;
    delta[14] = 1u << bit14;
    delta[15] = 1u << bit15;

    // Target: w1[i] for i=16..29
    uint32_t w1[32];
    for(int i=0;i<16;i++) w1[i] = W[i];
    for(int i=16;i<30;i++)
        w1[i] = sig1(w1[i-2]) + w1[i-7] + sig0(w1[i-15]) + w1[i-16];

    // w2 = perturbed message, built incrementally
    uint32_t w2[32];
    for(int i=0;i<16;i++) w2[i] = W[i] ^ delta[i];

    // Phase 1: Cancel W[16..23] by solving d[0..7]
    // For each k=0..7:
    //   W[16+k] = sig1(w2[14+k]) + w2[9+k] + sig0(w2[1+k]) + w2[k]
    //   We want w2[16+k] = w1[16+k]
    //   Unknown: w2[k] = W[k] ^ d[k]
    //   So: d[k] = W[k] ^ (w1[16+k] - sig1(w2[14+k]) - w2[9+k] - sig0(w2[1+k]))

    for(int k=0; k<8; k++) {
        int i = 16 + k;

        // All dependencies w2[14+k], w2[9+k], w2[1+k] are already set:
        // - w2[14+k]: k<2 → w2[14..15] set from delta[14..15]
        //             k>=2 → w2[16+k-2] set as w1[16+k-2] (cancelled prev step)
        // - w2[9+k]: k<7 → w2[9..15] set (d[9..13]=0, d[14..15] set)
        //            k=7 → w2[16] = w1[16] (cancelled)
        // - w2[1+k]: w2[1..8] — d[1..7] may already be solved, d[8] not yet

        // Handle w2[14+k]
        uint32_t v_im2;
        if(14+k < 16) v_im2 = w2[14+k];
        else v_im2 = w2[14+k]; // already set as w1[14+k] from cancellation

        // Handle w2[9+k]
        uint32_t v_im7;
        if(9+k < 16) v_im7 = w2[9+k];
        else v_im7 = w2[9+k]; // cancelled

        // Handle w2[1+k]
        uint32_t v_im15 = w2[1+k]; // already set (d[1..k-1] solved, or initial)

        // Solve for w2[k]
        uint32_t target_wk = w1[i] - sig1(v_im2) - v_im7 - sig0(v_im15);
        delta[k] = W[k] ^ target_wk;
        w2[k] = target_wk;

        // Set w2[i] = w1[i] (cancelled)
        w2[i] = w1[i];
    }

    // Refresh w2[0..15] with solved deltas
    for(int i=0;i<16;i++) w2[i] = W[i] ^ delta[i];

    // Recompute w2[16..23] to verify
    for(int i=16;i<24;i++)
        w2[i] = sig1(w2[i-2]) + w2[i-7] + sig0(w2[i-15]) + w2[i-16];

    // Phase 2: Cancel W[24..29] by solving d[8..13]
    // W[24+k] = sig1(w2[22+k]) + w2[17+k] + sig0(w2[9+k]) + w2[8+k]
    // Dependencies:
    //   w2[22+k]: for k<2, = w2[22..23] (from phase 1, should = w1)
    //             for k>=2, = w2[24+k-2] (cancelled in this phase)
    //   w2[17+k]: all cancelled in phase 1 (= w1)
    //   w2[9+k]:  d[9+k] — being solved NOW

    for(int k=0; k<6; k++) {
        int i = 24 + k;

        uint32_t v_im2;
        if(22+k < 24) v_im2 = w2[22+k]; // phase 1 result
        else v_im2 = w2[22+k]; // phase 2 cancelled

        uint32_t v_im7 = w2[17+k]; // cancelled in phase 1

        uint32_t v_im15 = w2[9+k]; // d[9+k] may already be solved

        uint32_t target_wk = w1[i] - sig1(v_im2) - v_im7 - sig0(v_im15);
        delta[8+k] = W[8+k] ^ target_wk;
        w2[8+k] = target_wk;

        // Set w2[i] = w1[i]
        w2[i] = w1[i];
    }
}

// GPU search: try all bit14, bit15 combinations × random messages
__global__
void search_full(uint64_t seed, int target_round,
                 int* best_state_diff, int* best_sched_total,
                 uint32_t* best_delta, uint32_t* best_msg,
                 int n_trials) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n_trials) return;

    uint64_t rng = seed + tid * 6364136223846793005ULL + 1;

    uint32_t W[16];
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
    }

    rng=rng*6364136223846793005ULL+1442695040888963407ULL;
    int b14 = (int)(rng>>32) & 31;
    int b15 = (int)((rng>>16) & 31);

    uint32_t delta[16];
    solve_full_cascade(W, b14, b15, delta);

    // Compute state diff
    uint32_t W2[16];
    for(int i=0;i<16;i++) W2[i] = W[i] ^ delta[i];
    uint32_t s1[8], s2[8];
    sha256_n(W, target_round, s1);
    sha256_n(W2, target_round, s2);
    int sd = sdiff(s1, s2);

    // Compute schedule diff W[16..31]
    uint32_t w1[32], w2[32];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W2[i];}
    for(int i=16;i<32;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    int sched = 0;
    for(int i=16;i<32;i++) sched += popcnt(w1[i]^w2[i]);

    int old = atomicMin(best_state_diff, sd);
    if(sd < old) {
        *best_sched_total = sched;
        for(int i=0;i<16;i++){best_delta[i]=delta[i];best_msg[i]=W[i];}
    }
}

int main() {
    printf("SHA-256 Push Beyond Round 20\n");
    printf("═══════════════════════════\n");
    printf("Two-sided cascade: d[0..7] cancel W[16..23], d[8..13] cancel W[24..29]\n");
    printf("Free params: d[14], d[15] (1 bit each)\n\n");

    int *d_sd, *d_sched;
    uint32_t *d_delta, *d_msg;
    cudaMalloc(&d_sd,4);cudaMalloc(&d_sched,4);
    cudaMalloc(&d_delta,64);cudaMalloc(&d_msg,64);

    int trials = 1 << 24;

    // First: verify cascade works on a known message
    printf("=== Verification on test message ===\n");
    {
        uint32_t W[16] = {0x11111111,0x22222222,0x33333333,0x44444444,
                          0x55555555,0x66666666,0x77777777,0x88888888,
                          0x99999999,0xaaaaaaaa,0xbbbbbbbb,0xcccccccc,
                          0xdddddddd,0xeeeeeeee,0xffffffff,0x12345678};
        uint32_t delta[16];
        solve_full_cascade(W, 5, 10, delta);

        uint32_t w1[32], w2[32];
        for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^delta[i];}
        for(int i=16;i<32;i++){
            w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
            w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
        }

        printf("Schedule delta:\n");
        int total_clean = 0;
        for(int i=16;i<32;i++){
            uint32_t d=w1[i]^w2[i];
            int bits = popcnt(d);
            printf("  W[%d]: %08x (%d bits)%s\n", i, d, bits, bits==0?" ✓":"");
            if(bits==0) total_clean++;
        }
        printf("Clean schedule words: %d / 16\n", total_clean);

        int db=0;
        for(int i=0;i<16;i++) db+=popcnt(delta[i]);
        printf("Input delta bits: %d\n\n", db);
    }

    // GPU search across rounds
    printf("=== GPU search: minimize state diff ===\n\n");

    for(int target = 20; target <= 32; target += 2) {
        int h_sd = 256, h_sched = 999;
        cudaMemcpy(d_sd,&h_sd,4,cudaMemcpyHostToDevice);
        cudaMemcpy(d_sched,&h_sched,4,cudaMemcpyHostToDevice);

        for(int pass=0;pass<8;pass++){
            search_full<<<trials/256,256>>>(
                pass*13579ULL+target*97,target,
                d_sd,d_sched,d_delta,d_msg,trials);
            cudaDeviceSynchronize();
        }

        cudaMemcpy(&h_sd,d_sd,4,cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_sched,d_sched,4,cudaMemcpyDeviceToHost);

        uint32_t h_delta[16];
        cudaMemcpy(h_delta,d_delta,64,cudaMemcpyDeviceToHost);

        int dbits=0,dwords=0;
        for(int i=0;i<16;i++)if(h_delta[i]){dwords++;dbits+=popcnt(h_delta[i]);}

        printf("Round %2d: state_diff = %3d | sched_diff(16..31) = %3d | %d words, %d delta bits\n",
               target, h_sd, h_sched, dwords, dbits);

        if(h_sd < 60) {
            printf("  *** SIGNIFICANT! ");
            for(int i=0;i<16;i++)if(h_delta[i])printf("W[%d]=0x%08x ",i,h_delta[i]);
            printf("\n");
        }
    }

    printf("\n=== Theory ===\n");
    printf("If W[16..29] all cancelled (14 clean words):\n");
    printf("  Rounds 1-15: delta only in input W[0..15] (controlled)\n");
    printf("  Rounds 16-29: zero schedule delta (cancelled algebraically)\n");
    printf("  State diff at round 29 = f(input delta, round function only)\n");
    printf("  This isolates the round function from message schedule!\n");
    printf("  29/64 rounds = 45%% of SHA-256 with controlled differential\n");

    cudaFree(d_sd);cudaFree(d_sched);cudaFree(d_delta);cudaFree(d_msg);
    return 0;
}

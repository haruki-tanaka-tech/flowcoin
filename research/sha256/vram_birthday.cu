/*
 * SHA-256 VRAM Birthday Attack
 * ==============================
 *
 * Use 16GB VRAM + 892 GB/s bandwidth for birthday collision search.
 *
 * Phase 1: Generate 2^30 (message, state_diff_at_R28) pairs
 * Phase 2: Store truncated diff hash in VRAM hash table
 * Phase 3: Find collisions — two messages with same diff pattern
 *
 * If diff pattern same → state diff propagation identical → same output diff
 * This finds messages where rounds 28-64 behave identically = near-collision
 *
 * Build: nvcc -O3 -arch=sm_120 --use_fast_math -diag-suppress 177,550,1835,20091 vram_birthday.cu -o vram_birthday
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
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

// Compute XOR diff of states at given round
__device__
uint64_t compute_diff_hash(const uint32_t W[16], const uint32_t delta[16], int at_round) {
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^delta[i];}
    for(int i=16;i<64;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a;
    uint32_t e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
    for(int i=0;i<at_round;i++){
        uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;
    }
    // Hash the full 256-bit XOR diff into 64 bits
    uint32_t x0=a1^a2, x1=b1^b2, x2=c1^c2, x3=d1^d2;
    uint32_t x4=e1^e2, x5=f1^f2, x6=g1^g2, x7=h1^h2;
    // FNV-like hash to 64 bits
    uint64_t h = 0xcbf29ce484222325ULL;
    h = (h ^ x0) * 0x100000001b3ULL;
    h = (h ^ x1) * 0x100000001b3ULL;
    h = (h ^ x2) * 0x100000001b3ULL;
    h = (h ^ x3) * 0x100000001b3ULL;
    h = (h ^ x4) * 0x100000001b3ULL;
    h = (h ^ x5) * 0x100000001b3ULL;
    h = (h ^ x6) * 0x100000001b3ULL;
    h = (h ^ x7) * 0x100000001b3ULL;
    return h;
}

// Also compute full state diff in bits
__device__
int full_state_diff(const uint32_t W[16], const uint32_t delta[16], int at_round) {
    uint32_t w1[64],w2[64];
    for(int i=0;i<16;i++){w1[i]=W[i];w2[i]=W[i]^delta[i];}
    for(int i=16;i<64;i++){
        w1[i]=sig1(w1[i-2])+w1[i-7]+sig0(w1[i-15])+w1[i-16];
        w2[i]=sig1(w2[i-2])+w2[i-7]+sig0(w2[i-15])+w2[i-16];
    }
    uint32_t a1=0x6a09e667,b1=0xbb67ae85,c1=0x3c6ef372,d1=0xa54ff53a;
    uint32_t e1=0x510e527f,f1=0x9b05688c,g1=0x1f83d9ab,h1=0x5be0cd19;
    uint32_t a2=a1,b2=b1,c2=c1,d2=d1,e2=e1,f2=f1,g2=g1,h2=h1;
    for(int i=0;i<at_round;i++){
        uint32_t t1=h1+S1(e1)+CH(e1,f1,g1)+K[i]+w1[i];uint32_t t2=S0(a1)+MAJ(a1,b1,c1);
        h1=g1;g1=f1;f1=e1;e1=d1+t1;d1=c1;c1=b1;b1=a1;a1=t1+t2;
        t1=h2+S1(e2)+CH(e2,f2,g2)+K[i]+w2[i];t2=S0(a2)+MAJ(a2,b2,c2);
        h2=g2;g2=f2;f2=e2;e2=d2+t1;d2=c2;c2=b2;b2=a2;a2=t1+t2;
    }
    return popcnt(a1^a2)+popcnt(b1^b2)+popcnt(c1^c2)+popcnt(d1^d2)+
           popcnt(e1^e2)+popcnt(f1^f2)+popcnt(g1^g2)+popcnt(h1^h2);
}

// Hash table entry: 8 bytes (truncated diff hash → message seed)
// Table size: 2^HASH_BITS entries
#define HASH_BITS 29  // 512M entries × 8 bytes = 4 GB
#define TABLE_SIZE (1u << HASH_BITS)
#define TABLE_MASK (TABLE_SIZE - 1)

struct HashEntry {
    uint32_t diff_hash;  // truncated diff hash (32 bits)
    uint32_t msg_seed;   // message seed to regenerate
};

// Phase 1: Fill hash table with (diff_hash, msg_seed) pairs
__global__
void fill_table(const uint32_t* delta, int at_round,
                HashEntry* table, uint64_t seed_base, int n) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n) return;

    uint64_t rng = seed_base + tid * 6364136223846793005ULL + 1;
    uint32_t W[16], d[16];
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
        d[i]=delta[i];
    }
    // Fix d[0,1]
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));

    uint64_t dh = compute_diff_hash(W, d, at_round);
    uint32_t slot = (uint32_t)(dh & TABLE_MASK);
    uint32_t tag = (uint32_t)(dh >> 32);

    // Linear probing insert
    for(int probe=0; probe<16; probe++){
        uint32_t idx = (slot + probe) & TABLE_MASK;
        if(table[idx].diff_hash == 0) {
            table[idx].diff_hash = tag | 1; // ensure nonzero
            table[idx].msg_seed = (uint32_t)tid;
            break;
        }
    }
}

// Phase 2: Check for collisions — same diff hash from different messages
__global__
void check_collisions(const uint32_t* delta, int at_round,
                      const HashEntry* table, uint64_t seed_base,
                      uint64_t seed_base2, // different seed for second set
                      int* n_collisions, int* best_r64_diff,
                      uint32_t* best_msg1, uint32_t* best_msg2,
                      int n) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if(tid >= n) return;

    uint64_t rng = seed_base2 + tid * 6364136223846793005ULL + 1;
    uint32_t W[16], d[16];
    for(int i=0;i<16;i++){
        rng=rng*6364136223846793005ULL+1442695040888963407ULL;
        W[i]=(uint32_t)(rng>>32);
        d[i]=delta[i];
    }
    d[1]=(uint32_t)(-(int32_t)(sig1(W[15]^d[15])-sig1(W[15])+d[10]+sig0(W[2]^d[2])-sig0(W[2])));
    d[0]=(uint32_t)(-(int32_t)(sig1(W[14]^d[14])-sig1(W[14])+d[9]+sig0(W[1]^d[1])-sig0(W[1])));

    uint64_t dh = compute_diff_hash(W, d, at_round);
    uint32_t slot = (uint32_t)(dh & TABLE_MASK);
    uint32_t tag = (uint32_t)(dh >> 32) | 1;

    // Check if same tag exists in table
    for(int probe=0; probe<16; probe++){
        uint32_t idx = (slot + probe) & TABLE_MASK;
        if(table[idx].diff_hash == tag) {
            // COLLISION on diff hash!
            atomicAdd(n_collisions, 1);

            // Regenerate first message
            uint32_t seed1 = table[idx].msg_seed;
            uint64_t rng1 = seed_base + (uint64_t)seed1 * 6364136223846793005ULL + 1;
            uint32_t W1[16], d1[16];
            for(int i=0;i<16;i++){
                rng1=rng1*6364136223846793005ULL+1442695040888963407ULL;
                W1[i]=(uint32_t)(rng1>>32);
                d1[i]=delta[i];
            }
            d1[1]=(uint32_t)(-(int32_t)(sig1(W1[15]^d1[15])-sig1(W1[15])+d1[10]+sig0(W1[2]^d1[2])-sig0(W1[2])));
            d1[0]=(uint32_t)(-(int32_t)(sig1(W1[14]^d1[14])-sig1(W1[14])+d1[9]+sig0(W1[1]^d1[1])-sig0(W1[1])));

            // Compute R64 diff for both
            int diff1_r64 = full_state_diff(W1, d1, 64);
            int diff2_r64 = full_state_diff(W, d, 64);

            // The one with lower R64 diff is interesting
            int min_diff = diff1_r64 < diff2_r64 ? diff1_r64 : diff2_r64;
            int old = atomicMin(best_r64_diff, min_diff);
            if(min_diff < old){
                if(diff1_r64 <= diff2_r64){
                    for(int i=0;i<16;i++) best_msg1[i]=W1[i];
                } else {
                    for(int i=0;i<16;i++) best_msg1[i]=W[i];
                }
            }
            break;
        }
        if(table[idx].diff_hash == 0) break; // empty slot
    }
}

int main(){
    printf("SHA-256 VRAM Birthday Attack\n");
    printf("════════════════════════════\n");
    printf("Table: 2^%d entries = %d MB\n", HASH_BITS, (int)(TABLE_SIZE*sizeof(HashEntry)/1048576));
    printf("Bandwidth: 892 GB/s\n\n");

    // Delta
    uint32_t h_delta[16]={0};
    h_delta[14] = 1 << 8;
    h_delta[15] = 1 << 8;

    uint32_t *d_delta;
    cudaMalloc(&d_delta, 64);
    cudaMemcpy(d_delta, h_delta, 64, cudaMemcpyHostToDevice);

    // Hash table in VRAM
    HashEntry *d_table;
    size_t table_bytes = (size_t)TABLE_SIZE * sizeof(HashEntry);
    printf("Allocating hash table: %zu MB...\n", table_bytes/1048576);
    cudaMalloc(&d_table, table_bytes);
    cudaMemset(d_table, 0, table_bytes);

    int *d_ncoll, *d_best_diff;
    uint32_t *d_msg1, *d_msg2;
    cudaMalloc(&d_ncoll, 4); cudaMalloc(&d_best_diff, 4);
    cudaMalloc(&d_msg1, 64); cudaMalloc(&d_msg2, 64);

    int threads = 1<<19; // 512K per launch
    int thermal = 300;

    // Try different target rounds
    for(int at_round = 32; at_round <= 44; at_round += 2) {
        printf("\n=== Birthday at Round %d ===\n", at_round);

        cudaMemset(d_table, 0, table_bytes);

        // Fill table: multiple passes
        int total_entries = 0;
        int fill_passes = TABLE_SIZE / threads + 1;
        if(fill_passes > 256) fill_passes = 256;

        printf("  Filling table: %d passes × %dK = %dM entries\n",
               fill_passes, threads/1024, fill_passes*threads/1000000);

        for(int p=0; p<fill_passes; p++){
            struct timespec ts={0, thermal*1000000L}; nanosleep(&ts, NULL);
            fill_table<<<threads/256,256>>>(d_delta, at_round,
                d_table, (uint64_t)p * threads * 7 + 42, threads);
            cudaDeviceSynchronize();
            total_entries += threads;
        }

        // Check collisions with different messages
        int h_ncoll=0, h_best=256;
        cudaMemcpy(d_ncoll, &h_ncoll, 4, cudaMemcpyHostToDevice);
        cudaMemcpy(d_best_diff, &h_best, 4, cudaMemcpyHostToDevice);

        printf("  Checking collisions...\n");
        for(int p=0; p<fill_passes; p++){
            struct timespec ts={0, thermal*1000000L}; nanosleep(&ts, NULL);
            check_collisions<<<threads/256,256>>>(d_delta, at_round,
                d_table, 42, (uint64_t)(p+fill_passes) * threads * 7 + 99999,
                d_ncoll, d_best_diff, d_msg1, d_msg2, threads);
            cudaDeviceSynchronize();
        }

        cudaMemcpy(&h_ncoll, d_ncoll, 4, cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_best, d_best_diff, 4, cudaMemcpyDeviceToHost);

        printf("  Collisions found: %d\n", h_ncoll);
        printf("  Best R64 diff from colliding pair: %d bits\n", h_best);

        if(h_best < 74) {
            printf("  *** BELOW 74-bit BARRIER! ***\n");
        }
        if(h_best == 0) {
            printf("  *** FULL COLLISION! ***\n");
            break;
        }
    }

    cudaFree(d_delta); cudaFree(d_table);
    cudaFree(d_ncoll); cudaFree(d_best_diff);
    cudaFree(d_msg1); cudaFree(d_msg2);
    return 0;
}

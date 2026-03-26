// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// CUDA Keccak-256d mining kernel.
//
// Implements the full Keccak-f[1600] permutation and Keccak-256 sponge
// construction on GPU. Uses original Keccak padding (0x01), NOT SHA-3 (0x06).
//
// Each GPU thread:
//   1. Copies the 92-byte unsigned header to registers
//   2. Writes its unique nonce at offset 84
//   3. Computes keccak256d(header) = keccak256(keccak256(header))
//   4. Compares result against target (big-endian, hash <= target)
//   5. If valid, atomically stores the winning nonce
//
// Host API (flow::miner::cuda namespace):
//   cuda_init()       — detect GPU, allocate device buffers
//   cuda_shutdown()   — free device buffers
//   cuda_mine_batch() — upload header+target, launch kernel, return nonce

#ifdef FLOWCOIN_USE_CUDA

#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

// ═══════════════════════════════════════════════════════════════════════
// Keccak-f[1600] round constants (24 rounds)
// ═══════════════════════════════════════════════════════════════════════

__constant__ uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

// ═══════════════════════════════════════════════════════════════════════
// Keccak-f[1600] permutation — 24 rounds
//
// Matches KeccakP-1600-reference.c exactly:
//   theta -> rho -> pi -> chi -> iota
//
// The rho+pi step uses the standard precomputed lane permutation and
// rotation offsets derived from the Keccak specification.
// ═══════════════════════════════════════════════════════════════════════

__device__ __forceinline__ uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

__device__ void keccak_f1600(uint64_t state[25]) {
    for (int round = 0; round < 24; round++) {
        // ----- theta -----
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; x++)
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];

        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 25; y += 5)
                state[y + x] ^= D[x];
        }

        // ----- rho and pi (combined) -----
        // Matches the reference implementation:
        //   rho: rotate each lane by KeccakRhoOffsets[index(x,y)]
        //   pi:  A[y, 2*x+3*y] = A[x, y]
        //
        // The combined form iterates the 24 non-identity lane positions
        // using precomputed destination indices (piln) and rotation
        // amounts (rotc), carrying forward one temporary value.
        {
            uint64_t temp = state[1];
            // piln[i]: destination index for the i-th step
            // rotc[i]: rotation amount for the i-th step
            //
            // These tables encode the composed rho+pi permutation.
            // Starting from lane (1,0), the pi mapping
            //   (x,y) -> (y, 2x+3y mod 5)
            // visits all 24 non-zero lanes. The rotation offset for
            // each lane is (t+1)(t+2)/2 mod 64 where t is the step index.
            const int piln[24] = {
                10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
                15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
            };
            const int rotc[24] = {
                 1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
                27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
            };
            for (int i = 0; i < 24; i++) {
                int j = piln[i];
                uint64_t tmp2 = state[j];
                state[j] = rotl64(temp, rotc[i]);
                temp = tmp2;
            }
        }

        // ----- chi -----
        for (int y = 0; y < 25; y += 5) {
            uint64_t t0 = state[y + 0], t1 = state[y + 1], t2 = state[y + 2],
                     t3 = state[y + 3], t4 = state[y + 4];
            state[y + 0] = t0 ^ ((~t1) & t2);
            state[y + 1] = t1 ^ ((~t2) & t3);
            state[y + 2] = t2 ^ ((~t3) & t4);
            state[y + 3] = t3 ^ ((~t4) & t0);
            state[y + 4] = t4 ^ ((~t0) & t1);
        }

        // ----- iota -----
        state[0] ^= RC[round];
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Keccak-256 hash
//
//   Rate     = 1088 bits = 136 bytes
//   Capacity = 512 bits
//   Output   = 256 bits = 32 bytes
//   Padding  = 0x01 (original Keccak, NOT SHA-3 0x06)
//
// The sponge absorbs data in 136-byte blocks, XOR-ing into the state,
// then applies keccak-f[1600]. After all data is absorbed, padding is
// applied: 0x01 after the last data byte, 0x80 at byte 135 of the
// final block (these may overlap when remaining == 135).
// ═══════════════════════════════════════════════════════════════════════

__device__ void keccak256_device(const uint8_t* data, int len, uint8_t hash[32]) {
    uint64_t state[25];
    #pragma unroll
    for (int i = 0; i < 25; i++)
        state[i] = 0;

    const int rate_bytes = 136;  // 1088 bits / 8

    // Absorb complete blocks
    int offset = 0;
    while (offset + rate_bytes <= len) {
        for (int i = 0; i < rate_bytes / 8; i++) {
            uint64_t word;
            memcpy(&word, data + offset + i * 8, 8);
            state[i] ^= word;
        }
        keccak_f1600(state);
        offset += rate_bytes;
    }

    // Final block with padding
    // Zero-init the block, copy remaining data, apply Keccak padding
    uint8_t block[136];
    memset(block, 0, rate_bytes);
    int remaining = len - offset;
    if (remaining > 0)
        memcpy(block, data + offset, remaining);

    // Keccak padding: 0x01 immediately after last data byte
    block[remaining] = 0x01;
    // 0x80 at the last byte of the rate block
    block[rate_bytes - 1] |= 0x80;

    // XOR padded block into state and permute
    for (int i = 0; i < rate_bytes / 8; i++) {
        uint64_t word;
        memcpy(&word, block + i * 8, 8);
        state[i] ^= word;
    }
    keccak_f1600(state);

    // Squeeze: extract 32 bytes (256 bits) from state
    memcpy(hash, state, 32);
}

// ═══════════════════════════════════════════════════════════════════════
// Keccak-256d (double hash)
//
// keccak256d(data) = keccak256(keccak256(data))
//
// Analogous to Bitcoin's SHA256d, provides domain separation and
// protects against length-extension attacks.
// ═══════════════════════════════════════════════════════════════════════

__device__ void keccak256d_device(const uint8_t* data, int len, uint8_t hash[32]) {
    uint8_t first[32];
    keccak256_device(data, len, first);
    keccak256_device(first, 32, hash);
}

// ═══════════════════════════════════════════════════════════════════════
// Target comparison (big-endian byte order)
//
// Returns true if hash <= target.
// Both hash and target are 32-byte big-endian integers; we compare
// byte-by-byte from the most significant byte (index 0).
// ═══════════════════════════════════════════════════════════════════════

__device__ bool hash_meets_target(const uint8_t hash[32], const uint8_t target[32]) {
    for (int i = 0; i < 32; i++) {
        if (hash[i] < target[i]) return true;
        if (hash[i] > target[i]) return false;
    }
    return true;  // equal counts as meeting target
}

// ═══════════════════════════════════════════════════════════════════════
// Mining kernel
//
// Each thread:
//   1. Computes its unique nonce = start_nonce + global_thread_id
//   2. Copies the unsigned header (92 bytes) to local memory
//   3. Patches the nonce at offset 84 (4 bytes, little-endian)
//   4. Computes keccak256d(header)
//   5. If hash <= target, atomically records the winning nonce
//
// Only the first thread to find a valid nonce writes its result.
// ═══════════════════════════════════════════════════════════════════════

__global__ void keccak256d_mine_kernel(
    const uint8_t* __restrict__ header_base,   // unsigned header (92 bytes)
    int            header_len,                 // header length in bytes
    uint32_t       start_nonce,                // first nonce for this batch
    const uint8_t* __restrict__ target,        // 32-byte target hash
    uint32_t*      found_nonce,                // output: winning nonce
    uint32_t*      found_count                 // output: number found (atomic)
) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t nonce = start_nonce + tid;

    // Copy header to thread-local memory and patch the nonce
    uint8_t header[92];
    memcpy(header, header_base, header_len);
    // Nonce sits at offset 84 in the unsigned header (little-endian uint32)
    header[84] = (uint8_t)(nonce);
    header[85] = (uint8_t)(nonce >> 8);
    header[86] = (uint8_t)(nonce >> 16);
    header[87] = (uint8_t)(nonce >> 24);

    // Double Keccak-256
    uint8_t hash[32];
    keccak256d_device(header, header_len, hash);

    // Check against target
    if (hash_meets_target(hash, target)) {
        uint32_t idx = atomicAdd(found_count, 1);
        if (idx == 0) {
            // First finder writes the nonce
            *found_nonce = nonce;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Host API
// ═══════════════════════════════════════════════════════════════════════

namespace flow { namespace miner { namespace cuda {

static uint8_t*  d_header     = nullptr;
static uint8_t*  d_target     = nullptr;
static uint32_t* d_found_nonce = nullptr;
static uint32_t* d_found_count = nullptr;
static bool      initialized  = false;
static int       num_sms      = 0;

// ---- cuda_init ----
// Detect GPU, print device info, allocate persistent device buffers.
// Returns false if no CUDA device is available.

bool cuda_init() {
    if (initialized) return true;

    int device_count = 0;
    cudaError_t err = cudaGetDeviceCount(&device_count);
    if (err != cudaSuccess || device_count == 0) {
        std::fprintf(stderr, "  CUDA: No devices found\n");
        return false;
    }

    err = cudaSetDevice(0);
    if (err != cudaSuccess) {
        std::fprintf(stderr, "  CUDA: Failed to set device 0\n");
        return false;
    }

    // Allocate persistent device buffers
    cudaMalloc(&d_header,     92);
    cudaMalloc(&d_target,     32);
    cudaMalloc(&d_found_nonce, sizeof(uint32_t));
    cudaMalloc(&d_found_count, sizeof(uint32_t));

    // Query device properties for tuning and display
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);
    num_sms = prop.multiProcessorCount;

    std::fprintf(stderr, "  CUDA: %s (%d SMs, %.1f GB, SM %d.%d)\n",
                 prop.name, num_sms,
                 prop.totalGlobalMem / 1e9,
                 prop.major, prop.minor);

    initialized = true;
    return true;
}

// ---- cuda_shutdown ----
// Free all device buffers and reset state.

void cuda_shutdown() {
    if (!initialized) return;

    cudaFree(d_header);
    cudaFree(d_target);
    cudaFree(d_found_nonce);
    cudaFree(d_found_count);

    d_header     = nullptr;
    d_target     = nullptr;
    d_found_nonce = nullptr;
    d_found_count = nullptr;
    initialized  = false;
}

// ---- cuda_mine_batch ----
// Mine a range of nonces on the GPU.
//
//   header_data  — unsigned block header (92 bytes typical)
//   header_len   — length in bytes
//   target_data  — 32-byte target hash (big-endian)
//   start_nonce  — first nonce to try
//   batch_size   — number of nonces to try (e.g. 1<<24 = 16M)
//
// Returns the winning nonce, or 0 if none found in this batch.
// Note: nonce 0 itself is never returned as "not found" — if nonce 0
// is actually valid, found_count will be > 0 on the device side.

uint32_t cuda_mine_batch(
    const uint8_t* header_data, int header_len,
    const uint8_t* target_data,
    uint32_t start_nonce,
    uint32_t batch_size
) {
    if (!initialized) return 0;

    // Upload header and target to device
    cudaMemcpy(d_header, header_data, header_len, cudaMemcpyHostToDevice);
    cudaMemcpy(d_target, target_data, 32,         cudaMemcpyHostToDevice);

    // Reset output buffers
    uint32_t zero = 0;
    cudaMemcpy(d_found_nonce, &zero, sizeof(uint32_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_found_count, &zero, sizeof(uint32_t), cudaMemcpyHostToDevice);

    // Launch configuration: 256 threads per block is a good default for
    // register-heavy kernels like Keccak
    const int threads_per_block = 256;
    const int blocks = (batch_size + threads_per_block - 1) / threads_per_block;

    keccak256d_mine_kernel<<<blocks, threads_per_block>>>(
        d_header, header_len, start_nonce, d_target,
        d_found_nonce, d_found_count
    );

    cudaDeviceSynchronize();

    // Check for kernel errors
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        std::fprintf(stderr, "  CUDA kernel error: %s\n", cudaGetErrorString(err));
        return 0;
    }

    // Read results back
    uint32_t host_count = 0;
    cudaMemcpy(&host_count, d_found_count, sizeof(uint32_t), cudaMemcpyDeviceToHost);

    if (host_count > 0) {
        uint32_t winning_nonce = 0;
        cudaMemcpy(&winning_nonce, d_found_nonce, sizeof(uint32_t), cudaMemcpyDeviceToHost);
        return winning_nonce;
    }

    return 0;  // no valid nonce found in this batch
}

}}} // namespace flow::miner::cuda

#endif // FLOWCOIN_USE_CUDA

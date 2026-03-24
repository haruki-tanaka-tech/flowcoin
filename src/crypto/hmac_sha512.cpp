// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "hmac_sha512.h"

#include <cstring>
#include <stdexcept>
#include <vector>

extern "C" {
#include "../hash/KeccakHash.h"
}

namespace flow {

// ===========================================================================
// SHA-512 Implementation (FIPS 180-4)
// ===========================================================================

// ---------------------------------------------------------------------------
// SHA-512 round constants (first 80 primes, cube roots, fractional parts)
// ---------------------------------------------------------------------------

static const uint64_t SHA512_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

// SHA-512 initial hash values (fractional parts of square roots of first 8 primes)
static const uint64_t SHA512_H0[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

// ---------------------------------------------------------------------------
// SHA-512 helper functions
// ---------------------------------------------------------------------------

static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint64_t Sigma0(uint64_t x) {
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

static inline uint64_t Sigma1(uint64_t x) {
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

static inline uint64_t sigma0(uint64_t x) {
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}

static inline uint64_t sigma1(uint64_t x) {
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

// Load big-endian uint64
static inline uint64_t load_be64(const uint8_t* p) {
    return (static_cast<uint64_t>(p[0]) << 56) |
           (static_cast<uint64_t>(p[1]) << 48) |
           (static_cast<uint64_t>(p[2]) << 40) |
           (static_cast<uint64_t>(p[3]) << 32) |
           (static_cast<uint64_t>(p[4]) << 24) |
           (static_cast<uint64_t>(p[5]) << 16) |
           (static_cast<uint64_t>(p[6]) << 8) |
           static_cast<uint64_t>(p[7]);
}

// Store big-endian uint64
static inline void store_be64(uint8_t* p, uint64_t v) {
    p[0] = static_cast<uint8_t>(v >> 56);
    p[1] = static_cast<uint8_t>(v >> 48);
    p[2] = static_cast<uint8_t>(v >> 40);
    p[3] = static_cast<uint8_t>(v >> 32);
    p[4] = static_cast<uint8_t>(v >> 24);
    p[5] = static_cast<uint8_t>(v >> 16);
    p[6] = static_cast<uint8_t>(v >> 8);
    p[7] = static_cast<uint8_t>(v);
}

// ---------------------------------------------------------------------------
// SHA-512 compression function (process one 128-byte block)
// ---------------------------------------------------------------------------

static void sha512_transform(uint64_t state[8], const uint8_t block[128]) {
    uint64_t W[80];

    // Prepare message schedule
    for (int t = 0; t < 16; ++t) {
        W[t] = load_be64(block + t * 8);
    }
    for (int t = 16; t < 80; ++t) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    // Initialize working variables
    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

    // 80 rounds
    for (int t = 0; t < 80; ++t) {
        uint64_t T1 = h + Sigma1(e) + Ch(e, f, g) + SHA512_K[t] + W[t];
        uint64_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // Add compressed chunk to hash value
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// ---------------------------------------------------------------------------
// SHA-512 public API
// ---------------------------------------------------------------------------

void sha512_init(SHA512Context& ctx) {
    for (int i = 0; i < 8; ++i) {
        ctx.state[i] = SHA512_H0[i];
    }
    ctx.count[0] = 0;
    ctx.count[1] = 0;
    std::memset(ctx.buffer, 0, sizeof(ctx.buffer));
}

void sha512_update(SHA512Context& ctx, const uint8_t* data, size_t len) {
    size_t buf_used = static_cast<size_t>((ctx.count[0] >> 3) & 0x7f);

    // Update bit count
    uint64_t bit_len = static_cast<uint64_t>(len) << 3;
    ctx.count[0] += bit_len;
    if (ctx.count[0] < bit_len) {
        ctx.count[1]++;
    }
    ctx.count[1] += static_cast<uint64_t>(len) >> 61;

    size_t offset = 0;

    // If we have buffered data, try to fill the buffer
    if (buf_used > 0) {
        size_t space = 128 - buf_used;
        size_t copy_len = (len < space) ? len : space;
        std::memcpy(ctx.buffer + buf_used, data, copy_len);
        offset += copy_len;
        buf_used += copy_len;

        if (buf_used == 128) {
            sha512_transform(ctx.state, ctx.buffer);
            buf_used = 0;
        }
    }

    // Process full blocks directly from input
    while (offset + 128 <= len) {
        sha512_transform(ctx.state, data + offset);
        offset += 128;
    }

    // Buffer remaining bytes
    if (offset < len) {
        std::memcpy(ctx.buffer, data + offset, len - offset);
    }
}

void sha512_final(SHA512Context& ctx, uint8_t out[64]) {
    size_t buf_used = static_cast<size_t>((ctx.count[0] >> 3) & 0x7f);

    // Append 0x80 byte
    ctx.buffer[buf_used++] = 0x80;

    // If not enough room for the 16-byte length, pad to 128 and process
    if (buf_used > 112) {
        std::memset(ctx.buffer + buf_used, 0, 128 - buf_used);
        sha512_transform(ctx.state, ctx.buffer);
        buf_used = 0;
    }

    // Pad to 112 bytes
    std::memset(ctx.buffer + buf_used, 0, 112 - buf_used);

    // Append 128-bit length in big-endian (high 64 bits, then low 64 bits)
    store_be64(ctx.buffer + 112, ctx.count[1]);
    store_be64(ctx.buffer + 120, ctx.count[0]);

    sha512_transform(ctx.state, ctx.buffer);

    // Output hash in big-endian
    for (int i = 0; i < 8; ++i) {
        store_be64(out + i * 8, ctx.state[i]);
    }

    // Wipe context
    std::memset(&ctx, 0, sizeof(ctx));
}

void sha512(const uint8_t* data, size_t len, uint8_t out[64]) {
    SHA512Context ctx;
    sha512_init(ctx);
    sha512_update(ctx, data, len);
    sha512_final(ctx, out);
}

uint512 sha512_hash(const uint8_t* data, size_t len) {
    uint512 result;
    sha512(data, len, result.data());
    return result;
}

// ===========================================================================
// HMAC-SHA-512 (RFC 4231)
// ===========================================================================

static constexpr size_t SHA512_BLOCK_SIZE = 128;
static constexpr size_t SHA512_OUTPUT_SIZE = 64;

uint512 hmac_sha512(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len)
{
    uint8_t key_block[SHA512_BLOCK_SIZE];
    std::memset(key_block, 0, SHA512_BLOCK_SIZE);

    // If key is longer than block size, hash it
    if (key_len > SHA512_BLOCK_SIZE) {
        sha512(key, key_len, key_block);
    } else {
        std::memcpy(key_block, key, key_len);
    }

    // Compute ipad and opad
    uint8_t ipad[SHA512_BLOCK_SIZE];
    uint8_t opad[SHA512_BLOCK_SIZE];
    for (size_t i = 0; i < SHA512_BLOCK_SIZE; ++i) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    // Inner hash = SHA-512(ipad || data)
    uint8_t inner_hash[SHA512_OUTPUT_SIZE];
    {
        SHA512Context ctx;
        sha512_init(ctx);
        sha512_update(ctx, ipad, SHA512_BLOCK_SIZE);
        sha512_update(ctx, data, data_len);
        sha512_final(ctx, inner_hash);
    }

    // Outer hash = SHA-512(opad || inner_hash)
    uint512 result;
    {
        SHA512Context ctx;
        sha512_init(ctx);
        sha512_update(ctx, opad, SHA512_BLOCK_SIZE);
        sha512_update(ctx, inner_hash, SHA512_OUTPUT_SIZE);
        sha512_final(ctx, result.data());
    }

    // Wipe sensitive intermediates
    std::memset(key_block, 0, sizeof(key_block));
    std::memset(ipad, 0, sizeof(ipad));
    std::memset(opad, 0, sizeof(opad));
    std::memset(inner_hash, 0, sizeof(inner_hash));

    return result;
}

// ===========================================================================
// Keccak-512 wrappers
// ===========================================================================

// Keccak-512 parameters
// rate = 576 bits = 72 bytes (this is the block size for HMAC)
static constexpr size_t KECCAK512_BLOCK_SIZE = 72;
static constexpr size_t KECCAK512_OUTPUT_SIZE = 64;

// ---------------------------------------------------------------------------
// Internal: raw Keccak-512 single-shot
// ---------------------------------------------------------------------------

static void keccak512_raw(const uint8_t* data, size_t len, uint8_t* out64) {
    Keccak_HashInstance ctx;
    if (Keccak_HashInitialize(&ctx, 576, 1024, 512, 0x01) != KECCAK_SUCCESS) {
        throw std::runtime_error("keccak512 init failed");
    }
    if (Keccak_HashUpdate(&ctx, data, len * 8) != KECCAK_SUCCESS) {
        throw std::runtime_error("keccak512 update failed");
    }
    if (Keccak_HashFinal(&ctx, out64) != KECCAK_SUCCESS) {
        throw std::runtime_error("keccak512 finalize failed");
    }
}

// ---------------------------------------------------------------------------
// Internal: Keccak-512 incremental
// ---------------------------------------------------------------------------

struct Keccak512Ctx {
    Keccak_HashInstance state;

    Keccak512Ctx() {
        if (Keccak_HashInitialize(&state, 576, 1024, 512, 0x01) != KECCAK_SUCCESS) {
            throw std::runtime_error("keccak512 ctx init failed");
        }
    }

    void update(const uint8_t* data, size_t len) {
        if (Keccak_HashUpdate(&state, data, len * 8) != KECCAK_SUCCESS) {
            throw std::runtime_error("keccak512 ctx update failed");
        }
    }

    void finalize(uint8_t* out64) {
        if (Keccak_HashFinal(&state, out64) != KECCAK_SUCCESS) {
            throw std::runtime_error("keccak512 ctx finalize failed");
        }
    }
};

// ---------------------------------------------------------------------------
// Public API: Keccak-512
// ---------------------------------------------------------------------------

void keccak512(const uint8_t* data, size_t len, uint8_t out[64]) {
    keccak512_raw(data, len, out);
}

uint512 keccak512_hash(const uint8_t* data, size_t len) {
    uint512 result;
    keccak512_raw(data, len, result.data());
    return result;
}

// ---------------------------------------------------------------------------
// HMAC-Keccak-512 (RFC 2104)
// ---------------------------------------------------------------------------

uint512 hmac_keccak512(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len)
{
    uint8_t key_block[KECCAK512_BLOCK_SIZE];
    std::memset(key_block, 0, KECCAK512_BLOCK_SIZE);

    // Step 1: If key is longer than block size, hash it
    if (key_len > KECCAK512_BLOCK_SIZE) {
        keccak512_raw(key, key_len, key_block);
        // key_block now contains the 64-byte hash, zero-padded to 72
    } else {
        std::memcpy(key_block, key, key_len);
        // Remaining bytes are already zero from memset
    }

    // Step 2: Compute ipad and opad
    uint8_t ipad[KECCAK512_BLOCK_SIZE];
    uint8_t opad[KECCAK512_BLOCK_SIZE];
    for (size_t i = 0; i < KECCAK512_BLOCK_SIZE; ++i) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    // Step 3: Inner hash = Keccak-512(ipad || data)
    uint8_t inner_hash[KECCAK512_OUTPUT_SIZE];
    {
        Keccak512Ctx ctx;
        ctx.update(ipad, KECCAK512_BLOCK_SIZE);
        ctx.update(data, data_len);
        ctx.finalize(inner_hash);
    }

    // Step 4: Outer hash = Keccak-512(opad || inner_hash)
    uint512 result;
    {
        Keccak512Ctx ctx;
        ctx.update(opad, KECCAK512_BLOCK_SIZE);
        ctx.update(inner_hash, KECCAK512_OUTPUT_SIZE);
        ctx.finalize(result.data());
    }

    // Wipe sensitive intermediates
    std::memset(key_block, 0, sizeof(key_block));
    std::memset(ipad, 0, sizeof(ipad));
    std::memset(opad, 0, sizeof(opad));
    std::memset(inner_hash, 0, sizeof(inner_hash));

    return result;
}

} // namespace flow

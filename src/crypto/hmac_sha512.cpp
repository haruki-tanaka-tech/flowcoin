// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// SHA-512 and HMAC-SHA512 implementation.
// Based on FIPS 180-4 and RFC 2104.

#include "hmac_sha512.h"
#include <cstring>

namespace flow::crypto {

static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t load_be64(const uint8_t* p) {
    return (uint64_t(p[0]) << 56) | (uint64_t(p[1]) << 48)
         | (uint64_t(p[2]) << 40) | (uint64_t(p[3]) << 32)
         | (uint64_t(p[4]) << 24) | (uint64_t(p[5]) << 16)
         | (uint64_t(p[6]) << 8)  |  uint64_t(p[7]);
}

static inline void store_be64(uint8_t* p, uint64_t v) {
    p[0] = uint8_t(v >> 56); p[1] = uint8_t(v >> 48);
    p[2] = uint8_t(v >> 40); p[3] = uint8_t(v >> 32);
    p[4] = uint8_t(v >> 24); p[5] = uint8_t(v >> 16);
    p[6] = uint8_t(v >> 8);  p[7] = uint8_t(v);
}

static void sha512_transform(uint64_t h[8], const uint8_t block[128]) {
    uint64_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = load_be64(block + i * 8);
    }
    for (int i = 16; i < 80; ++i) {
        uint64_t s0 = rotr64(w[i-15], 1) ^ rotr64(w[i-15], 8) ^ (w[i-15] >> 7);
        uint64_t s1 = rotr64(w[i-2], 19) ^ rotr64(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint64_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint64_t e = h[4], f = h[5], g = h[6], hh = h[7];

    for (int i = 0; i < 80; ++i) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t temp1 = hh + S1 + ch + K[i] + w[i];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temp2 = S0 + maj;

        hh = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void sha512_init(Sha512State& s) {
    s.h[0] = 0x6a09e667f3bcc908ULL;
    s.h[1] = 0xbb67ae8584caa73bULL;
    s.h[2] = 0x3c6ef372fe94f82bULL;
    s.h[3] = 0xa54ff53a5f1d36f1ULL;
    s.h[4] = 0x510e527fade682d1ULL;
    s.h[5] = 0x9b05688c2b3e6c1fULL;
    s.h[6] = 0x1f83d9abfb41bd6bULL;
    s.h[7] = 0x5be0cd19137e2179ULL;
    s.total[0] = s.total[1] = 0;
    s.buflen = 0;
}

void sha512_update(Sha512State& s, const uint8_t* data, size_t len) {
    s.total[0] += len;
    if (s.total[0] < len) s.total[1]++;

    while (len > 0) {
        size_t space = 128 - s.buflen;
        size_t copy = (len < space) ? len : space;
        std::memcpy(s.buffer + s.buflen, data, copy);
        s.buflen += copy;
        data += copy;
        len -= copy;

        if (s.buflen == 128) {
            sha512_transform(s.h, s.buffer);
            s.buflen = 0;
        }
    }
}

void sha512_final(Sha512State& s, uint8_t out[64]) {
    uint64_t total_bits_lo = s.total[0] * 8;
    uint64_t total_bits_hi = s.total[1] * 8 + (s.total[0] >> 61);

    // Padding
    s.buffer[s.buflen++] = 0x80;
    if (s.buflen > 112) {
        std::memset(s.buffer + s.buflen, 0, 128 - s.buflen);
        sha512_transform(s.h, s.buffer);
        s.buflen = 0;
    }
    std::memset(s.buffer + s.buflen, 0, 112 - s.buflen);
    store_be64(s.buffer + 112, total_bits_hi);
    store_be64(s.buffer + 120, total_bits_lo);
    sha512_transform(s.h, s.buffer);

    for (int i = 0; i < 8; ++i) {
        store_be64(out + i * 8, s.h[i]);
    }
}

void sha512(const uint8_t* data, size_t len, uint8_t out[64]) {
    Sha512State s;
    sha512_init(s);
    sha512_update(s, data, len);
    sha512_final(s, out);
}

void hmac_sha512(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t out[64]) {
    uint8_t k_pad[128];

    // If key > block size, hash it first
    uint8_t key_hash[64];
    if (key_len > 128) {
        sha512(key, key_len, key_hash);
        key = key_hash;
        key_len = 64;
    }

    // ipad
    std::memset(k_pad, 0x36, 128);
    for (size_t i = 0; i < key_len; ++i) {
        k_pad[i] ^= key[i];
    }

    Sha512State inner;
    sha512_init(inner);
    sha512_update(inner, k_pad, 128);
    sha512_update(inner, data, data_len);
    uint8_t inner_hash[64];
    sha512_final(inner, inner_hash);

    // opad
    std::memset(k_pad, 0x5c, 128);
    for (size_t i = 0; i < key_len; ++i) {
        k_pad[i] ^= key[i];
    }

    Sha512State outer;
    sha512_init(outer);
    sha512_update(outer, k_pad, 128);
    sha512_update(outer, inner_hash, 64);
    sha512_final(outer, out);
}

} // namespace flow::crypto

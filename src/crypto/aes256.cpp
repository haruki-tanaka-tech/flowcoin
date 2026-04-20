// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "aes256.h"
#include "../hash/keccak.h"
#include "keys.h"  // for secure_random, secure_wipe

#include <cstring>
#include <stdexcept>

namespace flow {

// ===========================================================================
// AES S-Box (Rijndael S-box, precomputed from GF(2^8) inversion + affine)
// ===========================================================================

const uint8_t AES256_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// ===========================================================================
// AES inverse S-Box
// ===========================================================================

const uint8_t AES256_INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

// ===========================================================================
// AES round constants for key expansion
// ===========================================================================

static const uint8_t AES_RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// ===========================================================================
// GF(2^8) multiplication
// ===========================================================================

uint8_t aes_xtime(uint8_t x) {
    return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

uint8_t aes_gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t temp = a;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) {
            result ^= temp;
        }
        temp = aes_xtime(temp);
        b >>= 1;
    }
    return result;
}

// ===========================================================================
// Key expansion helpers
// ===========================================================================

static uint32_t sub_word(uint32_t w) {
    uint8_t b[4];
    b[0] = AES256_SBOX[(w >> 24) & 0xFF];
    b[1] = AES256_SBOX[(w >> 16) & 0xFF];
    b[2] = AES256_SBOX[(w >> 8) & 0xFF];
    b[3] = AES256_SBOX[w & 0xFF];
    return (static_cast<uint32_t>(b[0]) << 24) |
           (static_cast<uint32_t>(b[1]) << 16) |
           (static_cast<uint32_t>(b[2]) << 8) |
           static_cast<uint32_t>(b[3]);
}

static uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

// ===========================================================================
// AES-256 key schedule
// ===========================================================================

void aes256_key_expand(AES256Context& ctx, const uint8_t key[32]) {
    // Load the 8 initial words from the 256-bit key (big-endian words)
    for (int i = 0; i < 8; ++i) {
        ctx.round_keys[i] = (static_cast<uint32_t>(key[4 * i]) << 24) |
                            (static_cast<uint32_t>(key[4 * i + 1]) << 16) |
                            (static_cast<uint32_t>(key[4 * i + 2]) << 8) |
                            static_cast<uint32_t>(key[4 * i + 3]);
    }

    // AES-256 key expansion: generate words 8..59
    for (int i = 8; i < 60; ++i) {
        uint32_t temp = ctx.round_keys[i - 1];
        if (i % 8 == 0) {
            temp = sub_word(rot_word(temp)) ^ (static_cast<uint32_t>(AES_RCON[i / 8 - 1]) << 24);
        } else if (i % 8 == 4) {
            temp = sub_word(temp);
        }
        ctx.round_keys[i] = ctx.round_keys[i - 8] ^ temp;
    }
}

// ===========================================================================
// AES round operations
// ===========================================================================

static void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) {
        state[i] = AES256_SBOX[state[i]];
    }
}

static void inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) {
        state[i] = AES256_INV_SBOX[state[i]];
    }
}

// State layout (column-major):
//  s0  s4  s8  s12
//  s1  s5  s9  s13
//  s2  s6  s10 s14
//  s3  s7  s11 s15

static void shift_rows(uint8_t s[16]) {
    // Row 0: no shift
    // Row 1: shift left by 1
    uint8_t t = s[1];
    s[1]  = s[5];
    s[5]  = s[9];
    s[9]  = s[13];
    s[13] = t;

    // Row 2: shift left by 2
    t = s[2];     s[2]  = s[10]; s[10] = t;
    t = s[6];     s[6]  = s[14]; s[14] = t;

    // Row 3: shift left by 3 (= shift right by 1)
    t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7]  = s[3];
    s[3]  = t;
}

static void inv_shift_rows(uint8_t s[16]) {
    // Row 1: shift right by 1
    uint8_t t = s[13];
    s[13] = s[9];
    s[9]  = s[5];
    s[5]  = s[1];
    s[1]  = t;

    // Row 2: shift right by 2
    t = s[2];  s[2]  = s[10]; s[10] = t;
    t = s[6];  s[6]  = s[14]; s[14] = t;

    // Row 3: shift right by 3 (= shift left by 1)
    t = s[3];
    s[3]  = s[7];
    s[7]  = s[11];
    s[11] = s[15];
    s[15] = t;
}

static void mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
        int i = c * 4;
        uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];

        s[i]     = aes_gf_mul(2, a0) ^ aes_gf_mul(3, a1) ^ a2 ^ a3;
        s[i + 1] = a0 ^ aes_gf_mul(2, a1) ^ aes_gf_mul(3, a2) ^ a3;
        s[i + 2] = a0 ^ a1 ^ aes_gf_mul(2, a2) ^ aes_gf_mul(3, a3);
        s[i + 3] = aes_gf_mul(3, a0) ^ a1 ^ a2 ^ aes_gf_mul(2, a3);
    }
}

static void inv_mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
        int i = c * 4;
        uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];

        s[i]     = aes_gf_mul(14, a0) ^ aes_gf_mul(11, a1) ^ aes_gf_mul(13, a2) ^ aes_gf_mul(9, a3);
        s[i + 1] = aes_gf_mul(9, a0) ^ aes_gf_mul(14, a1) ^ aes_gf_mul(11, a2) ^ aes_gf_mul(13, a3);
        s[i + 2] = aes_gf_mul(13, a0) ^ aes_gf_mul(9, a1) ^ aes_gf_mul(14, a2) ^ aes_gf_mul(11, a3);
        s[i + 3] = aes_gf_mul(11, a0) ^ aes_gf_mul(13, a1) ^ aes_gf_mul(9, a2) ^ aes_gf_mul(14, a3);
    }
}

static void add_round_key(uint8_t state[16], const uint32_t* rk) {
    for (int c = 0; c < 4; ++c) {
        uint32_t k = rk[c];
        state[c * 4]     ^= static_cast<uint8_t>(k >> 24);
        state[c * 4 + 1] ^= static_cast<uint8_t>(k >> 16);
        state[c * 4 + 2] ^= static_cast<uint8_t>(k >> 8);
        state[c * 4 + 3] ^= static_cast<uint8_t>(k);
    }
}

// ===========================================================================
// AES-256 ECB encrypt / decrypt
// ===========================================================================

void aes256_ecb_encrypt(const AES256Context& ctx,
                         const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[16];
    std::memcpy(state, in, 16);

    // Initial round key addition
    add_round_key(state, &ctx.round_keys[0]);

    // Rounds 1..13 (Nr-1 = 13 for AES-256)
    for (int round = 1; round <= 13; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ctx.round_keys[round * 4]);
    }

    // Final round (no MixColumns)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &ctx.round_keys[14 * 4]);

    std::memcpy(out, state, 16);
}

void aes256_ecb_decrypt(const AES256Context& ctx,
                         const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[16];
    std::memcpy(state, in, 16);

    // Initial round key addition (last round key)
    add_round_key(state, &ctx.round_keys[14 * 4]);

    // Rounds 13..1
    for (int round = 13; round >= 1; --round) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &ctx.round_keys[round * 4]);
        inv_mix_columns(state);
    }

    // Final round (no InvMixColumns)
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &ctx.round_keys[0]);

    std::memcpy(out, state, 16);
}

// ===========================================================================
// PKCS7 padding
// ===========================================================================

std::vector<uint8_t> aes_pkcs7_pad(const uint8_t* data, size_t len) {
    size_t pad_len = 16 - (len % 16);
    std::vector<uint8_t> result(len + pad_len);
    if (len > 0) {
        std::memcpy(result.data(), data, len);
    }
    for (size_t i = len; i < len + pad_len; ++i) {
        result[i] = static_cast<uint8_t>(pad_len);
    }
    return result;
}

std::vector<uint8_t> aes_pkcs7_unpad(const uint8_t* data, size_t len) {
    if (len == 0 || len % 16 != 0) {
        return {};
    }

    uint8_t pad_val = data[len - 1];
    if (pad_val == 0 || pad_val > 16) {
        return {};
    }

    // Verify all padding bytes (constant-time)
    uint8_t bad = 0;
    for (size_t i = len - pad_val; i < len; ++i) {
        bad |= data[i] ^ pad_val;
    }
    if (bad != 0) {
        return {};
    }

    size_t data_len = len - pad_val;
    return std::vector<uint8_t>(data, data + data_len);
}

// ===========================================================================
// CBC mode
// ===========================================================================

std::vector<uint8_t> aes256_cbc_encrypt(const uint8_t* data, size_t data_len,
                                          const uint8_t key[32],
                                          const uint8_t iv[16]) {
    AES256Context ctx;
    aes256_key_expand(ctx, key);

    // Pad the plaintext
    std::vector<uint8_t> padded = aes_pkcs7_pad(data, data_len);
    size_t num_blocks = padded.size() / 16;

    std::vector<uint8_t> result(padded.size());

    // CBC encryption
    uint8_t prev_block[16];
    std::memcpy(prev_block, iv, 16);

    for (size_t b = 0; b < num_blocks; ++b) {
        uint8_t block[16];
        std::memcpy(block, padded.data() + b * 16, 16);

        // XOR with previous ciphertext block (or IV)
        for (int i = 0; i < 16; ++i) {
            block[i] ^= prev_block[i];
        }

        uint8_t cipher_block[16];
        aes256_ecb_encrypt(ctx, block, cipher_block);

        std::memcpy(result.data() + b * 16, cipher_block, 16);
        std::memcpy(prev_block, cipher_block, 16);
    }

    aes256_wipe(ctx);
    return result;
}

std::vector<uint8_t> aes256_cbc_decrypt(const uint8_t* data, size_t data_len,
                                          const uint8_t key[32],
                                          const uint8_t iv[16]) {
    if (data_len == 0 || data_len % 16 != 0) {
        return {};
    }

    AES256Context ctx;
    aes256_key_expand(ctx, key);

    size_t num_blocks = data_len / 16;
    std::vector<uint8_t> padded(data_len);

    // CBC decryption
    uint8_t prev_block[16];
    std::memcpy(prev_block, iv, 16);

    for (size_t b = 0; b < num_blocks; ++b) {
        uint8_t cipher_block[16];
        std::memcpy(cipher_block, data + b * 16, 16);

        uint8_t plain_block[16];
        aes256_ecb_decrypt(ctx, cipher_block, plain_block);

        // XOR with previous ciphertext block (or IV)
        for (int i = 0; i < 16; ++i) {
            plain_block[i] ^= prev_block[i];
        }

        std::memcpy(padded.data() + b * 16, plain_block, 16);
        std::memcpy(prev_block, cipher_block, 16);
    }

    aes256_wipe(ctx);

    // Remove PKCS7 padding
    return aes_pkcs7_unpad(padded.data(), padded.size());
}

// CBC with IV prepended

std::vector<uint8_t> aes256_cbc_encrypt(const uint8_t* data, size_t len,
                                          const std::array<uint8_t, 32>& key) {
    // Generate random IV
    uint8_t iv[16];
    secure_random(iv, 16);

    // Encrypt
    std::vector<uint8_t> ciphertext = aes256_cbc_encrypt(data, len, key.data(), iv);

    // Prepend IV
    std::vector<uint8_t> result(16 + ciphertext.size());
    std::memcpy(result.data(), iv, 16);
    std::memcpy(result.data() + 16, ciphertext.data(), ciphertext.size());

    return result;
}

std::vector<uint8_t> aes256_cbc_decrypt(const uint8_t* data, size_t len,
                                          const std::array<uint8_t, 32>& key) {
    // Minimum: 16 byte IV + 16 byte ciphertext block
    if (len < 32 || (len - 16) % 16 != 0) {
        return {};
    }

    // Extract IV
    const uint8_t* iv = data;
    const uint8_t* ciphertext = data + 16;
    size_t cipher_len = len - 16;

    return aes256_cbc_decrypt(ciphertext, cipher_len, key.data(), iv);
}

// ===========================================================================
// CTR mode
// ===========================================================================

/** Increment a 16-byte counter (big-endian) by 1. */
static void increment_counter(uint8_t counter[16]) {
    for (int i = 15; i >= 0; --i) {
        if (++counter[i] != 0) break;
    }
}

std::vector<uint8_t> aes256_ctr(const uint8_t* data, size_t data_len,
                                  const uint8_t key[32],
                                  const uint8_t nonce[16]) {
    AES256Context ctx;
    aes256_key_expand(ctx, key);

    std::vector<uint8_t> result(data_len);

    uint8_t counter[16];
    std::memcpy(counter, nonce, 16);

    size_t offset = 0;
    while (offset < data_len) {
        // Encrypt the counter to produce a keystream block
        uint8_t keystream[16];
        aes256_ecb_encrypt(ctx, counter, keystream);

        // XOR keystream with data
        size_t block_len = data_len - offset;
        if (block_len > 16) block_len = 16;

        for (size_t i = 0; i < block_len; ++i) {
            result[offset + i] = data[offset + i] ^ keystream[i];
        }

        offset += block_len;
        increment_counter(counter);
    }

    aes256_wipe(ctx);
    return result;
}

// ===========================================================================
// Key derivation
// ===========================================================================

std::array<uint8_t, 32> keccak_kdf(const std::string& passphrase,
                                     const uint8_t* salt, size_t salt_len,
                                     uint32_t iterations) {
    if (iterations < 1) iterations = 1;

    // Initial: hash(passphrase || salt)
    std::vector<uint8_t> preimage;
    preimage.insert(preimage.end(),
        reinterpret_cast<const uint8_t*>(passphrase.data()),
        reinterpret_cast<const uint8_t*>(passphrase.data()) + passphrase.size());
    preimage.insert(preimage.end(), salt, salt + salt_len);

    uint256 hash = keccak256(preimage);

    // Iterate: hash = keccak256(hash || salt)
    for (uint32_t i = 1; i < iterations; ++i) {
        std::vector<uint8_t> next;
        next.insert(next.end(), hash.begin(), hash.end());
        next.insert(next.end(), salt, salt + salt_len);
        hash = keccak256(next);
    }

    return hash.m_data;
}

std::array<uint8_t, 32> keccak_kdf(const std::string& passphrase,
                                     const std::array<uint8_t, 16>& salt,
                                     uint32_t iterations) {
    return keccak_kdf(passphrase, salt.data(), salt.size(), iterations);
}

// ===========================================================================
// Utility
// ===========================================================================

void aes256_wipe(AES256Context& ctx) {
    secure_wipe(&ctx, sizeof(ctx));
}

bool aes_constant_time_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

} // namespace flow

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Benchmarks for cryptographic primitives: AES-256-CBC encrypt/decrypt,
// HMAC-SHA-512 / HMAC-Keccak-512, Bech32m encode/decode, and
// Bloom filter insert/query.

#include "bench.h"
#include "crypto/aes256.h"
#include "crypto/bech32.h"
#include "crypto/hmac_sha512.h"
#include "crypto/keys.h"
#include "hash/bloom.h"
#include "hash/keccak.h"

#include <array>
#include <cstring>
#include <string>
#include <vector>

namespace flow::bench {

// ===========================================================================
// AES-256-CBC
// ===========================================================================

BENCH(AES256_CBC_Encrypt_64B) {
    std::vector<uint8_t> data(64, 0xAA);
    uint8_t key[32];
    uint8_t iv[16];
    std::memset(key, 0x55, 32);
    std::memset(iv, 0x11, 16);

    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        auto ct = aes256_cbc_encrypt(data.data(), data.size(), key, iv);
        if (ct.empty()) break;
    }
}

BENCH(AES256_CBC_Encrypt_1KB) {
    std::vector<uint8_t> data(1024, 0xBB);
    uint8_t key[32];
    uint8_t iv[16];
    std::memset(key, 0x55, 32);
    std::memset(iv, 0x22, 16);

    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        auto ct = aes256_cbc_encrypt(data.data(), data.size(), key, iv);
        if (ct.empty()) break;
    }
}

BENCH(AES256_CBC_Encrypt_4KB) {
    std::vector<uint8_t> data(4096, 0xCC);
    uint8_t key[32];
    uint8_t iv[16];
    std::memset(key, 0x55, 32);
    std::memset(iv, 0x33, 16);

    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        auto ct = aes256_cbc_encrypt(data.data(), data.size(), key, iv);
        if (ct.empty()) break;
    }
}

BENCH(AES256_CBC_Decrypt_64B) {
    std::vector<uint8_t> data(64, 0xAA);
    uint8_t key[32];
    uint8_t iv[16];
    std::memset(key, 0x55, 32);
    std::memset(iv, 0x11, 16);
    auto ct = aes256_cbc_encrypt(data.data(), data.size(), key, iv);

    for (int i = 0; i < _iterations; i++) {
        auto pt = aes256_cbc_decrypt(ct.data(), ct.size(), key, iv);
        if (pt.empty()) break;
    }
}

BENCH(AES256_CBC_Decrypt_1KB) {
    std::vector<uint8_t> data(1024, 0xBB);
    uint8_t key[32];
    uint8_t iv[16];
    std::memset(key, 0x55, 32);
    std::memset(iv, 0x22, 16);
    auto ct = aes256_cbc_encrypt(data.data(), data.size(), key, iv);

    for (int i = 0; i < _iterations; i++) {
        auto pt = aes256_cbc_decrypt(ct.data(), ct.size(), key, iv);
        if (pt.empty()) break;
    }
}

BENCH(AES256_CBC_Decrypt_4KB) {
    std::vector<uint8_t> data(4096, 0xCC);
    uint8_t key[32];
    uint8_t iv[16];
    std::memset(key, 0x55, 32);
    std::memset(iv, 0x33, 16);
    auto ct = aes256_cbc_encrypt(data.data(), data.size(), key, iv);

    for (int i = 0; i < _iterations; i++) {
        auto pt = aes256_cbc_decrypt(ct.data(), ct.size(), key, iv);
        if (pt.empty()) break;
    }
}

// ===========================================================================
// AES-256-CTR
// ===========================================================================

BENCH(AES256_CTR_1KB) {
    std::vector<uint8_t> data(1024, 0xDD);
    uint8_t key[32];
    uint8_t nonce[16];
    std::memset(key, 0x66, 32);
    std::memset(nonce, 0x77, 16);

    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        auto ct = aes256_ctr(data.data(), data.size(), key, nonce);
        if (ct.empty()) break;
    }
}

// ===========================================================================
// AES key derivation (KDF)
// ===========================================================================

BENCH(KeccakKDF_100Rounds) {
    std::string passphrase = "benchmark_passphrase_12345";
    uint8_t salt[16];
    std::memset(salt, 0x42, 16);

    for (int i = 0; i < _iterations; i++) {
        auto key = keccak_kdf(passphrase, salt, 16, 100);
        (void)key;
    }
}

// ===========================================================================
// HMAC-SHA-512
// ===========================================================================

BENCH(HMAC_SHA512_32B) {
    uint8_t key[32];
    uint8_t data[32];
    std::memset(key, 0xAA, 32);
    std::memset(data, 0xBB, 32);

    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        uint512 mac = hmac_sha512(key, 32, data, 32);
        (void)mac;
    }
}

BENCH(HMAC_SHA512_1KB) {
    uint8_t key[32];
    std::vector<uint8_t> data(1024, 0xCC);
    std::memset(key, 0xAA, 32);

    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        uint512 mac = hmac_sha512(key, 32, data.data(), data.size());
        (void)mac;
    }
}

// ===========================================================================
// HMAC-Keccak-512
// ===========================================================================

BENCH(HMAC_Keccak512_32B) {
    uint8_t key[32];
    uint8_t data[32];
    std::memset(key, 0xDD, 32);
    std::memset(data, 0xEE, 32);

    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        uint512 mac = hmac_keccak512(key, 32, data, 32);
        (void)mac;
    }
}

BENCH(HMAC_Keccak512_1KB) {
    uint8_t key[32];
    std::vector<uint8_t> data(1024, 0xFF);
    std::memset(key, 0xDD, 32);

    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        uint512 mac = hmac_keccak512(key, 32, data.data(), data.size());
        (void)mac;
    }
}

// ===========================================================================
// Bech32m encode/decode
// ===========================================================================

BENCH(Bech32m_Encode) {
    // 20-byte program (typical P2PKH address)
    std::vector<uint8_t> program(20, 0xAB);
    for (int i = 0; i < _iterations; i++) {
        program[0] = static_cast<uint8_t>(i & 0xFF);
        std::string addr = bech32m_encode("fl", 0, program);
        if (addr.empty()) break;
    }
}

BENCH(Bech32m_Decode) {
    std::vector<uint8_t> program(20, 0xAB);
    std::string addr = bech32m_encode("fl", 0, program);

    for (int i = 0; i < _iterations; i++) {
        Bech32mDecoded decoded = bech32m_decode(addr);
        if (!decoded.valid) break;
    }
}

BENCH(Bech32m_RoundTrip) {
    std::vector<uint8_t> program(20);
    for (int i = 0; i < _iterations; i++) {
        program[0] = static_cast<uint8_t>(i & 0xFF);
        program[1] = static_cast<uint8_t>((i >> 8) & 0xFF);
        std::string addr = bech32m_encode("fl", 0, program);
        Bech32mDecoded decoded = bech32m_decode(addr);
        if (!decoded.valid) break;
    }
}

BENCH(Bech32m_ValidateAddress) {
    std::vector<uint8_t> program(20, 0xCD);
    std::string addr = bech32m_encode("fl", 0, program);

    for (int i = 0; i < _iterations; i++) {
        bool valid = validate_address(addr);
        if (!valid) break;
    }
}

BENCH(PubkeyToAddress) {
    uint8_t pubkey[32];
    std::memset(pubkey, 0x55, 32);
    for (int i = 0; i < _iterations; i++) {
        pubkey[0] = static_cast<uint8_t>(i & 0xFF);
        std::string addr = pubkey_to_address(pubkey);
        if (addr.empty()) break;
    }
}

// ===========================================================================
// Bloom filter
// ===========================================================================

BENCH(Bloom_Insert_1000) {
    CBloomFilter filter(1000, 0.001, 42);
    uint8_t data[32];
    for (int i = 0; i < _iterations; i++) {
        std::memcpy(data, &i, sizeof(i));
        filter.insert(data, 32);
    }
}

BENCH(Bloom_Query_1000) {
    CBloomFilter filter(1000, 0.001, 42);
    // Pre-insert
    for (int i = 0; i < 1000; i++) {
        uint8_t data[32];
        std::memset(data, 0, 32);
        std::memcpy(data, &i, sizeof(i));
        filter.insert(data, 32);
    }

    uint8_t data[32];
    for (int i = 0; i < _iterations; i++) {
        std::memset(data, 0, 32);
        std::memcpy(data, &i, sizeof(i));
        bool found = filter.contains(data, 32);
        (void)found;
    }
}

BENCH(Bloom_InsertHash) {
    CBloomFilter filter(10000, 0.0001, 99);
    for (int i = 0; i < _iterations; i++) {
        uint256 hash = keccak256(reinterpret_cast<const uint8_t*>(&i), sizeof(i));
        filter.insert_hash(hash);
    }
}

BENCH(Bloom_QueryHash) {
    CBloomFilter filter(10000, 0.0001, 99);
    // Pre-insert
    std::vector<uint256> hashes(10000);
    for (int i = 0; i < 10000; i++) {
        hashes[i] = keccak256(reinterpret_cast<const uint8_t*>(&i), sizeof(i));
        filter.insert_hash(hashes[i]);
    }

    for (int i = 0; i < _iterations; i++) {
        bool found = filter.contains_hash(hashes[i % 10000]);
        (void)found;
    }
}

// ===========================================================================
// Bech32 (non-m) operations
// ===========================================================================

BENCH(Bech32_Encode) {
    std::vector<uint8_t> data5(32, 0x0A);  // 5-bit values
    for (int i = 0; i < _iterations; i++) {
        data5[0] = static_cast<uint8_t>(i % 32);
        std::string encoded = bech32_encode("fl", data5, Bech32Encoding::BECH32);
        if (encoded.empty()) break;
    }
}

BENCH(Bech32_Decode) {
    std::vector<uint8_t> data5(32, 0x0A);
    std::string encoded = bech32_encode("fl", data5, Bech32Encoding::BECH32);
    for (int i = 0; i < _iterations; i++) {
        Bech32Decoded decoded = bech32_decode(encoded);
        if (decoded.encoding == Bech32Encoding::INVALID) break;
    }
}

// ===========================================================================
// Bit conversion
// ===========================================================================

BENCH(ConvertBits_8to5) {
    std::vector<uint8_t> in(20, 0xAB);
    for (int i = 0; i < _iterations; i++) {
        in[0] = static_cast<uint8_t>(i & 0xFF);
        std::vector<uint8_t> out;
        convertbits(out, in, 8, 5, true);
        if (out.empty()) break;
    }
}

BENCH(ConvertBits_5to8) {
    std::vector<uint8_t> in5(32, 0x0F);
    for (int i = 0; i < _iterations; i++) {
        in5[0] = static_cast<uint8_t>(i % 32);
        std::vector<uint8_t> out;
        convertbits(out, in5, 5, 8, false);
        (void)out;
    }
}

// ===========================================================================
// AES ECB (single block operations)
// ===========================================================================

BENCH(AES256_ECB_Encrypt) {
    uint8_t key[32], block[16], out[16];
    std::memset(key, 0x42, 32);
    std::memset(block, 0xAA, 16);
    AES256Context ctx;
    aes256_key_expand(ctx, key);
    for (int i = 0; i < _iterations; i++) {
        block[0] = static_cast<uint8_t>(i & 0xFF);
        aes256_ecb_encrypt(ctx, block, out);
    }
    aes256_wipe(ctx);
}

BENCH(AES256_ECB_Decrypt) {
    uint8_t key[32], block[16], out[16];
    std::memset(key, 0x42, 32);
    std::memset(block, 0xBB, 16);
    AES256Context ctx;
    aes256_key_expand(ctx, key);
    aes256_ecb_encrypt(ctx, block, out);
    for (int i = 0; i < _iterations; i++) {
        uint8_t dec[16];
        aes256_ecb_decrypt(ctx, out, dec);
        (void)dec;
    }
    aes256_wipe(ctx);
}

BENCH(AES256_KeyExpand) {
    uint8_t key[32];
    std::memset(key, 0x55, 32);
    for (int i = 0; i < _iterations; i++) {
        key[0] = static_cast<uint8_t>(i & 0xFF);
        AES256Context ctx;
        aes256_key_expand(ctx, key);
        aes256_wipe(ctx);
    }
}

// ===========================================================================
// PKCS7 padding
// ===========================================================================

BENCH(PKCS7_Pad_15B) {
    std::vector<uint8_t> data(15, 0xCC);
    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        auto padded = aes_pkcs7_pad(data.data(), data.size());
        if (padded.size() != 16) break;
    }
}

BENCH(PKCS7_Unpad_16B) {
    std::vector<uint8_t> data(15, 0xCC);
    auto padded = aes_pkcs7_pad(data.data(), data.size());
    for (int i = 0; i < _iterations; i++) {
        auto unpadded = aes_pkcs7_unpad(padded.data(), padded.size());
        if (unpadded.size() != 15) break;
    }
}

// ===========================================================================
// AES-256-CBC with prepended IV
// ===========================================================================

BENCH(AES256_CBC_EncryptWithIV) {
    std::vector<uint8_t> data(256, 0xDD);
    std::array<uint8_t, 32> key;
    std::memset(key.data(), 0x66, 32);
    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        auto ct = aes256_cbc_encrypt(data.data(), data.size(), key);
        if (ct.empty()) break;
    }
}

BENCH(AES256_CBC_DecryptWithIV) {
    std::vector<uint8_t> data(256, 0xDD);
    std::array<uint8_t, 32> key;
    std::memset(key.data(), 0x66, 32);
    auto ct = aes256_cbc_encrypt(data.data(), data.size(), key);
    for (int i = 0; i < _iterations; i++) {
        auto pt = aes256_cbc_decrypt(ct.data(), ct.size(), key);
        if (pt.empty()) break;
    }
}

// ===========================================================================
// GF(2^8) operations (AES internals)
// ===========================================================================

BENCH(AES_GfMul) {
    for (int i = 0; i < _iterations; i++) {
        uint8_t a = static_cast<uint8_t>(i & 0xFF);
        uint8_t b = static_cast<uint8_t>((i >> 8) & 0xFF);
        uint8_t r = aes_gf_mul(a, b);
        (void)r;
    }
}

BENCH(AES_Xtime) {
    for (int i = 0; i < _iterations; i++) {
        uint8_t x = static_cast<uint8_t>(i & 0xFF);
        uint8_t r = aes_xtime(x);
        (void)r;
    }
}

// ===========================================================================
// SHA-512
// ===========================================================================

BENCH(SHA512_32B) {
    uint8_t data[32], out[64];
    std::memset(data, 0xAA, 32);
    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        sha512(data, 32, out);
    }
}

BENCH(SHA512_1KB) {
    std::vector<uint8_t> data(1024, 0xBB);
    uint8_t out[64];
    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        sha512(data.data(), data.size(), out);
    }
}

// ===========================================================================
// Address operations
// ===========================================================================

BENCH(AddressToPubkeyHash) {
    uint8_t pubkey[32];
    std::memset(pubkey, 0x55, 32);
    std::string addr = pubkey_to_address(pubkey);
    for (int i = 0; i < _iterations; i++) {
        std::vector<uint8_t> hash_out;
        bool ok = address_to_pubkey_hash(addr, hash_out);
        if (!ok) break;
    }
}

BENCH(AddressValidation_Valid) {
    uint8_t pubkey[32];
    std::memset(pubkey, 0x55, 32);
    std::string addr = pubkey_to_address(pubkey);
    for (int i = 0; i < _iterations; i++) {
        bool valid = validate_address(addr);
        if (!valid) break;
    }
}

BENCH(AddressValidation_Invalid) {
    std::string bad_addr = "fl1qinvalidaddressstring";
    for (int i = 0; i < _iterations; i++) {
        bool valid = validate_address(bad_addr);
        if (valid) break;
    }
}

} // namespace flow::bench

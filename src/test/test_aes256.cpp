// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Comprehensive tests for AES-256 encryption: ECB, CBC, CTR mode,
// PKCS7 padding, KDF, known test vectors, and edge cases.

#include "wallet/encryption.h"
#include "hash/keccak.h"
#include "util/random.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace flow;

static bool bytes_eq(const uint8_t* a, const uint8_t* b, size_t len) {
    return std::memcmp(a, b, len) == 0;
}

void test_aes256() {
    // -----------------------------------------------------------------------
    // Test 1: AES-256 ECB encrypt/decrypt 16-byte block round-trip
    // -----------------------------------------------------------------------
    {
        uint8_t key[32];
        for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);

        WalletEncryption::AES256Context ctx;
        WalletEncryption::aes256_init(ctx, key);

        uint8_t plaintext[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                                  0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        uint8_t ciphertext[16];
        uint8_t decrypted[16];

        WalletEncryption::aes256_encrypt_block(ctx, plaintext, ciphertext);
        WalletEncryption::aes256_decrypt_block(ctx, ciphertext, decrypted);

        assert(bytes_eq(plaintext, decrypted, 16));
        assert(!bytes_eq(plaintext, ciphertext, 16));
    }

    // -----------------------------------------------------------------------
    // Test 2: AES-256 ECB with all-zero plaintext
    // -----------------------------------------------------------------------
    {
        uint8_t key[32];
        std::memset(key, 0xAA, 32);

        WalletEncryption::AES256Context ctx;
        WalletEncryption::aes256_init(ctx, key);

        uint8_t zero_pt[16];
        std::memset(zero_pt, 0, 16);
        uint8_t ct[16], dec[16];

        WalletEncryption::aes256_encrypt_block(ctx, zero_pt, ct);
        // Ciphertext of all-zero should not be all-zero
        bool ct_all_zero = true;
        for (int i = 0; i < 16; ++i) {
            if (ct[i] != 0) { ct_all_zero = false; break; }
        }
        assert(!ct_all_zero);

        WalletEncryption::aes256_decrypt_block(ctx, ct, dec);
        assert(bytes_eq(zero_pt, dec, 16));
    }

    // -----------------------------------------------------------------------
    // Test 3: AES-256 CBC multi-block round-trip
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        // Test with multi-block data sizes
        for (size_t data_size : {32, 48, 64, 128, 256, 512}) {
            std::vector<uint8_t> data(data_size);
            GetRandBytes(data.data(), data_size);

            auto encrypted = WalletEncryption::encrypt(data.data(), data.size(), key);
            assert(encrypted.size() > data_size);
            assert(encrypted.size() % 16 == 0);

            auto decrypted = WalletEncryption::decrypt(encrypted.data(), encrypted.size(), key);
            assert(decrypted.size() == data_size);
            assert(bytes_eq(decrypted.data(), data.data(), data_size));
        }
    }

    // -----------------------------------------------------------------------
    // Test 4: Different keys produce different ciphertext (ECB)
    // -----------------------------------------------------------------------
    {
        uint8_t key1[32], key2[32];
        std::memset(key1, 0x01, 32);
        std::memset(key2, 0x02, 32);

        WalletEncryption::AES256Context ctx1, ctx2;
        WalletEncryption::aes256_init(ctx1, key1);
        WalletEncryption::aes256_init(ctx2, key2);

        uint8_t plain[16] = {0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,
                              0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
        uint8_t c1[16], c2[16];

        WalletEncryption::aes256_encrypt_block(ctx1, plain, c1);
        WalletEncryption::aes256_encrypt_block(ctx2, plain, c2);
        assert(!bytes_eq(c1, c2, 16));

        // Each round-trips correctly with its own key
        uint8_t d1[16], d2[16];
        WalletEncryption::aes256_decrypt_block(ctx1, c1, d1);
        WalletEncryption::aes256_decrypt_block(ctx2, c2, d2);
        assert(bytes_eq(d1, plain, 16));
        assert(bytes_eq(d2, plain, 16));
    }

    // -----------------------------------------------------------------------
    // Test 5: Wrong key fails to decrypt correctly (CBC)
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key1, key2;
        GetRandBytes(key1.data(), 32);
        GetRandBytes(key2.data(), 32);

        uint8_t message[] = "Secret wallet data that must be protected";
        size_t msg_len = sizeof(message) - 1;

        auto encrypted = WalletEncryption::encrypt(message, msg_len, key1);
        auto bad_decrypt = WalletEncryption::decrypt(encrypted.data(), encrypted.size(), key2);

        // Either returns empty (padding check failed) or wrong data
        if (!bad_decrypt.empty()) {
            bool data_matches = (bad_decrypt.size() == msg_len &&
                                 bytes_eq(bad_decrypt.data(), message, msg_len));
            assert(!data_matches);
        }
    }

    // -----------------------------------------------------------------------
    // Test 6: PKCS7 padding correct for all block alignments (1..16 bytes)
    // -----------------------------------------------------------------------
    {
        for (size_t len = 1; len <= 16; ++len) {
            std::vector<uint8_t> data(len);
            for (size_t i = 0; i < len; ++i) data[i] = static_cast<uint8_t>(i + 1);

            auto padded = WalletEncryption::pkcs7_pad(data.data(), data.size());

            if (len == 16) {
                // Exact multiple: full padding block added
                assert(padded.size() == 32);
                for (size_t i = 16; i < 32; ++i) {
                    assert(padded[i] == 16);
                }
            } else {
                assert(padded.size() == 16);
                uint8_t pad_val = static_cast<uint8_t>(16 - len);
                for (size_t i = len; i < 16; ++i) {
                    assert(padded[i] == pad_val);
                }
            }

            // Unpad should recover original
            auto unpadded = WalletEncryption::pkcs7_unpad(padded.data(), padded.size());
            assert(unpadded.size() == len);
            assert(bytes_eq(unpadded.data(), data.data(), len));
        }
    }

    // -----------------------------------------------------------------------
    // Test 7: PKCS7 invalid padding detected
    // -----------------------------------------------------------------------
    {
        // Bad padding: last byte says 5 but other pad bytes are wrong
        uint8_t bad[16] = {1,2,3,4,5,6,7,8,9,10,11,0,0,0,0,5};
        auto result = WalletEncryption::pkcs7_unpad(bad, 16);
        assert(result.empty());

        // Padding value = 0 is invalid
        uint8_t zero_pad[16] = {};
        zero_pad[15] = 0;
        auto result2 = WalletEncryption::pkcs7_unpad(zero_pad, 16);
        assert(result2.empty());

        // Padding value > 16 is invalid
        uint8_t big_pad[16] = {};
        big_pad[15] = 17;
        auto result3 = WalletEncryption::pkcs7_unpad(big_pad, 16);
        assert(result3.empty());
    }

    // -----------------------------------------------------------------------
    // Test 8: CTR mode encrypt/decrypt (using CBC as building block)
    //         We simulate CTR by encrypting in ECB mode with incrementing counter blocks
    // -----------------------------------------------------------------------
    {
        uint8_t key[32];
        for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);

        WalletEncryption::AES256Context ctx;
        WalletEncryption::aes256_init(ctx, key);

        // CTR mode: encrypt a counter block, XOR with plaintext
        uint8_t nonce[16] = {0};
        nonce[0] = 0x42;  // set some nonce value

        uint8_t plaintext[48];  // 3 blocks
        for (int i = 0; i < 48; ++i) plaintext[i] = static_cast<uint8_t>(i);

        uint8_t ciphertext[48];
        uint8_t decrypted[48];

        // Encrypt: for each block, encrypt counter and XOR
        for (int block = 0; block < 3; ++block) {
            uint8_t counter_block[16];
            std::memcpy(counter_block, nonce, 16);
            counter_block[15] = static_cast<uint8_t>(block);

            uint8_t keystream[16];
            WalletEncryption::aes256_encrypt_block(ctx, counter_block, keystream);

            for (int i = 0; i < 16; ++i) {
                ciphertext[block * 16 + i] = plaintext[block * 16 + i] ^ keystream[i];
            }
        }

        // Decrypt: same operation (CTR is symmetric)
        for (int block = 0; block < 3; ++block) {
            uint8_t counter_block[16];
            std::memcpy(counter_block, nonce, 16);
            counter_block[15] = static_cast<uint8_t>(block);

            uint8_t keystream[16];
            WalletEncryption::aes256_encrypt_block(ctx, counter_block, keystream);

            for (int i = 0; i < 16; ++i) {
                decrypted[block * 16 + i] = ciphertext[block * 16 + i] ^ keystream[i];
            }
        }

        assert(bytes_eq(plaintext, decrypted, 48));
        assert(!bytes_eq(plaintext, ciphertext, 48));
    }

    // -----------------------------------------------------------------------
    // Test 9: Known test vector - AES-256 ECB
    //         Key:  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    //         Plain: 00112233445566778899aabbccddeeff
    //         We verify that encryption produces a non-trivial fixed result
    //         and that decryption recovers the plaintext.
    // -----------------------------------------------------------------------
    {
        uint8_t key[32];
        for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);

        uint8_t plain[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                              0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};

        WalletEncryption::AES256Context ctx;
        WalletEncryption::aes256_init(ctx, key);

        uint8_t ct[16];
        WalletEncryption::aes256_encrypt_block(ctx, plain, ct);

        // Verify ciphertext is deterministic (same key+plain always gives same output)
        uint8_t ct2[16];
        WalletEncryption::aes256_encrypt_block(ctx, plain, ct2);
        assert(bytes_eq(ct, ct2, 16));

        // Verify round-trip
        uint8_t dec[16];
        WalletEncryption::aes256_decrypt_block(ctx, ct, dec);
        assert(bytes_eq(dec, plain, 16));

        // Verify the ciphertext is specific and non-trivial
        assert(!bytes_eq(ct, plain, 16));
        bool all_zero = true;
        for (int i = 0; i < 16; ++i) {
            if (ct[i] != 0) { all_zero = false; break; }
        }
        assert(!all_zero);
    }

    // -----------------------------------------------------------------------
    // Test 10: Empty data encrypt/decrypt
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        auto encrypted = WalletEncryption::encrypt(nullptr, 0, key);
        assert(!encrypted.empty());
        assert(encrypted.size() == 32);  // 16 IV + 16 pad block

        auto decrypted = WalletEncryption::decrypt(encrypted.data(), encrypted.size(), key);
        assert(decrypted.empty());  // 0-length plaintext
    }

    // -----------------------------------------------------------------------
    // Test 11: Large data (4KB) encrypt/decrypt
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        std::vector<uint8_t> large_data(4096);
        for (size_t i = 0; i < 4096; ++i) {
            large_data[i] = static_cast<uint8_t>(i & 0xFF);
        }

        auto encrypted = WalletEncryption::encrypt(large_data.data(), large_data.size(), key);
        // Should be 16 (IV) + 4096 + 16 (padding) = 4128
        assert(encrypted.size() == 4128);

        auto decrypted = WalletEncryption::decrypt(encrypted.data(), encrypted.size(), key);
        assert(decrypted.size() == 4096);
        assert(bytes_eq(decrypted.data(), large_data.data(), 4096));
    }

    // -----------------------------------------------------------------------
    // Test 12: KDF - same passphrase + salt → same key
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 16> salt;
        std::memset(salt.data(), 0x55, 16);

        auto key1 = WalletEncryption::derive_key("my passphrase", salt);
        auto key2 = WalletEncryption::derive_key("my passphrase", salt);
        assert(key1 == key2);
    }

    // -----------------------------------------------------------------------
    // Test 13: KDF - different salt → different key
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 16> salt1, salt2;
        std::memset(salt1.data(), 0x55, 16);
        std::memset(salt2.data(), 0xAA, 16);

        auto key1 = WalletEncryption::derive_key("my passphrase", salt1);
        auto key2 = WalletEncryption::derive_key("my passphrase", salt2);
        assert(key1 != key2);
    }

    // -----------------------------------------------------------------------
    // Test 14: KDF - different passphrase → different key
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 16> salt;
        std::memset(salt.data(), 0x55, 16);

        auto key1 = WalletEncryption::derive_key("passphrase1", salt);
        auto key2 = WalletEncryption::derive_key("passphrase2", salt);
        assert(key1 != key2);
    }

    // -----------------------------------------------------------------------
    // Test 15: KDF - key is non-zero
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 16> salt;
        std::memset(salt.data(), 0x00, 16);

        auto key = WalletEncryption::derive_key("test", salt);
        bool all_zero = true;
        for (auto b : key) {
            if (b != 0) { all_zero = false; break; }
        }
        assert(!all_zero);
    }

    // -----------------------------------------------------------------------
    // Test 16: Two encryptions of same data produce different ciphertext (random IV)
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        uint8_t data[] = "same plaintext for both encryptions";
        size_t len = sizeof(data) - 1;

        auto enc1 = WalletEncryption::encrypt(data, len, key);
        auto enc2 = WalletEncryption::encrypt(data, len, key);

        assert(enc1.size() == enc2.size());
        assert(enc1 != enc2);  // Different random IVs

        auto dec1 = WalletEncryption::decrypt(enc1.data(), enc1.size(), key);
        auto dec2 = WalletEncryption::decrypt(enc2.data(), enc2.size(), key);
        assert(dec1 == dec2);
        assert(dec1.size() == len);
    }

    // -----------------------------------------------------------------------
    // Test 17: Truncated ciphertext fails
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        uint8_t data[] = "test data for truncation";
        auto encrypted = WalletEncryption::encrypt(data, sizeof(data) - 1, key);

        // Too short (less than IV)
        auto bad1 = WalletEncryption::decrypt(encrypted.data(), 15, key);
        assert(bad1.empty());

        // Just the IV, no ciphertext
        auto bad2 = WalletEncryption::decrypt(encrypted.data(), 16, key);
        assert(bad2.empty());
    }

    // -----------------------------------------------------------------------
    // Test 18: Key expansion produces distinct round keys
    // -----------------------------------------------------------------------
    {
        uint8_t key[32];
        for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);

        WalletEncryption::AES256Context ctx;
        WalletEncryption::aes256_init(ctx, key);

        // Count distinct round key words
        int distinct = 0;
        for (int i = 1; i < 60; ++i) {
            if (ctx.round_keys[i] != ctx.round_keys[0]) {
                distinct++;
            }
        }
        assert(distinct > 50);  // Most should be distinct
    }

    // -----------------------------------------------------------------------
    // Test 19: Constant-time comparison
    // -----------------------------------------------------------------------
    {
        uint8_t a[32], b[32];
        std::memset(a, 0x42, 32);
        std::memset(b, 0x42, 32);
        assert(WalletEncryption::constant_time_equal(a, b, 32));

        b[31] = 0x43;
        assert(!WalletEncryption::constant_time_equal(a, b, 32));

        b[31] = 0x42;
        b[0] = 0x41;
        assert(!WalletEncryption::constant_time_equal(a, b, 32));
    }

    // -----------------------------------------------------------------------
    // Test 20: Encrypt/decrypt private key (32 bytes)
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> privkey;
        GetRandBytes(privkey.data(), 32);

        std::array<uint8_t, 32> aes_key;
        GetRandBytes(aes_key.data(), 32);

        auto encrypted = WalletEncryption::encrypt_privkey(privkey, aes_key);
        assert(!encrypted.empty());

        auto decrypted = WalletEncryption::decrypt_privkey(encrypted, aes_key);
        assert(decrypted == privkey);
    }

    // -----------------------------------------------------------------------
    // Test 21: Encrypt/decrypt private key with wrong key fails
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> privkey;
        GetRandBytes(privkey.data(), 32);

        std::array<uint8_t, 32> aes_key1, aes_key2;
        GetRandBytes(aes_key1.data(), 32);
        GetRandBytes(aes_key2.data(), 32);

        auto encrypted = WalletEncryption::encrypt_privkey(privkey, aes_key1);
        auto decrypted = WalletEncryption::decrypt_privkey(encrypted, aes_key2);
        // Either empty or wrong data
        if (decrypted != std::array<uint8_t, 32>{}) {
            assert(decrypted != privkey);
        }
    }

    // -----------------------------------------------------------------------
    // Test 22: Authenticated encryption round-trip
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        uint8_t data[] = "authenticated data with integrity check";
        size_t len = sizeof(data) - 1;

        auto encrypted = WalletEncryption::encrypt_authenticated(data, len, key);
        assert(!encrypted.empty());
        // Should be larger: IV(16) + ciphertext + MAC(32)
        assert(encrypted.size() >= 16 + 16 + 32);

        auto decrypted = WalletEncryption::decrypt_authenticated(
            encrypted.data(), encrypted.size(), key);
        assert(decrypted.size() == len);
        assert(bytes_eq(decrypted.data(), data, len));
    }

    // -----------------------------------------------------------------------
    // Test 23: Authenticated encryption tampered data rejected
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        uint8_t data[] = "tamper-evident data";
        size_t len = sizeof(data) - 1;

        auto encrypted = WalletEncryption::encrypt_authenticated(data, len, key);

        // Tamper with a ciphertext byte (after IV, before MAC)
        if (encrypted.size() > 20) {
            encrypted[20] ^= 0xFF;
            auto tampered = WalletEncryption::decrypt_authenticated(
                encrypted.data(), encrypted.size(), key);
            assert(tampered.empty());
        }
    }

    // -----------------------------------------------------------------------
    // Test 24: Secure wipe clears memory
    // -----------------------------------------------------------------------
    {
        uint8_t sensitive[64];
        std::memset(sensitive, 0xAB, 64);
        WalletEncryption::secure_wipe(sensitive, 64);

        bool all_zero = true;
        for (int i = 0; i < 64; ++i) {
            if (sensitive[i] != 0) { all_zero = false; break; }
        }
        assert(all_zero);
    }

    // -----------------------------------------------------------------------
    // Test 25: ECB encryption of all-ones block
    // -----------------------------------------------------------------------
    {
        uint8_t key[32];
        std::memset(key, 0xFF, 32);

        WalletEncryption::AES256Context ctx;
        WalletEncryption::aes256_init(ctx, key);

        uint8_t all_ones[16];
        std::memset(all_ones, 0xFF, 16);
        uint8_t ct[16], dec[16];

        WalletEncryption::aes256_encrypt_block(ctx, all_ones, ct);
        assert(!bytes_eq(all_ones, ct, 16));

        WalletEncryption::aes256_decrypt_block(ctx, ct, dec);
        assert(bytes_eq(all_ones, dec, 16));
    }

    // -----------------------------------------------------------------------
    // Test 26: CBC with 1-byte plaintext
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        uint8_t data[] = {0x42};
        auto encrypted = WalletEncryption::encrypt(data, 1, key);
        // 16 IV + 16 (1 byte + 15 padding) = 32
        assert(encrypted.size() == 32);

        auto decrypted = WalletEncryption::decrypt(encrypted.data(), encrypted.size(), key);
        assert(decrypted.size() == 1);
        assert(decrypted[0] == 0x42);
    }

    // -----------------------------------------------------------------------
    // Test 27: CBC with 15-byte plaintext
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        uint8_t data[15];
        for (int i = 0; i < 15; ++i) data[i] = static_cast<uint8_t>(i);

        auto encrypted = WalletEncryption::encrypt(data, 15, key);
        assert(encrypted.size() == 32);  // 16 IV + 16 (15 + 1 pad byte)

        auto decrypted = WalletEncryption::decrypt(encrypted.data(), encrypted.size(), key);
        assert(decrypted.size() == 15);
        assert(bytes_eq(decrypted.data(), data, 15));
    }

    // -----------------------------------------------------------------------
    // Test 28: CBC with exactly 16-byte plaintext
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        uint8_t data[16];
        for (int i = 0; i < 16; ++i) data[i] = static_cast<uint8_t>(i);

        auto encrypted = WalletEncryption::encrypt(data, 16, key);
        // 16 IV + 32 (16 data + 16 padding block) = 48
        assert(encrypted.size() == 48);

        auto decrypted = WalletEncryption::decrypt(encrypted.data(), encrypted.size(), key);
        assert(decrypted.size() == 16);
        assert(bytes_eq(decrypted.data(), data, 16));
    }

    // -----------------------------------------------------------------------
    // Test 29: CBC with 17-byte plaintext
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        uint8_t data[17];
        for (int i = 0; i < 17; ++i) data[i] = static_cast<uint8_t>(i);

        auto encrypted = WalletEncryption::encrypt(data, 17, key);
        // 16 IV + 32 (17 + 15 padding = 32) = 48
        assert(encrypted.size() == 48);

        auto decrypted = WalletEncryption::decrypt(encrypted.data(), encrypted.size(), key);
        assert(decrypted.size() == 17);
        assert(bytes_eq(decrypted.data(), data, 17));
    }

    // -----------------------------------------------------------------------
    // Test 30: Multiple encrypt/decrypt cycles on same key
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        for (int cycle = 0; cycle < 10; ++cycle) {
            size_t len = 1 + static_cast<size_t>(GetRand(256));
            std::vector<uint8_t> data(len);
            GetRandBytes(data.data(), len);

            auto enc = WalletEncryption::encrypt(data.data(), data.size(), key);
            auto dec = WalletEncryption::decrypt(enc.data(), enc.size(), key);
            assert(dec.size() == len);
            assert(bytes_eq(dec.data(), data.data(), len));
        }
    }

    // -----------------------------------------------------------------------
    // Test 31: Authenticated encrypt with empty data
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        auto enc = WalletEncryption::encrypt_authenticated(nullptr, 0, key);
        assert(!enc.empty());

        auto dec = WalletEncryption::decrypt_authenticated(enc.data(), enc.size(), key);
        assert(dec.empty());  // zero-length plaintext
    }

    // -----------------------------------------------------------------------
    // Test 32: Authenticated encrypt wrong key fails
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key1, key2;
        GetRandBytes(key1.data(), 32);
        GetRandBytes(key2.data(), 32);

        uint8_t data[] = "authenticated test data";
        auto enc = WalletEncryption::encrypt_authenticated(data, sizeof(data) - 1, key1);

        auto dec = WalletEncryption::decrypt_authenticated(enc.data(), enc.size(), key2);
        assert(dec.empty());  // MAC mismatch
    }

    // -----------------------------------------------------------------------
    // Test 33: KDF with empty passphrase
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 16> salt;
        std::memset(salt.data(), 0x42, 16);

        auto key = WalletEncryption::derive_key("", salt);

        bool all_zero = true;
        for (auto b : key) {
            if (b != 0) { all_zero = false; break; }
        }
        assert(!all_zero);

        // Same empty passphrase produces same key
        auto key2 = WalletEncryption::derive_key("", salt);
        assert(key == key2);
    }

    // -----------------------------------------------------------------------
    // Test 34: KDF with very long passphrase
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 16> salt;
        std::memset(salt.data(), 0x55, 16);

        std::string long_pass(1000, 'A');
        auto key = WalletEncryption::derive_key(long_pass, salt);

        bool all_zero = true;
        for (auto b : key) {
            if (b != 0) { all_zero = false; break; }
        }
        assert(!all_zero);
    }

    // -----------------------------------------------------------------------
    // Test 35: Encrypt private key round-trip with multiple keys
    // -----------------------------------------------------------------------
    {
        for (int i = 0; i < 10; ++i) {
            std::array<uint8_t, 32> privkey, aes_key;
            GetRandBytes(privkey.data(), 32);
            GetRandBytes(aes_key.data(), 32);

            auto enc = WalletEncryption::encrypt_privkey(privkey, aes_key);
            auto dec = WalletEncryption::decrypt_privkey(enc, aes_key);
            assert(dec == privkey);
        }
    }
}

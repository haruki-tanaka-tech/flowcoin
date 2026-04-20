// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for AES-256-CBC wallet encryption.

#include "wallet/encryption.h"
#include "hash/keccak.h"
#include "util/random.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace flow;

// Helper: check if two byte arrays are equal
static bool bytes_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    return std::memcmp(a, b, len) == 0;
}

void test_encryption() {
    // -----------------------------------------------------------------------
    // Test 1: AES-256 single block encrypt/decrypt round-trip
    // -----------------------------------------------------------------------
    {
        uint8_t key[32];
        std::memset(key, 0x42, 32);

        WalletEncryption::AES256Context ctx;
        WalletEncryption::aes256_init(ctx, key);

        uint8_t plaintext[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                                  0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        uint8_t ciphertext[16];
        uint8_t decrypted[16];

        WalletEncryption::aes256_encrypt_block(ctx, plaintext, ciphertext);
        WalletEncryption::aes256_decrypt_block(ctx, ciphertext, decrypted);

        assert(bytes_equal(plaintext, decrypted, 16));
        // Ciphertext should differ from plaintext
        assert(!bytes_equal(plaintext, ciphertext, 16));
    }

    // -----------------------------------------------------------------------
    // Test 2: Different keys produce different ciphertext
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
        uint8_t cipher1[16], cipher2[16];

        WalletEncryption::aes256_encrypt_block(ctx1, plain, cipher1);
        WalletEncryption::aes256_encrypt_block(ctx2, plain, cipher2);

        assert(!bytes_equal(cipher1, cipher2, 16));

        // But each round-trips correctly
        uint8_t dec1[16], dec2[16];
        WalletEncryption::aes256_decrypt_block(ctx1, cipher1, dec1);
        WalletEncryption::aes256_decrypt_block(ctx2, cipher2, dec2);
        assert(bytes_equal(dec1, plain, 16));
        assert(bytes_equal(dec2, plain, 16));
    }

    // -----------------------------------------------------------------------
    // Test 3: PKCS7 padding correct
    // -----------------------------------------------------------------------
    {
        // Test padding of various lengths
        uint8_t data5[] = {1, 2, 3, 4, 5};
        auto padded5 = WalletEncryption::pkcs7_pad(data5, 5);
        assert(padded5.size() == 16);
        // Padding bytes should be 11 (= 16 - 5)
        for (size_t i = 5; i < 16; ++i) {
            assert(padded5[i] == 11);
        }

        // Unpad should recover original
        auto unpadded5 = WalletEncryption::pkcs7_unpad(padded5.data(), padded5.size());
        assert(unpadded5.size() == 5);
        assert(bytes_equal(unpadded5.data(), data5, 5));

        // Exact multiple of 16: should add full 16-byte pad block
        uint8_t data16[16];
        std::memset(data16, 0xAB, 16);
        auto padded16 = WalletEncryption::pkcs7_pad(data16, 16);
        assert(padded16.size() == 32);
        for (size_t i = 16; i < 32; ++i) {
            assert(padded16[i] == 16);
        }

        auto unpadded16 = WalletEncryption::pkcs7_unpad(padded16.data(), padded16.size());
        assert(unpadded16.size() == 16);

        // Empty data: should produce 16 bytes of padding value 16
        auto padded0 = WalletEncryption::pkcs7_pad(nullptr, 0);
        assert(padded0.size() == 16);
        for (size_t i = 0; i < 16; ++i) {
            assert(padded0[i] == 16);
        }

        auto unpadded0 = WalletEncryption::pkcs7_unpad(padded0.data(), padded0.size());
        assert(unpadded0.size() == 0);

        // Invalid padding: wrong padding byte
        uint8_t bad_pad[16];
        std::memset(bad_pad, 0, 16);
        bad_pad[15] = 5;  // claims 5 bytes of padding but others are 0
        auto bad_unpad = WalletEncryption::pkcs7_unpad(bad_pad, 16);
        assert(bad_unpad.empty());
    }

    // -----------------------------------------------------------------------
    // Test 4: CBC encrypt/decrypt round-trip
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        // Test with various data sizes
        for (size_t data_size : {0, 1, 15, 16, 17, 31, 32, 100, 256, 1000}) {
            std::vector<uint8_t> data(data_size);
            if (data_size > 0) {
                GetRandBytes(data.data(), data_size);
            }

            auto encrypted = WalletEncryption::encrypt(
                data.data(), data.size(), key);

            // Encrypted should be larger (IV + padding)
            assert(encrypted.size() >= 32);  // at least IV + 1 block
            assert(encrypted.size() % 16 == 0);  // IV is 16, padded ciphertext is multiple of 16

            auto decrypted = WalletEncryption::decrypt(
                encrypted.data(), encrypted.size(), key);

            assert(decrypted.size() == data_size);
            if (data_size > 0) {
                assert(bytes_equal(decrypted.data(), data.data(), data_size));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 5: Wrong key fails to decrypt correctly
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key1, key2;
        GetRandBytes(key1.data(), 32);
        GetRandBytes(key2.data(), 32);

        uint8_t message[] = "Secret wallet data that must be protected";
        size_t msg_len = sizeof(message) - 1;

        auto encrypted = WalletEncryption::encrypt(message, msg_len, key1);

        // Try to decrypt with wrong key
        auto bad_decrypt = WalletEncryption::decrypt(
            encrypted.data(), encrypted.size(), key2);

        // Either returns empty (padding check failed) or wrong data
        if (!bad_decrypt.empty()) {
            // If PKCS7 happened to pass, the data should be different
            bool data_matches = (bad_decrypt.size() == msg_len &&
                                 bytes_equal(bad_decrypt.data(), message, msg_len));
            assert(!data_matches);
        }
        // If empty, that's expected (padding validation caught the error)
    }

    // -----------------------------------------------------------------------
    // Test 6: KDF produces deterministic key from passphrase + salt
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 16> salt;
        std::memset(salt.data(), 0x55, 16);

        auto key1 = WalletEncryption::derive_key("my passphrase", salt);
        auto key2 = WalletEncryption::derive_key("my passphrase", salt);
        assert(key1 == key2);

        // Different passphrase = different key
        auto key3 = WalletEncryption::derive_key("other passphrase", salt);
        assert(key1 != key3);

        // Different salt = different key
        std::array<uint8_t, 16> salt2;
        std::memset(salt2.data(), 0xAA, 16);
        auto key4 = WalletEncryption::derive_key("my passphrase", salt2);
        assert(key1 != key4);

        // Key should be non-zero
        bool all_zero = true;
        for (auto b : key1) {
            if (b != 0) { all_zero = false; break; }
        }
        assert(!all_zero);
    }

    // -----------------------------------------------------------------------
    // Test 7: Encrypt empty data
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        auto encrypted = WalletEncryption::encrypt(nullptr, 0, key);
        assert(!encrypted.empty());
        assert(encrypted.size() == 32);  // 16 IV + 16 pad block

        auto decrypted = WalletEncryption::decrypt(
            encrypted.data(), encrypted.size(), key);
        assert(decrypted.empty());  // 0-length plaintext
    }

    // -----------------------------------------------------------------------
    // Test 8: Encrypt large data (multiple blocks)
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        // 1024 bytes = 64 AES blocks
        std::vector<uint8_t> large_data(1024);
        for (size_t i = 0; i < 1024; ++i) {
            large_data[i] = static_cast<uint8_t>(i & 0xFF);
        }

        auto encrypted = WalletEncryption::encrypt(
            large_data.data(), large_data.size(), key);

        // Should be 16 (IV) + 1024 + 16 (padding) = 1056
        assert(encrypted.size() == 1056);

        auto decrypted = WalletEncryption::decrypt(
            encrypted.data(), encrypted.size(), key);
        assert(decrypted.size() == 1024);
        assert(bytes_equal(decrypted.data(), large_data.data(), 1024));
    }

    // -----------------------------------------------------------------------
    // Test 9: Two encryptions of same data produce different ciphertext (random IV)
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        uint8_t data[] = "same plaintext for both";
        size_t len = sizeof(data) - 1;

        auto enc1 = WalletEncryption::encrypt(data, len, key);
        auto enc2 = WalletEncryption::encrypt(data, len, key);

        // Different IVs should produce different ciphertext
        assert(enc1.size() == enc2.size());
        assert(enc1 != enc2);  // IVs are random, so ciphertext differs

        // But both decrypt to the same plaintext
        auto dec1 = WalletEncryption::decrypt(enc1.data(), enc1.size(), key);
        auto dec2 = WalletEncryption::decrypt(enc2.data(), enc2.size(), key);
        assert(dec1.size() == len);
        assert(dec2.size() == len);
        assert(dec1 == dec2);
    }

    // -----------------------------------------------------------------------
    // Test 10: Truncated ciphertext fails
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        uint8_t data[] = "test data for truncation";
        auto encrypted = WalletEncryption::encrypt(data, sizeof(data) - 1, key);

        // Try with too-short data
        auto bad1 = WalletEncryption::decrypt(encrypted.data(), 15, key);
        assert(bad1.empty());

        // Try with just the IV (no ciphertext)
        auto bad2 = WalletEncryption::decrypt(encrypted.data(), 16, key);
        assert(bad2.empty());
    }

    // -----------------------------------------------------------------------
    // Test 11: AES-256 key expansion produces distinct round keys
    // -----------------------------------------------------------------------
    {
        uint8_t key[32];
        for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);

        WalletEncryption::AES256Context ctx;
        WalletEncryption::aes256_init(ctx, key);

        // Verify that not all round keys are the same
        bool all_same = true;
        for (int i = 1; i < 60; ++i) {
            if (ctx.round_keys[i] != ctx.round_keys[0]) {
                all_same = false;
                break;
            }
        }
        assert(!all_same);
    }
}

// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// AES-256-CBC wallet encryption with Keccak-based key derivation.
// Pure implementation, no OpenSSL dependency.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace flow {

// AES S-box and inverse S-box lookup tables
extern const uint8_t AES_SBOX[256];
extern const uint8_t AES_INV_SBOX[256];

class WalletEncryption {
public:
    // AES-256 context holding the expanded round keys.
    // AES-256 uses 14 rounds, requiring 15 round keys of 4 words each = 60 words.
    struct AES256Context {
        uint32_t round_keys[60];
    };

    // ---- Key derivation ----

    /// Derive a 32-byte encryption key from a passphrase and salt.
    /// key = keccak256(keccak256(passphrase || salt) || salt)
    /// This provides key stretching through double hashing.
    static std::array<uint8_t, 32> derive_key(const std::string& passphrase,
                                               const std::array<uint8_t, 16>& salt);

    // ---- Encrypt / Decrypt ----

    /// Encrypt data with AES-256-CBC.
    /// Output format: [16 bytes IV][ciphertext with PKCS7 padding]
    /// IV is randomly generated for each call.
    static std::vector<uint8_t> encrypt(const uint8_t* data, size_t len,
                                         const std::array<uint8_t, 32>& key);

    /// Decrypt data previously encrypted with encrypt().
    /// Input format: [16 bytes IV][ciphertext with PKCS7 padding]
    /// Returns empty vector on error (wrong key, corrupted data, bad padding).
    static std::vector<uint8_t> decrypt(const uint8_t* data, size_t len,
                                         const std::array<uint8_t, 32>& key);

    // ---- AES-256 core operations ----

    /// Initialize AES-256 key schedule (key expansion).
    static void aes256_init(AES256Context& ctx, const uint8_t key[32]);

    /// Encrypt a single 16-byte block with AES-256.
    static void aes256_encrypt_block(const AES256Context& ctx,
                                      const uint8_t in[16], uint8_t out[16]);

    /// Decrypt a single 16-byte block with AES-256.
    static void aes256_decrypt_block(const AES256Context& ctx,
                                      const uint8_t in[16], uint8_t out[16]);

    // ---- PKCS7 padding ----

    /// Apply PKCS7 padding to data so its length is a multiple of 16.
    static std::vector<uint8_t> pkcs7_pad(const uint8_t* data, size_t len);

    /// Remove PKCS7 padding. Returns empty vector if padding is invalid.
    static std::vector<uint8_t> pkcs7_unpad(const uint8_t* data, size_t len);

    // ---- Utility ----

    /// Securely wipe memory (prevents compiler optimization from removing the clear).
    static void secure_wipe(void* data, size_t len);

    /// Constant-time comparison of two byte buffers.
    /// Returns true if they are equal, false otherwise.
    /// Runs in constant time regardless of where (or if) the buffers differ.
    static bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t len);

    /// Encrypt a private key (32 bytes) with the given AES key.
    /// Returns the encrypted blob (IV + ciphertext).
    static std::vector<uint8_t> encrypt_privkey(const std::array<uint8_t, 32>& privkey,
                                                  const std::array<uint8_t, 32>& aes_key);

    /// Decrypt a private key blob back to 32 bytes.
    /// Returns empty array on error.
    static std::array<uint8_t, 32> decrypt_privkey(const std::vector<uint8_t>& encrypted,
                                                     const std::array<uint8_t, 32>& aes_key);

    /// Encrypt arbitrary data and return it with a keyed MAC for integrity.
    /// Format: [16 IV][ciphertext][32 MAC]
    /// MAC = keccak256(key || IV || ciphertext)
    static std::vector<uint8_t> encrypt_authenticated(const uint8_t* data, size_t len,
                                                        const std::array<uint8_t, 32>& key);

    /// Decrypt authenticated data. Verifies MAC before returning plaintext.
    /// Returns empty vector on MAC mismatch or decryption error.
    static std::vector<uint8_t> decrypt_authenticated(const uint8_t* data, size_t len,
                                                        const std::array<uint8_t, 32>& key);

private:
    // AES round operations on a 4x4 state matrix (column-major)
    static void sub_bytes(uint8_t state[16]);
    static void inv_sub_bytes(uint8_t state[16]);
    static void shift_rows(uint8_t state[16]);
    static void inv_shift_rows(uint8_t state[16]);
    static void mix_columns(uint8_t state[16]);
    static void inv_mix_columns(uint8_t state[16]);
    static void add_round_key(uint8_t state[16], const uint32_t* rk);

    // GF(2^8) multiplication helpers for MixColumns
    static uint8_t gf_mul(uint8_t a, uint8_t b);
    static uint8_t xtime(uint8_t x);

    // Key expansion helper: apply S-box to each byte of a 32-bit word
    static uint32_t sub_word(uint32_t w);

    // Key expansion helper: rotate word left by 8 bits
    static uint32_t rot_word(uint32_t w);
};

} // namespace flow

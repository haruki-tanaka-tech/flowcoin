// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// AES-256 implementation: ECB, CBC, and CTR modes.
// Pure C++ implementation with no external dependencies.
// Used for wallet encryption and key storage.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// AES S-Box tables (declared here, defined in aes256.cpp)
// ---------------------------------------------------------------------------

extern const uint8_t AES256_SBOX[256];
extern const uint8_t AES256_INV_SBOX[256];

// ---------------------------------------------------------------------------
// AES-256 context
// ---------------------------------------------------------------------------

/** AES-256 context holding the expanded round keys.
 *  AES-256 uses 14 rounds, requiring 15 round keys of 4 words each = 60 words.
 */
struct AES256Context {
    uint32_t round_keys[60];
};

// ---------------------------------------------------------------------------
// AES-256 core operations
// ---------------------------------------------------------------------------

/** Initialize AES-256 key schedule (key expansion).
 *  @param ctx  Context to initialize.
 *  @param key  32-byte encryption key.
 */
void aes256_key_expand(AES256Context& ctx, const uint8_t key[32]);

/** Encrypt a single 16-byte block with AES-256 ECB.
 *  @param ctx  Initialized AES-256 context.
 *  @param in   16-byte plaintext block.
 *  @param out  16-byte ciphertext block.
 */
void aes256_ecb_encrypt(const AES256Context& ctx,
                         const uint8_t in[16], uint8_t out[16]);

/** Decrypt a single 16-byte block with AES-256 ECB.
 *  @param ctx  Initialized AES-256 context.
 *  @param in   16-byte ciphertext block.
 *  @param out  16-byte plaintext block.
 */
void aes256_ecb_decrypt(const AES256Context& ctx,
                         const uint8_t in[16], uint8_t out[16]);

// ---------------------------------------------------------------------------
// CBC mode
// ---------------------------------------------------------------------------

/** Encrypt data with AES-256-CBC.
 *  @param data      Plaintext data.
 *  @param data_len  Length of plaintext in bytes.
 *  @param key       32-byte encryption key.
 *  @param iv        16-byte initialization vector.
 *  @return          Ciphertext (PKCS7-padded, multiple of 16 bytes).
 */
std::vector<uint8_t> aes256_cbc_encrypt(const uint8_t* data, size_t data_len,
                                          const uint8_t key[32],
                                          const uint8_t iv[16]);

/** Decrypt data with AES-256-CBC.
 *  @param data      Ciphertext (must be multiple of 16 bytes).
 *  @param data_len  Length of ciphertext in bytes.
 *  @param key       32-byte encryption key.
 *  @param iv        16-byte initialization vector.
 *  @return          Decrypted plaintext (PKCS7 padding removed).
 *                   Empty vector on error (bad padding or invalid length).
 */
std::vector<uint8_t> aes256_cbc_decrypt(const uint8_t* data, size_t data_len,
                                          const uint8_t key[32],
                                          const uint8_t iv[16]);

/** Encrypt with random IV prepended to output.
 *  Output format: [16-byte IV][ciphertext]
 *  @param data  Plaintext data.
 *  @param len   Length of plaintext.
 *  @param key   32-byte encryption key.
 *  @return      IV + ciphertext.
 */
std::vector<uint8_t> aes256_cbc_encrypt(const uint8_t* data, size_t len,
                                          const std::array<uint8_t, 32>& key);

/** Decrypt data with IV prepended.
 *  Input format: [16-byte IV][ciphertext]
 *  @param data  IV + ciphertext.
 *  @param len   Total length (must be >= 32, and (len-16) % 16 == 0).
 *  @param key   32-byte encryption key.
 *  @return      Decrypted plaintext. Empty on error.
 */
std::vector<uint8_t> aes256_cbc_decrypt(const uint8_t* data, size_t len,
                                          const std::array<uint8_t, 32>& key);

// ---------------------------------------------------------------------------
// CTR mode
// ---------------------------------------------------------------------------

/** Encrypt/decrypt data with AES-256-CTR.
 *  CTR mode is symmetric: encrypt and decrypt use the same operation.
 *  @param data      Input data.
 *  @param data_len  Length of input data.
 *  @param key       32-byte encryption key.
 *  @param nonce     16-byte nonce/counter initial value.
 *  @return          Output data (same length as input).
 */
std::vector<uint8_t> aes256_ctr(const uint8_t* data, size_t data_len,
                                  const uint8_t key[32],
                                  const uint8_t nonce[16]);

// ---------------------------------------------------------------------------
// PKCS7 padding
// ---------------------------------------------------------------------------

/** Apply PKCS7 padding to data (pad to 16-byte boundary).
 *  @param data  Input data.
 *  @param len   Length of input data.
 *  @return      Padded data (length is multiple of 16).
 */
std::vector<uint8_t> aes_pkcs7_pad(const uint8_t* data, size_t len);

/** Remove PKCS7 padding from data.
 *  @param data  Padded data.
 *  @param len   Length of padded data (must be multiple of 16).
 *  @return      Unpadded data. Empty vector on invalid padding.
 */
std::vector<uint8_t> aes_pkcs7_unpad(const uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/** Derive a 32-byte AES key from a passphrase using iterated Keccak hashing.
 *  key = keccak256^N(passphrase || salt)
 *  where N = iterations (minimum 1).
 *
 *  @param passphrase   User passphrase.
 *  @param salt         Salt bytes.
 *  @param salt_len     Length of salt.
 *  @param iterations   Number of hash iterations (minimum 1, recommended >= 10000).
 *  @return             32-byte derived key.
 */
std::array<uint8_t, 32> keccak_kdf(const std::string& passphrase,
                                     const uint8_t* salt, size_t salt_len,
                                     uint32_t iterations);

/** Derive a 32-byte AES key with a 16-byte salt array.
 *  Convenience wrapper.
 */
std::array<uint8_t, 32> keccak_kdf(const std::string& passphrase,
                                     const std::array<uint8_t, 16>& salt,
                                     uint32_t iterations);

// ---------------------------------------------------------------------------
// GF(2^8) multiplication (exposed for testing)
// ---------------------------------------------------------------------------

/** Multiply two elements in GF(2^8) with the AES irreducible polynomial. */
uint8_t aes_gf_mul(uint8_t a, uint8_t b);

/** Double an element in GF(2^8) (xtime operation). */
uint8_t aes_xtime(uint8_t x);

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/** Securely wipe an AES context from memory. */
void aes256_wipe(AES256Context& ctx);

/** Constant-time comparison of two byte buffers. */
bool aes_constant_time_equal(const uint8_t* a, const uint8_t* b, size_t len);

} // namespace flow

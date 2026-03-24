// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// HMAC-Keccak-512 and SHA-512 implementations.
// HMAC-Keccak-512 (RFC 2104 with Keccak-512) is used for SLIP-0010 HD key
// derivation, consistent with the Keccak-512 used inside Ed25519 signing.
// SHA-512 is provided as a standalone primitive for interoperability.

#pragma once

#include "../util/types.h"
#include <cstddef>
#include <cstdint>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// SHA-512
// ---------------------------------------------------------------------------

/** SHA-512 context for incremental hashing. */
struct SHA512Context {
    uint64_t state[8];       /**< Intermediate hash state */
    uint64_t count[2];       /**< Number of bits processed */
    uint8_t buffer[128];     /**< Input buffer (128-byte block) */
};

/** Initialize a SHA-512 context. */
void sha512_init(SHA512Context& ctx);

/** Update a SHA-512 context with additional data. */
void sha512_update(SHA512Context& ctx, const uint8_t* data, size_t len);

/** Finalize a SHA-512 context and produce the 64-byte digest. */
void sha512_final(SHA512Context& ctx, uint8_t out[64]);

/** Compute SHA-512 of a single block of data.
 *  @param data  Pointer to input data.
 *  @param len   Length of input data in bytes.
 *  @param out   Output buffer for the 64-byte digest.
 */
void sha512(const uint8_t* data, size_t len, uint8_t out[64]);

/** Compute SHA-512 and return as uint512. */
uint512 sha512_hash(const uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// HMAC-SHA-512 (RFC 4231)
// ---------------------------------------------------------------------------

/** Compute HMAC-SHA-512.
 *  @param key       HMAC key (arbitrary length).
 *  @param key_len   Length of the key in bytes.
 *  @param data      Message data (arbitrary length).
 *  @param data_len  Length of the data in bytes.
 *  @return          64-byte (512-bit) HMAC result.
 */
uint512 hmac_sha512(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len);

// ---------------------------------------------------------------------------
// HMAC-Keccak-512 (RFC 2104 with Keccak-512)
// ---------------------------------------------------------------------------

/** Compute HMAC-Keccak-512.
 *  @param key       HMAC key (arbitrary length).
 *  @param key_len   Length of the key in bytes.
 *  @param data      Message data (arbitrary length).
 *  @param data_len  Length of the data in bytes.
 *  @return          64-byte (512-bit) HMAC result.
 */
uint512 hmac_keccak512(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len);

// ---------------------------------------------------------------------------
// Keccak-512 single-shot (convenience wrapper)
// ---------------------------------------------------------------------------

/** Compute Keccak-512 hash of data.
 *  @param data  Pointer to input data.
 *  @param len   Length of input data in bytes.
 *  @param out   Output buffer for the 64-byte digest.
 */
void keccak512(const uint8_t* data, size_t len, uint8_t out[64]);

/** Compute Keccak-512 and return as uint512. */
uint512 keccak512_hash(const uint8_t* data, size_t len);

} // namespace flow

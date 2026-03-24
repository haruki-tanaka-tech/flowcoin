// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// HMAC-Keccak-512 implementation (RFC 2104 with Keccak-512).
// Used for SLIP-0010 HD key derivation, consistent with the
// Keccak-512 used inside Ed25519 signing.

#pragma once

#include "../util/types.h"
#include <cstddef>
#include <cstdint>

namespace flow {

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

} // namespace flow

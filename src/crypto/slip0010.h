// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// SLIP-0010 HD key derivation for Ed25519 using HMAC-Keccak-512.
// Ed25519 only supports hardened child derivation.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace flow {

/** Extended key: private key + chain code from HD derivation. */
struct ExtendedKey {
    std::array<uint8_t, 32> key;        /**< Private key (32 bytes) */
    std::array<uint8_t, 32> chain_code; /**< Chain code (32 bytes) */
};

/** Derive the master extended key from a seed.
 *  master = HMAC-Keccak-512(key="ed25519 seed", data=seed)
 *  Left 32 bytes = private key, right 32 bytes = chain code.
 */
ExtendedKey slip0010_master(const uint8_t* seed, size_t seed_len);

/** Derive a hardened child key from a parent extended key.
 *  child = HMAC-Keccak-512(key=parent.chain_code,
 *                           data=0x00 || parent.key || index_be32)
 *  The index must have bit 31 set (hardened). This function sets it
 *  automatically: the caller passes the logical index (0, 1, 2, ...)
 *  and the hardened flag (0x80000000) is OR'd in.
 */
ExtendedKey slip0010_derive_hardened(const ExtendedKey& parent, uint32_t index);

/** Derive the full BIP-44 path: m/44'/9555'/0'/0'/i'
 *  All derivation steps are hardened (Ed25519 requirement).
 *  @param seed           BIP-39 seed bytes.
 *  @param seed_len       Length of the seed.
 *  @param address_index  The final index i in the path.
 *  @return               Extended key at the derived path.
 */
ExtendedKey slip0010_derive_path(const uint8_t* seed, size_t seed_len, uint32_t address_index);

} // namespace flow

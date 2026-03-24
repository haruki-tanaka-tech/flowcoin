// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// SLIP-0010 HD key derivation for Ed25519 using HMAC-Keccak-512.
// Ed25519 only supports hardened child derivation.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace flow {

// Forward declaration
struct KeyPair;

/** Extended key: private key + chain code from HD derivation. */
struct ExtendedKey {
    std::array<uint8_t, 32> key;        /**< Private key (32 bytes) */
    std::array<uint8_t, 32> chain_code; /**< Chain code (32 bytes) */

    /** Check if the key is valid (non-zero). */
    bool is_valid() const;

    /** Wipe the key material from memory. */
    void wipe();

    /** Compare two extended keys for equality. */
    bool operator==(const ExtendedKey& other) const;
    bool operator!=(const ExtendedKey& other) const;
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

/** Derive with a custom BIP-44 path.
 *  @param seed       BIP-39 seed bytes.
 *  @param seed_len   Length of the seed.
 *  @param coin_type  Coin type (9555 for FlowCoin).
 *  @param account    Account number.
 *  @param change     Change index (0 = external, 1 = internal). Hardened for Ed25519.
 *  @param index      Address index.
 *  @return           Extended key at the derived path.
 */
ExtendedKey slip0010_derive_path(const uint8_t* seed, size_t seed_len,
                                  uint32_t coin_type, uint32_t account,
                                  uint32_t change, uint32_t index);

/** Derive a keypair (private + public key) from a seed and index.
 *  Convenience wrapper that derives the key and computes the Ed25519 pubkey.
 *  @param seed   BIP-39 seed bytes.
 *  @param seed_len Length of the seed.
 *  @param index  Address index in the BIP-44 path.
 *  @return       KeyPair with private and public keys.
 */
KeyPair derive_keypair(const uint8_t* seed, size_t seed_len, uint32_t index);

/** Derive a batch of keypairs from a seed.
 *  @param seed       BIP-39 seed bytes.
 *  @param seed_len   Length of the seed.
 *  @param start      Starting index (inclusive).
 *  @param count      Number of keypairs to derive.
 *  @return           Vector of derived keypairs.
 */
std::vector<KeyPair> derive_keypair_batch(const uint8_t* seed, size_t seed_len,
                                           uint32_t start, uint32_t count);

/** Parse a BIP-44 derivation path string like "m/44'/9555'/0'/0'/0'"
 *  into a vector of indices (with hardened bit set where indicated by ').
 *  @param path  Path string.
 *  @param indices  Receives the parsed indices.
 *  @return true on success.
 */
bool parse_derivation_path(const std::string& path, std::vector<uint32_t>& indices);

/** Derive using an arbitrary path of hardened indices.
 *  @param seed     BIP-39 seed bytes.
 *  @param seed_len Length of the seed.
 *  @param indices  Vector of raw indices (hardened bit must already be set).
 *  @return         Extended key at the derived path.
 */
ExtendedKey slip0010_derive_path(const uint8_t* seed, size_t seed_len,
                                  const std::vector<uint32_t>& indices);

/** FlowCoin coin type for BIP-44. */
static constexpr uint32_t FLOWCOIN_COIN_TYPE = 9555;

/** Hardened derivation flag. */
static constexpr uint32_t HARDENED = 0x80000000u;

} // namespace flow

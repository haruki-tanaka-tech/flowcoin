// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Ed25519 key generation using ed25519-donna with Keccak-512 internals.

#pragma once

#include <array>
#include <cstdint>

namespace flow {

/** An Ed25519 keypair (seed + public key). */
struct KeyPair {
    std::array<uint8_t, 32> privkey;  /**< Ed25519 secret key seed (32 bytes) */
    std::array<uint8_t, 32> pubkey;   /**< Ed25519 public key (32 bytes) */
};

/** Generate a new random Ed25519 keypair using OS-provided entropy. */
KeyPair generate_keypair();

/** Derive the Ed25519 public key from a 32-byte private key seed. */
std::array<uint8_t, 32> derive_pubkey(const uint8_t* privkey_seed);

} // namespace flow

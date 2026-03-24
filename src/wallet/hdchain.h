// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// HD key derivation chain for FlowCoin wallets.
// Uses SLIP-0010 with Keccak-512 HMAC for Ed25519 key derivation.
// Path: m/44'/9555'/0'/0'/index' (all hardened, as required by Ed25519).

#pragma once

#include "crypto/keys.h"

#include <cstdint>
#include <vector>

namespace flow {

class HDChain {
public:
    /// Initialize with a new random master seed (256 bits from /dev/urandom).
    void generate_seed();

    /// Initialize with an existing seed (e.g., restored from backup).
    void set_seed(const std::vector<uint8_t>& seed);

    /// Get the master seed bytes (for encrypted backup).
    const std::vector<uint8_t>& seed() const { return seed_; }

    /// Derive the keypair at path m/44'/9555'/0'/0'/index'.
    /// Uses SLIP-0010 derivation, then derives the Ed25519 public key.
    KeyPair derive_key(uint32_t index) const;

    /// Get the next unused derivation index.
    uint32_t next_index() const { return next_index_; }

    /// Advance the derivation index by one.
    void advance() { next_index_++; }

    /// Set the index (for restoring from a backed-up wallet).
    void set_index(uint32_t idx) { next_index_ = idx; }

private:
    std::vector<uint8_t> seed_;   // 32-byte master seed
    uint32_t next_index_ = 0;
};

} // namespace flow

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "wallet/hdchain.h"

#include "crypto/keys.h"
#include "crypto/slip0010.h"
#include "util/random.h"

#include <cstring>
#include <stdexcept>

namespace flow {

// ---------------------------------------------------------------------------
// Seed generation
// ---------------------------------------------------------------------------

void HDChain::generate_seed() {
    seed_.resize(32);
    GetRandBytes(seed_.data(), 32);
    next_index_ = 0;
}

void HDChain::set_seed(const std::vector<uint8_t>& seed) {
    if (seed.size() < 16) {
        throw std::runtime_error("HDChain: seed must be at least 16 bytes");
    }
    seed_ = seed;
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

KeyPair HDChain::derive_key(uint32_t index) const {
    if (seed_.empty()) {
        throw std::runtime_error("HDChain: no seed set");
    }

    // Derive the extended key at m/44'/9555'/0'/0'/index'
    ExtendedKey ext = slip0010_derive_path(
        seed_.data(), seed_.size(), index);

    // Use the derived key as the Ed25519 private key seed,
    // then compute the corresponding public key.
    KeyPair kp;
    kp.privkey = ext.key;
    kp.pubkey = derive_pubkey(ext.key.data());
    return kp;
}

} // namespace flow

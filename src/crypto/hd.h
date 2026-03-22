// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// SLIP-0010 hierarchical deterministic key derivation for Ed25519.
// All derivation is hardened (Ed25519 requirement).

#pragma once

#include "core/types.h"
#include <cstdint>
#include <vector>

namespace flow::crypto {

struct ExtKey {
    PrivKey key;         // 32-byte private key
    Blob<32> chain_code; // 32-byte chain code
};

// Derive master key from seed using SLIP-0010.
// key = "ed25519 seed", data = seed
ExtKey master_key_from_seed(const uint8_t* seed, size_t seed_len);

// Derive child key at hardened index.
// SLIP-0010 for Ed25519: only hardened derivation is supported.
// index must have bit 31 set (>= 0x80000000).
ExtKey derive_child(const ExtKey& parent, uint32_t index);

// Derive key at path like m/44'/9555'/0'/0/0
// All indices are automatically hardened.
ExtKey derive_path(const ExtKey& master, const std::vector<uint32_t>& path);

// Default derivation path: m/44'/9555'/0'/0/{index}
// BIP44 coin type 9555 for FlowCoin.
ExtKey derive_default(const ExtKey& master, uint32_t address_index);

} // namespace flow::crypto

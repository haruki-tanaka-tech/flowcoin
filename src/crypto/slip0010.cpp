// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "slip0010.h"
#include "hmac_sha512.h"

#include <cstring>

namespace flow {

// ---------------------------------------------------------------------------
// Master key derivation
// ---------------------------------------------------------------------------

ExtendedKey slip0010_master(const uint8_t* seed, size_t seed_len) {
    // HMAC key is the ASCII string "ed25519 seed"
    static constexpr uint8_t hmac_key[] = "ed25519 seed";
    static constexpr size_t hmac_key_len = 12;  // strlen("ed25519 seed")

    uint512 I = hmac_keccak512(hmac_key, hmac_key_len, seed, seed_len);

    ExtendedKey master;
    std::memcpy(master.key.data(), I.data(), 32);
    std::memcpy(master.chain_code.data(), I.data() + 32, 32);

    return master;
}

// ---------------------------------------------------------------------------
// Hardened child derivation
// ---------------------------------------------------------------------------

ExtendedKey slip0010_derive_hardened(const ExtendedKey& parent, uint32_t index) {
    // Set the hardened bit
    uint32_t hardened_index = index | 0x80000000u;

    // data = 0x00 || parent.key (32 bytes) || index (4 bytes big-endian)
    // Total: 1 + 32 + 4 = 37 bytes
    uint8_t data[37];
    data[0] = 0x00;
    std::memcpy(data + 1, parent.key.data(), 32);
    data[33] = static_cast<uint8_t>((hardened_index >> 24) & 0xFF);
    data[34] = static_cast<uint8_t>((hardened_index >> 16) & 0xFF);
    data[35] = static_cast<uint8_t>((hardened_index >> 8) & 0xFF);
    data[36] = static_cast<uint8_t>((hardened_index) & 0xFF);

    uint512 I = hmac_keccak512(parent.chain_code.data(), 32, data, 37);

    ExtendedKey child;
    std::memcpy(child.key.data(), I.data(), 32);
    std::memcpy(child.chain_code.data(), I.data() + 32, 32);

    return child;
}

// ---------------------------------------------------------------------------
// Full BIP-44 path derivation: m/44'/9555'/0'/0'/i'
// ---------------------------------------------------------------------------

ExtendedKey slip0010_derive_path(const uint8_t* seed, size_t seed_len, uint32_t address_index) {
    ExtendedKey key = slip0010_master(seed, seed_len);

    // m/44'
    key = slip0010_derive_hardened(key, 44);

    // m/44'/9555'  (FlowCoin coin type)
    key = slip0010_derive_hardened(key, 9555);

    // m/44'/9555'/0'  (account 0)
    key = slip0010_derive_hardened(key, 0);

    // m/44'/9555'/0'/0'  (change 0, hardened for Ed25519)
    key = slip0010_derive_hardened(key, 0);

    // m/44'/9555'/0'/0'/i'
    key = slip0010_derive_hardened(key, address_index);

    return key;
}

} // namespace flow

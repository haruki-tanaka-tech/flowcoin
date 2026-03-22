// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// SLIP-0010 HD derivation for Ed25519.
// Reference: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

#include "hd.h"
#include "hmac_sha512.h"

#include <cstring>

namespace flow::crypto {

ExtKey master_key_from_seed(const uint8_t* seed, size_t seed_len) {
    // SLIP-0010: I = HMAC-SHA512(Key = "ed25519 seed", Data = seed)
    static const uint8_t slip_key[] = "ed25519 seed";
    uint8_t I[64];
    hmac_sha512(slip_key, 12, seed, seed_len, I);

    ExtKey result;
    std::memcpy(result.key.bytes(), I, 32);         // IL = private key
    std::memcpy(result.chain_code.bytes(), I + 32, 32); // IR = chain code
    return result;
}

ExtKey derive_child(const ExtKey& parent, uint32_t index) {
    // SLIP-0010 Ed25519: only hardened derivation
    uint32_t hardened_index = index | 0x80000000u;

    // Data = 0x00 || ser256(kpar) || ser32(index)
    uint8_t data[1 + 32 + 4];
    data[0] = 0x00;
    std::memcpy(data + 1, parent.key.bytes(), 32);
    // ser32(index) in big-endian
    data[33] = static_cast<uint8_t>(hardened_index >> 24);
    data[34] = static_cast<uint8_t>(hardened_index >> 16);
    data[35] = static_cast<uint8_t>(hardened_index >> 8);
    data[36] = static_cast<uint8_t>(hardened_index);

    // I = HMAC-SHA512(Key = cpar, Data = data)
    uint8_t I[64];
    hmac_sha512(parent.chain_code.bytes(), 32, data, sizeof(data), I);

    ExtKey result;
    std::memcpy(result.key.bytes(), I, 32);
    std::memcpy(result.chain_code.bytes(), I + 32, 32);
    return result;
}

ExtKey derive_path(const ExtKey& master, const std::vector<uint32_t>& path) {
    ExtKey current = master;
    for (uint32_t index : path) {
        current = derive_child(current, index);
    }
    return current;
}

ExtKey derive_default(const ExtKey& master, uint32_t address_index) {
    // m/44'/9555'/0'/0/{address_index}
    // All hardened for Ed25519
    return derive_path(master, {44, 9555, 0, 0, address_index});
}

} // namespace flow::crypto

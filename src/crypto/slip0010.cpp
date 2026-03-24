// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "slip0010.h"
#include "hmac_sha512.h"
#include "keys.h"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace flow {

// ---------------------------------------------------------------------------
// ExtendedKey methods
// ---------------------------------------------------------------------------

bool ExtendedKey::is_valid() const {
    for (size_t i = 0; i < 32; ++i) {
        if (key[i] != 0) return true;
    }
    return false;
}

void ExtendedKey::wipe() {
    // Use volatile to prevent compiler from optimizing away the clear
    volatile uint8_t* p = const_cast<volatile uint8_t*>(key.data());
    for (size_t i = 0; i < 32; ++i) p[i] = 0;
    p = const_cast<volatile uint8_t*>(chain_code.data());
    for (size_t i = 0; i < 32; ++i) p[i] = 0;
}

bool ExtendedKey::operator==(const ExtendedKey& other) const {
    return key == other.key && chain_code == other.chain_code;
}

bool ExtendedKey::operator!=(const ExtendedKey& other) const {
    return !(*this == other);
}

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
    uint32_t hardened_index = index | HARDENED;

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

    // Wipe intermediate data
    std::memset(data, 0, sizeof(data));

    return child;
}

// ---------------------------------------------------------------------------
// Full BIP-44 path derivation: m/44'/9555'/0'/0'/i'
// ---------------------------------------------------------------------------

ExtendedKey slip0010_derive_path(const uint8_t* seed, size_t seed_len, uint32_t address_index) {
    return slip0010_derive_path(seed, seed_len, FLOWCOIN_COIN_TYPE, 0, 0, address_index);
}

ExtendedKey slip0010_derive_path(const uint8_t* seed, size_t seed_len,
                                  uint32_t coin_type, uint32_t account,
                                  uint32_t change, uint32_t index) {
    ExtendedKey key = slip0010_master(seed, seed_len);

    // m/44'
    key = slip0010_derive_hardened(key, 44);

    // m/44'/coin_type'
    key = slip0010_derive_hardened(key, coin_type);

    // m/44'/coin_type'/account'
    key = slip0010_derive_hardened(key, account);

    // m/44'/coin_type'/account'/change' (hardened for Ed25519)
    key = slip0010_derive_hardened(key, change);

    // m/44'/coin_type'/account'/change'/index'
    key = slip0010_derive_hardened(key, index);

    return key;
}

ExtendedKey slip0010_derive_path(const uint8_t* seed, size_t seed_len,
                                  const std::vector<uint32_t>& indices) {
    ExtendedKey key = slip0010_master(seed, seed_len);

    for (uint32_t idx : indices) {
        // For Ed25519, all derivation must be hardened.
        // The caller may or may not have set the hardened bit;
        // we enforce it here.
        uint32_t hardened_idx = idx & 0x7FFFFFFF;  // strip any existing hardened bit
        key = slip0010_derive_hardened(key, hardened_idx);
    }

    return key;
}

// ---------------------------------------------------------------------------
// Convenience: derive keypair
// ---------------------------------------------------------------------------

KeyPair derive_keypair(const uint8_t* seed, size_t seed_len, uint32_t index) {
    ExtendedKey ext = slip0010_derive_path(seed, seed_len, index);

    KeyPair kp;
    std::memcpy(kp.privkey.data(), ext.key.data(), 32);
    kp.pubkey = derive_pubkey(ext.key.data());

    // Wipe the extended key
    ext.wipe();

    return kp;
}

std::vector<KeyPair> derive_keypair_batch(const uint8_t* seed, size_t seed_len,
                                           uint32_t start, uint32_t count) {
    std::vector<KeyPair> result;
    result.reserve(count);

    // Derive up to the parent of the index level once
    // m/44'/9555'/0'/0'
    ExtendedKey parent = slip0010_master(seed, seed_len);
    parent = slip0010_derive_hardened(parent, 44);
    parent = slip0010_derive_hardened(parent, FLOWCOIN_COIN_TYPE);
    parent = slip0010_derive_hardened(parent, 0);
    parent = slip0010_derive_hardened(parent, 0);

    // Now derive each index from the common parent
    for (uint32_t i = 0; i < count; ++i) {
        ExtendedKey child = slip0010_derive_hardened(parent, start + i);

        KeyPair kp;
        std::memcpy(kp.privkey.data(), child.key.data(), 32);
        kp.pubkey = derive_pubkey(child.key.data());

        child.wipe();
        result.push_back(std::move(kp));
    }

    parent.wipe();
    return result;
}

// ---------------------------------------------------------------------------
// Path parsing
// ---------------------------------------------------------------------------

bool parse_derivation_path(const std::string& path, std::vector<uint32_t>& indices) {
    indices.clear();

    if (path.empty()) return false;

    // Must start with "m" or "m/"
    size_t pos = 0;
    if (path[0] != 'm' && path[0] != 'M') return false;
    pos = 1;

    if (pos >= path.size()) {
        // Just "m" — master key, no derivation steps
        return true;
    }

    if (path[pos] != '/') return false;
    pos++;

    // Parse each component separated by '/'
    while (pos < path.size()) {
        // Find end of this component (next '/' or end of string)
        size_t end = path.find('/', pos);
        if (end == std::string::npos) end = path.size();

        std::string component = path.substr(pos, end - pos);
        if (component.empty()) return false;

        // Check for hardened marker
        bool hardened = false;
        if (component.back() == '\'' || component.back() == 'h' || component.back() == 'H') {
            hardened = true;
            component.pop_back();
        }

        if (component.empty()) return false;

        // Parse the index number
        uint32_t index = 0;
        for (char c : component) {
            if (c < '0' || c > '9') return false;
            uint64_t next = static_cast<uint64_t>(index) * 10 + (c - '0');
            if (next > 0x7FFFFFFF) return false;  // overflow
            index = static_cast<uint32_t>(next);
        }

        if (hardened) {
            index |= HARDENED;
        }

        indices.push_back(index);
        pos = end + 1;
    }

    return true;
}

} // namespace flow

// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "keys.h"
#include "../hash/keccak.h"
#include "../util/strencodings.h"

#include <cstring>
#include <stdexcept>

#if defined(__linux__)
#include <sys/random.h>
#include <sys/mman.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#include <sys/mman.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <cstdio>
#endif

extern "C" {
#include "ed25519.h"
}

namespace flow {

// ---------------------------------------------------------------------------
// Platform-specific secure random bytes
// ---------------------------------------------------------------------------

void secure_random(void* buf, size_t len) {
#if defined(__linux__)
    ssize_t ret = getrandom(buf, len, 0);
    if (ret < 0 || static_cast<size_t>(ret) != len) {
        throw std::runtime_error("getrandom failed");
    }
#elif defined(__APPLE__)
    if (SecRandomCopyBytes(kSecRandomDefault, len, static_cast<uint8_t*>(buf)) != errSecSuccess) {
        throw std::runtime_error("SecRandomCopyBytes failed");
    }
#elif defined(_WIN32)
    if (BCryptGenRandom(NULL, static_cast<PUCHAR>(buf), static_cast<ULONG>(len),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw std::runtime_error("BCryptGenRandom failed");
    }
#else
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) {
        throw std::runtime_error("cannot open /dev/urandom");
    }
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    if (n != len) {
        throw std::runtime_error("short read from /dev/urandom");
    }
#endif
}

// ---------------------------------------------------------------------------
// Secure memory operations
// ---------------------------------------------------------------------------

void secure_wipe(void* data, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }
}

bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

// ---------------------------------------------------------------------------
// KeyPair methods
// ---------------------------------------------------------------------------

bool KeyPair::is_valid() const {
    for (size_t i = 0; i < 32; ++i) {
        if (privkey[i] != 0) return true;
    }
    return false;
}

void KeyPair::wipe() {
    secure_wipe(privkey.data(), 32);
    secure_wipe(pubkey.data(), 32);
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

KeyPair generate_keypair() {
    KeyPair kp;

    // Generate 32 bytes of cryptographically secure random data as the seed
    secure_random(kp.privkey.data(), 32);

    // Derive the public key from the seed using ed25519-donna
    ed25519_publickey(kp.privkey.data(), kp.pubkey.data());

    return kp;
}

KeyPair generate_keypair_from_seed(const uint8_t* seed, size_t len) {
    KeyPair kp;

    // Hash the seed to produce a 32-byte private key
    uint256 hash = keccak256(seed, len);
    std::memcpy(kp.privkey.data(), hash.data(), 32);

    // Derive the public key
    ed25519_publickey(kp.privkey.data(), kp.pubkey.data());

    return kp;
}

std::array<uint8_t, 32> derive_pubkey(const uint8_t* privkey_seed) {
    std::array<uint8_t, 32> pubkey;
    ed25519_publickey(privkey_seed, pubkey.data());
    return pubkey;
}

// ===========================================================================
// PrivKey implementation
// ===========================================================================

SecurePrivKey::SecurePrivKey() : locked_(false) {
    std::memset(key_, 0, 32);
}

SecurePrivKey::SecurePrivKey(const uint8_t* data) : locked_(false) {
    std::memcpy(key_, data, 32);
    lock_memory();
}

SecurePrivKey::SecurePrivKey(const std::array<uint8_t, 32>& data) : locked_(false) {
    std::memcpy(key_, data.data(), 32);
    lock_memory();
}

SecurePrivKey::~SecurePrivKey() {
    wipe();
    unlock_memory();
}

SecurePrivKey::SecurePrivKey(SecurePrivKey&& other) noexcept : locked_(false) {
    std::memcpy(key_, other.key_, 32);
    locked_ = other.locked_;
    other.locked_ = false;
    secure_wipe(other.key_, 32);
    if (!locked_) {
        lock_memory();
    }
}

SecurePrivKey& SecurePrivKey::operator=(SecurePrivKey&& other) noexcept {
    if (this != &other) {
        wipe();
        unlock_memory();
        std::memcpy(key_, other.key_, 32);
        locked_ = other.locked_;
        other.locked_ = false;
        secure_wipe(other.key_, 32);
        if (!locked_) {
            lock_memory();
        }
    }
    return *this;
}

bool SecurePrivKey::is_valid() const {
    for (size_t i = 0; i < 32; ++i) {
        if (key_[i] != 0) return true;
    }
    return false;
}

std::string SecurePrivKey::to_hex() const {
    return hex_encode(key_, 32);
}

bool SecurePrivKey::from_hex(const std::string& hex) {
    if (hex.size() != 64) return false;
    std::vector<uint8_t> bytes = hex_decode(hex);
    if (bytes.size() != 32) return false;
    std::memcpy(key_, bytes.data(), 32);
    lock_memory();
    return true;
}

std::array<uint8_t, 32> SecurePrivKey::to_array() const {
    std::array<uint8_t, 32> arr;
    std::memcpy(arr.data(), key_, 32);
    return arr;
}

std::array<uint8_t, 32> SecurePrivKey::derive_pubkey() const {
    return flow::derive_pubkey(key_);
}

std::vector<uint8_t> SecurePrivKey::get_key_id() const {
    std::array<uint8_t, 32> pubkey = derive_pubkey();
    uint256 hash = keccak256d(pubkey.data(), 32);
    return std::vector<uint8_t>(hash.data(), hash.data() + 20);
}

bool SecurePrivKey::equals(const SecurePrivKey& other) const {
    return constant_time_compare(key_, other.key_, 32);
}

bool SecurePrivKey::equals(const uint8_t* other, size_t len) const {
    if (len != 32) return false;
    return constant_time_compare(key_, other, 32);
}

void SecurePrivKey::wipe() {
    secure_wipe(key_, 32);
}

void SecurePrivKey::lock_memory() {
#if defined(__linux__) || defined(__APPLE__)
    // Try to lock the key memory to prevent it from being swapped to disk
    if (mlock(key_, 32) == 0) {
        locked_ = true;
    }
#elif defined(_WIN32)
    if (VirtualLock(key_, 32)) {
        locked_ = true;
    }
#endif
}

void SecurePrivKey::unlock_memory() {
    if (!locked_) return;
#if defined(__linux__) || defined(__APPLE__)
    munlock(key_, 32);
#elif defined(_WIN32)
    VirtualUnlock(key_, 32);
#endif
    locked_ = false;
}

// ===========================================================================
// PubKey implementation
// ===========================================================================

SecurePubKey::SecurePubKey() {
    std::memset(key_, 0, 32);
}

SecurePubKey::SecurePubKey(const uint8_t* data) {
    std::memcpy(key_, data, 32);
}

SecurePubKey::SecurePubKey(const std::array<uint8_t, 32>& data) {
    std::memcpy(key_, data.data(), 32);
}

bool SecurePubKey::is_valid() const {
    for (size_t i = 0; i < 32; ++i) {
        if (key_[i] != 0) return true;
    }
    return false;
}

std::string SecurePubKey::to_hex() const {
    return hex_encode(key_, 32);
}

bool SecurePubKey::from_hex(const std::string& hex) {
    if (hex.size() != 64) return false;
    std::vector<uint8_t> bytes = hex_decode(hex);
    if (bytes.size() != 32) return false;
    std::memcpy(key_, bytes.data(), 32);
    return true;
}

std::array<uint8_t, 32> SecurePubKey::to_array() const {
    std::array<uint8_t, 32> arr;
    std::memcpy(arr.data(), key_, 32);
    return arr;
}

std::vector<uint8_t> SecurePubKey::get_id() const {
    uint256 hash = keccak256d(key_, 32);
    return std::vector<uint8_t>(hash.data(), hash.data() + 20);
}

uint256 SecurePubKey::get_hash() const {
    return keccak256d(key_, 32);
}

bool SecurePubKey::operator==(const SecurePubKey& other) const {
    return std::memcmp(key_, other.key_, 32) == 0;
}

bool SecurePubKey::operator!=(const SecurePubKey& other) const {
    return !(*this == other);
}

bool SecurePubKey::operator<(const SecurePubKey& other) const {
    return std::memcmp(key_, other.key_, 32) < 0;
}

// ===========================================================================
// Key serialization
// ===========================================================================

std::string export_privkey_hex(const uint8_t* privkey) {
    // Key hex
    std::string key_hex = hex_encode(privkey, 32);

    // Compute checksum: first 4 bytes of keccak256d(privkey)
    uint256 hash = keccak256d(privkey, 32);
    std::string checksum_hex = hex_encode(hash.data(), 4);

    return key_hex + checksum_hex;
}

bool import_privkey_hex(const std::string& hex_str,
                         std::array<uint8_t, 32>& privkey) {
    // Expected: 64 hex chars (key) + 8 hex chars (checksum) = 72
    if (hex_str.size() != 72) return false;

    // Decode key portion
    std::string key_part = hex_str.substr(0, 64);
    std::string checksum_part = hex_str.substr(64, 8);

    std::vector<uint8_t> key_bytes = hex_decode(key_part);
    if (key_bytes.size() != 32) return false;

    std::vector<uint8_t> checksum_bytes = hex_decode(checksum_part);
    if (checksum_bytes.size() != 4) return false;

    // Verify checksum
    uint256 hash = keccak256d(key_bytes.data(), 32);
    if (!constant_time_compare(hash.data(), checksum_bytes.data(), 4)) {
        return false;
    }

    std::memcpy(privkey.data(), key_bytes.data(), 32);
    return true;
}

} // namespace flow

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Ed25519 key generation and management using ed25519-donna with Keccak-512.
// Provides secure key containers with proper lifecycle management.

#pragma once

#include "../util/types.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// KeyPair: basic Ed25519 keypair
// ---------------------------------------------------------------------------

/** An Ed25519 keypair (seed + public key). */
struct KeyPair {
    std::array<uint8_t, 32> privkey;  /**< Ed25519 secret key seed (32 bytes) */
    std::array<uint8_t, 32> pubkey;   /**< Ed25519 public key (32 bytes) */

    /** Check if the keypair has a non-zero private key. */
    bool is_valid() const;

    /** Wipe both keys from memory. */
    void wipe();
};

/** Generate a new random Ed25519 keypair using OS-provided entropy. */
KeyPair generate_keypair();

/** Generate a deterministic Ed25519 keypair from a seed.
 *  @param seed  Arbitrary seed data.
 *  @param len   Length of the seed.
 *  @return      Deterministic keypair (keccak256(seed) used as private key seed).
 */
KeyPair generate_keypair_from_seed(const uint8_t* seed, size_t len);

/** Derive the Ed25519 public key from a 32-byte private key seed. */
std::array<uint8_t, 32> derive_pubkey(const uint8_t* privkey_seed);

// ---------------------------------------------------------------------------
// PrivKey: secure private key container
// ---------------------------------------------------------------------------

/** Secure container for a 32-byte Ed25519 private key seed.
 *  - Zeroizes memory on destruction
 *  - Uses mlock to prevent swapping to disk (if available)
 *  - Non-copyable, only moveable
 *  - Provides hex import/export
 */
class SecurePrivKey {
public:
    SecurePrivKey();
    explicit SecurePrivKey(const uint8_t* data);
    explicit SecurePrivKey(const std::array<uint8_t, 32>& data);

    ~SecurePrivKey();

    // Non-copyable
    SecurePrivKey(const SecurePrivKey&) = delete;
    SecurePrivKey& operator=(const SecurePrivKey&) = delete;

    // Moveable
    SecurePrivKey(SecurePrivKey&& other) noexcept;
    SecurePrivKey& operator=(SecurePrivKey&& other) noexcept;

    /** Check if the key is non-zero. */
    bool is_valid() const;

    /** Raw byte access. */
    const uint8_t* data() const { return key_; }
    uint8_t* data() { return key_; }
    static constexpr size_t size() { return 32; }

    /** Convert to hex string. */
    std::string to_hex() const;

    /** Import from hex string. Returns false on invalid hex. */
    bool from_hex(const std::string& hex);

    /** Convert to a std::array. */
    std::array<uint8_t, 32> to_array() const;

    /** Derive the corresponding public key. */
    std::array<uint8_t, 32> derive_pubkey() const;

    /** Get the key ID: keccak256d(pubkey)[0..19]. */
    std::vector<uint8_t> get_key_id() const;

    /** Constant-time comparison. */
    bool equals(const SecurePrivKey& other) const;
    bool equals(const uint8_t* other, size_t len) const;

    /** Zeroize the key memory. */
    void wipe();

private:
    uint8_t key_[32];
    bool locked_;  /**< Whether mlock was successful */

    void lock_memory();
    void unlock_memory();
};

// ---------------------------------------------------------------------------
// PubKey: public key container
// ---------------------------------------------------------------------------

/** Container for a 32-byte Ed25519 public key.
 *  Provides validation, serialization, and key ID computation.
 */
class SecurePubKey {
public:
    SecurePubKey();
    explicit SecurePubKey(const uint8_t* data);
    explicit SecurePubKey(const std::array<uint8_t, 32>& data);

    /** Check if the public key is non-zero (basic validity). */
    bool is_valid() const;

    /** Raw byte access. */
    const uint8_t* data() const { return key_; }
    uint8_t* data() { return key_; }
    static constexpr size_t size() { return 32; }

    /** Convert to hex string. */
    std::string to_hex() const;

    /** Import from hex string. Returns false on invalid hex. */
    bool from_hex(const std::string& hex);

    /** Convert to a std::array. */
    std::array<uint8_t, 32> to_array() const;

    /** Get the key ID: keccak256d(pubkey)[0..19] = 20-byte identifier.
     *  This is the hash used in P2PKH scripts and Bech32m addresses.
     */
    std::vector<uint8_t> get_id() const;

    /** Get the full 32-byte keccak256d hash of the public key. */
    uint256 get_hash() const;

    /** Comparison operators. */
    bool operator==(const SecurePubKey& other) const;
    bool operator!=(const SecurePubKey& other) const;
    bool operator<(const SecurePubKey& other) const;

private:
    uint8_t key_[32];
};

// ---------------------------------------------------------------------------
// Key serialization utilities
// ---------------------------------------------------------------------------

/** Export a private key as a hex string with a 4-byte checksum.
 *  Format: hex(privkey) + hex(keccak256d(privkey)[0..3])
 *  Total: 64 hex chars key + 8 hex chars checksum = 72 hex chars.
 */
std::string export_privkey_hex(const uint8_t* privkey);

/** Import a private key from a hex-with-checksum string.
 *  Verifies the 4-byte checksum.
 *  @param hex_str  72-character hex string.
 *  @param privkey  Receives the 32-byte private key on success.
 *  @return         true on success, false if invalid format or checksum.
 */
bool import_privkey_hex(const std::string& hex_str,
                         std::array<uint8_t, 32>& privkey);

/** Constant-time comparison of two byte buffers. */
bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len);

/** Securely wipe memory (prevents compiler optimization). */
void secure_wipe(void* data, size_t len);

/** Fill buffer with cryptographically secure random bytes. */
void secure_random(void* buf, size_t len);

} // namespace flow

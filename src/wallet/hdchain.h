// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// HD key derivation chain for FlowCoin wallets.
// Uses SLIP-0010 with Keccak-512 HMAC for Ed25519 key derivation.
// Path: m/44'/9555'/account'/change'/index' (all hardened, as required by Ed25519).
//
// Supports multiple accounts, separate receive/change chains,
// key caching for performance, and serialization for persistent storage.

#pragma once

#include "crypto/keys.h"
#include "util/types.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace flow {

// Forward declaration
struct ExtendedKey;

class HDChain {
public:
    HDChain();

    // -------------------------------------------------------------------
    // Initialization
    // -------------------------------------------------------------------

    /// Initialize with a new random master seed (256 bits from /dev/urandom).
    void generate_seed();

    /// Initialize with an existing seed (e.g., restored from backup).
    void set_seed(const std::vector<uint8_t>& seed);

    /// Initialize from a raw key and chain code (for recovery).
    void init_from_key(const std::array<uint8_t, 32>& key,
                       const std::array<uint8_t, 32>& chain_code);

    /// Check if the chain is initialized with a seed.
    bool is_initialized() const { return initialized_; }

    // -------------------------------------------------------------------
    // Seed access
    // -------------------------------------------------------------------

    /// Get the master seed bytes (for encrypted backup).
    const std::vector<uint8_t>& seed() const { return seed_; }

    /// Get the hash of the master seed (for identification, not the seed itself).
    uint256 get_seed_hash() const;

    // -------------------------------------------------------------------
    // Key derivation
    // -------------------------------------------------------------------

    /// Derived key result with full path information.
    struct DerivedKey {
        std::array<uint8_t, 32> privkey;
        std::array<uint8_t, 32> pubkey;
        std::array<uint8_t, 32> chain_code;
        uint32_t account;
        uint32_t change;
        uint32_t index;
        std::string path;   // e.g., "m/44'/9555'/0'/0'/42'"
    };

    /// Derive the keypair at path m/44'/9555'/0'/0'/index' (default account).
    /// Uses SLIP-0010 derivation, then derives the Ed25519 public key.
    KeyPair derive_key(uint32_t index) const;

    /// Derive a key at the full BIP-44 path with explicit account and change.
    /// Path: m/44'/9555'/account'/change'/index'
    DerivedKey derive_key_full(uint32_t account, uint32_t change,
                                uint32_t index) const;

    /// Derive the next receiving address key (account 0, change 0).
    /// Automatically advances the next_index counter.
    DerivedKey derive_next_key();

    /// Derive the next change address key (account 0, change 1).
    /// Automatically advances the next_change_index counter.
    DerivedKey derive_next_change_key();

    /// Derive a key at an arbitrary path specified as a vector of indices.
    /// Each index in the path will have the hardened flag set automatically.
    DerivedKey derive_path(const std::vector<uint32_t>& path) const;

    // -------------------------------------------------------------------
    // Index management
    // -------------------------------------------------------------------

    /// Get the next unused derivation index for receiving addresses.
    uint32_t next_index() const { return next_index_; }

    /// Get the next unused derivation index for change addresses.
    uint32_t next_change_index() const { return next_change_index_; }

    /// Advance the derivation index by one.
    void advance() { next_index_++; }

    /// Advance the change derivation index by one.
    void advance_change() { next_change_index_++; }

    /// Set the next receiving index (for restoring from a backed-up wallet).
    void set_index(uint32_t idx) { next_index_ = idx; }

    /// Set the next change index (for restoring from backup).
    void set_change_index(uint32_t idx) { next_change_index_ = idx; }

    /// Get the highest index that has been derived (for gap limit scanning).
    uint32_t highest_derived_index() const { return highest_derived_; }

    /// Get the highest change index that has been derived.
    uint32_t highest_derived_change_index() const { return highest_change_derived_; }

    // -------------------------------------------------------------------
    // Key lookup cache
    // -------------------------------------------------------------------

    /// Check if a key at the given index has been derived and cached.
    bool has_cached_key(uint32_t index) const;

    /// Check if a key at the given change index has been derived and cached.
    bool has_cached_change_key(uint32_t index) const;

    /// Get a cached key by index. Returns false if not cached.
    bool get_cached_key(uint32_t index, DerivedKey& out) const;

    /// Clear the key cache (for memory management or security).
    void clear_cache();

    /// Get the number of cached keys.
    size_t cache_size() const;

    // -------------------------------------------------------------------
    // Serialization for wallet DB storage
    // -------------------------------------------------------------------

    /// Serialize the HD chain state to a byte vector.
    /// Includes: seed, indices, but not the key cache.
    std::vector<uint8_t> serialize() const;

    /// Deserialize HD chain state from a byte vector.
    static HDChain deserialize(const std::vector<uint8_t>& data);

    // -------------------------------------------------------------------
    // Account management
    // -------------------------------------------------------------------

    /// Get the number of accounts that have been used.
    uint32_t account_count() const { return account_count_; }

    /// Create a new account (increments account counter).
    uint32_t create_account();

    /// Get the next index for a specific account and change chain.
    uint32_t get_next_index(uint32_t account, uint32_t change) const;

    /// Set the next index for a specific account and change chain.
    void set_next_index(uint32_t account, uint32_t change, uint32_t index);

private:
    std::vector<uint8_t> seed_;   // master seed (typically 32 bytes)
    uint32_t next_index_ = 0;
    uint32_t next_change_index_ = 0;
    bool initialized_ = false;

    // Key cache: maps (account, change, index) to derived keys
    struct CacheKey {
        uint32_t account;
        uint32_t change;
        uint32_t index;

        bool operator<(const CacheKey& o) const {
            if (account != o.account) return account < o.account;
            if (change != o.change) return change < o.change;
            return index < o.index;
        }
    };
    mutable std::map<CacheKey, DerivedKey> cache_;

    // Intermediate key cache for performance (account-level keys)
    struct IntermediateKey {
        std::array<uint8_t, 32> key;
        std::array<uint8_t, 32> chain_code;
    };
    mutable std::map<std::string, IntermediateKey> intermediate_cache_;

    // Tracking
    uint32_t highest_derived_ = 0;
    uint32_t highest_change_derived_ = 0;
    uint32_t account_count_ = 1; // default: 1 account

    // Per-account index tracking
    mutable std::map<std::pair<uint32_t, uint32_t>, uint32_t> account_indices_;

    // Build a path string from components
    static std::string build_path_string(uint32_t account, uint32_t change,
                                          uint32_t index);
};

} // namespace flow

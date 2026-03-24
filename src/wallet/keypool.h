// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Pre-generated key pool for the wallet. Keys are derived from the HD chain
// and kept ready for immediate use, avoiding key derivation latency during
// transaction creation.

#pragma once

#include "wallet/hdchain.h"
#include "wallet/walletdb.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <set>
#include <vector>

namespace flow {

class KeyPool {
public:
    /// Construct a key pool backed by an HD chain and wallet database.
    KeyPool(HDChain& hd, WalletDB& db);

    /// Pre-generate keys up to the target pool size.
    /// Derives new keys from the HD chain and stores them in the database.
    /// Thread-safe.
    void fill(size_t target_size = 100);

    /// Get the next unused key from the pool.
    /// If the pool is empty, derives a new key on the spot.
    /// Thread-safe.
    KeyPair get_key();

    /// Return a key to the pool (e.g., if a transaction was rejected).
    /// The key must have been previously obtained via get_key().
    /// Thread-safe.
    void return_key(const std::array<uint8_t, 32>& pubkey);

    /// Mark a key as permanently used (remove from pool, will not be reused).
    /// Thread-safe.
    void mark_used(const std::array<uint8_t, 32>& pubkey);

    /// Current number of keys available in the pool.
    /// Thread-safe.
    size_t size() const;

    /// Check if a key is in the pool.
    /// Thread-safe.
    bool contains(const std::array<uint8_t, 32>& pubkey) const;

    /// Get the set of all public keys that have been marked as used.
    std::set<std::array<uint8_t, 32>> get_used_keys() const;

    /// Get the HD index of the oldest key in the pool.
    /// Returns 0 if pool is empty.
    uint32_t oldest_index() const;

    /// Get the HD index of the newest key in the pool.
    /// Returns 0 if pool is empty.
    uint32_t newest_index() const;

private:
    HDChain& hd_;
    WalletDB& db_;

    struct PoolEntry {
        KeyPair kp;
        uint32_t hd_index;
    };

    std::deque<PoolEntry> pool_;
    std::set<std::array<uint8_t, 32>> used_keys_;
    mutable std::mutex mutex_;

    /// Derive a key at the next HD index, store in database, return the entry.
    PoolEntry derive_and_store();
};

} // namespace flow

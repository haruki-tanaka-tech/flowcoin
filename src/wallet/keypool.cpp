// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "wallet/keypool.h"
#include "crypto/bech32.h"
#include "hash/keccak.h"

#include <chrono>
#include <cstring>
#include <stdexcept>

namespace flow {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

KeyPool::KeyPool(HDChain& hd, WalletDB& db)
    : hd_(hd), db_(db) {}

// ---------------------------------------------------------------------------
// Fill the pool to the target size
// ---------------------------------------------------------------------------

void KeyPool::fill(size_t target_size) {
    std::lock_guard<std::mutex> lock(mutex_);

    while (pool_.size() < target_size) {
        PoolEntry entry = derive_and_store();
        pool_.push_back(entry);
    }
}

// ---------------------------------------------------------------------------
// Get the next key from the pool
// ---------------------------------------------------------------------------

KeyPair KeyPool::get_key() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (pool_.empty()) {
        // Pool exhausted; derive a fresh key on the spot
        PoolEntry entry = derive_and_store();
        used_keys_.insert(entry.kp.pubkey);
        return entry.kp;
    }

    PoolEntry entry = pool_.front();
    pool_.pop_front();
    used_keys_.insert(entry.kp.pubkey);
    return entry.kp;
}

// ---------------------------------------------------------------------------
// Return a key to the pool
// ---------------------------------------------------------------------------

void KeyPool::return_key(const std::array<uint8_t, 32>& pubkey) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Remove from used set
    used_keys_.erase(pubkey);

    // Find the key record in the database to reconstruct the pool entry
    WalletDB::KeyRecord kr;
    if (!db_.load_key(pubkey, kr)) {
        // Key not found in database; cannot return it
        return;
    }

    // Parse the HD index from the derivation path
    uint32_t hd_index = 0;
    if (kr.derivation_path != "imported") {
        size_t last_slash = kr.derivation_path.rfind('/');
        if (last_slash != std::string::npos) {
            std::string idx_str = kr.derivation_path.substr(last_slash + 1);
            if (!idx_str.empty() && idx_str.back() == '\'') {
                idx_str.pop_back();
            }
            hd_index = static_cast<uint32_t>(std::stoul(idx_str));
        }
    }

    // Re-derive the full keypair from the HD chain
    KeyPair kp = hd_.derive_key(hd_index);

    PoolEntry entry;
    entry.kp = kp;
    entry.hd_index = hd_index;

    // Add to the front of the pool (LIFO for returned keys)
    pool_.push_front(entry);
}

// ---------------------------------------------------------------------------
// Mark a key as permanently used
// ---------------------------------------------------------------------------

void KeyPool::mark_used(const std::array<uint8_t, 32>& pubkey) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Remove from pool if present
    for (auto it = pool_.begin(); it != pool_.end(); ++it) {
        if (it->kp.pubkey == pubkey) {
            pool_.erase(it);
            break;
        }
    }

    used_keys_.insert(pubkey);
}

// ---------------------------------------------------------------------------
// Pool size
// ---------------------------------------------------------------------------

size_t KeyPool::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pool_.size();
}

// ---------------------------------------------------------------------------
// Check if a key is in the pool
// ---------------------------------------------------------------------------

bool KeyPool::contains(const std::array<uint8_t, 32>& pubkey) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : pool_) {
        if (entry.kp.pubkey == pubkey) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Get used keys
// ---------------------------------------------------------------------------

std::set<std::array<uint8_t, 32>> KeyPool::get_used_keys() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return used_keys_;
}

// ---------------------------------------------------------------------------
// Oldest/newest index
// ---------------------------------------------------------------------------

uint32_t KeyPool::oldest_index() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pool_.empty()) return 0;
    return pool_.front().hd_index;
}

uint32_t KeyPool::newest_index() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pool_.empty()) return 0;
    return pool_.back().hd_index;
}

// ---------------------------------------------------------------------------
// Internal: derive a key and store in database
// ---------------------------------------------------------------------------

KeyPool::PoolEntry KeyPool::derive_and_store() {
    uint32_t idx = hd_.next_index();
    KeyPair kp = hd_.derive_key(idx);
    hd_.advance();

    // Persist HD index
    db_.store_hd_index(hd_.next_index());

    // Encrypt and store the key. Use keccak256(seed || index_be4) as mask.
    std::vector<uint8_t> mask_input;
    mask_input.insert(mask_input.end(), hd_.seed().begin(), hd_.seed().end());
    uint8_t idx_be[4];
    idx_be[0] = static_cast<uint8_t>((idx >> 24) & 0xFF);
    idx_be[1] = static_cast<uint8_t>((idx >> 16) & 0xFF);
    idx_be[2] = static_cast<uint8_t>((idx >> 8) & 0xFF);
    idx_be[3] = static_cast<uint8_t>(idx & 0xFF);
    mask_input.insert(mask_input.end(), idx_be, idx_be + 4);
    uint256 mask = keccak256(mask_input);

    std::vector<uint8_t> encrypted(32);
    for (size_t i = 0; i < 32; ++i) {
        encrypted[i] = kp.privkey[i] ^ mask[i];
    }

    std::string path = "m/44'/9555'/0'/0'/" + std::to_string(idx) + "'";

    WalletDB::KeyRecord kr;
    kr.derivation_path = path;
    kr.pubkey = kp.pubkey;
    kr.encrypted_privkey = encrypted;
    db_.store_key(kr);

    // Store the address record
    std::string address = pubkey_to_address(kp.pubkey.data());
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    WalletDB::AddressRecord ar;
    ar.address = address;
    ar.pubkey = kp.pubkey;
    ar.hd_index = idx;
    ar.created_at = now;
    db_.store_address(ar);

    PoolEntry entry;
    entry.kp = kp;
    entry.hd_index = idx;
    return entry;
}

} // namespace flow

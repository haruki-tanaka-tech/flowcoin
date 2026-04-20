// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "wallet/hdchain.h"

#include "crypto/keys.h"
#include "crypto/slip0010.h"
#include "hash/keccak.h"
#include "util/random.h"

#include <cstring>
#include <stdexcept>

namespace flow {

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

HDChain::HDChain()
    : next_index_(0), next_change_index_(0), initialized_(false),
      highest_derived_(0), highest_change_derived_(0), account_count_(1) {}

// ---------------------------------------------------------------------------
// Seed management
// ---------------------------------------------------------------------------

void HDChain::generate_seed() {
    seed_.resize(32);
    GetRandBytes(seed_.data(), 32);
    next_index_ = 0;
    next_change_index_ = 0;
    highest_derived_ = 0;
    highest_change_derived_ = 0;
    initialized_ = true;
    cache_.clear();
    intermediate_cache_.clear();
}

void HDChain::set_seed(const std::vector<uint8_t>& seed) {
    if (seed.size() < 16) {
        throw std::runtime_error("HDChain: seed must be at least 16 bytes");
    }
    seed_ = seed;
    initialized_ = true;
    cache_.clear();
    intermediate_cache_.clear();
}

void HDChain::init_from_key(const std::array<uint8_t, 32>& key,
                             const std::array<uint8_t, 32>& chain_code) {
    // Store the key and chain code as a 64-byte "seed" for serialization
    seed_.resize(64);
    std::memcpy(seed_.data(), key.data(), 32);
    std::memcpy(seed_.data() + 32, chain_code.data(), 32);
    initialized_ = true;
    cache_.clear();
    intermediate_cache_.clear();
}

uint256 HDChain::get_seed_hash() const {
    if (seed_.empty()) {
        uint256 zero;
        zero.set_null();
        return zero;
    }
    return keccak256d(seed_.data(), seed_.size());
}

// ---------------------------------------------------------------------------
// Key derivation (existing simple interface)
// ---------------------------------------------------------------------------

KeyPair HDChain::derive_key(uint32_t index) const {
    if (!initialized_ || seed_.empty()) {
        throw std::runtime_error("HDChain: no seed set");
    }

    // For seeds <= 32 bytes, use the original simple path
    if (seed_.size() <= 32) {
        ExtendedKey ext = slip0010_derive_path(
            seed_.data(), seed_.size(), index);

        KeyPair kp;
        kp.privkey = ext.key;
        kp.pubkey = derive_pubkey(ext.key.data());
        return kp;
    }

    // For 64-byte seeds (from init_from_key), extract key/chain_code
    // and derive directly
    ExtendedKey parent;
    std::memcpy(parent.key.data(), seed_.data(), 32);
    std::memcpy(parent.chain_code.data(), seed_.data() + 32, 32);

    ExtendedKey child = slip0010_derive_hardened(parent, index);
    KeyPair kp;
    kp.privkey = child.key;
    kp.pubkey = derive_pubkey(child.key.data());
    return kp;
}

// ---------------------------------------------------------------------------
// Full key derivation with path
// ---------------------------------------------------------------------------

HDChain::DerivedKey HDChain::derive_key_full(uint32_t account, uint32_t change,
                                              uint32_t index) const {
    if (!initialized_ || seed_.empty()) {
        throw std::runtime_error("HDChain: no seed set");
    }

    // Check the cache first
    CacheKey ck{account, change, index};
    auto cache_it = cache_.find(ck);
    if (cache_it != cache_.end()) {
        return cache_it->second;
    }

    // Derive the master key from seed
    ExtendedKey master;
    if (seed_.size() <= 32) {
        master = slip0010_master(seed_.data(), seed_.size());
    } else {
        // 64-byte seed: first 32 = key, second 32 = chain_code
        std::memcpy(master.key.data(), seed_.data(), 32);
        std::memcpy(master.chain_code.data(), seed_.data() + 32, 32);
    }

    // Check for cached intermediate key at the account level
    // Path: m/44'/9555'/account'
    std::string account_path = "m/44'/9555'/" + std::to_string(account) + "'";
    ExtendedKey account_key;

    auto inter_it = intermediate_cache_.find(account_path);
    if (inter_it != intermediate_cache_.end()) {
        account_key.key = inter_it->second.key;
        account_key.chain_code = inter_it->second.chain_code;
    } else {
        // Derive: m/44' -> m/44'/9555' -> m/44'/9555'/account'
        ExtendedKey k44 = slip0010_derive_hardened(master, 44);
        ExtendedKey k9555 = slip0010_derive_hardened(k44, 9555);
        account_key = slip0010_derive_hardened(k9555, account);

        // Cache the intermediate
        IntermediateKey ik;
        ik.key = account_key.key;
        ik.chain_code = account_key.chain_code;
        intermediate_cache_[account_path] = ik;
    }

    // Check for cached intermediate key at the change level
    // Path: m/44'/9555'/account'/change'
    std::string change_path = account_path + "/" + std::to_string(change) + "'";
    ExtendedKey change_key;

    inter_it = intermediate_cache_.find(change_path);
    if (inter_it != intermediate_cache_.end()) {
        change_key.key = inter_it->second.key;
        change_key.chain_code = inter_it->second.chain_code;
    } else {
        change_key = slip0010_derive_hardened(account_key, change);

        IntermediateKey ik;
        ik.key = change_key.key;
        ik.chain_code = change_key.chain_code;
        intermediate_cache_[change_path] = ik;
    }

    // Derive the final key at the index
    ExtendedKey final_key = slip0010_derive_hardened(change_key, index);

    DerivedKey result;
    result.privkey = final_key.key;
    result.pubkey = derive_pubkey(final_key.key.data());
    result.chain_code = final_key.chain_code;
    result.account = account;
    result.change = change;
    result.index = index;
    result.path = build_path_string(account, change, index);

    // Store in cache
    cache_[ck] = result;

    return result;
}

HDChain::DerivedKey HDChain::derive_next_key() {
    DerivedKey key = derive_key_full(0, 0, next_index_);

    if (next_index_ > highest_derived_) {
        highest_derived_ = next_index_;
    }

    next_index_++;
    return key;
}

HDChain::DerivedKey HDChain::derive_next_change_key() {
    DerivedKey key = derive_key_full(0, 1, next_change_index_);

    if (next_change_index_ > highest_change_derived_) {
        highest_change_derived_ = next_change_index_;
    }

    next_change_index_++;
    return key;
}

HDChain::DerivedKey HDChain::derive_path(const std::vector<uint32_t>& path) const {
    if (!initialized_ || seed_.empty()) {
        throw std::runtime_error("HDChain: no seed set");
    }

    // Start from master
    ExtendedKey current;
    if (seed_.size() <= 32) {
        current = slip0010_master(seed_.data(), seed_.size());
    } else {
        std::memcpy(current.key.data(), seed_.data(), 32);
        std::memcpy(current.chain_code.data(), seed_.data() + 32, 32);
    }

    // Derive each level
    std::string path_str = "m";
    for (uint32_t component : path) {
        current = slip0010_derive_hardened(current, component);
        path_str += "/" + std::to_string(component) + "'";
    }

    DerivedKey result;
    result.privkey = current.key;
    result.pubkey = derive_pubkey(current.key.data());
    result.chain_code = current.chain_code;
    result.account = (path.size() > 2) ? path[2] : 0;
    result.change = (path.size() > 3) ? path[3] : 0;
    result.index = (path.size() > 4) ? path[4] : 0;
    result.path = path_str;

    return result;
}

// ---------------------------------------------------------------------------
// Key cache
// ---------------------------------------------------------------------------

bool HDChain::has_cached_key(uint32_t index) const {
    CacheKey ck{0, 0, index};
    return cache_.find(ck) != cache_.end();
}

bool HDChain::has_cached_change_key(uint32_t index) const {
    CacheKey ck{0, 1, index};
    return cache_.find(ck) != cache_.end();
}

bool HDChain::get_cached_key(uint32_t index, DerivedKey& out) const {
    CacheKey ck{0, 0, index};
    auto it = cache_.find(ck);
    if (it == cache_.end()) return false;
    out = it->second;
    return true;
}

void HDChain::clear_cache() {
    cache_.clear();
    intermediate_cache_.clear();
}

size_t HDChain::cache_size() const {
    return cache_.size();
}

// ---------------------------------------------------------------------------
// Account management
// ---------------------------------------------------------------------------

uint32_t HDChain::create_account() {
    uint32_t new_account = account_count_;
    account_count_++;
    return new_account;
}

uint32_t HDChain::get_next_index(uint32_t account, uint32_t change) const {
    auto key = std::make_pair(account, change);
    auto it = account_indices_.find(key);
    if (it != account_indices_.end()) {
        return it->second;
    }

    // Default: for account 0, use the main indices
    if (account == 0 && change == 0) return next_index_;
    if (account == 0 && change == 1) return next_change_index_;
    return 0;
}

void HDChain::set_next_index(uint32_t account, uint32_t change, uint32_t index) {
    if (account == 0 && change == 0) {
        next_index_ = index;
    } else if (account == 0 && change == 1) {
        next_change_index_ = index;
    }
    account_indices_[std::make_pair(account, change)] = index;
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

std::vector<uint8_t> HDChain::serialize() const {
    // Format:
    //   [4] version (1)
    //   [4] seed_len
    //   [seed_len] seed
    //   [4] next_index
    //   [4] next_change_index
    //   [4] highest_derived
    //   [4] highest_change_derived
    //   [4] account_count
    //   [4] num_account_indices
    //   for each account index:
    //     [4] account
    //     [4] change
    //     [4] index

    std::vector<uint8_t> out;
    auto write_u32 = [&out](uint32_t v) {
        out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(v & 0xFF));
    };

    write_u32(1); // version
    write_u32(static_cast<uint32_t>(seed_.size()));
    out.insert(out.end(), seed_.begin(), seed_.end());
    write_u32(next_index_);
    write_u32(next_change_index_);
    write_u32(highest_derived_);
    write_u32(highest_change_derived_);
    write_u32(account_count_);

    // Account indices
    write_u32(static_cast<uint32_t>(account_indices_.size()));
    for (const auto& [key, index] : account_indices_) {
        write_u32(key.first);   // account
        write_u32(key.second);  // change
        write_u32(index);
    }

    return out;
}

HDChain HDChain::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 28) { // minimum: version(4) + seed_len(4) + indices(20)
        throw std::runtime_error("HDChain::deserialize: data too short");
    }

    const uint8_t* p = data.data();
    auto read_u32 = [&p]() -> uint32_t {
        uint32_t v = (static_cast<uint32_t>(p[0]) << 24) |
                     (static_cast<uint32_t>(p[1]) << 16) |
                     (static_cast<uint32_t>(p[2]) << 8) |
                     static_cast<uint32_t>(p[3]);
        p += 4;
        return v;
    };

    uint32_t version = read_u32();
    if (version != 1) {
        throw std::runtime_error("HDChain::deserialize: unsupported version " +
                                  std::to_string(version));
    }

    HDChain chain;

    uint32_t seed_len = read_u32();
    if (seed_len > 0 && p + seed_len <= data.data() + data.size()) {
        chain.seed_.assign(p, p + seed_len);
        p += seed_len;
        chain.initialized_ = true;
    }

    if (p + 20 <= data.data() + data.size()) {
        chain.next_index_ = read_u32();
        chain.next_change_index_ = read_u32();
        chain.highest_derived_ = read_u32();
        chain.highest_change_derived_ = read_u32();
        chain.account_count_ = read_u32();
    }

    // Read account indices if present
    if (p + 4 <= data.data() + data.size()) {
        uint32_t num_indices = read_u32();
        for (uint32_t i = 0; i < num_indices && p + 12 <= data.data() + data.size(); ++i) {
            uint32_t account = read_u32();
            uint32_t change = read_u32();
            uint32_t index = read_u32();
            chain.account_indices_[std::make_pair(account, change)] = index;
        }
    }

    return chain;
}

// ---------------------------------------------------------------------------
// Path string builder
// ---------------------------------------------------------------------------

std::string HDChain::build_path_string(uint32_t account, uint32_t change,
                                        uint32_t index) {
    return "m/44'/9555'/" + std::to_string(account) + "'/" +
           std::to_string(change) + "'/" + std::to_string(index) + "'";
}

} // namespace flow

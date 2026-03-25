// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Full addrman implementation with New/Tried bucket tables.
// Deterministic bucket assignment using a secret key prevents
// an attacker from predicting or influencing peer selection,
// which is the primary defense against eclipse attacks.

#include "net/addrman.h"
#include "hash/keccak.h"
#include "util/random.h"
#include "util/serialize.h"
#include "util/time.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include "logging.h"

namespace flow {

// ===========================================================================
// File format magic for peers.dat
// ===========================================================================

static constexpr uint32_t ADDRMAN_FILE_MAGIC    = 0x46414D41;  // "FAMA"
static constexpr uint32_t ADDRMAN_FILE_VERSION  = 1;

// ===========================================================================
// AddrInfo helper methods
// ===========================================================================

std::vector<uint8_t> AddrMan::AddrInfo::get_group() const {
    std::vector<uint8_t> group;

    if (addr.is_ipv4()) {
        // IPv4-mapped: group by /16 prefix
        group.push_back(1);  // NET_IPV4
        group.push_back(addr.ip[12]);
        group.push_back(addr.ip[13]);
    } else {
        // IPv6: group by /32 prefix
        group.push_back(2);  // NET_IPV6
        group.push_back(addr.ip[0]);
        group.push_back(addr.ip[1]);
        group.push_back(addr.ip[2]);
        group.push_back(addr.ip[3]);
    }
    return group;
}

int AddrMan::AddrInfo::get_new_bucket(const uint256& key, const CNetAddr& src) const {
    // Compute: hash(key, addr_group, source_group) % NEW_BUCKET_COUNT
    auto addr_group = get_group();

    // Source group
    std::vector<uint8_t> src_group;
    if (src.is_ipv4()) {
        src_group.push_back(1);
        src_group.push_back(src.ip[12]);
        src_group.push_back(src.ip[13]);
    } else {
        src_group.push_back(2);
        src_group.push_back(src.ip[0]);
        src_group.push_back(src.ip[1]);
        src_group.push_back(src.ip[2]);
        src_group.push_back(src.ip[3]);
    }

    // Hash: key + addr_group + source_group
    DataWriter w(64);
    w.write_bytes(key.data(), 32);
    w.write_u8(static_cast<uint8_t>(addr_group.size()));
    w.write_bytes(addr_group.data(), addr_group.size());
    w.write_u8(static_cast<uint8_t>(src_group.size()));
    w.write_bytes(src_group.data(), src_group.size());

    uint256 hash = keccak256(w.data().data(), w.data().size());
    uint64_t h = 0;
    std::memcpy(&h, hash.data(), 8);
    return static_cast<int>(h % NEW_BUCKET_COUNT);
}

int AddrMan::AddrInfo::get_tried_bucket(const uint256& key) const {
    // Compute: hash(key, addr_group) % TRIED_BUCKET_COUNT
    auto addr_group = get_group();

    DataWriter w(64);
    w.write_bytes(key.data(), 32);
    w.write_u8(static_cast<uint8_t>(addr_group.size()));
    w.write_bytes(addr_group.data(), addr_group.size());

    uint256 hash = keccak256(w.data().data(), w.data().size());
    uint64_t h = 0;
    std::memcpy(&h, hash.data(), 8);
    return static_cast<int>(h % TRIED_BUCKET_COUNT);
}

int AddrMan::AddrInfo::get_bucket_position(const uint256& key, bool is_new, int bucket) const {
    // Compute: hash(key, is_new, bucket, addr) % BUCKET_SIZE
    DataWriter w(64);
    w.write_bytes(key.data(), 32);
    w.write_u8(is_new ? 1 : 0);
    w.write_u32_le(static_cast<uint32_t>(bucket));
    addr.serialize(w);

    uint256 hash = keccak256(w.data().data(), w.data().size());
    uint64_t h = 0;
    std::memcpy(&h, hash.data(), 8);
    int bucket_size = is_new ? NEW_BUCKET_SIZE : TRIED_BUCKET_SIZE;
    return static_cast<int>(h % static_cast<uint64_t>(bucket_size));
}

bool AddrMan::AddrInfo::is_terrible(int64_t now) const {
    // Last seen more than 30 days ago
    if (last_seen > 0 && now - last_seen > 30 * 24 * 3600) return true;

    // Never successfully connected and too many attempts
    if (last_success == 0 && attempts >= 3) return true;

    // Not seen in 10 days and 3+ failed attempts
    if (now - last_seen > 10 * 24 * 3600 && attempts >= 3) return true;

    // Too many consecutive failures
    if (attempts >= 10) return true;

    return false;
}

double AddrMan::AddrInfo::get_chance(int64_t now) const {
    double chance = 1.0;

    // Reduce chance for entries not seen recently
    int64_t since_last_seen = std::max<int64_t>(now - last_seen, 0);
    if (since_last_seen > 0) {
        // Exponential decay: halve every 8 hours
        double hours = static_cast<double>(since_last_seen) / 3600.0;
        chance *= std::pow(0.5, hours / 8.0);
    }

    // Penalize entries with many failed attempts
    if (attempts > 0) {
        // Each failed attempt reduces chance by ~66%
        chance /= std::pow(1.5, static_cast<double>(attempts));
    }

    // Boost tried entries
    if (in_tried) {
        chance *= 2.0;
    }

    return std::max(chance, 0.001);
}

// ===========================================================================
// AddrMan construction
// ===========================================================================

AddrMan::AddrMan() {
    // Generate a random secret key for bucket assignment
    secret_key_ = GetRandUint256();

    // Initialize tables to -1 (empty)
    for (int i = 0; i < NEW_BUCKET_COUNT; i++) {
        for (int j = 0; j < NEW_BUCKET_SIZE; j++) {
            new_table_[i][j] = -1;
        }
    }
    for (int i = 0; i < TRIED_BUCKET_COUNT; i++) {
        for (int j = 0; j < TRIED_BUCKET_SIZE; j++) {
            tried_table_[i][j] = -1;
        }
    }
}

// ===========================================================================
// Lookup helpers
// ===========================================================================

int AddrMan::find_id(const CNetAddr& addr) const {
    std::string key = addr.to_string();
    auto it = map_addr_.find(key);
    if (it == map_addr_.end()) return -1;
    return it->second;
}

int AddrMan::find_index(const CNetAddr& addr) const {
    return find_id(addr);
}

// ===========================================================================
// Entry creation and deletion
// ===========================================================================

int AddrMan::create_entry(const CNetAddr& addr, const CNetAddr& source, int64_t time_seen) {
    int id = next_id_++;

    AddrInfo info;
    info.addr = addr;
    info.source = source;
    info.last_seen = time_seen;
    info.id = id;

    map_info_[id] = info;
    map_addr_[addr.to_string()] = id;

    return id;
}

void AddrMan::delete_entry(int id) {
    auto it = map_info_.find(id);
    if (it == map_info_.end()) return;

    AddrInfo& info = it->second;

    // Remove from New table
    if (!info.in_tried) {
        for (int b = 0; b < NEW_BUCKET_COUNT; b++) {
            for (int p = 0; p < NEW_BUCKET_SIZE; p++) {
                if (new_table_[b][p] == id) {
                    new_table_[b][p] = -1;
                    info.ref_count--;
                    new_count_--;
                }
            }
        }
    }

    // Remove from Tried table
    if (info.in_tried) {
        int bucket = info.get_tried_bucket(secret_key_);
        int pos = info.get_bucket_position(secret_key_, false, bucket);
        if (pos >= 0 && pos < TRIED_BUCKET_SIZE && tried_table_[bucket][pos] == id) {
            tried_table_[bucket][pos] = -1;
            tried_count_--;
        }
    }

    // Remove from lookup maps
    map_addr_.erase(info.addr.to_string());
    map_info_.erase(it);
}

// ===========================================================================
// add — insert an address into the New table
// ===========================================================================

void AddrMan::add(const CNetAddr& addr, int64_t time_seen) {
    CNetAddr source("0.0.0.0", 0);  // unknown source
    add(addr, time_seen, source);
}

void AddrMan::add(const CNetAddr& addr, int64_t time_seen, const CNetAddr& source) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (addr.port == 0) return;

    int existing_id = find_id(addr);
    if (existing_id >= 0) {
        // Already known — update last_seen if newer
        auto it = map_info_.find(existing_id);
        if (it != map_info_.end()) {
            if (time_seen > it->second.last_seen) {
                it->second.last_seen = time_seen;
            }
        }
        return;
    }

    // Limit total entries to prevent memory exhaustion
    if (map_info_.size() >= 20480) {
        return;
    }

    // Create the entry
    int id = create_entry(addr, source, time_seen);
    auto& info = map_info_[id];

    // Determine the New table bucket and position
    int bucket = info.get_new_bucket(secret_key_, source);
    int pos = info.get_bucket_position(secret_key_, true, bucket);

    if (pos < 0 || pos >= NEW_BUCKET_SIZE) {
        delete_entry(id);
        return;
    }

    // Check if the position is already occupied
    if (new_table_[bucket][pos] != -1) {
        int existing = new_table_[bucket][pos];
        auto eit = map_info_.find(existing);
        if (eit != map_info_.end()) {
            // Check if the existing entry is terrible
            int64_t now = GetTime();
            if (eit->second.is_terrible(now)) {
                // Evict the terrible entry
                eit->second.ref_count--;
                if (eit->second.ref_count <= 0) {
                    delete_entry(existing);
                }
            } else {
                // Don't evict a good entry — try a different position
                // Scan for an empty slot in the same bucket
                bool placed = false;
                for (int p = 0; p < NEW_BUCKET_SIZE; p++) {
                    if (new_table_[bucket][p] == -1) {
                        new_table_[bucket][p] = id;
                        info.ref_count++;
                        new_count_++;
                        placed = true;
                        break;
                    }
                }
                if (!placed) {
                    // Bucket is completely full — drop the new entry
                    delete_entry(id);
                }
                return;
            }
        }
    }

    // Place the entry
    new_table_[bucket][pos] = id;
    info.ref_count++;
    new_count_++;
}

void AddrMan::add(const std::vector<CNetAddr>& addrs, int64_t time_seen) {
    for (const auto& addr : addrs) {
        add(addr, time_seen);
    }
}

// ===========================================================================
// make_tried — move an entry from New to Tried table
// ===========================================================================

void AddrMan::make_tried(int id) {
    auto it = map_info_.find(id);
    if (it == map_info_.end()) return;

    AddrInfo& info = it->second;

    // Remove from all New table positions
    for (int b = 0; b < NEW_BUCKET_COUNT; b++) {
        for (int p = 0; p < NEW_BUCKET_SIZE; p++) {
            if (new_table_[b][p] == id) {
                new_table_[b][p] = -1;
                info.ref_count--;
                new_count_--;
            }
        }
    }

    info.ref_count = 0;

    // Determine Tried table bucket and position
    int bucket = info.get_tried_bucket(secret_key_);
    int pos = info.get_bucket_position(secret_key_, false, bucket);

    if (pos < 0 || pos >= TRIED_BUCKET_SIZE) return;

    // Handle collision in Tried table
    if (tried_table_[bucket][pos] != -1) {
        int evict_id = tried_table_[bucket][pos];
        auto evict_it = map_info_.find(evict_id);
        if (evict_it != map_info_.end()) {
            // Move the evicted entry back to New table
            AddrInfo& evicted = evict_it->second;
            evicted.in_tried = false;
            tried_table_[bucket][pos] = -1;
            tried_count_--;

            // Place evicted entry into New table
            int new_bucket = evicted.get_new_bucket(secret_key_, evicted.source);
            int new_pos = evicted.get_bucket_position(secret_key_, true, new_bucket);

            if (new_pos >= 0 && new_pos < NEW_BUCKET_SIZE) {
                // Clear the position if occupied by a terrible entry
                clear_new_position(new_bucket, new_pos);
                if (new_table_[new_bucket][new_pos] == -1) {
                    new_table_[new_bucket][new_pos] = evict_id;
                    evicted.ref_count++;
                    new_count_++;
                }
            }
        }
    }

    // Place the entry in the Tried table
    tried_table_[bucket][pos] = id;
    info.in_tried = true;
    tried_count_++;
}

void AddrMan::clear_new_position(int bucket, int position) {
    if (bucket < 0 || bucket >= NEW_BUCKET_COUNT) return;
    if (position < 0 || position >= NEW_BUCKET_SIZE) return;

    int id = new_table_[bucket][position];
    if (id == -1) return;

    auto it = map_info_.find(id);
    if (it == map_info_.end()) {
        new_table_[bucket][position] = -1;
        return;
    }

    int64_t now = GetTime();
    if (it->second.is_terrible(now)) {
        it->second.ref_count--;
        new_table_[bucket][position] = -1;
        new_count_--;
        if (it->second.ref_count <= 0) {
            delete_entry(id);
        }
    }
}

// ===========================================================================
// mark_good — successfully connected, move to Tried
// ===========================================================================

void AddrMan::mark_good(const CNetAddr& addr) {
    std::lock_guard<std::mutex> lock(mutex_);

    int id = find_id(addr);
    if (id < 0) return;

    auto it = map_info_.find(id);
    if (it == map_info_.end()) return;

    int64_t now = GetTime();
    it->second.last_success = now;
    it->second.last_seen = now;
    it->second.last_try = now;
    it->second.attempts = 0;

    // Move to Tried if not already there
    if (!it->second.in_tried) {
        make_tried(id);
    }
}

// ===========================================================================
// mark_failed — connection attempt failed
// ===========================================================================

void AddrMan::mark_failed(const CNetAddr& addr) {
    std::lock_guard<std::mutex> lock(mutex_);

    int id = find_id(addr);
    if (id < 0) return;

    auto it = map_info_.find(id);
    if (it == map_info_.end()) return;

    it->second.last_try = GetTime();
    it->second.attempts++;
}

// ===========================================================================
// get_addresses — return addresses for relay (~23% of known)
// ===========================================================================

std::vector<CNetAddr> AddrMan::get_addresses(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<CNetAddr> result;
    if (map_info_.empty()) return result;

    // Collect all entries, compute the 23% limit
    size_t max_return = static_cast<size_t>(
        static_cast<double>(map_info_.size()) * ADDR_RELAY_FRACTION);
    max_return = std::max(max_return, static_cast<size_t>(1));
    max_return = std::min(max_return, count);

    // Collect all valid entries sorted by last_seen (most recent first)
    struct SortEntry {
        int64_t last_seen;
        CNetAddr addr;
    };
    std::vector<SortEntry> entries;
    entries.reserve(map_info_.size());

    for (const auto& [id, info] : map_info_) {
        if (info.addr.port == 0) continue;
        entries.push_back({info.last_seen, info.addr});
    }

    std::sort(entries.begin(), entries.end(),
              [](const SortEntry& a, const SortEntry& b) {
                  return a.last_seen > b.last_seen;
              });

    size_t n = std::min(max_return, entries.size());
    result.reserve(n);
    for (size_t i = 0; i < n; i++) {
        result.push_back(entries[i].addr);
    }

    return result;
}

// ===========================================================================
// select — pick a random address for connection attempt
// ===========================================================================

CNetAddr AddrMan::select() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (map_info_.empty()) return CNetAddr();

    // 50% chance of selecting from New, 50% from Tried
    bool use_new = (GetRandUint64() % 2 == 0);

    // If the chosen table is empty, try the other
    if (use_new && new_count_ == 0) use_new = false;
    if (!use_new && tried_count_ == 0) use_new = true;

    return select_from_table(use_new);
}

CNetAddr AddrMan::select_from_new() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (new_count_ == 0) return CNetAddr();
    return select_from_table(true);
}

CNetAddr AddrMan::select_from_table(bool use_new) const {
    int64_t now = GetTime();

    // Weighted random selection with multiple attempts
    // Try up to 50 random positions and pick the best candidate
    double best_chance = -1.0;
    int best_id = -1;

    int bucket_count = use_new ? NEW_BUCKET_COUNT : TRIED_BUCKET_COUNT;
    int bucket_size = use_new ? NEW_BUCKET_SIZE : TRIED_BUCKET_SIZE;

    for (int attempt = 0; attempt < 50; attempt++) {
        int bucket = static_cast<int>(GetRandUint64() % static_cast<uint64_t>(bucket_count));
        int pos = static_cast<int>(GetRandUint64() % static_cast<uint64_t>(bucket_size));

        int id = use_new ? new_table_[bucket][pos] : tried_table_[bucket][pos];
        if (id == -1) continue;

        auto it = map_info_.find(id);
        if (it == map_info_.end()) continue;

        const AddrInfo& info = it->second;

        // Skip terrible entries
        if (info.is_terrible(now)) continue;

        // Skip entries tried too recently
        if (now - info.last_try < 60) continue;

        double chance = info.get_chance(now);
        if (chance > best_chance) {
            best_chance = chance;
            best_id = id;
        }
    }

    if (best_id == -1) {
        // Fallback: iterate all entries and pick the first valid one
        for (const auto& [id, info] : map_info_) {
            if (info.addr.port == 0) continue;
            if (now - info.last_try < 10) continue;
            if (info.attempts >= 10 && !info.in_tried) continue;
            return info.addr;
        }
        return CNetAddr();
    }

    return map_info_.at(best_id).addr;
}

// ===========================================================================
// size queries
// ===========================================================================

size_t AddrMan::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return map_info_.size();
}

size_t AddrMan::new_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<size_t>(std::max(new_count_, 0));
}

size_t AddrMan::tried_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<size_t>(std::max(tried_count_, 0));
}

bool AddrMan::contains(const CNetAddr& addr) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return find_id(addr) >= 0;
}

// ===========================================================================
// cleanup — remove stale entries
// ===========================================================================

void AddrMan::cleanup() {
    std::lock_guard<std::mutex> lock(mutex_);

    int64_t now = GetTime();
    std::vector<int> to_remove;

    for (const auto& [id, info] : map_info_) {
        // Remove entries not seen for STALE_THRESHOLD and never successfully connected
        if (info.last_success == 0 &&
            info.last_seen > 0 &&
            now - info.last_seen > STALE_THRESHOLD) {
            to_remove.push_back(id);
            continue;
        }

        // Remove entries with too many failures and no recent success
        if (info.attempts >= 10 &&
            info.last_success > 0 &&
            now - info.last_success > STALE_THRESHOLD) {
            to_remove.push_back(id);
            continue;
        }

        // Remove entries that are terrible and have no references
        if (info.is_terrible(now) && info.ref_count <= 0 && !info.in_tried) {
            to_remove.push_back(id);
            continue;
        }
    }

    for (int id : to_remove) {
        delete_entry(id);
    }

    if (!to_remove.empty()) {
        LogWarn("net", "cleaned up %zu stale entries, "
                "%zu remaining (new: %d, tried: %d)",
                to_remove.size(), map_info_.size(), new_count_, tried_count_);
    }
}

// ===========================================================================
// Serialization — peers.dat format
// ===========================================================================

std::vector<uint8_t> AddrMan::serialize() const {
    std::lock_guard<std::mutex> lock(mutex_);

    DataWriter w(4096);

    // File header
    w.write_u32_le(ADDRMAN_FILE_MAGIC);
    w.write_u32_le(ADDRMAN_FILE_VERSION);

    // Secret key
    w.write_bytes(secret_key_.data(), 32);

    // Number of entries
    w.write_u32_le(static_cast<uint32_t>(map_info_.size()));

    // Write all entries
    for (const auto& [id, info] : map_info_) {
        w.write_u32_le(static_cast<uint32_t>(id));
        info.addr.serialize(w);
        info.source.serialize(w);
        w.write_i64_le(info.last_seen);
        w.write_i64_le(info.last_try);
        w.write_i64_le(info.last_success);
        w.write_u32_le(static_cast<uint32_t>(info.attempts));
        w.write_u32_le(static_cast<uint32_t>(info.ref_count));
        w.write_u8(info.in_tried ? 1 : 0);
    }

    // Write New table bucket contents
    w.write_u32_le(static_cast<uint32_t>(NEW_BUCKET_COUNT));
    for (int b = 0; b < NEW_BUCKET_COUNT; b++) {
        // Count non-empty entries in this bucket
        int count = 0;
        for (int p = 0; p < NEW_BUCKET_SIZE; p++) {
            if (new_table_[b][p] != -1) count++;
        }
        w.write_u32_le(static_cast<uint32_t>(count));
        for (int p = 0; p < NEW_BUCKET_SIZE; p++) {
            if (new_table_[b][p] != -1) {
                w.write_u32_le(static_cast<uint32_t>(p));
                w.write_u32_le(static_cast<uint32_t>(new_table_[b][p]));
            }
        }
    }

    // Write Tried table bucket contents
    w.write_u32_le(static_cast<uint32_t>(TRIED_BUCKET_COUNT));
    for (int b = 0; b < TRIED_BUCKET_COUNT; b++) {
        int count = 0;
        for (int p = 0; p < TRIED_BUCKET_SIZE; p++) {
            if (tried_table_[b][p] != -1) count++;
        }
        w.write_u32_le(static_cast<uint32_t>(count));
        for (int p = 0; p < TRIED_BUCKET_SIZE; p++) {
            if (tried_table_[b][p] != -1) {
                w.write_u32_le(static_cast<uint32_t>(p));
                w.write_u32_le(static_cast<uint32_t>(tried_table_[b][p]));
            }
        }
    }

    return w.release();
}

bool AddrMan::deserialize(const uint8_t* data, size_t len) {
    std::lock_guard<std::mutex> lock(mutex_);

    DataReader r(data, len);

    // Verify magic and version
    uint32_t magic = r.read_u32_le();
    if (r.error() || magic != ADDRMAN_FILE_MAGIC) return false;

    uint32_t version = r.read_u32_le();
    if (r.error() || version != ADDRMAN_FILE_VERSION) return false;

    // Read secret key
    auto key_bytes = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(secret_key_.data(), key_bytes.data(), 32);

    // Clear existing state
    map_info_.clear();
    map_addr_.clear();
    new_count_ = 0;
    tried_count_ = 0;
    for (int i = 0; i < NEW_BUCKET_COUNT; i++)
        for (int j = 0; j < NEW_BUCKET_SIZE; j++)
            new_table_[i][j] = -1;
    for (int i = 0; i < TRIED_BUCKET_COUNT; i++)
        for (int j = 0; j < TRIED_BUCKET_SIZE; j++)
            tried_table_[i][j] = -1;

    // Read entries
    uint32_t entry_count = r.read_u32_le();
    if (r.error() || entry_count > 50000) return false;

    int max_id = 0;
    for (uint32_t e = 0; e < entry_count; e++) {
        int id = static_cast<int>(r.read_u32_le());
        if (r.error()) return false;

        AddrInfo info;
        info.id = id;
        info.addr = CNetAddr::deserialize(r);
        info.source = CNetAddr::deserialize(r);
        info.last_seen = r.read_i64_le();
        info.last_try = r.read_i64_le();
        info.last_success = r.read_i64_le();
        info.attempts = static_cast<int>(r.read_u32_le());
        info.ref_count = static_cast<int>(r.read_u32_le());
        info.in_tried = (r.read_u8() != 0);
        if (r.error()) return false;

        map_info_[id] = info;
        map_addr_[info.addr.to_string()] = id;
        if (id >= max_id) max_id = id + 1;
    }
    next_id_ = max_id;

    // Read New table
    uint32_t new_buckets = r.read_u32_le();
    if (r.error() || new_buckets != NEW_BUCKET_COUNT) return false;

    for (uint32_t b = 0; b < new_buckets; b++) {
        uint32_t count = r.read_u32_le();
        if (r.error()) return false;
        for (uint32_t i = 0; i < count; i++) {
            uint32_t pos = r.read_u32_le();
            uint32_t entry_id = r.read_u32_le();
            if (r.error()) return false;
            if (pos < NEW_BUCKET_SIZE && map_info_.count(static_cast<int>(entry_id))) {
                new_table_[b][pos] = static_cast<int>(entry_id);
                new_count_++;
            }
        }
    }

    // Read Tried table
    uint32_t tried_buckets = r.read_u32_le();
    if (r.error() || tried_buckets != TRIED_BUCKET_COUNT) return false;

    for (uint32_t b = 0; b < tried_buckets; b++) {
        uint32_t count = r.read_u32_le();
        if (r.error()) return false;
        for (uint32_t i = 0; i < count; i++) {
            uint32_t pos = r.read_u32_le();
            uint32_t entry_id = r.read_u32_le();
            if (r.error()) return false;
            if (pos < TRIED_BUCKET_SIZE && map_info_.count(static_cast<int>(entry_id))) {
                tried_table_[b][pos] = static_cast<int>(entry_id);
                tried_count_++;
            }
        }
    }

    LogInfo("net", "loaded %u entries (new: %d, tried: %d)",
            entry_count, new_count_, tried_count_);
    return true;
}

// ===========================================================================
// File I/O
// ===========================================================================

bool AddrMan::save_to_file(const std::string& path) const {
    auto data = serialize();

    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        LogError("net", "failed to open %s for writing", path.c_str());
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));
    if (!file.good()) {
        LogError("net", "write error to %s", path.c_str());
        return false;
    }

    LogInfo("net", "saved %zu entries to %s (%zu bytes)",
            map_info_.size(), path.c_str(), data.size());
    return true;
}

bool AddrMan::load_from_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return false;
    }

    auto file_size = file.tellg();
    if (file_size <= 0 || file_size > 10 * 1024 * 1024) {
        LogError("net", "file %s has invalid size", path.c_str());
        return false;
    }

    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(static_cast<size_t>(file_size));
    file.read(reinterpret_cast<char*>(data.data()),
              static_cast<std::streamsize>(file_size));

    if (!file.good()) {
        LogError("net", "read error from %s", path.c_str());
        return false;
    }

    return deserialize(data.data(), data.size());
}

} // namespace flow

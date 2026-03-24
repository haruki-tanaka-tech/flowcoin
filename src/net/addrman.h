// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Address manager for tracking known network peers.
// Full Bitcoin Core style CAddrMan with New and Tried tables using
// deterministic bucket assignment to prevent eclipse attacks.
//
// Architecture:
//   New table: 64 buckets * 64 entries = 4096 slots
//     - Addresses we've heard about but never connected to
//     - Bucket = hash(group, source_group) % 64
//   Tried table: 256 buckets * 64 entries = 16384 slots
//     - Addresses we've successfully connected to
//     - Bucket = hash(key, addr_group) % 256
//
// The secret key ensures that an attacker cannot predict which bucket
// an address will land in, preventing targeted eclipse attacks.

#ifndef FLOWCOIN_NET_ADDRMAN_H
#define FLOWCOIN_NET_ADDRMAN_H

#include "net/protocol.h"
#include "util/types.h"

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace flow {

class AddrMan {
public:
    AddrMan();

    // Bucket configuration
    static constexpr int NEW_BUCKET_COUNT       = 64;
    static constexpr int NEW_BUCKET_SIZE        = 64;
    static constexpr int TRIED_BUCKET_COUNT     = 256;
    static constexpr int TRIED_BUCKET_SIZE      = 64;
    static constexpr int NEW_TABLE_SIZE         = NEW_BUCKET_COUNT * NEW_BUCKET_SIZE;       // 4096
    static constexpr int TRIED_TABLE_SIZE       = TRIED_BUCKET_COUNT * TRIED_BUCKET_SIZE;   // 16384

    // Stale entry threshold: not seen for 30 days
    static constexpr int64_t STALE_THRESHOLD    = 30 * 24 * 3600;

    // Maximum number of retries before giving up on an address
    static constexpr int MAX_RETRIES            = 3;

    // Maximum age for address relay: 3 hours
    static constexpr int64_t MAX_ADDR_AGE       = 3 * 3600;

    // Fraction of addresses to return for addr relay (23% like Bitcoin)
    static constexpr double ADDR_RELAY_FRACTION = 0.23;

    // Add a known address with the time it was last seen
    void add(const CNetAddr& addr, int64_t time_seen);

    // Add with source address for bucket assignment
    void add(const CNetAddr& addr, int64_t time_seen, const CNetAddr& source);

    // Add multiple addresses at once
    void add(const std::vector<CNetAddr>& addrs, int64_t time_seen);

    // Get addresses to relay to peers (up to count, returning ~23% of known)
    std::vector<CNetAddr> get_addresses(size_t count) const;

    // Select a random address to attempt connection to.
    // Prefers addresses that have not been tried recently.
    // 50% chance of selecting from New table, 50% from Tried table.
    // Returns a default (zero) CNetAddr if no candidates available.
    CNetAddr select() const;

    // Select specifically from New (for feeler connections)
    CNetAddr select_from_new() const;

    // Mark an address as successfully connected (move from New to Tried)
    void mark_good(const CNetAddr& addr);

    // Mark an address as failed (connection attempt failed)
    void mark_failed(const CNetAddr& addr);

    // Number of known addresses total
    size_t size() const;

    // Number of addresses in the New table
    size_t new_size() const;

    // Number of addresses in the Tried table
    size_t tried_size() const;

    // Check if we already know about this address
    bool contains(const CNetAddr& addr) const;

    // Remove stale entries (not seen for > STALE_THRESHOLD)
    void cleanup();

    // Serialize to a byte vector (for peers.dat persistence)
    std::vector<uint8_t> serialize() const;

    // Deserialize from a byte vector (for peers.dat loading)
    bool deserialize(const uint8_t* data, size_t len);

    // Save to file (peers.dat)
    bool save_to_file(const std::string& path) const;

    // Load from file (peers.dat)
    bool load_from_file(const std::string& path);

    // Get the secret key (for testing)
    const uint256& secret_key() const { return secret_key_; }

private:
    // Extended address info for bucket management
    struct AddrInfo {
        CNetAddr addr;
        CNetAddr source;         // address that told us about this entry
        int64_t last_seen = 0;   // last time we heard about this addr
        int64_t last_try = 0;    // last time we tried to connect
        int64_t last_success = 0;// last time connection succeeded
        int attempts = 0;        // number of consecutive failed attempts
        int ref_count = 0;       // number of New buckets referencing this entry
        bool in_tried = false;   // is this entry in the Tried table
        int id = -1;             // unique identifier within the address manager

        // Get the address group for bucketing
        std::vector<uint8_t> get_group() const;

        // Calculate the deterministic bucket for the New table
        int get_new_bucket(const uint256& key, const CNetAddr& src) const;

        // Calculate the deterministic bucket for the Tried table
        int get_tried_bucket(const uint256& key) const;

        // Calculate position within a bucket
        int get_bucket_position(const uint256& key, bool is_new, int bucket) const;

        // Is this entry considered "terrible" (should be removed)?
        bool is_terrible(int64_t now) const;

        // Chance of selection (higher for more recent, tried entries)
        double get_chance(int64_t now) const;
    };

    mutable std::mutex mutex_;

    // Secret key for deterministic bucket assignment (generated on first use)
    uint256 secret_key_;

    // Master address table: id -> AddrInfo
    std::map<int, AddrInfo> map_info_;
    int next_id_ = 0;

    // Address -> id lookup
    std::map<std::string, int> map_addr_;  // addr.to_string() -> id

    // New table: bucket[i][j] = id of address info, or -1 if empty
    int new_table_[NEW_BUCKET_COUNT][NEW_BUCKET_SIZE];

    // Tried table: bucket[i][j] = id of address info, or -1 if empty
    int tried_table_[TRIED_BUCKET_COUNT][TRIED_BUCKET_SIZE];

    // Count of entries in each table
    int new_count_ = 0;
    int tried_count_ = 0;

    // Find an AddrInfo by address, return its id or -1
    int find_id(const CNetAddr& addr) const;

    // Create a new entry and return its id
    int create_entry(const CNetAddr& addr, const CNetAddr& source, int64_t time_seen);

    // Delete an entry by id
    void delete_entry(int id);

    // Move an entry from New to Tried table
    void make_tried(int id);

    // Clear a position in the New table, evicting if needed
    void clear_new_position(int bucket, int position);

    // Internal select from a specific table
    CNetAddr select_from_table(bool use_new) const;

    // Compatibility: find by address in the old-style flat list
    int find_index(const CNetAddr& addr) const;
};

} // namespace flow

#endif // FLOWCOIN_NET_ADDRMAN_H

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Address manager for tracking known network peers.
// Simplified version of Bitcoin Core's CAddrMan. Maintains a list of
// known peer addresses with metadata about connection attempts and
// success/failure history.

#ifndef FLOWCOIN_NET_ADDRMAN_H
#define FLOWCOIN_NET_ADDRMAN_H

#include "net/protocol.h"

#include <cstdint>
#include <mutex>
#include <vector>

namespace flow {

class AddrMan {
public:
    // Add a known address with the time it was last seen
    void add(const CNetAddr& addr, int64_t time_seen);

    // Add multiple addresses at once
    void add(const std::vector<CNetAddr>& addrs, int64_t time_seen);

    // Get addresses to relay to peers (up to count)
    std::vector<CNetAddr> get_addresses(size_t count) const;

    // Select a random address to attempt connection to.
    // Prefers addresses that have not been tried recently.
    // Returns a default (zero) CNetAddr if no candidates available.
    CNetAddr select() const;

    // Mark an address as successfully connected
    void mark_good(const CNetAddr& addr);

    // Mark an address as failed (connection attempt failed)
    void mark_failed(const CNetAddr& addr);

    // Number of known addresses
    size_t size() const;

    // Check if we already know about this address
    bool contains(const CNetAddr& addr) const;

private:
    struct AddrInfo {
        CNetAddr addr;
        int64_t last_seen = 0;      // last time we heard about this addr
        int64_t last_try = 0;        // last time we tried to connect
        int64_t last_success = 0;    // last time connection succeeded
        int attempts = 0;            // number of failed connection attempts
        bool tried = false;          // successfully connected at least once
    };

    mutable std::mutex mutex_;
    std::vector<AddrInfo> addrs_;

    // Find index of an address, or -1 if not found
    int find_index(const CNetAddr& addr) const;
};

} // namespace flow

#endif // FLOWCOIN_NET_ADDRMAN_H

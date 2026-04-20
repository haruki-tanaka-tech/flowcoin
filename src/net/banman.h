// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Ban manager: tracks banned peer addresses by IP.
// Peers are banned for a configurable duration (default 24 hours)
// after accumulating sufficient misbehavior score or sending invalid data.

#ifndef FLOWCOIN_NET_BANMAN_H
#define FLOWCOIN_NET_BANMAN_H

#include "net/protocol.h"

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace flow {

class BanMan {
public:
    BanMan() = default;

    // Default ban duration: 24 hours
    static constexpr int64_t DEFAULT_BAN_DURATION = 86400;

    // Ban a peer's address for duration seconds
    void ban(const CNetAddr& addr, int64_t duration_secs = DEFAULT_BAN_DURATION);

    // Check if banned
    bool is_banned(const CNetAddr& addr) const;

    // Unban
    void unban(const CNetAddr& addr);

    // Unban all
    void clear();

    // List banned addresses
    struct BanEntry {
        std::string addr_string;
        int64_t ban_until;  // unix timestamp
        int64_t ban_created; // when the ban was created
    };
    std::vector<BanEntry> list_banned() const;

    // Number of active bans
    size_t count() const;

    // Clear expired bans
    void sweep();

private:
    mutable std::mutex mutex_;

    struct BanRecord {
        int64_t ban_until;    // unix timestamp when ban expires
        int64_t ban_created;  // unix timestamp when ban was created
    };

    std::map<std::string, BanRecord> bans_;  // addr_string -> ban record
};

} // namespace flow

#endif // FLOWCOIN_NET_BANMAN_H

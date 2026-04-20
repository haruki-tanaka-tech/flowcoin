// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Ban manager implementation.

#include "net/banman.h"
#include "util/time.h"

#include <algorithm>

namespace flow {

// ════════════════════════════════════════════════════════════════════════════
// ban — add a ban for the given address
// ════════════════════════════════════════════════════════════════════════════

void BanMan::ban(const CNetAddr& addr, int64_t duration_secs) {
    std::lock_guard<std::mutex> lock(mutex_);

    int64_t now = GetTime();
    int64_t ban_until = now + duration_secs;
    std::string key = addr.to_string();

    // If already banned, extend the ban if the new ban is longer
    auto it = bans_.find(key);
    if (it != bans_.end()) {
        if (ban_until > it->second.ban_until) {
            it->second.ban_until = ban_until;
        }
        return;
    }

    BanRecord record;
    record.ban_until = ban_until;
    record.ban_created = now;
    bans_[key] = record;
}

// ════════════════════════════════════════════════════════════════════════════
// is_banned — check if an address is currently banned
// ════════════════════════════════════════════════════════════════════════════

bool BanMan::is_banned(const CNetAddr& addr) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string key = addr.to_string();
    auto it = bans_.find(key);
    if (it == bans_.end()) {
        return false;
    }

    int64_t now = GetTime();
    if (now >= it->second.ban_until) {
        // Ban has expired — will be cleaned up by sweep()
        return false;
    }

    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// unban — remove a ban for the given address
// ════════════════════════════════════════════════════════════════════════════

void BanMan::unban(const CNetAddr& addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    bans_.erase(addr.to_string());
}

// ════════════════════════════════════════════════════════════════════════════
// clear — remove all bans
// ════════════════════════════════════════════════════════════════════════════

void BanMan::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    bans_.clear();
}

// ════════════════════════════════════════════════════════════════════════════
// list_banned — return all active bans
// ════════════════════════════════════════════════════════════════════════════

std::vector<BanMan::BanEntry> BanMan::list_banned() const {
    std::lock_guard<std::mutex> lock(mutex_);

    int64_t now = GetTime();
    std::vector<BanEntry> result;
    result.reserve(bans_.size());

    for (const auto& [addr_str, record] : bans_) {
        if (now < record.ban_until) {
            BanEntry entry;
            entry.addr_string = addr_str;
            entry.ban_until = record.ban_until;
            entry.ban_created = record.ban_created;
            result.push_back(entry);
        }
    }

    return result;
}

// ════════════════════════════════════════════════════════════════════════════
// count — number of active bans
// ════════════════════════════════════════════════════════════════════════════

size_t BanMan::count() const {
    std::lock_guard<std::mutex> lock(mutex_);

    int64_t now = GetTime();
    size_t active = 0;

    for (const auto& [addr_str, record] : bans_) {
        if (now < record.ban_until) {
            active++;
        }
    }

    return active;
}

// ════════════════════════════════════════════════════════════════════════════
// sweep — remove expired bans
// ════════════════════════════════════════════════════════════════════════════

void BanMan::sweep() {
    std::lock_guard<std::mutex> lock(mutex_);

    int64_t now = GetTime();
    auto it = bans_.begin();
    while (it != bans_.end()) {
        if (now >= it->second.ban_until) {
            it = bans_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace flow

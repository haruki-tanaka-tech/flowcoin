// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "net/addrman.h"
#include "util/random.h"
#include "util/time.h"

#include <algorithm>
#include <cstring>

namespace flow {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

int AddrMan::find_index(const CNetAddr& addr) const {
    for (size_t i = 0; i < addrs_.size(); ++i) {
        if (addrs_[i].addr == addr) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void AddrMan::add(const CNetAddr& addr, int64_t time_seen) {
    std::lock_guard<std::mutex> lock(mutex_);

    int idx = find_index(addr);
    if (idx >= 0) {
        // Already known -- update last_seen if newer
        if (time_seen > addrs_[idx].last_seen) {
            addrs_[idx].last_seen = time_seen;
        }
        return;
    }

    // Cap at 10000 addresses to bound memory
    if (addrs_.size() >= 10000) {
        return;
    }

    AddrInfo info;
    info.addr = addr;
    info.last_seen = time_seen;
    addrs_.push_back(info);
}

void AddrMan::add(const std::vector<CNetAddr>& addrs, int64_t time_seen) {
    for (const auto& addr : addrs) {
        add(addr, time_seen);
    }
}

std::vector<CNetAddr> AddrMan::get_addresses(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<CNetAddr> result;
    if (addrs_.empty()) return result;

    // Collect indices sorted by last_seen (most recently seen first)
    std::vector<size_t> indices;
    indices.reserve(addrs_.size());
    for (size_t i = 0; i < addrs_.size(); ++i) {
        indices.push_back(i);
    }

    std::sort(indices.begin(), indices.end(), [this](size_t a, size_t b) {
        return addrs_[a].last_seen > addrs_[b].last_seen;
    });

    size_t n = std::min(count, indices.size());
    result.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        result.push_back(addrs_[indices[i]].addr);
    }
    return result;
}

CNetAddr AddrMan::select() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (addrs_.empty()) return CNetAddr();

    int64_t now = GetTime();

    // Build a candidate list: addresses not tried in the last 60 seconds,
    // with fewer than 10 failed attempts (unless previously successful)
    std::vector<size_t> candidates;
    for (size_t i = 0; i < addrs_.size(); ++i) {
        const auto& info = addrs_[i];
        if (now - info.last_try < 60) continue;
        if (info.attempts >= 10 && !info.tried) continue;
        candidates.push_back(i);
    }

    if (candidates.empty()) {
        // Fall back: pick any address not tried in the last 10 seconds
        for (size_t i = 0; i < addrs_.size(); ++i) {
            if (now - addrs_[i].last_try >= 10) {
                candidates.push_back(i);
            }
        }
    }

    if (candidates.empty()) return CNetAddr();

    // Simple weighted selection: tried addresses appear twice for higher priority
    std::vector<size_t> weighted;
    weighted.reserve(candidates.size() * 2);
    for (size_t idx : candidates) {
        weighted.push_back(idx);
        if (addrs_[idx].tried) {
            weighted.push_back(idx);
        }
    }

    uint64_t rand_val = GetRandUint64();
    size_t pick = static_cast<size_t>(rand_val % weighted.size());
    return addrs_[weighted[pick]].addr;
}

void AddrMan::mark_good(const CNetAddr& addr) {
    std::lock_guard<std::mutex> lock(mutex_);

    int idx = find_index(addr);
    if (idx < 0) return;

    int64_t now = GetTime();
    addrs_[idx].last_success = now;
    addrs_[idx].last_seen = now;
    addrs_[idx].tried = true;
    addrs_[idx].attempts = 0;
}

void AddrMan::mark_failed(const CNetAddr& addr) {
    std::lock_guard<std::mutex> lock(mutex_);

    int idx = find_index(addr);
    if (idx < 0) return;

    addrs_[idx].last_try = GetTime();
    addrs_[idx].attempts++;
}

size_t AddrMan::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return addrs_.size();
}

bool AddrMan::contains(const CNetAddr& addr) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return find_index(addr) >= 0;
}

} // namespace flow

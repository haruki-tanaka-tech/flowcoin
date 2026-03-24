// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Peer state tracking implementation.
// Handles bandwidth measurement, inventory deduplication, request tracking,
// per-message-type statistics, stall detection, and eviction scoring.

#include "net/peer.h"
#include "util/time.h"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace flow {

// ===========================================================================
// Construction
// ===========================================================================

Peer::Peer(uint64_t id, const CNetAddr& addr, bool inbound)
    : id_(id)
    , addr_(addr)
    , inbound_(inbound)
    , state_(PeerState::CONNECTING)
    , start_height_(0)
    , protocol_version_(0)
    , nonce_(0)
    , services_(0)
    , last_ping_time_(0)
    , ping_nonce_(0)
    , ping_latency_us_(0)
    , min_ping_us_(INT64_MAX)
    , misbehavior_(0)
    , connect_time_(GetTime())
    , last_recv_time_(0)
    , last_send_time_(0)
    , version_received_(false)
    , verack_received_(false)
    , version_sent_(false)
    , tcp_handle_(nullptr)
    , messages_recv_(0)
    , messages_sent_(0)
    , bytes_recv_(0)
    , bytes_sent_(0)
    , synced_headers_(0)
    , synced_blocks_(0)
    , fee_filter_(0)
    , supports_cmpct_(false)
    , cmpct_version_(0)
    , cmpct_high_bandwidth_(false)
    , prefers_headers_(false)
    , prefers_cmpct_(false)
    , bw_recv_start_bytes_(0)
    , bw_send_start_bytes_(0)
    , bw_start_time_(0)
    , bw_recv_rate_(0.0)
    , bw_send_rate_(0.0)
    , is_feeler_(false)
{
    recv_buf_.reserve(4096);
    bw_start_time_ = GetTime();
}

// ===========================================================================
// Per-message-type counters
// ===========================================================================

void Peer::record_message_recv(const std::string& command, uint64_t bytes) {
    auto& stats = recv_msg_stats_[command];
    stats.count++;
    stats.bytes += bytes;
}

void Peer::record_message_sent(const std::string& command, uint64_t bytes) {
    auto& stats = sent_msg_stats_[command];
    stats.count++;
    stats.bytes += bytes;
}

// ===========================================================================
// Inventory tracking
// ===========================================================================

bool Peer::has_announced(const uint256& hash) const {
    return announced_inv_.count(hash) > 0;
}

void Peer::mark_announced(const uint256& hash) {
    announced_inv_.insert(hash);
}

bool Peer::has_received_inv(const uint256& hash) const {
    return received_inv_.count(hash) > 0;
}

void Peer::mark_received_inv(const uint256& hash) {
    received_inv_.insert(hash);
}

void Peer::prune_inventory() {
    // Keep inventory sets bounded. If either set exceeds 50000 entries,
    // clear the oldest half. Since std::set doesn't track insertion order,
    // we simply clear when the limit is reached. This is acceptable because
    // the only cost is a few duplicate announcements.
    static constexpr size_t MAX_INV_SIZE = 50000;

    if (announced_inv_.size() > MAX_INV_SIZE) {
        // Remove roughly half the entries (arbitrary selection since set is sorted)
        auto it = announced_inv_.begin();
        size_t to_remove = announced_inv_.size() / 2;
        for (size_t i = 0; i < to_remove && it != announced_inv_.end(); i++) {
            it = announced_inv_.erase(it);
        }
    }

    if (received_inv_.size() > MAX_INV_SIZE) {
        auto it = received_inv_.begin();
        size_t to_remove = received_inv_.size() / 2;
        for (size_t i = 0; i < to_remove && it != received_inv_.end(); i++) {
            it = received_inv_.erase(it);
        }
    }
}

// ===========================================================================
// getdata request tracking
// ===========================================================================

void Peer::add_pending_request(const uint256& hash, InvType type, int64_t now) {
    PendingRequest req;
    req.hash = hash;
    req.type = type;
    req.request_time = now;
    pending_requests_[hash] = req;
}

void Peer::fulfill_request(const uint256& hash) {
    pending_requests_.erase(hash);
}

std::vector<Peer::PendingRequest> Peer::get_stalled_requests(int64_t now) const {
    std::vector<PendingRequest> stalled;

    for (const auto& [hash, req] : pending_requests_) {
        int64_t elapsed = now - req.request_time;

        // Blocks: stall after 2 seconds
        if (req.type == INV_BLOCK && elapsed > 2) {
            stalled.push_back(req);
        }
        // Transactions: stall after 20 seconds
        else if (req.type == INV_TX && elapsed > 20) {
            stalled.push_back(req);
        }
    }

    return stalled;
}

// ===========================================================================
// Bandwidth tracking
// ===========================================================================

void Peer::update_bandwidth(int64_t now) {
    int64_t elapsed = now - bw_start_time_;
    if (elapsed < 1) return;  // Need at least 1 second

    uint64_t recv_delta = bytes_recv_ - bw_recv_start_bytes_;
    uint64_t send_delta = bytes_sent_ - bw_send_start_bytes_;

    bw_recv_rate_ = static_cast<double>(recv_delta) / static_cast<double>(elapsed);
    bw_send_rate_ = static_cast<double>(send_delta) / static_cast<double>(elapsed);

    // Reset measurement window every 30 seconds
    if (elapsed >= 30) {
        bw_recv_start_bytes_ = bytes_recv_;
        bw_send_start_bytes_ = bytes_sent_;
        bw_start_time_ = now;
    }

    // Track minimum ping
    if (ping_latency_us_ > 0 && ping_latency_us_ < min_ping_us_) {
        min_ping_us_ = ping_latency_us_;
    }
}

double Peer::recv_bandwidth() const {
    return bw_recv_rate_;
}

double Peer::send_bandwidth() const {
    return bw_send_rate_;
}

// ===========================================================================
// Eviction scoring
// ===========================================================================

double Peer::eviction_score() const {
    // Higher score = more protected from eviction.
    // Factors that increase protection:
    //   - Low latency (fast peers are valuable)
    //   - Long connection time (stable peers)
    //   - Relevant services (full nodes)
    //   - Recent data transfer (actively useful)
    //   - Outbound connection (we chose them for a reason)
    double score = 0.0;

    // Low latency: up to 100 points
    if (min_ping_us_ > 0 && min_ping_us_ < INT64_MAX) {
        double ping_ms = static_cast<double>(min_ping_us_) / 1000.0;
        if (ping_ms < 50.0) {
            score += 100.0;
        } else if (ping_ms < 200.0) {
            score += 50.0;
        } else if (ping_ms < 500.0) {
            score += 20.0;
        }
    }

    // Long connection time: up to 50 points
    int64_t now = GetTime();
    int64_t conn_duration = now - connect_time_;
    if (conn_duration > 3600) {
        score += 50.0;
    } else if (conn_duration > 600) {
        score += 25.0;
    } else if (conn_duration > 120) {
        score += 10.0;
    }

    // Full node service: 30 points
    if (services_ & PEER_NODE_NETWORK) {
        score += 30.0;
    }

    // Recent data transfer: up to 40 points
    if (last_recv_time_ > 0) {
        int64_t since_recv = now - last_recv_time_;
        if (since_recv < 60) {
            score += 40.0;
        } else if (since_recv < 300) {
            score += 20.0;
        }
    }

    // Outbound bonus: 20 points (we chose this peer)
    if (!inbound_) {
        score += 20.0;
    }

    // Higher start height bonus: up to 30 points
    if (start_height_ > 0) {
        score += std::min(30.0, static_cast<double>(start_height_) / 10000.0 * 30.0);
    }

    // High bandwidth bonus: up to 20 points
    double total_bw = bw_recv_rate_ + bw_send_rate_;
    if (total_bw > 100000.0) {
        score += 20.0;
    } else if (total_bw > 10000.0) {
        score += 10.0;
    }

    return score;
}

// ===========================================================================
// Subnet identification
// ===========================================================================

uint16_t Peer::get_subnet_id() const {
    if (addr_.is_ipv4()) {
        // /16 subnet = first two octets of the IPv4 address
        return static_cast<uint16_t>((addr_.ip[12] << 8) | addr_.ip[13]);
    }
    // IPv6: use first 2 bytes of the address
    return static_cast<uint16_t>((addr_.ip[0] << 8) | addr_.ip[1]);
}

} // namespace flow

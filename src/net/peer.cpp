// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Peer state tracking implementation.
// Handles bandwidth measurement, inventory deduplication, request tracking,
// per-message-type statistics, stall detection, and eviction scoring.

#include "net/peer.h"
#include "util/time.h"
#include "json/json.hpp"

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

// ===========================================================================
// Peer scoring system
// ===========================================================================

Peer::PeerScore Peer::compute_score() const {
    PeerScore score;
    int64_t now = GetTime();

    // Performance metrics
    score.avg_latency_ms = (ping_latency_us_ > 0)
        ? static_cast<double>(ping_latency_us_) / 1000.0
        : -1.0;

    double total_bw = bw_recv_rate_ + bw_send_rate_;
    score.bandwidth_kbps = total_bw / 1024.0;

    // Count blocks and txs served from message stats
    score.blocks_served = 0;
    auto block_it = sent_msg_stats_.find("block");
    if (block_it != sent_msg_stats_.end()) {
        score.blocks_served = static_cast<int>(block_it->second.count);
    }

    score.txs_served = 0;
    auto tx_it = sent_msg_stats_.find("tx");
    if (tx_it != sent_msg_stats_.end()) {
        score.txs_served = static_cast<int>(tx_it->second.count);
    }

    score.headers_served = 0;
    auto hdr_it = sent_msg_stats_.find("headers");
    if (hdr_it != sent_msg_stats_.end()) {
        score.headers_served = static_cast<int>(hdr_it->second.count);
    }

    // Reliability
    score.successful_connections = 1;  // current connection counts
    score.failed_connections = 0;
    score.timeouts = 0;
    score.stalls = static_cast<int>(pending_requests_.size());

    int64_t connection_duration = now - connect_time_;
    if (connection_duration > 0) {
        int64_t active_time = (last_recv_time_ > 0)
            ? last_recv_time_ - connect_time_ : connection_duration;
        score.uptime_ratio = static_cast<double>(active_time) /
                             static_cast<double>(connection_duration);
    } else {
        score.uptime_ratio = 1.0;
    }

    // Behavior
    score.misbehavior_score = misbehavior_;
    score.invalid_blocks_sent = 0;
    score.invalid_txs_sent = 0;
    score.addr_spam_count = 0;

    // Count addr messages received (spam detection)
    auto addr_it = recv_msg_stats_.find("addr");
    if (addr_it != recv_msg_stats_.end()) {
        // More than 1000 addr messages is suspicious
        if (addr_it->second.count > 1000) {
            score.addr_spam_count = static_cast<int>(addr_it->second.count - 1000);
        }
    }

    return score;
}

double Peer::PeerScore::overall_score() const {
    double s = 0.0;

    // Latency bonus (max 100 points)
    if (avg_latency_ms > 0 && avg_latency_ms < 50.0) {
        s += 100.0;
    } else if (avg_latency_ms > 0 && avg_latency_ms < 200.0) {
        s += 50.0;
    } else if (avg_latency_ms > 0 && avg_latency_ms < 500.0) {
        s += 20.0;
    }

    // Bandwidth bonus (max 50 points)
    if (bandwidth_kbps > 100.0) {
        s += 50.0;
    } else if (bandwidth_kbps > 10.0) {
        s += 25.0;
    } else if (bandwidth_kbps > 1.0) {
        s += 10.0;
    }

    // Service bonus (max 60 points)
    s += std::min(20.0, static_cast<double>(blocks_served) * 2.0);
    s += std::min(20.0, static_cast<double>(txs_served) * 0.5);
    s += std::min(20.0, static_cast<double>(headers_served) * 1.0);

    // Uptime bonus (max 30 points)
    s += uptime_ratio * 30.0;

    // Penalties
    s -= misbehavior_score * 10.0;
    s -= invalid_blocks_sent * 50.0;
    s -= invalid_txs_sent * 5.0;
    s -= addr_spam_count * 1.0;
    s -= stalls * 5.0;

    return std::max(0.0, s);
}

bool Peer::PeerScore::is_good_peer() const {
    // A peer is "good" if it has a reasonable score and no serious misbehavior
    if (misbehavior_score >= 50) return false;
    if (invalid_blocks_sent > 0) return false;
    if (overall_score() < 30.0) return false;
    return true;
}

bool Peer::PeerScore::should_evict() const {
    // Evict if the overall score is very low
    if (overall_score() < 10.0) return true;
    if (misbehavior_score >= 80) return true;
    return false;
}

bool Peer::PeerScore::should_ban() const {
    // Ban for serious protocol violations
    if (misbehavior_score >= 100) return true;
    if (invalid_blocks_sent >= 3) return true;
    return false;
}

std::string Peer::PeerScore::format() const {
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "Score: %.1f (latency=%.1fms, bw=%.1f kB/s, "
        "blocks=%d, txs=%d, headers=%d, "
        "uptime=%.0f%%, misbehavior=%d, stalls=%d)",
        overall_score(),
        avg_latency_ms,
        bandwidth_kbps,
        blocks_served,
        txs_served,
        headers_served,
        uptime_ratio * 100.0,
        misbehavior_score,
        stalls);
    return std::string(buf);
}

// ===========================================================================
// Full peer statistics
// ===========================================================================

Peer::PeerStats Peer::get_full_stats() const {
    PeerStats stats;

    // Connection timing
    stats.connect_time = connect_time_;
    stats.last_send = last_send_time_;
    stats.last_recv = last_recv_time_;

    // Find last block/tx times from message stats
    stats.last_block = 0;
    auto blk_it = recv_msg_stats_.find("block");
    if (blk_it != recv_msg_stats_.end() && blk_it->second.count > 0) {
        // We don't track per-message timestamps, use last_recv as approximation
        stats.last_block = last_recv_time_;
    }
    stats.last_tx = 0;
    auto tx_it = recv_msg_stats_.find("tx");
    if (tx_it != recv_msg_stats_.end() && tx_it->second.count > 0) {
        stats.last_tx = last_recv_time_;
    }

    // Transfer stats
    stats.bytes_sent = static_cast<int64_t>(bytes_sent_);
    stats.bytes_received = static_cast<int64_t>(bytes_recv_);

    int64_t elapsed = GetTime() - connect_time_;
    if (elapsed > 0) {
        stats.avg_bandwidth = (stats.bytes_sent + stats.bytes_received) / elapsed;
    } else {
        stats.avg_bandwidth = 0;
    }

    // Per-message-type statistics
    for (const auto& [cmd, ms] : sent_msg_stats_) {
        stats.msgs_sent[cmd] = static_cast<int64_t>(ms.count);
    }
    for (const auto& [cmd, ms] : recv_msg_stats_) {
        stats.msgs_received[cmd] = static_cast<int64_t>(ms.count);
    }

    // Sync state
    stats.synced_headers = synced_headers_;
    stats.synced_blocks = synced_blocks_;
    stats.start_height = start_height_;

    // Quality metrics
    stats.ping_time_ms = static_cast<double>(ping_latency_us_) / 1000.0;
    stats.ping_wait_ms = 0;
    if (ping_nonce_ != 0 && last_ping_time_ > 0) {
        stats.ping_wait_ms = (GetTimeMicros() - last_ping_time_) / 1000;
    }
    stats.misbehavior = misbehavior_;

    return stats;
}

nlohmann::json Peer::PeerStats::to_json() const {
    nlohmann::json j;

    j["connect_time"] = connect_time;
    j["last_send"] = last_send;
    j["last_recv"] = last_recv;
    j["last_block"] = last_block;
    j["last_tx"] = last_tx;
    j["bytes_sent"] = bytes_sent;
    j["bytes_received"] = bytes_received;
    j["avg_bandwidth"] = avg_bandwidth;

    // Message counts
    nlohmann::json sent_j = nlohmann::json::object();
    for (const auto& [cmd, count] : msgs_sent) {
        sent_j[cmd] = count;
    }
    j["msgs_sent"] = sent_j;

    nlohmann::json recv_j = nlohmann::json::object();
    for (const auto& [cmd, count] : msgs_received) {
        recv_j[cmd] = count;
    }
    j["msgs_received"] = recv_j;

    j["synced_headers"] = synced_headers;
    j["synced_blocks"] = synced_blocks;
    j["start_height"] = start_height;
    j["ping_time_ms"] = ping_time_ms;
    j["ping_wait_ms"] = ping_wait_ms;
    j["misbehavior"] = misbehavior;

    return j;
}

// ===========================================================================
// Peer preferences
// ===========================================================================

Peer::PeerPreferences Peer::get_preferences() const {
    PeerPreferences prefs;

    prefs.wants_headers = prefers_headers_;
    prefs.wants_compact_blocks = supports_cmpct_;
    prefs.high_bandwidth_mode = cmpct_high_bandwidth_;
    prefs.fee_filter = fee_filter_;
    prefs.services = services_;
    prefs.protocol_version = static_cast<int>(protocol_version_);
    prefs.user_agent = user_agent_;
    prefs.start_height = static_cast<int>(start_height_);
    prefs.relay_txs = true;  // default; would need sendtx message to change

    return prefs;
}

// ===========================================================================
// Misbehavior management
// ===========================================================================

// add_misbehavior is defined inline in peer.h

int Peer::misbehavior() const {
    return misbehavior_;
}

bool Peer::should_disconnect() const {
    // Disconnect if misbehavior score exceeds threshold
    return misbehavior_ >= 100;
}

void Peer::reset_misbehavior() {
    misbehavior_ = 0;
}

// ===========================================================================
// Connection quality assessment
// ===========================================================================

Peer::ConnectionQuality Peer::assess_connection() const {
    ConnectionQuality quality;
    int64_t now = GetTime();
    int64_t uptime = now - connect_time_;

    // Connection stability
    if (uptime > 3600) {
        quality.stability = "excellent";
        quality.stability_score = 100;
    } else if (uptime > 600) {
        quality.stability = "good";
        quality.stability_score = 70;
    } else if (uptime > 120) {
        quality.stability = "fair";
        quality.stability_score = 40;
    } else {
        quality.stability = "new";
        quality.stability_score = 10;
    }

    // Latency assessment
    if (min_ping_us_ > 0 && min_ping_us_ < INT64_MAX) {
        double ping_ms = static_cast<double>(min_ping_us_) / 1000.0;
        if (ping_ms < 50) {
            quality.latency = "excellent";
            quality.latency_score = 100;
        } else if (ping_ms < 200) {
            quality.latency = "good";
            quality.latency_score = 70;
        } else if (ping_ms < 500) {
            quality.latency = "fair";
            quality.latency_score = 40;
        } else {
            quality.latency = "poor";
            quality.latency_score = 10;
        }
    } else {
        quality.latency = "unknown";
        quality.latency_score = 0;
    }

    // Throughput assessment
    double total_kbps = (bw_recv_rate_ + bw_send_rate_) / 1024.0;
    if (total_kbps > 100) {
        quality.throughput = "excellent";
        quality.throughput_score = 100;
    } else if (total_kbps > 10) {
        quality.throughput = "good";
        quality.throughput_score = 70;
    } else if (total_kbps > 1) {
        quality.throughput = "fair";
        quality.throughput_score = 40;
    } else {
        quality.throughput = "low";
        quality.throughput_score = 10;
    }

    // Overall
    quality.overall_score = (quality.stability_score +
                             quality.latency_score +
                             quality.throughput_score) / 3;

    return quality;
}

nlohmann::json Peer::ConnectionQuality::to_json() const {
    return {
        {"stability", stability},
        {"stability_score", stability_score},
        {"latency", latency},
        {"latency_score", latency_score},
        {"throughput", throughput},
        {"throughput_score", throughput_score},
        {"overall_score", overall_score}
    };
}

// ===========================================================================
// Service flag helpers
// ===========================================================================

// has_service(uint64_t) is defined inline in peer.h

bool Peer::is_full_node() const {
    return has_service(PEER_NODE_NETWORK);
}

std::string Peer::services_string() const {
    std::string result;

    if (services_ & PEER_NODE_NETWORK) {
        if (!result.empty()) result += ", ";
        result += "NETWORK";
    }
    if (services_ & 0x0002) {
        if (!result.empty()) result += ", ";
        result += "GETUTXO";
    }
    if (services_ & 0x0004) {
        if (!result.empty()) result += ", ";
        result += "BLOOM";
    }
    if (services_ & 0x0008) {
        if (!result.empty()) result += ", ";
        result += "WITNESS";
    }
    if (services_ & 0x0400) {
        if (!result.empty()) result += ", ";
        result += "NETWORK_LIMITED";
    }

    if (result.empty()) {
        result = "NONE";
    }

    return result;
}

// ===========================================================================
// Peer info serialization (for RPC getpeerinfo)
// ===========================================================================

nlohmann::json Peer::to_json() const {
    nlohmann::json j;

    j["id"] = id_;
    j["addr"] = addr_.to_string();
    j["inbound"] = inbound_;
    j["version"] = protocol_version_;
    j["subver"] = user_agent_;
    j["services"] = services_string();
    j["services_hex"] = services_;
    j["startingheight"] = start_height_;

    int64_t now = GetTime();
    j["conntime"] = connect_time_;
    j["timeoffset"] = 0;
    j["connection_duration_s"] = now - connect_time_;

    j["last_send"] = last_send_time_;
    j["last_recv"] = last_recv_time_;

    j["bytessent"] = bytes_sent_;
    j["bytesrecv"] = bytes_recv_;
    j["messages_sent"] = messages_sent_;
    j["messages_recv"] = messages_recv_;

    // Ping stats
    j["pingtime_ms"] = static_cast<double>(ping_latency_us_) / 1000.0;
    j["minping_ms"] = (min_ping_us_ < INT64_MAX)
        ? static_cast<double>(min_ping_us_) / 1000.0
        : -1.0;
    j["pingwait_ms"] = (ping_nonce_ != 0 && last_ping_time_ > 0)
        ? static_cast<double>(GetTimeMicros() - last_ping_time_) / 1000.0
        : 0.0;

    // Sync state
    j["synced_headers"] = synced_headers_;
    j["synced_blocks"] = synced_blocks_;

    // Bandwidth
    j["bw_recv_bytes_per_sec"] = bw_recv_rate_;
    j["bw_send_bytes_per_sec"] = bw_send_rate_;

    // Misbehavior
    j["banscore"] = misbehavior_;

    // Compact blocks
    j["compact_blocks"] = supports_cmpct_;
    j["compact_version"] = cmpct_version_;
    j["compact_high_bandwidth"] = cmpct_high_bandwidth_;

    // Preferences
    j["prefers_headers"] = prefers_headers_;
    j["fee_filter"] = fee_filter_;

    // State
    std::string state_str;
    switch (state_) {
        case PeerState::CONNECTING:     state_str = "connecting"; break;
        case PeerState::VERSION_SENT:   state_str = "version_sent"; break;
        case PeerState::HANDSHAKE_DONE: state_str = "connected"; break;
        default:                        state_str = "unknown"; break;
    }
    j["state"] = state_str;

    j["is_feeler"] = is_feeler_;

    // Connection quality
    auto quality = assess_connection();
    j["quality"] = quality.to_json();

    return j;
}

// ===========================================================================
// Peer address management
// ===========================================================================

void Peer::set_addr(const CNetAddr& addr) {
    addr_ = addr;
}

// addr() is defined inline in peer.h (returns const ref)

std::string Peer::addr_string() const {
    return addr_.to_string();
}

// ===========================================================================
// Synced state tracking
// ===========================================================================

// set_synced_headers, set_synced_blocks, synced_headers, synced_blocks
// are defined inline in peer.h

bool Peer::is_synced_to(uint64_t height) const {
    return synced_blocks_ >= height;
}

} // namespace flow

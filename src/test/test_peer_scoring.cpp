// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for peer scoring: good/bad peer scores, timeout penalties,
// misbehavior ban thresholds, PeerStats tracking, PeerPreferences,
// eviction scoring, and bandwidth measurement.

#include "consensus/params.h"
#include "net/peer.h"
#include "net/protocol.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <map>
#include <numeric>
#include <string>
#include <vector>

using namespace flow;

// ---------------------------------------------------------------------------
// PeerScore — scoring system for peer quality
// ---------------------------------------------------------------------------

class PeerScore {
public:
    explicit PeerScore(uint64_t peer_id) : peer_id_(peer_id) {}

    void record_valid_block() { valid_blocks_++; score_ += 10; }
    void record_invalid_block() { invalid_blocks_++; score_ -= 50; }
    void record_valid_tx() { valid_txs_++; score_ += 1; }
    void record_invalid_tx() { invalid_txs_++; score_ -= 10; }
    void record_timeout() { timeouts_++; score_ -= 5; }
    void record_pong(int64_t latency_ms) {
        pong_count_++;
        last_latency_ms_ = latency_ms;
        total_latency_ms_ += latency_ms;
        if (latency_ms < min_latency_ms_ || min_latency_ms_ == 0) {
            min_latency_ms_ = latency_ms;
        }
    }

    int score() const { return score_; }
    uint64_t peer_id() const { return peer_id_; }
    int valid_blocks() const { return valid_blocks_; }
    int invalid_blocks() const { return invalid_blocks_; }
    int valid_txs() const { return valid_txs_; }
    int invalid_txs() const { return invalid_txs_; }
    int timeouts() const { return timeouts_; }

    bool should_ban() const { return score_ <= -100; }
    bool is_good() const { return score_ >= 50; }
    bool is_bad() const { return score_ < 0; }

    double avg_latency_ms() const {
        return (pong_count_ > 0) ?
            static_cast<double>(total_latency_ms_) / pong_count_ : 0.0;
    }

    int64_t min_latency() const { return min_latency_ms_; }

private:
    uint64_t peer_id_;
    int score_ = 0;
    int valid_blocks_ = 0;
    int invalid_blocks_ = 0;
    int valid_txs_ = 0;
    int invalid_txs_ = 0;
    int timeouts_ = 0;
    int pong_count_ = 0;
    int64_t last_latency_ms_ = 0;
    int64_t total_latency_ms_ = 0;
    int64_t min_latency_ms_ = 0;
};

// ---------------------------------------------------------------------------
// PeerStats — message-level tracking
// ---------------------------------------------------------------------------

class PeerStats {
public:
    void record_message(const std::string& msg_type, size_t bytes) {
        message_counts_[msg_type]++;
        message_bytes_[msg_type] += bytes;
        total_messages_++;
        total_bytes_ += bytes;
    }

    uint64_t get_count(const std::string& msg_type) const {
        auto it = message_counts_.find(msg_type);
        return (it != message_counts_.end()) ? it->second : 0;
    }

    uint64_t get_bytes(const std::string& msg_type) const {
        auto it = message_bytes_.find(msg_type);
        return (it != message_bytes_.end()) ? it->second : 0;
    }

    uint64_t total_messages() const { return total_messages_; }
    uint64_t total_bytes() const { return total_bytes_; }

    std::vector<std::string> message_types() const {
        std::vector<std::string> types;
        for (const auto& [k, v] : message_counts_) {
            types.push_back(k);
        }
        return types;
    }

private:
    std::map<std::string, uint64_t> message_counts_;
    std::map<std::string, uint64_t> message_bytes_;
    uint64_t total_messages_ = 0;
    uint64_t total_bytes_ = 0;
};

// ---------------------------------------------------------------------------
// PeerPreferences — negotiated peer capabilities
// ---------------------------------------------------------------------------

struct PeerPreferences {
    bool supports_compact_blocks = false;
    bool wants_headers_announcements = false;
    Amount fee_filter = 0;
    uint64_t services = 0;
    std::string user_agent;

    static PeerPreferences from_handshake(uint64_t services,
                                           const std::string& ua,
                                           bool sendcmpct,
                                           bool sendheaders,
                                           Amount feefilter) {
        PeerPreferences prefs;
        prefs.services = services;
        prefs.user_agent = ua;
        prefs.supports_compact_blocks = sendcmpct;
        prefs.wants_headers_announcements = sendheaders;
        prefs.fee_filter = feefilter;
        return prefs;
    }

    bool is_full_node() const {
        return (services & PEER_NODE_NETWORK) != 0;
    }
};

// ---------------------------------------------------------------------------
// EvictionScore — for deciding which peers to evict
// ---------------------------------------------------------------------------

struct EvictionCandidate {
    uint64_t peer_id;
    int score;
    int64_t connect_time;
    int64_t min_ping;
    bool is_inbound;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
};

static std::vector<uint64_t> select_for_eviction(
    std::vector<EvictionCandidate>& candidates, size_t max_to_evict) {
    // Sort by score (ascending), evict lowest-scoring peers first
    std::sort(candidates.begin(), candidates.end(),
              [](const EvictionCandidate& a, const EvictionCandidate& b) {
                  return a.score < b.score;
              });

    std::vector<uint64_t> evicted;
    for (size_t i = 0; i < candidates.size() && evicted.size() < max_to_evict; ++i) {
        // Only evict inbound peers with negative scores
        if (candidates[i].is_inbound && candidates[i].score < 0) {
            evicted.push_back(candidates[i].peer_id);
        }
    }
    return evicted;
}

// ---------------------------------------------------------------------------
// BandwidthMeasure — track bandwidth usage
// ---------------------------------------------------------------------------

class BandwidthMeasure {
public:
    void record_sent(size_t bytes, int64_t timestamp) {
        sent_total_ += bytes;
        samples_.push_back({bytes, timestamp, true});
    }

    void record_recv(size_t bytes, int64_t timestamp) {
        recv_total_ += bytes;
        samples_.push_back({bytes, timestamp, false});
    }

    size_t total_sent() const { return sent_total_; }
    size_t total_recv() const { return recv_total_; }

    double avg_send_rate(int64_t window_start, int64_t window_end) const {
        size_t total = 0;
        for (const auto& s : samples_) {
            if (s.is_sent && s.timestamp >= window_start && s.timestamp <= window_end) {
                total += s.bytes;
            }
        }
        int64_t duration = window_end - window_start;
        return (duration > 0) ? static_cast<double>(total) / duration : 0.0;
    }

    double avg_recv_rate(int64_t window_start, int64_t window_end) const {
        size_t total = 0;
        for (const auto& s : samples_) {
            if (!s.is_sent && s.timestamp >= window_start && s.timestamp <= window_end) {
                total += s.bytes;
            }
        }
        int64_t duration = window_end - window_start;
        return (duration > 0) ? static_cast<double>(total) / duration : 0.0;
    }

private:
    struct Sample {
        size_t bytes;
        int64_t timestamp;
        bool is_sent;
    };

    size_t sent_total_ = 0;
    size_t recv_total_ = 0;
    std::vector<Sample> samples_;
};

void test_peer_scoring() {

    // -----------------------------------------------------------------------
    // Test 1: Good peer: high score
    // -----------------------------------------------------------------------
    {
        PeerScore ps(1);

        for (int i = 0; i < 10; ++i) ps.record_valid_block();
        for (int i = 0; i < 50; ++i) ps.record_valid_tx();

        assert(ps.score() == 10 * 10 + 50 * 1);  // 150
        assert(ps.is_good());
        assert(!ps.is_bad());
        assert(!ps.should_ban());
    }

    // -----------------------------------------------------------------------
    // Test 2: Bad peer (invalid blocks): low score
    // -----------------------------------------------------------------------
    {
        PeerScore ps(2);

        ps.record_invalid_block();
        ps.record_invalid_block();

        assert(ps.score() == -100);
        assert(ps.is_bad());
        assert(!ps.is_good());
        assert(ps.should_ban());
    }

    // -----------------------------------------------------------------------
    // Test 3: Timeout penalty affects score
    // -----------------------------------------------------------------------
    {
        PeerScore ps(3);
        ps.record_valid_block();  // +10
        assert(ps.score() == 10);

        ps.record_timeout();  // -5
        assert(ps.score() == 5);

        ps.record_timeout();  // -5
        assert(ps.score() == 0);

        ps.record_timeout();  // -5
        assert(ps.score() == -5);
        assert(ps.is_bad());
    }

    // -----------------------------------------------------------------------
    // Test 4: Misbehavior threshold triggers ban
    // -----------------------------------------------------------------------
    {
        PeerScore ps(4);

        // Accumulate bad behavior until ban
        while (!ps.should_ban()) {
            ps.record_invalid_tx();  // -10 each
        }

        assert(ps.score() <= -100);
        assert(ps.should_ban());
        assert(ps.invalid_txs() == 10);
    }

    // -----------------------------------------------------------------------
    // Test 5: PeerStats tracks all message types
    // -----------------------------------------------------------------------
    {
        PeerStats stats;

        stats.record_message("version", 100);
        stats.record_message("verack", 24);
        stats.record_message("block", 50000);
        stats.record_message("tx", 300);
        stats.record_message("tx", 250);
        stats.record_message("ping", 32);
        stats.record_message("pong", 32);

        assert(stats.total_messages() == 7);
        assert(stats.get_count("tx") == 2);
        assert(stats.get_count("block") == 1);
        assert(stats.get_count("ping") == 1);
        assert(stats.get_bytes("tx") == 550);
        assert(stats.get_bytes("block") == 50000);
        assert(stats.total_bytes() == 100 + 24 + 50000 + 300 + 250 + 32 + 32);

        auto types = stats.message_types();
        assert(types.size() == 5);  // version, verack, block, tx, ping, pong (unique)
    }

    // -----------------------------------------------------------------------
    // Test 6: PeerPreferences from handshake
    // -----------------------------------------------------------------------
    {
        auto prefs = PeerPreferences::from_handshake(
            PEER_NODE_NETWORK | PEER_NODE_BLOOM,
            "/FlowCoin:1.0.0/",
            true,   // sendcmpct
            true,   // sendheaders
            1000    // feefilter
        );

        assert(prefs.is_full_node());
        assert(prefs.supports_compact_blocks);
        assert(prefs.wants_headers_announcements);
        assert(prefs.fee_filter == 1000);
        assert(prefs.user_agent == "/FlowCoin:1.0.0/");
        assert((prefs.services & PEER_NODE_BLOOM) != 0);
    }

    // -----------------------------------------------------------------------
    // Test 7: Eviction scoring prefers keeping good peers
    // -----------------------------------------------------------------------
    {
        std::vector<EvictionCandidate> candidates = {
            {1, 100, 1000, 50, true, 5000, 5000},   // good
            {2, -50, 2000, 100, true, 1000, 1000},   // bad
            {3, 200, 500, 30, true, 10000, 10000},    // very good
            {4, -30, 3000, 200, true, 500, 500},       // bad
            {5, 50, 1500, 80, false, 3000, 3000},      // outbound
        };

        auto evicted = select_for_eviction(candidates, 2);

        // Should evict the bad inbound peers (id 2 and 4)
        assert(evicted.size() == 2);
        bool has_2 = std::find(evicted.begin(), evicted.end(), 2) != evicted.end();
        bool has_4 = std::find(evicted.begin(), evicted.end(), 4) != evicted.end();
        assert(has_2 && has_4);

        // Good peers and outbound should not be evicted
        bool has_1 = std::find(evicted.begin(), evicted.end(), 1) != evicted.end();
        bool has_3 = std::find(evicted.begin(), evicted.end(), 3) != evicted.end();
        bool has_5 = std::find(evicted.begin(), evicted.end(), 5) != evicted.end();
        assert(!has_1 && !has_3 && !has_5);
    }

    // -----------------------------------------------------------------------
    // Test 8: Bandwidth measurement accuracy
    // -----------------------------------------------------------------------
    {
        BandwidthMeasure bw;

        bw.record_sent(1000, 100);
        bw.record_sent(2000, 200);
        bw.record_recv(500, 100);
        bw.record_recv(1500, 200);

        assert(bw.total_sent() == 3000);
        assert(bw.total_recv() == 2000);

        double send_rate = bw.avg_send_rate(100, 200);
        assert(send_rate > 0.0);
        assert(std::abs(send_rate - 3000.0 / 100.0) < 0.01);

        double recv_rate = bw.avg_recv_rate(100, 200);
        assert(recv_rate > 0.0);
        assert(std::abs(recv_rate - 2000.0 / 100.0) < 0.01);
    }

    // -----------------------------------------------------------------------
    // Test 9: Peer score tracking counts
    // -----------------------------------------------------------------------
    {
        PeerScore ps(5);

        ps.record_valid_block();
        ps.record_valid_block();
        ps.record_invalid_block();
        ps.record_valid_tx();
        ps.record_valid_tx();
        ps.record_valid_tx();
        ps.record_invalid_tx();
        ps.record_timeout();
        ps.record_timeout();

        assert(ps.valid_blocks() == 2);
        assert(ps.invalid_blocks() == 1);
        assert(ps.valid_txs() == 3);
        assert(ps.invalid_txs() == 1);
        assert(ps.timeouts() == 2);
    }

    // -----------------------------------------------------------------------
    // Test 10: Ping latency tracking
    // -----------------------------------------------------------------------
    {
        PeerScore ps(6);

        ps.record_pong(100);
        ps.record_pong(200);
        ps.record_pong(50);
        ps.record_pong(150);

        assert(ps.min_latency() == 50);
        assert(std::abs(ps.avg_latency_ms() - 125.0) < 0.1);
    }

    // -----------------------------------------------------------------------
    // Test 11: PeerPreferences: non-full node
    // -----------------------------------------------------------------------
    {
        auto prefs = PeerPreferences::from_handshake(
            PEER_NODE_NETWORK_LIMITED,
            "/FlowCoin:1.0.0/",
            false, false, 0
        );

        assert(!prefs.is_full_node());
        assert(!prefs.supports_compact_blocks);
    }

    // -----------------------------------------------------------------------
    // Test 12: Eviction with no bad peers -> no evictions
    // -----------------------------------------------------------------------
    {
        std::vector<EvictionCandidate> candidates = {
            {1, 100, 1000, 50, true, 5000, 5000},
            {2, 50, 2000, 100, true, 3000, 3000},
        };

        auto evicted = select_for_eviction(candidates, 1);
        assert(evicted.empty());
    }

    // -----------------------------------------------------------------------
    // Test 13: Bandwidth with empty window
    // -----------------------------------------------------------------------
    {
        BandwidthMeasure bw;
        double rate = bw.avg_send_rate(0, 0);
        assert(rate == 0.0);
    }

    // -----------------------------------------------------------------------
    // Test 14: PeerStats for unrecorded message type
    // -----------------------------------------------------------------------
    {
        PeerStats stats;
        assert(stats.get_count("nonexistent") == 0);
        assert(stats.get_bytes("nonexistent") == 0);
    }

    // -----------------------------------------------------------------------
    // Test 15: Fresh peer starts with score 0
    // -----------------------------------------------------------------------
    {
        PeerScore ps(7);
        assert(ps.score() == 0);
        assert(!ps.is_good());
        assert(!ps.is_bad());
        assert(!ps.should_ban());
    }
}

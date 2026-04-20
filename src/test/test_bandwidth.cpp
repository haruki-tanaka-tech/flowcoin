// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for bandwidth tracking and limiting: bytes sent/received per peer,
// per-message-type counters, send/recv rate calculation, upload rate limiting,
// BandwidthStats totals, and rolling bandwidth measurement.

#include "net/peer.h"
#include "net/protocol.h"
#include "consensus/params.h"
#include "util/random.h"
#include "util/types.h"

#include <cassert>
#include <cmath>
#include <cstring>
#include <map>
#include <string>
#include <vector>

using namespace flow;

// ---- BandwidthStats helper -------------------------------------------------

struct BandwidthStats {
    uint64_t total_bytes_recv = 0;
    uint64_t total_bytes_sent = 0;
    uint64_t total_messages_recv = 0;
    uint64_t total_messages_sent = 0;
    double avg_recv_rate = 0.0;     // bytes/sec
    double avg_send_rate = 0.0;     // bytes/sec
    int64_t measurement_start = 0;
    int64_t measurement_end = 0;

    void accumulate(const Peer& peer) {
        total_bytes_recv += peer.bytes_recv();
        total_bytes_sent += peer.bytes_sent();
        total_messages_recv += peer.messages_recv();
        total_messages_sent += peer.messages_sent();
    }

    void compute_rates() {
        double duration = static_cast<double>(measurement_end - measurement_start);
        if (duration > 0) {
            avg_recv_rate = static_cast<double>(total_bytes_recv) / duration;
            avg_send_rate = static_cast<double>(total_bytes_sent) / duration;
        }
    }
};

// Simple upload rate limiter
class RateLimiter {
public:
    RateLimiter(uint64_t max_bytes_per_sec, int64_t now)
        : max_rate_(max_bytes_per_sec), window_start_(now), bytes_in_window_(0) {}

    bool can_send(uint64_t bytes, int64_t now) {
        // Reset window every second
        if (now - window_start_ >= 1) {
            window_start_ = now;
            bytes_in_window_ = 0;
        }
        return (bytes_in_window_ + bytes) <= max_rate_;
    }

    void record_sent(uint64_t bytes, int64_t now) {
        if (now - window_start_ >= 1) {
            window_start_ = now;
            bytes_in_window_ = 0;
        }
        bytes_in_window_ += bytes;
    }

    uint64_t max_rate() const { return max_rate_; }
    uint64_t bytes_in_window() const { return bytes_in_window_; }

private:
    uint64_t max_rate_;
    int64_t window_start_;
    uint64_t bytes_in_window_;
};

void test_bandwidth() {

    // -----------------------------------------------------------------------
    // Test 1: Bytes sent/received tracked per peer
    // -----------------------------------------------------------------------
    {
        CNetAddr addr("192.168.1.1", 9333);
        Peer peer(1, addr, false);

        assert(peer.bytes_recv() == 0);
        assert(peer.bytes_sent() == 0);

        peer.add_bytes_recv(1000);
        assert(peer.bytes_recv() == 1000);

        peer.add_bytes_sent(500);
        assert(peer.bytes_sent() == 500);

        peer.add_bytes_recv(2000);
        assert(peer.bytes_recv() == 3000);

        peer.add_bytes_sent(1500);
        assert(peer.bytes_sent() == 2000);
    }

    // -----------------------------------------------------------------------
    // Test 2: Per-message-type counters correct
    // -----------------------------------------------------------------------
    {
        CNetAddr addr("192.168.1.2", 9333);
        Peer peer(2, addr, true);

        peer.record_message_recv("version", 120);
        peer.record_message_recv("verack", 24);
        peer.record_message_recv("inv", 500);
        peer.record_message_recv("inv", 300);

        auto& stats = peer.recv_msg_stats();

        // version: 1 message, 120 bytes
        assert(stats.at("version").count == 1);
        assert(stats.at("version").bytes == 120);

        // verack: 1 message, 24 bytes
        assert(stats.at("verack").count == 1);
        assert(stats.at("verack").bytes == 24);

        // inv: 2 messages, 800 bytes total
        assert(stats.at("inv").count == 2);
        assert(stats.at("inv").bytes == 800);
    }

    // -----------------------------------------------------------------------
    // Test 3: Sent message type tracking
    // -----------------------------------------------------------------------
    {
        CNetAddr addr("192.168.1.3", 9333);
        Peer peer(3, addr, false);

        peer.record_message_sent("block", 50000);
        peer.record_message_sent("block", 45000);
        peer.record_message_sent("tx", 350);
        peer.record_message_sent("ping", 32);

        auto& sent = peer.sent_msg_stats();
        assert(sent.at("block").count == 2);
        assert(sent.at("block").bytes == 95000);
        assert(sent.at("tx").count == 1);
        assert(sent.at("tx").bytes == 350);
        assert(sent.at("ping").count == 1);
        assert(sent.at("ping").bytes == 32);
    }

    // -----------------------------------------------------------------------
    // Test 4: Send rate calculation
    // -----------------------------------------------------------------------
    {
        BandwidthStats stats;
        stats.total_bytes_sent = 10000;
        stats.measurement_start = 1000;
        stats.measurement_end = 1010;  // 10 seconds

        stats.compute_rates();
        assert(std::abs(stats.avg_send_rate - 1000.0) < 0.01);
    }

    // -----------------------------------------------------------------------
    // Test 5: Recv rate calculation
    // -----------------------------------------------------------------------
    {
        BandwidthStats stats;
        stats.total_bytes_recv = 50000;
        stats.measurement_start = 0;
        stats.measurement_end = 100;  // 100 seconds

        stats.compute_rates();
        assert(std::abs(stats.avg_recv_rate - 500.0) < 0.01);
    }

    // -----------------------------------------------------------------------
    // Test 6: Zero duration gives zero rate
    // -----------------------------------------------------------------------
    {
        BandwidthStats stats;
        stats.total_bytes_recv = 50000;
        stats.total_bytes_sent = 30000;
        stats.measurement_start = 100;
        stats.measurement_end = 100;  // zero duration

        stats.compute_rates();
        assert(stats.avg_recv_rate == 0.0);
        assert(stats.avg_send_rate == 0.0);
    }

    // -----------------------------------------------------------------------
    // Test 7: Upload rate limiting — can_send blocks when over limit
    // -----------------------------------------------------------------------
    {
        int64_t now = 1000;
        RateLimiter limiter(10000, now);  // 10 KB/s

        // Should be able to send up to 10000 bytes in this window
        assert(limiter.can_send(5000, now));
        limiter.record_sent(5000, now);
        assert(limiter.bytes_in_window() == 5000);

        assert(limiter.can_send(5000, now));
        limiter.record_sent(5000, now);
        assert(limiter.bytes_in_window() == 10000);

        // At limit, can't send 1 more byte
        assert(!limiter.can_send(1, now));

        // After 1 second, window resets
        now += 1;
        assert(limiter.can_send(10000, now));
    }

    // -----------------------------------------------------------------------
    // Test 8: Rate limiter window reset
    // -----------------------------------------------------------------------
    {
        int64_t now = 2000;
        RateLimiter limiter(5000, now);

        limiter.record_sent(5000, now);
        assert(!limiter.can_send(1, now));

        // Move forward 1 second
        now += 1;
        assert(limiter.can_send(5000, now));
        limiter.record_sent(3000, now);
        assert(limiter.can_send(2000, now));
        assert(!limiter.can_send(2001, now));
    }

    // -----------------------------------------------------------------------
    // Test 9: BandwidthStats accumulates from multiple peers
    // -----------------------------------------------------------------------
    {
        CNetAddr addr1("10.0.0.1", 9333);
        Peer peer1(10, addr1, false);
        peer1.add_bytes_recv(1000);
        peer1.add_bytes_sent(500);
        peer1.inc_messages_recv();
        peer1.inc_messages_sent();

        CNetAddr addr2("10.0.0.2", 9333);
        Peer peer2(11, addr2, true);
        peer2.add_bytes_recv(2000);
        peer2.add_bytes_sent(1500);
        peer2.inc_messages_recv();
        peer2.inc_messages_recv();
        peer2.inc_messages_sent();

        BandwidthStats stats;
        stats.accumulate(peer1);
        stats.accumulate(peer2);

        assert(stats.total_bytes_recv == 3000);
        assert(stats.total_bytes_sent == 2000);
        assert(stats.total_messages_recv == 3);
        assert(stats.total_messages_sent == 2);
    }

    // -----------------------------------------------------------------------
    // Test 10: Rolling bandwidth measurement over time window
    // -----------------------------------------------------------------------
    {
        // Simulate bandwidth samples over a 10-second window
        struct Sample {
            int64_t time;
            uint64_t bytes;
        };

        std::vector<Sample> samples = {
            {0, 1000}, {1, 1500}, {2, 2000}, {3, 1000},
            {4, 500},  {5, 3000}, {6, 2500}, {7, 1500},
            {8, 1000}, {9, 2000},
        };

        uint64_t total = 0;
        for (auto& s : samples) total += s.bytes;

        // Total bytes over 10 seconds
        assert(total == 16000);

        // Average rate = 16000 / 10 = 1600 bytes/sec
        double rate = static_cast<double>(total) / 10.0;
        assert(std::abs(rate - 1600.0) < 0.01);
    }

    // -----------------------------------------------------------------------
    // Test 11: Message count tracking
    // -----------------------------------------------------------------------
    {
        CNetAddr addr("10.0.0.3", 9333);
        Peer peer(12, addr, false);

        assert(peer.messages_recv() == 0);
        assert(peer.messages_sent() == 0);

        for (int i = 0; i < 10; i++) peer.inc_messages_recv();
        for (int i = 0; i < 5; i++) peer.inc_messages_sent();

        assert(peer.messages_recv() == 10);
        assert(peer.messages_sent() == 5);
    }

    // -----------------------------------------------------------------------
    // Test 12: Large data transfer tracked correctly
    // -----------------------------------------------------------------------
    {
        CNetAddr addr("10.0.0.4", 9333);
        Peer peer(13, addr, false);

        // Simulate receiving a large block
        uint64_t block_size = 5'000'000;  // 5 MB
        peer.add_bytes_recv(block_size);
        peer.record_message_recv("block", block_size);

        assert(peer.bytes_recv() == block_size);
        assert(peer.recv_msg_stats().at("block").bytes == block_size);
    }

    // -----------------------------------------------------------------------
    // Test 13: Rate limiter with very high rate
    // -----------------------------------------------------------------------
    {
        int64_t now = 3000;
        uint64_t max_rate = 100'000'000;  // 100 MB/s
        RateLimiter limiter(max_rate, now);

        assert(limiter.can_send(50'000'000, now));
        limiter.record_sent(50'000'000, now);
        assert(limiter.can_send(50'000'000, now));
        limiter.record_sent(50'000'000, now);
        assert(!limiter.can_send(1, now));
        assert(limiter.max_rate() == max_rate);
    }

    // -----------------------------------------------------------------------
    // Test 14: BandwidthStats rates with realistic data
    // -----------------------------------------------------------------------
    {
        BandwidthStats stats;
        stats.total_bytes_recv = 100'000'000;   // 100 MB
        stats.total_bytes_sent = 50'000'000;    // 50 MB
        stats.measurement_start = 0;
        stats.measurement_end = 3600;           // 1 hour

        stats.compute_rates();

        // recv rate: ~27.78 KB/s
        assert(stats.avg_recv_rate > 27000 && stats.avg_recv_rate < 28000);
        // send rate: ~13.89 KB/s
        assert(stats.avg_send_rate > 13000 && stats.avg_send_rate < 14000);
    }

    // -----------------------------------------------------------------------
    // Test 15: Per-peer bandwidth isolation
    // -----------------------------------------------------------------------
    {
        CNetAddr addr1("10.0.0.5", 9333);
        Peer p1(14, addr1, false);
        CNetAddr addr2("10.0.0.6", 9333);
        Peer p2(15, addr2, true);

        p1.add_bytes_recv(5000);
        p2.add_bytes_recv(10000);

        // Each peer tracks independently
        assert(p1.bytes_recv() == 5000);
        assert(p2.bytes_recv() == 10000);
        assert(p1.bytes_recv() != p2.bytes_recv());
    }
}

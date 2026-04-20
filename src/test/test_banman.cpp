// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for ban management: ban/unban peers, expiry, and listing.
// Uses the AddrMan and Peer infrastructure to simulate ban scenarios.
// Since FlowCoin uses misbehavior scoring on Peer objects and address
// management via AddrMan, these tests verify the ban lifecycle
// through those mechanisms.

#include "net/addrman.h"
#include "net/peer.h"
#include "net/protocol.h"
#include "util/types.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <set>
#include <string>
#include <vector>

// Simple BanMan implementation for testing, wrapping the ban lifecycle.
// In production, this is integrated into NetManager; here we test the
// core logic independently.
class TestBanMan {
public:
    struct BanEntry {
        flow::CNetAddr addr;
        int64_t ban_until;    // Unix timestamp when ban expires (0 = permanent)
        std::string reason;
    };

    void ban(const flow::CNetAddr& addr, int64_t duration_seconds,
             const std::string& reason = "")
    {
        // Remove existing ban for this addr first
        unban(addr);

        BanEntry entry;
        entry.addr = addr;
        entry.ban_until = (duration_seconds > 0)
            ? (current_time_ + duration_seconds) : 0;
        entry.reason = reason;
        bans_.push_back(entry);
    }

    bool is_banned(const flow::CNetAddr& addr) const {
        for (const auto& ban : bans_) {
            if (ban.addr == addr) {
                // Check if expired
                if (ban.ban_until > 0 && ban.ban_until <= current_time_) {
                    continue;  // Expired
                }
                return true;
            }
        }
        return false;
    }

    void unban(const flow::CNetAddr& addr) {
        bans_.erase(
            std::remove_if(bans_.begin(), bans_.end(),
                [&addr](const BanEntry& e) { return e.addr == addr; }),
            bans_.end()
        );
    }

    // Remove expired bans
    void sweep() {
        bans_.erase(
            std::remove_if(bans_.begin(), bans_.end(),
                [this](const BanEntry& e) {
                    return e.ban_until > 0 && e.ban_until <= current_time_;
                }),
            bans_.end()
        );
    }

    std::vector<BanEntry> list_banned() const {
        std::vector<BanEntry> result;
        for (const auto& ban : bans_) {
            // Only include non-expired bans
            if (ban.ban_until == 0 || ban.ban_until > current_time_) {
                result.push_back(ban);
            }
        }
        return result;
    }

    size_t size() const { return list_banned().size(); }

    // Advance the simulated clock
    void advance_time(int64_t seconds) { current_time_ += seconds; }
    void set_time(int64_t t) { current_time_ = t; }

private:
    std::vector<BanEntry> bans_;
    int64_t current_time_ = 1742515200;  // Genesis timestamp
};

void test_banman() {
    using namespace flow;

    // Test 1: ban / is_banned / unban cycle
    {
        TestBanMan banman;

        CNetAddr addr1("192.168.1.100", 9333);
        CNetAddr addr2("10.0.0.50", 9333);

        assert(!banman.is_banned(addr1));
        assert(!banman.is_banned(addr2));

        // Ban addr1 for 24 hours
        banman.ban(addr1, 86400, "misbehavior");
        assert(banman.is_banned(addr1));
        assert(!banman.is_banned(addr2));

        // Ban addr2 permanently
        banman.ban(addr2, 0, "attack");
        assert(banman.is_banned(addr1));
        assert(banman.is_banned(addr2));

        // Unban addr1
        banman.unban(addr1);
        assert(!banman.is_banned(addr1));
        assert(banman.is_banned(addr2));

        // Unban addr2
        banman.unban(addr2);
        assert(!banman.is_banned(addr1));
        assert(!banman.is_banned(addr2));
    }

    // Test 2: Expired bans cleared by sweep
    {
        TestBanMan banman;
        banman.set_time(1000);

        CNetAddr addr("172.16.0.1", 9333);

        // Ban for 60 seconds
        banman.ban(addr, 60, "test");
        assert(banman.is_banned(addr));
        assert(banman.size() == 1);

        // Advance 30 seconds — still banned
        banman.advance_time(30);
        assert(banman.is_banned(addr));

        // Advance past expiry
        banman.advance_time(31);
        assert(!banman.is_banned(addr));

        // Sweep should remove the expired entry
        banman.sweep();
        assert(banman.size() == 0);
    }

    // Test 3: list_banned returns entries
    {
        TestBanMan banman;

        CNetAddr addr1("10.0.0.1", 9333);
        CNetAddr addr2("10.0.0.2", 9333);
        CNetAddr addr3("10.0.0.3", 9333);

        banman.ban(addr1, 3600, "reason1");
        banman.ban(addr2, 0, "reason2");     // Permanent
        banman.ban(addr3, 7200, "reason3");

        auto banned = banman.list_banned();
        assert(banned.size() == 3);

        // Verify entries contain the addresses
        std::set<std::string> banned_ips;
        for (const auto& entry : banned) {
            banned_ips.insert(entry.addr.to_string());
        }
        assert(banned_ips.count("10.0.0.1:9333") == 1 ||
               banned_ips.count("10.0.0.1") == 1);
    }

    // Test 4: Permanent ban never expires
    {
        TestBanMan banman;
        banman.set_time(1000);

        CNetAddr addr("1.2.3.4", 9333);
        banman.ban(addr, 0, "permanent");

        // Advance a very long time
        banman.advance_time(86400 * 365 * 10);  // 10 years
        assert(banman.is_banned(addr));

        // Sweep should not remove it
        banman.sweep();
        assert(banman.is_banned(addr));
        assert(banman.size() == 1);
    }

    // Test 5: Re-banning extends the ban
    {
        TestBanMan banman;
        banman.set_time(1000);

        CNetAddr addr("5.6.7.8", 9333);

        // Ban for 60 seconds
        banman.ban(addr, 60, "first offense");
        assert(banman.is_banned(addr));

        // Advance 30 seconds, then re-ban for 120 seconds
        banman.advance_time(30);
        banman.ban(addr, 120, "second offense");

        // At t=1030+120=1150, ban should still be active at t=1100
        banman.advance_time(70);  // Now at t=1100
        assert(banman.is_banned(addr));

        // At t=1151, ban should be expired
        banman.advance_time(51);  // Now at t=1151
        assert(!banman.is_banned(addr));
    }

    // Test 6: Misbehavior score triggers ban
    {
        CNetAddr addr("8.8.8.8", 9333);
        Peer peer(1, addr, true);

        assert(!peer.should_ban());

        // Accumulate misbehavior
        for (int i = 0; i < 10; i++) {
            peer.add_misbehavior(10);
        }
        assert(peer.misbehavior_score() == 100);
        assert(peer.should_ban());

        // If should_ban() is true, the net manager bans the peer
        TestBanMan banman;
        if (peer.should_ban()) {
            banman.ban(peer.addr(), 86400, "misbehavior score >= 100");
        }
        assert(banman.is_banned(addr));
    }

    // Test 7: Multiple bans, selective unban
    {
        TestBanMan banman;

        CNetAddr a1("10.0.0.1", 9333);
        CNetAddr a2("10.0.0.2", 9333);
        CNetAddr a3("10.0.0.3", 9333);

        banman.ban(a1, 3600);
        banman.ban(a2, 3600);
        banman.ban(a3, 3600);
        assert(banman.size() == 3);

        banman.unban(a2);
        assert(banman.size() == 2);
        assert(banman.is_banned(a1));
        assert(!banman.is_banned(a2));
        assert(banman.is_banned(a3));
    }

    // Test 8: Sweep with mixed expired and active bans
    {
        TestBanMan banman;
        banman.set_time(1000);

        CNetAddr a1("10.0.0.1", 9333);
        CNetAddr a2("10.0.0.2", 9333);
        CNetAddr a3("10.0.0.3", 9333);

        banman.ban(a1, 30);    // Expires at 1030
        banman.ban(a2, 0);     // Permanent
        banman.ban(a3, 120);   // Expires at 1120

        banman.advance_time(50);  // Now at 1050
        // a1 expired, a2 permanent, a3 still active
        banman.sweep();

        assert(!banman.is_banned(a1));
        assert(banman.is_banned(a2));
        assert(banman.is_banned(a3));
        assert(banman.size() == 2);
    }
}

// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for network address parsing, classification, and serialization.
// Since we don't have a standalone NetAddress class, we test the P2P
// address handling logic using primitive types and helper functions.

#include "consensus/params.h"
#include "hash/keccak.h"
#include "util/random.h"
#include "util/strencodings.h"
#include "util/types.h"

#include <array>
#include <cassert>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace flow;

// ---------------------------------------------------------------------------
// Network address primitives for testing
// ---------------------------------------------------------------------------

struct NetAddress {
    std::array<uint8_t, 16> ip{};  // IPv6 or IPv4-mapped-IPv6
    uint16_t port = 0;

    bool is_ipv4() const {
        // IPv4-mapped IPv6: ::ffff:a.b.c.d
        static const uint8_t ipv4_prefix[12] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
        };
        return std::memcmp(ip.data(), ipv4_prefix, 12) == 0;
    }

    bool is_ipv6() const { return !is_ipv4(); }

    bool is_local() const {
        if (is_ipv4()) {
            return ip[12] == 127;  // 127.x.x.x
        }
        // ::1
        for (int i = 0; i < 15; ++i) {
            if (ip[i] != 0) return false;
        }
        return ip[15] == 1;
    }

    bool is_routable() const {
        if (is_local()) return false;
        if (is_ipv4()) {
            // 10.x.x.x, 172.16-31.x.x, 192.168.x.x are private
            if (ip[12] == 10) return false;
            if (ip[12] == 172 && (ip[13] & 0xf0) == 16) return false;
            if (ip[12] == 192 && ip[13] == 168) return false;
            if (ip[12] == 0) return false;  // 0.x.x.x
        }
        // All zeros = unspecified
        bool all_zero = true;
        for (auto b : ip) { if (b != 0) { all_zero = false; break; } }
        if (all_zero) return false;
        return true;
    }

    bool is_valid() const {
        // Not all zeros and not a multicast address
        bool all_zero = true;
        for (auto b : ip) { if (b != 0) { all_zero = false; break; } }
        return !all_zero;
    }

    // Get network group for bucketing (first 2 bytes of IPv4, /16)
    std::array<uint8_t, 2> get_group() const {
        if (is_ipv4()) {
            return {ip[12], ip[13]};
        }
        return {ip[0], ip[1]};
    }

    std::string to_string() const {
        if (is_ipv4()) {
            return std::to_string(ip[12]) + "." + std::to_string(ip[13]) + "." +
                   std::to_string(ip[14]) + "." + std::to_string(ip[15]) +
                   ":" + std::to_string(port);
        }
        // Simplified IPv6 display
        std::string result = "[";
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) result += ":";
            char buf[8];
            snprintf(buf, sizeof(buf), "%02x%02x", ip[i], ip[i + 1]);
            result += buf;
        }
        result += "]:" + std::to_string(port);
        return result;
    }

    // Serialize to bytes
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data(18);
        std::memcpy(data.data(), ip.data(), 16);
        data[16] = static_cast<uint8_t>(port >> 8);
        data[17] = static_cast<uint8_t>(port & 0xFF);
        return data;
    }

    // Deserialize from bytes
    static NetAddress deserialize(const uint8_t* data) {
        NetAddress addr;
        std::memcpy(addr.ip.data(), data, 16);
        addr.port = (static_cast<uint16_t>(data[16]) << 8) | data[17];
        return addr;
    }
};

// Parse an IPv4 address string
static NetAddress parse_ipv4(const std::string& ip_str, uint16_t port) {
    NetAddress addr;
    addr.port = port;

    // Set IPv4-mapped prefix
    std::memset(addr.ip.data(), 0, 10);
    addr.ip[10] = 0xff;
    addr.ip[11] = 0xff;

    // Parse dotted quad
    unsigned int a, b, c, d;
    if (sscanf(ip_str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return addr;
    }

    addr.ip[12] = static_cast<uint8_t>(a);
    addr.ip[13] = static_cast<uint8_t>(b);
    addr.ip[14] = static_cast<uint8_t>(c);
    addr.ip[15] = static_cast<uint8_t>(d);
    return addr;
}

void test_netaddress() {
    // -----------------------------------------------------------------------
    // Test 1: IPv4 parsing and display
    // -----------------------------------------------------------------------
    {
        NetAddress addr = parse_ipv4("192.168.1.100", 9333);
        assert(addr.is_ipv4());
        assert(!addr.is_ipv6());
        assert(addr.ip[12] == 192);
        assert(addr.ip[13] == 168);
        assert(addr.ip[14] == 1);
        assert(addr.ip[15] == 100);
        assert(addr.port == 9333);

        std::string s = addr.to_string();
        assert(s == "192.168.1.100:9333");
    }

    // -----------------------------------------------------------------------
    // Test 2: IPv6 construction and display
    // -----------------------------------------------------------------------
    {
        NetAddress addr;
        // fe80::1
        addr.ip[0] = 0xfe;
        addr.ip[1] = 0x80;
        addr.ip[15] = 0x01;
        addr.port = 8080;

        assert(addr.is_ipv6());
        assert(!addr.is_ipv4());
    }

    // -----------------------------------------------------------------------
    // Test 3: IPv4-mapped IPv6 detection
    // -----------------------------------------------------------------------
    {
        NetAddress addr = parse_ipv4("10.0.0.1", 80);
        assert(addr.is_ipv4());

        // Verify the mapped prefix
        for (int i = 0; i < 10; ++i) assert(addr.ip[i] == 0);
        assert(addr.ip[10] == 0xff);
        assert(addr.ip[11] == 0xff);
    }

    // -----------------------------------------------------------------------
    // Test 4: GetGroup() bucketing
    // -----------------------------------------------------------------------
    {
        NetAddress addr1 = parse_ipv4("192.168.1.1", 9333);
        NetAddress addr2 = parse_ipv4("192.168.2.1", 9333);
        NetAddress addr3 = parse_ipv4("10.0.0.1", 9333);

        auto g1 = addr1.get_group();
        auto g2 = addr2.get_group();
        auto g3 = addr3.get_group();

        // Same /16 network should have same group
        assert(g1 == g2);

        // Different /16 should have different group
        assert(g1 != g3);
    }

    // -----------------------------------------------------------------------
    // Test 5: IsLocal
    // -----------------------------------------------------------------------
    {
        NetAddress local_v4 = parse_ipv4("127.0.0.1", 9333);
        assert(local_v4.is_local());

        NetAddress local_v4_2 = parse_ipv4("127.0.0.2", 9333);
        assert(local_v4_2.is_local());

        NetAddress not_local = parse_ipv4("192.168.1.1", 9333);
        assert(!not_local.is_local());

        // IPv6 loopback ::1
        NetAddress local_v6;
        local_v6.ip[15] = 1;
        local_v6.port = 9333;
        assert(local_v6.is_local());
    }

    // -----------------------------------------------------------------------
    // Test 6: IsRoutable
    // -----------------------------------------------------------------------
    {
        // Routable public IP
        NetAddress pub = parse_ipv4("8.8.8.8", 9333);
        assert(pub.is_routable());

        // Private IPs
        NetAddress priv1 = parse_ipv4("10.0.0.1", 9333);
        assert(!priv1.is_routable());

        NetAddress priv2 = parse_ipv4("172.16.0.1", 9333);
        assert(!priv2.is_routable());

        NetAddress priv3 = parse_ipv4("192.168.0.1", 9333);
        assert(!priv3.is_routable());

        // Loopback
        NetAddress loopback = parse_ipv4("127.0.0.1", 9333);
        assert(!loopback.is_routable());

        // 0.0.0.0 is not routable
        NetAddress zero = parse_ipv4("0.0.0.0", 9333);
        assert(!zero.is_routable());
    }

    // -----------------------------------------------------------------------
    // Test 7: IsValid
    // -----------------------------------------------------------------------
    {
        NetAddress valid = parse_ipv4("1.2.3.4", 80);
        assert(valid.is_valid());

        // All-zero address is invalid
        NetAddress invalid;
        assert(!invalid.is_valid());
    }

    // -----------------------------------------------------------------------
    // Test 8: Serialize/deserialize round-trip
    // -----------------------------------------------------------------------
    {
        NetAddress orig = parse_ipv4("203.0.113.42", 9333);
        auto data = orig.serialize();
        assert(data.size() == 18);

        NetAddress restored = NetAddress::deserialize(data.data());
        assert(orig.ip == restored.ip);
        assert(orig.port == restored.port);
        assert(restored.to_string() == orig.to_string());
    }

    // -----------------------------------------------------------------------
    // Test 9: CService with port — different ports are different addresses
    // -----------------------------------------------------------------------
    {
        NetAddress a1 = parse_ipv4("1.2.3.4", 9333);
        NetAddress a2 = parse_ipv4("1.2.3.4", 9334);

        assert(a1.ip == a2.ip);
        assert(a1.port != a2.port);
        assert(a1.to_string() != a2.to_string());
    }

    // -----------------------------------------------------------------------
    // Test 10: Multiple IP parsing
    // -----------------------------------------------------------------------
    {
        std::vector<std::string> ips = {
            "0.0.0.0", "255.255.255.255", "1.1.1.1",
            "192.168.100.200", "172.31.255.254"
        };

        for (const auto& ip : ips) {
            NetAddress addr = parse_ipv4(ip, 80);
            assert(addr.is_ipv4());
            // to_string should contain the port
            std::string s = addr.to_string();
            assert(s.find(":80") != std::string::npos);
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: Serialize/deserialize IPv6
    // -----------------------------------------------------------------------
    {
        NetAddress addr;
        addr.ip[0] = 0x20;
        addr.ip[1] = 0x01;
        addr.ip[2] = 0x0d;
        addr.ip[3] = 0xb8;
        addr.port = 443;

        auto data = addr.serialize();
        NetAddress restored = NetAddress::deserialize(data.data());
        assert(restored.ip == addr.ip);
        assert(restored.port == 443);
    }

    // -----------------------------------------------------------------------
    // Test 12: Private address ranges
    // -----------------------------------------------------------------------
    {
        // 172.16.0.0 - 172.31.255.255
        NetAddress in_range = parse_ipv4("172.16.0.1", 80);
        assert(!in_range.is_routable());

        NetAddress out_range = parse_ipv4("172.32.0.1", 80);
        assert(out_range.is_routable());
    }
}

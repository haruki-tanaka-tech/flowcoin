// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "net/protocol.h"
#include "hash/keccak.h"

#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace flow {

// ===========================================================================
// CNetAddr
// ===========================================================================

CNetAddr::CNetAddr() : port(0) {
    std::memset(ip, 0, sizeof(ip));
}

CNetAddr::CNetAddr(const std::string& ip_str, uint16_t p) : port(p) {
    std::memset(ip, 0, sizeof(ip));

    // Try to parse as IPv4 first
    struct in_addr addr4;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr4) == 1) {
        // Store as IPv4-mapped IPv6: ::ffff:x.x.x.x
        ip[10] = 0xff;
        ip[11] = 0xff;
        std::memcpy(&ip[12], &addr4.s_addr, 4);
        return;
    }

    // Try IPv6
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, ip_str.c_str(), &addr6) == 1) {
        std::memcpy(ip, &addr6, 16);
    }
}

bool CNetAddr::is_ipv4() const {
    // IPv4-mapped IPv6: first 10 bytes zero, bytes 10-11 = 0xff
    static const uint8_t ipv4_prefix[12] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
    };
    return std::memcmp(ip, ipv4_prefix, 12) == 0;
}

std::string CNetAddr::to_string() const {
    char buf[64];
    if (is_ipv4()) {
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u",
                      ip[12], ip[13], ip[14], ip[15], port);
    } else {
        char ip6_str[INET6_ADDRSTRLEN];
        struct in6_addr addr6;
        std::memcpy(&addr6, ip, 16);
        inet_ntop(AF_INET6, &addr6, ip6_str, sizeof(ip6_str));
        std::snprintf(buf, sizeof(buf), "[%s]:%u", ip6_str, port);
    }
    return buf;
}

bool CNetAddr::operator==(const CNetAddr& other) const {
    return std::memcmp(ip, other.ip, 16) == 0 && port == other.port;
}

bool CNetAddr::operator!=(const CNetAddr& other) const {
    return !(*this == other);
}

void CNetAddr::serialize(DataWriter& w) const {
    w.write_bytes(ip, 16);
    // Port is big-endian (Bitcoin convention)
    w.write_u8(static_cast<uint8_t>(port >> 8));
    w.write_u8(static_cast<uint8_t>(port & 0xff));
}

CNetAddr CNetAddr::deserialize(DataReader& r) {
    CNetAddr addr;
    auto ip_bytes = r.read_bytes(16);
    if (!r.error() && ip_bytes.size() == 16) {
        std::memcpy(addr.ip, ip_bytes.data(), 16);
    }
    uint8_t hi = r.read_u8();
    uint8_t lo = r.read_u8();
    addr.port = static_cast<uint16_t>((hi << 8) | lo);
    return addr;
}

// ===========================================================================
// MessageHeader
// ===========================================================================

void MessageHeader::serialize(DataWriter& w) const {
    w.write_u32_le(magic);
    // Command: 12 bytes, null-padded
    uint8_t cmd[12] = {};
    size_t cmd_len = std::strlen(command);
    if (cmd_len > 12) cmd_len = 12;
    std::memcpy(cmd, command, cmd_len);
    w.write_bytes(cmd, 12);
    w.write_u32_le(payload_size);
    w.write_u32_le(checksum);
}

bool MessageHeader::deserialize(DataReader& r, MessageHeader& out) {
    out.magic = r.read_u32_le();
    auto cmd_bytes = r.read_bytes(12);
    if (r.error()) return false;
    std::memcpy(out.command, cmd_bytes.data(), 12);
    out.payload_size = r.read_u32_le();
    out.checksum = r.read_u32_le();
    return !r.error();
}

std::string MessageHeader::command_string() const {
    // Find the null terminator or end of the 12-byte field
    size_t len = 0;
    while (len < 12 && command[len] != '\0') {
        len++;
    }
    return std::string(command, len);
}

// ===========================================================================
// Checksum computation — first 4 bytes of keccak256d(payload). Bitcoin uses
// SHA-256d; we substitute our Keccak-based double-hash so that the codebase
// has one fewer hash dependency and the checksum matches the block-id hash.
// ===========================================================================

uint32_t compute_checksum(const uint8_t* data, size_t len) {
    uint256 hash = keccak256d(data, len);
    uint32_t result = 0;
    std::memcpy(&result, hash.data(), 4);
    return result;
}

// ===========================================================================
// build_message
// ===========================================================================

std::vector<uint8_t> build_message(uint32_t magic, const std::string& command,
                                   const std::vector<uint8_t>& payload) {
    MessageHeader hdr;
    hdr.magic = magic;

    // Fill command field (12 bytes, null-padded)
    std::memset(hdr.command, 0, 12);
    size_t cmd_len = command.size();
    if (cmd_len > 12) cmd_len = 12;
    std::memcpy(hdr.command, command.c_str(), cmd_len);

    hdr.payload_size = static_cast<uint32_t>(payload.size());

    if (payload.empty()) {
        // Checksum of empty data
        hdr.checksum = compute_checksum(nullptr, 0);
    } else {
        hdr.checksum = compute_checksum(payload.data(), payload.size());
    }

    DataWriter w(MessageHeader::SIZE + payload.size());
    hdr.serialize(w);
    if (!payload.empty()) {
        w.write_bytes(payload.data(), payload.size());
    }
    return w.release();
}

// ===========================================================================
// VersionMessage
// ===========================================================================

std::vector<uint8_t> VersionMessage::serialize() const {
    DataWriter w(128);

    // Fixed-size prefix — matches Bitcoin's version layout byte-for-byte.
    w.write_u32_le(static_cast<uint32_t>(protocol_version));
    w.write_u64_le(services);
    w.write_i64_le(timestamp);

    w.write_u64_le(addr_recv_services);
    addr_recv.serialize(w);           // 16 bytes ip + 2 bytes port (big-endian)

    w.write_u64_le(addr_from_services);
    addr_from.serialize(w);

    w.write_u64_le(nonce);

    // User agent
    w.write_compact_size(user_agent.size());
    if (!user_agent.empty()) {
        w.write_bytes(reinterpret_cast<const uint8_t*>(user_agent.data()),
                      user_agent.size());
    }

    w.write_u32_le(static_cast<uint32_t>(start_height));
    w.write_u8(relay ? 1 : 0);

    return w.release();
}

bool VersionMessage::deserialize(const uint8_t* data, size_t len, VersionMessage& out) {
    DataReader r(data, len);

    out.protocol_version    = static_cast<int32_t>(r.read_u32_le());
    out.services            = r.read_u64_le();
    out.timestamp           = r.read_i64_le();

    out.addr_recv_services  = r.read_u64_le();
    out.addr_recv           = CNetAddr::deserialize(r);

    out.addr_from_services  = r.read_u64_le();
    out.addr_from           = CNetAddr::deserialize(r);

    out.nonce               = r.read_u64_le();

    uint64_t ua_len = r.read_compact_size();
    if (r.error() || ua_len > 256) return false;

    if (ua_len > 0) {
        auto ua_bytes = r.read_bytes(static_cast<size_t>(ua_len));
        if (r.error()) return false;
        out.user_agent.assign(reinterpret_cast<const char*>(ua_bytes.data()),
                              ua_bytes.size());
    } else {
        out.user_agent.clear();
    }

    out.start_height = static_cast<int32_t>(r.read_u32_le());

    // fRelay is optional for backward compatibility with pre-70001 peers.
    if (!r.error() && r.remaining() >= 1) {
        out.relay = r.read_u8() != 0;
    } else {
        out.relay = true;
    }

    return !r.error();
}

} // namespace flow

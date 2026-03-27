// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Full network address handling implementation.

#include "net/netaddress.h"
#include "hash/keccak.h"

#include <cstdio>
#include <cstring>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace flow {

// ===========================================================================
// Network name lookup
// ===========================================================================

const char* GetNetworkName(Network net) {
    switch (net) {
        case NET_IPV4:       return "ipv4";
        case NET_IPV6:       return "ipv6";
        case NET_TOR:        return "onion";
        case NET_INTERNAL:   return "internal";
        case NET_UNROUTABLE: return "unroutable";
        default:             return "unknown";
    }
}

// ===========================================================================
// Static constexpr arrays (out-of-line definitions for C++17 ODR)
// ===========================================================================

constexpr uint8_t CNetAddr2::TOR_PREFIX[];
constexpr uint8_t CNetAddr2::INTERNAL_PREFIX[];
constexpr uint8_t CNetAddr2::IPV4_PREFIX[];

// ===========================================================================
// CNetAddr2 construction
// ===========================================================================

CNetAddr2::CNetAddr2() {
    std::memset(ip_, 0, sizeof(ip_));
}

CNetAddr2::CNetAddr2(const std::string& ip_str) {
    std::memset(ip_, 0, sizeof(ip_));
    ParseIP(ip_str, *this);
}

CNetAddr2::CNetAddr2(const uint8_t* ip_data, size_t len) {
    std::memset(ip_, 0, sizeof(ip_));
    if (len == 4) {
        // IPv4: store as mapped
        ip_[10] = 0xff;
        ip_[11] = 0xff;
        std::memcpy(&ip_[12], ip_data, 4);
    } else if (len == 16) {
        std::memcpy(ip_, ip_data, 16);
    }
}

// ===========================================================================
// ParseIP
// ===========================================================================

bool CNetAddr2::ParseIP(const std::string& str, CNetAddr2& out) {
    std::memset(out.ip_, 0, sizeof(out.ip_));

    // Try IPv4
    struct in_addr addr4;
    if (inet_pton(AF_INET, str.c_str(), &addr4) == 1) {
        out.ip_[10] = 0xff;
        out.ip_[11] = 0xff;
        std::memcpy(&out.ip_[12], &addr4.s_addr, 4);
        return true;
    }

    // Try IPv6
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, str.c_str(), &addr6) == 1) {
        std::memcpy(out.ip_, &addr6, 16);
        return true;
    }

    return false;
}

// ===========================================================================
// Prefix helper
// ===========================================================================

bool CNetAddr2::HasPrefix(const uint8_t* prefix, size_t len) const {
    return std::memcmp(ip_, prefix, len) == 0;
}

// ===========================================================================
// Classification methods
// ===========================================================================

bool CNetAddr2::IsIPv4() const {
    return HasPrefix(IPV4_PREFIX, 12);
}

bool CNetAddr2::IsIPv6() const {
    return !IsIPv4() && !IsTor() && !IsInternal();
}

bool CNetAddr2::IsTor() const {
    return HasPrefix(TOR_PREFIX, sizeof(TOR_PREFIX));
}

bool CNetAddr2::IsInternal() const {
    return HasPrefix(INTERNAL_PREFIX, sizeof(INTERNAL_PREFIX));
}

bool CNetAddr2::IsLocal() const {
    return IsLoopback() || IsRFC3927() || IsRFC4862();
}

bool CNetAddr2::IsLoopback() const {
    if (IsIPv4()) {
        return ip_[12] == 127;
    }
    // IPv6 ::1
    static const uint8_t loopback[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    };
    return std::memcmp(ip_, loopback, 16) == 0;
}

bool CNetAddr2::IsMulticast() const {
    if (IsIPv4()) {
        return (ip_[12] & 0xf0) == 0xe0;  // 224.0.0.0/4
    }
    return ip_[0] == 0xff;
}

bool CNetAddr2::IsRFC1918() const {
    if (!IsIPv4()) return false;
    // 10.0.0.0/8
    if (ip_[12] == 10) return true;
    // 172.16.0.0/12
    if (ip_[12] == 172 && (ip_[13] >= 16 && ip_[13] <= 31)) return true;
    // 192.168.0.0/16
    if (ip_[12] == 192 && ip_[13] == 168) return true;
    return false;
}

bool CNetAddr2::IsRFC2544() const {
    if (!IsIPv4()) return false;
    return ip_[12] == 198 && (ip_[13] == 18 || ip_[13] == 19);
}

bool CNetAddr2::IsRFC6598() const {
    if (!IsIPv4()) return false;
    return ip_[12] == 100 && (ip_[13] >= 64 && ip_[13] <= 127);
}

bool CNetAddr2::IsRFC5737() const {
    if (!IsIPv4()) return false;
    // 192.0.2.0/24
    if (ip_[12] == 192 && ip_[13] == 0 && ip_[14] == 2) return true;
    // 198.51.100.0/24
    if (ip_[12] == 198 && ip_[13] == 51 && ip_[14] == 100) return true;
    // 203.0.113.0/24
    if (ip_[12] == 203 && ip_[13] == 0 && ip_[14] == 113) return true;
    return false;
}

bool CNetAddr2::IsRFC3849() const {
    if (IsIPv4()) return false;
    return ip_[0] == 0x20 && ip_[1] == 0x01 && ip_[2] == 0x0d && ip_[3] == 0xb8;
}

bool CNetAddr2::IsRFC3927() const {
    if (!IsIPv4()) return false;
    return ip_[12] == 169 && ip_[13] == 254;
}

bool CNetAddr2::IsRFC3964() const {
    if (IsIPv4()) return false;
    return ip_[0] == 0x20 && ip_[1] == 0x02;
}

bool CNetAddr2::IsRFC4193() const {
    if (IsIPv4()) return false;
    return (ip_[0] & 0xfe) == 0xfc;
}

bool CNetAddr2::IsRFC4380() const {
    if (IsIPv4()) return false;
    return ip_[0] == 0x20 && ip_[1] == 0x01 && ip_[2] == 0x00 && ip_[3] == 0x00;
}

bool CNetAddr2::IsRFC4843() const {
    if (IsIPv4()) return false;
    return ip_[0] == 0x20 && ip_[1] == 0x01 && ip_[2] == 0x00 &&
           (ip_[3] & 0xf0) == 0x10;
}

bool CNetAddr2::IsRFC4862() const {
    if (IsIPv4()) return false;
    return ip_[0] == 0xfe && (ip_[1] & 0xc0) == 0x80;
}

bool CNetAddr2::IsRFC6052() const {
    if (IsIPv4()) return false;
    static const uint8_t prefix[] = {
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    return std::memcmp(ip_, prefix, 12) == 0;
}

bool CNetAddr2::IsRFC6145() const {
    if (IsIPv4()) return false;
    static const uint8_t prefix[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00
    };
    return std::memcmp(ip_, prefix, 12) == 0;
}

bool CNetAddr2::IsValid() const {
    if (IsNull()) return false;
    if (IsInternal()) return false;
    if (IsIPv4()) {
        // 0.0.0.0/8 is invalid
        if (ip_[12] == 0) return false;
        // 255.255.255.255 is invalid
        if (ip_[12] == 255 && ip_[13] == 255 && ip_[14] == 255 && ip_[15] == 255)
            return false;
    }
    return true;
}

bool CNetAddr2::IsRoutable() const {
    if (!IsValid()) return false;
    if (IsLocal()) return false;
    if (IsRFC1918()) return false;
    if (IsRFC2544()) return false;
    if (IsRFC3927()) return false;
    if (IsRFC4862()) return false;
    if (IsRFC6598()) return false;
    if (IsRFC5737()) return false;
    if (IsRFC4193()) return false;
    if (IsRFC4843()) return false;
    if (IsRFC3849()) return false;
    if (IsMulticast()) return false;
    if (IsInternal()) return false;
    return true;
}

Network CNetAddr2::GetNetwork() const {
    if (IsInternal()) return NET_INTERNAL;
    if (!IsRoutable()) return NET_UNROUTABLE;
    if (IsIPv4()) return NET_IPV4;
    if (IsTor()) return NET_TOR;
    return NET_IPV6;
}

// ===========================================================================
// GetGroup — for addrman bucket assignment
// ===========================================================================

std::vector<uint8_t> CNetAddr2::GetGroup() const {
    std::vector<uint8_t> group;

    Network net = GetNetwork();
    group.push_back(static_cast<uint8_t>(net));

    if (IsLocal() || IsInternal()) {
        // All local/internal addresses in one group
        return group;
    }

    if (IsTor()) {
        // All Tor addresses in a single group (4 bytes of onion address for diversity)
        group.push_back(ip_[6]);
        group.push_back(ip_[7]);
        group.push_back(ip_[8]);
        group.push_back(ip_[9]);
        return group;
    }

    if (IsIPv4()) {
        // /16 prefix (first 2 octets of the IPv4 address)
        group.push_back(ip_[12]);
        group.push_back(ip_[13]);
        return group;
    }

    if (IsRFC6052() || IsRFC6145()) {
        // IPv4-translated: group by the embedded IPv4 /16
        group.push_back(ip_[12]);
        group.push_back(ip_[13]);
        return group;
    }

    if (IsRFC3964()) {
        // 6to4: group by the embedded IPv4 /16
        group.push_back(ip_[2]);
        group.push_back(ip_[3]);
        return group;
    }

    if (IsRFC4380()) {
        // Teredo: group by the server IPv4 /16
        group.push_back(ip_[12] ^ 0xff);
        group.push_back(ip_[13] ^ 0xff);
        return group;
    }

    // Generic IPv6: /32 prefix (first 4 bytes)
    group.push_back(ip_[0]);
    group.push_back(ip_[1]);
    group.push_back(ip_[2]);
    group.push_back(ip_[3]);
    return group;
}

// ===========================================================================
// Accessors
// ===========================================================================

uint32_t CNetAddr2::GetIPv4() const {
    if (!IsIPv4()) return 0;
    uint32_t result = 0;
    std::memcpy(&result, &ip_[12], 4);
    return result;
}

bool CNetAddr2::IsNull() const {
    static const uint8_t zeros[16] = {};
    return std::memcmp(ip_, zeros, 16) == 0;
}

// ===========================================================================
// Setters
// ===========================================================================

void CNetAddr2::SetIPv4(uint32_t ipv4) {
    std::memset(ip_, 0, sizeof(ip_));
    ip_[10] = 0xff;
    ip_[11] = 0xff;
    std::memcpy(&ip_[12], &ipv4, 4);
}

void CNetAddr2::SetIPv6(const uint8_t* ipv6) {
    std::memcpy(ip_, ipv6, 16);
}

void CNetAddr2::SetTor(const uint8_t* tor_addr) {
    std::memcpy(ip_, TOR_PREFIX, sizeof(TOR_PREFIX));
    std::memcpy(ip_ + sizeof(TOR_PREFIX), tor_addr, 10);
}

void CNetAddr2::SetInternal(const std::string& name) {
    std::memset(ip_, 0, sizeof(ip_));
    std::memcpy(ip_, INTERNAL_PREFIX, sizeof(INTERNAL_PREFIX));
    // Hash the name into the remaining bytes for uniqueness
    uint256 hash = keccak256(reinterpret_cast<const uint8_t*>(name.data()), name.size());
    size_t remaining = 16 - sizeof(INTERNAL_PREFIX);
    std::memcpy(ip_ + sizeof(INTERNAL_PREFIX), hash.data(), remaining);
}

// ===========================================================================
// String conversion
// ===========================================================================

std::string CNetAddr2::ToStringIP() const {
    if (IsInternal()) {
        return "[internal]";
    }
    if (IsTor()) {
        // Represent as hex of the 10-byte onion address
        char buf[64];
        std::snprintf(buf, sizeof(buf),
                      "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x.onion",
                      ip_[6], ip_[7], ip_[8], ip_[9], ip_[10],
                      ip_[11], ip_[12], ip_[13], ip_[14], ip_[15]);
        return buf;
    }
    if (IsIPv4()) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                      ip_[12], ip_[13], ip_[14], ip_[15]);
        return buf;
    }
    // IPv6
    char buf[INET6_ADDRSTRLEN];
    struct in6_addr addr6;
    std::memcpy(&addr6, ip_, 16);
    inet_ntop(AF_INET6, &addr6, buf, sizeof(buf));
    return buf;
}

std::string CNetAddr2::ToString() const {
    return ToStringIP();
}

// ===========================================================================
// Comparison operators
// ===========================================================================

bool CNetAddr2::operator==(const CNetAddr2& other) const {
    return std::memcmp(ip_, other.ip_, 16) == 0;
}

bool CNetAddr2::operator!=(const CNetAddr2& other) const {
    return !(*this == other);
}

bool CNetAddr2::operator<(const CNetAddr2& other) const {
    return std::memcmp(ip_, other.ip_, 16) < 0;
}

// ===========================================================================
// Serialization
// ===========================================================================

void CNetAddr2::Serialize(DataWriter& w) const {
    w.write_bytes(ip_, 16);
}

CNetAddr2 CNetAddr2::Deserialize(DataReader& r) {
    CNetAddr2 addr;
    auto bytes = r.read_bytes(16);
    if (!r.error() && bytes.size() == 16) {
        std::memcpy(addr.ip_, bytes.data(), 16);
    }
    return addr;
}

// ===========================================================================
// CService construction
// ===========================================================================

CService::CService() : CNetAddr2(), port_(0) {}

CService::CService(const CNetAddr2& addr, uint16_t port)
    : CNetAddr2(addr), port_(port) {}

CService::CService(const std::string& ip_str, uint16_t port)
    : CNetAddr2(ip_str), port_(port) {}

// ===========================================================================
// CService string conversion
// ===========================================================================

std::string CService::ToString() const {
    if (IsIPv4() || IsTor() || IsInternal()) {
        return ToStringIP() + ":" + std::to_string(port_);
    }
    // IPv6: wrap in brackets
    return "[" + ToStringIP() + "]:" + std::to_string(port_);
}

bool CService::Parse(const std::string& str, CService& out) {
    // Handle [ipv6]:port
    if (!str.empty() && str[0] == '[') {
        size_t close = str.find(']');
        if (close == std::string::npos) return false;
        std::string ip_part = str.substr(1, close - 1);
        if (close + 1 >= str.size() || str[close + 1] != ':') return false;
        std::string port_str = str.substr(close + 2);
        int port = 0;
        try { port = std::stoi(port_str); } catch (...) { return false; }
        if (port <= 0 || port > 65535) return false;
        if (!CNetAddr2::ParseIP(ip_part, out)) return false;
        out.port_ = static_cast<uint16_t>(port);
        return true;
    }

    // Handle ipv4:port or hostname:port
    size_t colon = str.rfind(':');
    if (colon == std::string::npos) return false;
    std::string ip_part = str.substr(0, colon);
    std::string port_str = str.substr(colon + 1);
    int port = 0;
    try { port = std::stoi(port_str); } catch (...) { return false; }
    if (port <= 0 || port > 65535) return false;
    if (!CNetAddr2::ParseIP(ip_part, out)) return false;
    out.port_ = static_cast<uint16_t>(port);
    return true;
}

// ===========================================================================
// CService comparison
// ===========================================================================

bool CService::operator==(const CService& other) const {
    return CNetAddr2::operator==(other) && port_ == other.port_;
}

bool CService::operator!=(const CService& other) const {
    return !(*this == other);
}

bool CService::operator<(const CService& other) const {
    if (CNetAddr2::operator<(other)) return true;
    if (other.CNetAddr2::operator<(*this)) return false;
    return port_ < other.port_;
}

// ===========================================================================
// CService serialization
// ===========================================================================

void CService::SerializeFull(DataWriter& w, int64_t timestamp, uint64_t services) const {
    w.write_u32_le(static_cast<uint32_t>(timestamp));
    w.write_u64_le(services);
    Serialize(w);
    // Port is big-endian (Bitcoin convention)
    w.write_u8(static_cast<uint8_t>(port_ >> 8));
    w.write_u8(static_cast<uint8_t>(port_ & 0xff));
}

CService CService::DeserializeFull(DataReader& r, int64_t& timestamp, uint64_t& services) {
    timestamp = static_cast<int64_t>(r.read_u32_le());
    services = r.read_u64_le();
    CNetAddr2 addr = CNetAddr2::Deserialize(r);
    uint8_t hi = r.read_u8();
    uint8_t lo = r.read_u8();
    uint16_t port = static_cast<uint16_t>((hi << 8) | lo);
    return CService(addr, port);
}

void CService::SerializeCompact(DataWriter& w) const {
    Serialize(w);
    w.write_u8(static_cast<uint8_t>(port_ >> 8));
    w.write_u8(static_cast<uint8_t>(port_ & 0xff));
}

CService CService::DeserializeCompact(DataReader& r) {
    CNetAddr2 addr = CNetAddr2::Deserialize(r);
    uint8_t hi = r.read_u8();
    uint8_t lo = r.read_u8();
    uint16_t port = static_cast<uint16_t>((hi << 8) | lo);
    return CService(addr, port);
}

// ===========================================================================
// Hash functions for addrman bucketing
// ===========================================================================

uint64_t HashAddr(const CNetAddr2& addr, const uint256& key) {
    DataWriter w(64);
    w.write_bytes(key.data(), 32);
    addr.Serialize(w);
    uint256 hash = keccak256(w.data().data(), w.data().size());
    uint64_t result = 0;
    std::memcpy(&result, hash.data(), 8);
    return result;
}

uint64_t HashAddrGroup(const std::vector<uint8_t>& addr_group,
                       const std::vector<uint8_t>& source_group,
                       const uint256& key) {
    DataWriter w(64);
    w.write_bytes(key.data(), 32);
    w.write_compact_size(addr_group.size());
    if (!addr_group.empty()) {
        w.write_bytes(addr_group.data(), addr_group.size());
    }
    w.write_compact_size(source_group.size());
    if (!source_group.empty()) {
        w.write_bytes(source_group.data(), source_group.size());
    }
    uint256 hash = keccak256(w.data().data(), w.data().size());
    uint64_t result = 0;
    std::memcpy(&result, hash.data(), 8);
    return result;
}

uint64_t HashAddrTried(const CNetAddr2& addr,
                       const std::vector<uint8_t>& addr_group,
                       const uint256& key) {
    DataWriter w(64);
    w.write_bytes(key.data(), 32);
    addr.Serialize(w);
    w.write_compact_size(addr_group.size());
    if (!addr_group.empty()) {
        w.write_bytes(addr_group.data(), addr_group.size());
    }
    uint256 hash = keccak256(w.data().data(), w.data().size());
    uint64_t result = 0;
    std::memcpy(&result, hash.data(), 8);
    return result;
}

} // namespace flow

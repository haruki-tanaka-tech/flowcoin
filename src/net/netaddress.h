// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Full network address handling (Bitcoin Core style).
// CNetAddr: internal 16-byte storage, IPv4 as ::ffff:x.x.x.x, IPv6 native.
// CService = CNetAddr + port.
// Supports IPv4, IPv6, Tor (.onion), and internal network types.
// Provides group-based bucketing for addrman eclipse-attack prevention.

#ifndef FLOWCOIN_NET_NETADDRESS_H
#define FLOWCOIN_NET_NETADDRESS_H

#include "util/serialize.h"
#include "util/types.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace flow {

// Network type classification for address routing and bucketing
enum Network : int {
    NET_UNROUTABLE = 0,
    NET_IPV4       = 1,
    NET_IPV6       = 2,
    NET_TOR        = 3,
    NET_INTERNAL   = 4,
    NET_MAX        = 5,
};

// Return human-readable name for a network type
const char* GetNetworkName(Network net);

// ---------------------------------------------------------------------------
// CNetAddr — network address without port (16-byte internal representation)
// ---------------------------------------------------------------------------

class CNetAddr2 {
public:
    CNetAddr2();
    explicit CNetAddr2(const std::string& ip_str);
    CNetAddr2(const uint8_t* ip_data, size_t len);

    // Parse an IP address string (IPv4 dotted-quad or IPv6 colon-hex)
    static bool ParseIP(const std::string& str, CNetAddr2& out);

    // Classification
    bool IsIPv4() const;
    bool IsIPv6() const;
    bool IsTor() const;
    bool IsInternal() const;
    bool IsLocal() const;
    bool IsRoutable() const;
    bool IsValid() const;
    bool IsRFC1918() const;    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    bool IsRFC2544() const;    // 198.18.0.0/15
    bool IsRFC6598() const;    // 100.64.0.0/10
    bool IsRFC5737() const;    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    bool IsRFC3849() const;    // 2001:0db8::/32 (documentation)
    bool IsRFC3927() const;    // 169.254.0.0/16 (link-local)
    bool IsRFC3964() const;    // 2002::/16 (6to4)
    bool IsRFC4193() const;    // fc00::/7 (unique local)
    bool IsRFC4380() const;    // 2001::/32 (Teredo)
    bool IsRFC4843() const;    // 2001:10::/28 (ORCHID)
    bool IsRFC4862() const;    // fe80::/10 (link-local)
    bool IsRFC6052() const;    // 64:ff9b::/96 (NAT64)
    bool IsRFC6145() const;    // ::ffff:0:0/96 (IPv4-translated)
    bool IsMulticast() const;  // ff00::/8 for IPv6, 224.0.0.0/4 for IPv4
    bool IsLoopback() const;   // ::1 or 127.0.0.0/8

    // Get the network type
    Network GetNetwork() const;

    // Get the address group for addrman bucketing
    // IPv4: /16 prefix (first 2 octets)
    // IPv6: /32 prefix (first 4 bytes)
    // Tor: all Tor addresses in one group
    // Internal: all internal addresses in one group
    std::vector<uint8_t> GetGroup() const;

    // Get the raw IPv4 address (only valid if IsIPv4() returns true)
    uint32_t GetIPv4() const;

    // Get the raw 16-byte address
    const uint8_t* GetBytes() const { return ip_; }

    // String conversion
    std::string ToString() const;
    std::string ToStringIP() const;

    // Comparison
    bool operator==(const CNetAddr2& other) const;
    bool operator!=(const CNetAddr2& other) const;
    bool operator<(const CNetAddr2& other) const;

    // Serialization for addr messages (16 bytes IP, network byte order)
    void Serialize(DataWriter& w) const;
    static CNetAddr2 Deserialize(DataReader& r);

    // Set from IPv4 (4 bytes, host byte order)
    void SetIPv4(uint32_t ipv4);

    // Set from IPv6 (16 bytes)
    void SetIPv6(const uint8_t* ipv6);

    // Set as Tor address (10-byte onion address encoded in IPv6 space)
    void SetTor(const uint8_t* tor_addr);

    // Set as internal address (for testing / local use)
    void SetInternal(const std::string& name);

    // Check if the address is all zeros (unset)
    bool IsNull() const;

protected:
    uint8_t ip_[16];  // IPv6 representation (IPv4 stored as ::ffff:x.x.x.x)

    // Tor onion prefix: fd87:d87e:eb43::/48
    static constexpr uint8_t TOR_PREFIX[] = {
        0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43
    };

    // Internal prefix: 0xfd + "fc" + 0x00 (4 bytes)
    static constexpr uint8_t INTERNAL_PREFIX[] = {
        0xfd, 0x6b, 0x88, 0xc0
    };

    // IPv4-mapped prefix: ::ffff:0:0/96
    static constexpr uint8_t IPV4_PREFIX[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff
    };

    bool HasPrefix(const uint8_t* prefix, size_t len) const;
};

// ---------------------------------------------------------------------------
// CService — CNetAddr2 + port (endpoint for TCP connections)
// ---------------------------------------------------------------------------

class CService : public CNetAddr2 {
public:
    CService();
    CService(const CNetAddr2& addr, uint16_t port);
    CService(const std::string& ip_str, uint16_t port);

    uint16_t GetPort() const { return port_; }
    void SetPort(uint16_t port) { port_ = port; }

    // String conversion: "ip:port" or "[ipv6]:port"
    std::string ToString() const;

    // Parse "host:port" string
    static bool Parse(const std::string& str, CService& out);

    bool operator==(const CService& other) const;
    bool operator!=(const CService& other) const;
    bool operator<(const CService& other) const;

    // Serialization for addr messages: timestamp(4) + services(8) + ip(16) + port(2)
    void SerializeFull(DataWriter& w, int64_t timestamp, uint64_t services) const;
    static CService DeserializeFull(DataReader& r, int64_t& timestamp, uint64_t& services);

    // Compact serialization: ip(16) + port(2)
    void SerializeCompact(DataWriter& w) const;
    static CService DeserializeCompact(DataReader& r);

private:
    uint16_t port_ = 0;
};

// ---------------------------------------------------------------------------
// Address-to-key hash for deterministic bucket assignment
// ---------------------------------------------------------------------------

// Hash an address + key for deterministic addrman bucket selection
uint64_t HashAddr(const CNetAddr2& addr, const uint256& key);

// Hash an address group + source group + key for New table bucketing
uint64_t HashAddrGroup(const std::vector<uint8_t>& addr_group,
                       const std::vector<uint8_t>& source_group,
                       const uint256& key);

// Hash an address + address group + key for Tried table bucketing
uint64_t HashAddrTried(const CNetAddr2& addr,
                       const std::vector<uint8_t>& addr_group,
                       const uint256& key);

} // namespace flow

#endif // FLOWCOIN_NET_NETADDRESS_H

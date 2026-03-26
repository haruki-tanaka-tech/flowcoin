// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Wire protocol definitions for the FlowCoin P2P network.
// Message format: 24-byte header + variable payload.
// Header: [4 magic][12 command][4 payload_size][4 checksum]
// Checksum is the first 4 bytes of keccak256(payload).

#ifndef FLOWCOIN_NET_PROTOCOL_H
#define FLOWCOIN_NET_PROTOCOL_H

#include "util/types.h"
#include "util/serialize.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// Wire protocol command strings (12 bytes, null-padded ASCII)
// ---------------------------------------------------------------------------

namespace NetCmd {
    constexpr const char* VERSION    = "version";
    constexpr const char* VERACK     = "verack";
    constexpr const char* PING       = "ping";
    constexpr const char* PONG       = "pong";
    constexpr const char* GETADDR    = "getaddr";
    constexpr const char* ADDR       = "addr";
    constexpr const char* INV        = "inv";
    constexpr const char* GETDATA    = "getdata";
    constexpr const char* BLOCK      = "block";
    constexpr const char* TX         = "tx";
    constexpr const char* GETBLOCKS  = "getblocks";
    constexpr const char* GETHEADERS = "getheaders";
    constexpr const char* HEADERS    = "headers";
    constexpr const char* NOTFOUND   = "notfound";
    constexpr const char* REJECT     = "reject";
    constexpr const char* SENDHEADERS = "sendheaders";
    constexpr const char* SENDCMPCT  = "sendcmpct";
    constexpr const char* CMPCTBLOCK = "cmpctblock";
    constexpr const char* GETBLOCKTXN = "getblocktxn";
    constexpr const char* BLOCKTXN   = "blocktxn";
    constexpr const char* FEEFILTER  = "feefilter";
} // namespace NetCmd

// ---------------------------------------------------------------------------
// Inventory item types
// ---------------------------------------------------------------------------

enum InvType : uint32_t {
    INV_TX    = 1,
    INV_BLOCK = 2,
};

struct InvItem {
    InvType type;
    uint256 hash;
};

// ---------------------------------------------------------------------------
// Network address (IPv4 stored as IPv4-mapped IPv6: ::ffff:x.x.x.x)
// ---------------------------------------------------------------------------

struct CNetAddr {
    uint8_t ip[16];   // IPv6 address (or IPv4-mapped)
    uint16_t port;

    CNetAddr();
    CNetAddr(const std::string& ip_str, uint16_t port);

    bool is_ipv4() const;
    std::string to_string() const;

    bool operator==(const CNetAddr& other) const;
    bool operator!=(const CNetAddr& other) const;

    // Serialize: 16 bytes IP + 2 bytes port (big-endian for port, Bitcoin convention)
    void serialize(DataWriter& w) const;
    static CNetAddr deserialize(DataReader& r);
};

// ---------------------------------------------------------------------------
// Message header: 24 bytes
// [4 magic][12 command][4 size][4 checksum]
// ---------------------------------------------------------------------------

struct MessageHeader {
    uint32_t magic;
    char command[12];
    uint32_t payload_size;
    uint32_t checksum;   // first 4 bytes of keccak256(payload)

    static constexpr size_t SIZE = 24;

    // Maximum allowed payload size (32 MB, matching MAX_BLOCK_SIZE)
    static constexpr uint32_t MAX_PAYLOAD_SIZE = 32'000'000;

    void serialize(DataWriter& w) const;
    static bool deserialize(DataReader& r, MessageHeader& out);

    std::string command_string() const;
};

// ---------------------------------------------------------------------------
// Build a complete wire message: header + payload
// ---------------------------------------------------------------------------

std::vector<uint8_t> build_message(uint32_t magic, const std::string& command,
                                   const std::vector<uint8_t>& payload);

// Compute checksum: first 4 bytes of keccak256(payload)
uint32_t compute_checksum(const uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// Version message payload
// ---------------------------------------------------------------------------

struct VersionMessage {
    uint32_t protocol_version;
    uint64_t services;         // bitfield: 1 = NODE_NETWORK
    int64_t  timestamp;
    CNetAddr addr_recv;        // recipient's address
    CNetAddr addr_from;        // sender's address
    uint64_t nonce;            // random, for self-connection detection
    std::string user_agent;    // e.g. "/FlowCoin:1.0.0/"
    uint64_t start_height;     // sender's best block height
    uint64_t node_id;          // persistent node identity (for multi-address dedup)

    std::vector<uint8_t> serialize() const;
    static bool deserialize(const uint8_t* data, size_t len, VersionMessage& out);
};

// ---------------------------------------------------------------------------
// Service flags
// ---------------------------------------------------------------------------

enum ServiceFlags : uint64_t {
    NODE_NONE    = 0,
    NODE_NETWORK = (1 << 0),   // Full node, can serve blocks
};

} // namespace flow

#endif // FLOWCOIN_NET_PROTOCOL_H

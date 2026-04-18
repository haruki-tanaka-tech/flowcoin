// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Wire protocol definitions for the FlowCoin P2P network.
//
// Layout is intentionally Bitcoin-Core-compatible everywhere except the
// magic bytes, the checksum hash (keccak256d instead of SHA-256d), and
// any message named after a feature we do not support. A node or tool
// written for Bitcoin's wire protocol parses our traffic without
// modification other than those two constants.
//
// Message format: 24-byte header + variable payload.
// Header: [4 magic][12 command][4 payload_size][4 checksum]
// Checksum is the first 4 bytes of keccak256d(payload).

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
    // Handshake
    constexpr const char* VERSION      = "version";
    constexpr const char* VERACK       = "verack";

    // Keepalive (BIP31)
    constexpr const char* PING         = "ping";
    constexpr const char* PONG         = "pong";

    // Address / peer discovery
    constexpr const char* GETADDR      = "getaddr";
    constexpr const char* ADDR         = "addr";
    constexpr const char* ADDRV2       = "addrv2";       // BIP155
    constexpr const char* SENDADDRV2   = "sendaddrv2";   // BIP155 negotiation

    // Inventory exchange
    constexpr const char* INV          = "inv";
    constexpr const char* GETDATA      = "getdata";
    constexpr const char* NOTFOUND     = "notfound";
    constexpr const char* MEMPOOL      = "mempool";      // BIP35

    // Blocks / headers
    constexpr const char* BLOCK        = "block";
    constexpr const char* TX           = "tx";
    constexpr const char* GETBLOCKS    = "getblocks";
    constexpr const char* GETHEADERS   = "getheaders";
    constexpr const char* HEADERS      = "headers";
    constexpr const char* SENDHEADERS  = "sendheaders";  // BIP130

    // Compact block relay (BIP152)
    constexpr const char* SENDCMPCT    = "sendcmpct";
    constexpr const char* CMPCTBLOCK   = "cmpctblock";
    constexpr const char* GETBLOCKTXN  = "getblocktxn";
    constexpr const char* BLOCKTXN     = "blocktxn";

    // Bloom filtering (BIP37)
    constexpr const char* FILTERLOAD   = "filterload";
    constexpr const char* FILTERADD    = "filteradd";
    constexpr const char* FILTERCLEAR  = "filterclear";
    constexpr const char* MERKLEBLOCK  = "merkleblock";

    // Fee / relay negotiation
    constexpr const char* FEEFILTER    = "feefilter";    // BIP133
    constexpr const char* WTXIDRELAY   = "wtxidrelay";   // BIP339

    // Deprecated but still recognised for forward compatibility
    constexpr const char* REJECT       = "reject";
} // namespace NetCmd

// ---------------------------------------------------------------------------
// Inventory item types (matches Bitcoin's GetDataMsg enum)
// ---------------------------------------------------------------------------

/// Bit flag OR'd into an InvType to request the witness-data variant of a
/// TX or BLOCK. Part of BIP144. FlowCoin has no witness data but keeps the
/// constant for structural compatibility with Bitcoin-wire-aware tooling.
constexpr uint32_t MSG_WITNESS_FLAG = 1u << 30;

enum InvType : uint32_t {
    INV_TX             = 1,
    INV_BLOCK          = 2,
    INV_FILTERED_BLOCK = 3,   // BIP37 merkle block
    INV_CMPCT_BLOCK    = 4,   // BIP152 compact block
    INV_WTX            = 5,   // BIP339 wtxid-based inventory
    INV_WITNESS_TX     = INV_TX    | MSG_WITNESS_FLAG,
    INV_WITNESS_BLOCK  = INV_BLOCK | MSG_WITNESS_FLAG,
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
// Version message payload (byte-for-byte compatible with Bitcoin's version
// message, minus the magic bytes on the enclosing frame and the checksum
// hash function — see file-level comment above).
//
// Field-by-field layout (wire):
//   int32   protocol_version        (4)
//   uint64  services                (8)
//   int64   timestamp               (8)
//   uint64  addr_recv_services      (8)   "services you claim" — legacy duplicate
//   bytes   addr_recv_ip            (16)
//   uint16  addr_recv_port (big-endian) (2)
//   uint64  addr_from_services      (8)   our services, again — legacy duplicate
//   bytes   addr_from_ip            (16)
//   uint16  addr_from_port (big-endian) (2)
//   uint64  nonce                   (8)
//   compact+bytes  user_agent        (variable)
//   int32   start_height            (4)
//   uint8   relay                   (1)   fRelay flag (BIP37)
// Fixed portion: 85 bytes + variable user-agent.
// ---------------------------------------------------------------------------

struct VersionMessage {
    int32_t     protocol_version    = 0;
    uint64_t    services            = 0;
    int64_t     timestamp           = 0;

    uint64_t    addr_recv_services  = 0;
    CNetAddr    addr_recv;

    uint64_t    addr_from_services  = 0;
    CNetAddr    addr_from;

    uint64_t    nonce               = 0;
    std::string user_agent;
    int32_t     start_height        = 0;
    bool        relay               = true;

    std::vector<uint8_t> serialize() const;
    static bool deserialize(const uint8_t* data, size_t len, VersionMessage& out);
};

// ---------------------------------------------------------------------------
// Service flags — bit-compatible with Bitcoin's ServiceFlags so tooling can
// parse the nServices field of a version message without remapping.
// Unsupported flags (WITNESS, BLOOM, ...) are defined but not advertised.
// ---------------------------------------------------------------------------

enum ServiceFlags : uint64_t {
    NODE_NONE            = 0,
    NODE_NETWORK         = (1u << 0),   // Serves the full chain
    NODE_BLOOM           = (1u << 2),   // BIP37 bloom filters (unsupported)
    NODE_WITNESS         = (1u << 3),   // BIP144 witness data  (unsupported)
    NODE_COMPACT_FILTERS = (1u << 6),   // BIP157/158 compact filters
    NODE_NETWORK_LIMITED = (1u << 10),  // BIP159 limited full chain (last 288)
    NODE_P2P_V2          = (1u << 11),  // BIP324 v2 transport encryption
};

// ---------------------------------------------------------------------------
// Milestone versions — same numeric values as Bitcoin Core so a peer can
// check `version < MILESTONE` in the usual idiom.
// The canonical PROTOCOL_VERSION / MIN_PROTOCOL_VERSION live in consensus.
// ---------------------------------------------------------------------------

constexpr uint32_t INIT_PROTO_VERSION        = 209;
constexpr uint32_t BIP0031_VERSION           = 60000;  // ping/pong support
constexpr uint32_t SENDHEADERS_VERSION       = 70012;  // BIP130
constexpr uint32_t FEEFILTER_VERSION         = 70013;  // BIP133
constexpr uint32_t SHORT_IDS_BLOCKS_VERSION  = 70014;  // BIP152 compact blocks
constexpr uint32_t WTXID_RELAY_VERSION       = 70016;  // BIP339

} // namespace flow

#endif // FLOWCOIN_NET_PROTOCOL_H

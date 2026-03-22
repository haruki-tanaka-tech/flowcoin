// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// FlowCoin network protocol: message types and wire format.
//
// Message format:
//   [4 bytes magic: 0x464C4F57 "FLOW"]
//   [12 bytes command: null-padded ASCII]
//   [4 bytes payload_size: LE uint32]
//   [4 bytes checksum: first 4 bytes of keccak256(payload)]
//   [payload]

#pragma once

#include "core/types.h"
#include "core/hash.h"
#include "core/serialize.h"
#include "consensus/params.h"

#include <cstring>
#include <string>
#include <vector>

namespace flow::net {

static constexpr size_t COMMAND_SIZE = 12;
static constexpr size_t HEADER_SIZE = 4 + 12 + 4 + 4; // 24 bytes

// Network message header
struct MessageHeader {
    uint32_t magic{consensus::MAINNET_MAGIC};
    char     command[COMMAND_SIZE]{};
    uint32_t payload_size{0};
    uint32_t checksum{0};

    std::string command_str() const {
        return std::string(command, strnlen(command, COMMAND_SIZE));
    }

    void set_command(const std::string& cmd) {
        std::memset(command, 0, COMMAND_SIZE);
        std::memcpy(command, cmd.data(), std::min(cmd.size(), COMMAND_SIZE));
    }

    std::array<uint8_t, HEADER_SIZE> serialize() const {
        std::array<uint8_t, HEADER_SIZE> buf{};
        write_le32(buf.data(), magic);
        std::memcpy(buf.data() + 4, command, COMMAND_SIZE);
        write_le32(buf.data() + 16, payload_size);
        write_le32(buf.data() + 20, checksum);
        return buf;
    }

    static MessageHeader deserialize(const uint8_t* data) {
        MessageHeader h;
        h.magic = read_le32(data);
        std::memcpy(h.command, data + 4, COMMAND_SIZE);
        h.payload_size = read_le32(data + 16);
        h.checksum = read_le32(data + 20);
        return h;
    }
};

// Compute the 4-byte checksum of a payload
inline uint32_t compute_checksum(const uint8_t* data, size_t len) {
    Hash256 hash = keccak256(data, len);
    return read_le32(hash.bytes());
}

// Build a complete network message (header + payload)
std::vector<uint8_t> build_message(const std::string& command,
                                    const std::vector<uint8_t>& payload);

// Message commands
namespace cmd {
    constexpr const char* VERSION    = "version";
    constexpr const char* VERACK     = "verack";
    constexpr const char* GETBLOCKS  = "getblocks";
    constexpr const char* INV        = "inv";
    constexpr const char* GETDATA    = "getdata";
    constexpr const char* BLOCK      = "block";
    constexpr const char* TX         = "tx";
    constexpr const char* PING       = "ping";
    constexpr const char* PONG       = "pong";
    constexpr const char* ADDR       = "addr";
    constexpr const char* GETADDR    = "getaddr";
}

// Version message payload
struct VersionMessage {
    uint32_t protocol_version{consensus::PROTOCOL_VERSION};
    uint64_t best_height{0};
    int64_t  timestamp{0};
    uint16_t listen_port{0}; // port this node listens on (0 = not accepting inbound)

    std::vector<uint8_t> serialize() const;
    static VersionMessage deserialize(const uint8_t* data, size_t len);
};

// Inventory item
enum class InvType : uint32_t {
    BLOCK = 1,
    TX    = 2,
};

struct InvItem {
    InvType type;
    Hash256 hash;
};

} // namespace flow::net

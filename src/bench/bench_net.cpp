// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Benchmarks for network subsystem: message serialization, protocol
// parsing, checksum computation, version message handling, and
// address manager selection.

#include "bench.h"
#include "hash/keccak.h"
#include "net/addrman.h"
#include "net/protocol.h"

#include <cstring>
#include <string>
#include <vector>

namespace flow::bench {

// ===========================================================================
// Message construction
// ===========================================================================

BENCH(Net_BuildMessage_Empty) {
    std::vector<uint8_t> empty_payload;
    for (int i = 0; i < _iterations; i++) {
        auto msg = build_message(0x464C4F57, "ping", empty_payload);
        if (msg.size() < MessageHeader::SIZE) break;
    }
}

BENCH(Net_BuildMessage_1KB) {
    std::vector<uint8_t> payload(1024, 0xAB);
    for (int i = 0; i < _iterations; i++) {
        payload[0] = static_cast<uint8_t>(i & 0xFF);
        auto msg = build_message(0x464C4F57, "block", payload);
        if (msg.size() < MessageHeader::SIZE) break;
    }
}

BENCH(Net_BuildMessage_32KB) {
    std::vector<uint8_t> payload(32 * 1024, 0xCD);
    for (int i = 0; i < _iterations; i++) {
        payload[0] = static_cast<uint8_t>(i & 0xFF);
        auto msg = build_message(0x464C4F57, "block", payload);
        if (msg.size() < MessageHeader::SIZE) break;
    }
}

// ===========================================================================
// Checksum computation
// ===========================================================================

BENCH(Net_Checksum_64B) {
    std::vector<uint8_t> data(64, 0xEE);
    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        uint32_t cs = compute_checksum(data.data(), data.size());
        (void)cs;
    }
}

BENCH(Net_Checksum_1KB) {
    std::vector<uint8_t> data(1024, 0xFF);
    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        uint32_t cs = compute_checksum(data.data(), data.size());
        (void)cs;
    }
}

BENCH(Net_Checksum_1MB) {
    std::vector<uint8_t> data(1024 * 1024, 0x42);
    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        uint32_t cs = compute_checksum(data.data(), data.size());
        (void)cs;
    }
}

// ===========================================================================
// Version message serialization
// ===========================================================================

BENCH(Net_VersionMsg_Serialize) {
    VersionMessage vmsg;
    vmsg.protocol_version = 1;
    vmsg.services = 1;
    vmsg.timestamp = 1700000000;
    vmsg.nonce = 123456789;
    vmsg.user_agent = "/FlowCoin:1.0.0/";
    vmsg.start_height = 100000;

    for (int i = 0; i < _iterations; i++) {
        vmsg.nonce = static_cast<uint64_t>(i);
        auto data = vmsg.serialize();
        if (data.empty()) break;
    }
}

BENCH(Net_VersionMsg_Deserialize) {
    VersionMessage vmsg;
    vmsg.protocol_version = 1;
    vmsg.services = 1;
    vmsg.timestamp = 1700000000;
    vmsg.nonce = 123456789;
    vmsg.user_agent = "/FlowCoin:1.0.0/";
    vmsg.start_height = 100000;
    auto data = vmsg.serialize();

    for (int i = 0; i < _iterations; i++) {
        VersionMessage parsed;
        bool ok = VersionMessage::deserialize(data.data(), data.size(), parsed);
        if (!ok) break;
    }
}

// ===========================================================================
// CNetAddr operations
// ===========================================================================

BENCH(Net_CNetAddr_FromString_IPv4) {
    for (int i = 0; i < _iterations; i++) {
        CNetAddr addr("192.168.1." + std::to_string(i % 256), 9333);
        (void)addr;
    }
}

BENCH(Net_CNetAddr_ToString) {
    CNetAddr addr("192.168.1.100", 9333);
    for (int i = 0; i < _iterations; i++) {
        std::string s = addr.to_string();
        if (s.empty()) break;
    }
}

BENCH(Net_CNetAddr_IsIPv4) {
    CNetAddr addr("192.168.1.100", 9333);
    for (int i = 0; i < _iterations; i++) {
        bool is4 = addr.is_ipv4();
        (void)is4;
    }
}

// ===========================================================================
// AddrMan operations
// ===========================================================================

BENCH(AddrMan_Add) {
    AddrMan addrman;
    for (int i = 0; i < _iterations; i++) {
        CNetAddr addr(
            std::to_string(10 + (i / 65536) % 246) + "." +
            std::to_string((i / 256) % 256) + "." +
            std::to_string(i % 256) + ".1",
            9333);
        addrman.add(addr, 1700000000 + i);
    }
}

BENCH(AddrMan_Select) {
    AddrMan addrman;
    // Pre-populate with 1000 addresses
    for (int i = 0; i < 1000; i++) {
        CNetAddr addr(
            std::to_string(10 + i / 256) + "." +
            std::to_string(i % 256) + ".1.1",
            9333);
        addrman.add(addr, 1700000000);
    }

    for (int i = 0; i < _iterations; i++) {
        CNetAddr selected = addrman.select();
        (void)selected;
    }
}

BENCH(AddrMan_GetAddresses) {
    AddrMan addrman;
    for (int i = 0; i < 1000; i++) {
        CNetAddr addr(
            std::to_string(10 + i / 256) + "." +
            std::to_string(i % 256) + ".1.1",
            9333);
        addrman.add(addr, 1700000000);
    }

    for (int i = 0; i < _iterations; i++) {
        auto addrs = addrman.get_addresses(100);
        if (addrs.empty()) break;
    }
}

BENCH(AddrMan_MarkGood) {
    AddrMan addrman;
    std::vector<CNetAddr> addrs(500);
    for (int i = 0; i < 500; i++) {
        addrs[i] = CNetAddr(
            std::to_string(10 + i / 256) + "." +
            std::to_string(i % 256) + ".1.1",
            9333);
        addrman.add(addrs[i], 1700000000);
    }

    for (int i = 0; i < _iterations; i++) {
        addrman.mark_good(addrs[i % 500]);
    }
}

// ===========================================================================
// InvItem serialization
// ===========================================================================

BENCH(Net_InvItem_Creation) {
    for (int i = 0; i < _iterations; i++) {
        InvItem item;
        item.type = (i % 2 == 0) ? INV_TX : INV_BLOCK;
        std::memset(item.hash.data(), static_cast<int>(i & 0xFF), 32);
        (void)item;
    }
}

// ===========================================================================
// MessageHeader parsing
// ===========================================================================

BENCH(Net_MessageHeader_CommandString) {
    MessageHeader hdr;
    hdr.magic = 0x464C4F57;
    std::memset(hdr.command, 0, 12);
    std::memcpy(hdr.command, "getblocks", 9);
    hdr.payload_size = 1024;
    hdr.checksum = 0xDEADBEEF;

    for (int i = 0; i < _iterations; i++) {
        std::string cmd = hdr.command_string();
        if (cmd.empty()) break;
    }
}

// ===========================================================================
// Large message construction for block relay
// ===========================================================================

BENCH(Net_BuildMessage_1MB) {
    std::vector<uint8_t> payload(1024 * 1024, 0x42);
    for (int i = 0; i < _iterations; i++) {
        payload[0] = static_cast<uint8_t>(i & 0xFF);
        auto msg = build_message(0x464C4F57, "block", payload);
        if (msg.size() < MessageHeader::SIZE) break;
    }
}

// ===========================================================================
// AddrMan large-scale operations
// ===========================================================================

BENCH(AddrMan_Add_WithSource) {
    AddrMan addrman;
    CNetAddr source("192.168.1.1", 9333);
    for (int i = 0; i < _iterations; i++) {
        CNetAddr addr(
            std::to_string(10 + (i / 65536) % 246) + "." +
            std::to_string((i / 256) % 256) + "." +
            std::to_string(i % 256) + ".1",
            9333);
        addrman.add(addr, 1700000000 + i, source);
    }
}

BENCH(AddrMan_SelectFromNew) {
    AddrMan addrman;
    for (int i = 0; i < 500; i++) {
        CNetAddr addr(
            std::to_string(10 + i / 256) + "." +
            std::to_string(i % 256) + ".1.1",
            9333);
        addrman.add(addr, 1700000000);
    }

    for (int i = 0; i < _iterations; i++) {
        CNetAddr selected = addrman.select_from_new();
        (void)selected;
    }
}

BENCH(AddrMan_Bulk_Add_1000) {
    AddrMan addrman;
    std::vector<CNetAddr> addrs(1000);
    for (int i = 0; i < 1000; i++) {
        addrs[i] = CNetAddr(
            std::to_string(10 + i / 256) + "." +
            std::to_string(i % 256) + ".1.1",
            9333);
    }

    for (int i = 0; i < _iterations; i++) {
        addrman.add(addrs, 1700000000 + i);
    }
}

} // namespace flow::bench

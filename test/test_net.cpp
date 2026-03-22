// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include <gtest/gtest.h>
#include "net/protocol.h"
#include "net/peer.h"

using namespace flow;
using namespace flow::net;

TEST(ProtocolTest, BuildAndParseMessage) {
    std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0x04};
    auto msg = build_message("ping", payload);

    // Should be header (24) + payload (4) = 28 bytes
    ASSERT_EQ(msg.size(), HEADER_SIZE + payload.size());

    // Parse header
    auto hdr = MessageHeader::deserialize(msg.data());
    EXPECT_EQ(hdr.magic, consensus::MAINNET_MAGIC);
    EXPECT_EQ(hdr.command_str(), "ping");
    EXPECT_EQ(hdr.payload_size, 4u);

    // Verify checksum
    uint32_t expected_cksum = compute_checksum(payload.data(), payload.size());
    EXPECT_EQ(hdr.checksum, expected_cksum);
}

TEST(ProtocolTest, EmptyPayload) {
    auto msg = build_message("verack", {});
    ASSERT_EQ(msg.size(), HEADER_SIZE);

    auto hdr = MessageHeader::deserialize(msg.data());
    EXPECT_EQ(hdr.command_str(), "verack");
    EXPECT_EQ(hdr.payload_size, 0u);
}

TEST(ProtocolTest, VersionMessageRoundTrip) {
    VersionMessage v;
    v.protocol_version = 1;
    v.best_height = 42;
    v.timestamp = 1742515200;

    auto bytes = v.serialize();
    auto v2 = VersionMessage::deserialize(bytes.data(), bytes.size());

    EXPECT_EQ(v2.protocol_version, 1u);
    EXPECT_EQ(v2.best_height, 42u);
    EXPECT_EQ(v2.timestamp, 1742515200);
}

TEST(PeerTest, ReceiveCompleteMessage) {
    Peer peer(1, "127.0.0.1", 9555, false);

    auto msg = build_message("ping", {0xAA, 0xBB});

    std::string received_cmd;
    std::vector<uint8_t> received_payload;

    peer.receive_data(msg.data(), msg.size(), [&](uint64_t id, const std::string& cmd,
                                                   const std::vector<uint8_t>& payload) {
        received_cmd = cmd;
        received_payload = payload;
    });

    EXPECT_EQ(received_cmd, "ping");
    ASSERT_EQ(received_payload.size(), 2u);
    EXPECT_EQ(received_payload[0], 0xAA);
    EXPECT_EQ(received_payload[1], 0xBB);
}

TEST(PeerTest, ReceiveFragmented) {
    Peer peer(1, "127.0.0.1", 9555, false);

    auto msg = build_message("pong", {0x01, 0x02, 0x03});

    int recv_count = 0;

    // Send first 10 bytes
    peer.receive_data(msg.data(), 10, [&](uint64_t, const std::string&,
                                           const std::vector<uint8_t>&) {
        recv_count++;
    });
    EXPECT_EQ(recv_count, 0); // not enough data yet

    // Send rest
    peer.receive_data(msg.data() + 10, msg.size() - 10,
        [&](uint64_t, const std::string& cmd, const std::vector<uint8_t>& payload) {
            recv_count++;
            EXPECT_EQ(cmd, "pong");
            EXPECT_EQ(payload.size(), 3u);
        });
    EXPECT_EQ(recv_count, 1);
}

TEST(PeerTest, ReceiveMultipleMessages) {
    Peer peer(1, "127.0.0.1", 9555, false);

    auto msg1 = build_message("ping", {});
    auto msg2 = build_message("pong", {});

    // Concatenate both messages
    std::vector<uint8_t> both;
    both.insert(both.end(), msg1.begin(), msg1.end());
    both.insert(both.end(), msg2.begin(), msg2.end());

    std::vector<std::string> commands;
    peer.receive_data(both.data(), both.size(),
        [&](uint64_t, const std::string& cmd, const std::vector<uint8_t>&) {
            commands.push_back(cmd);
        });

    ASSERT_EQ(commands.size(), 2u);
    EXPECT_EQ(commands[0], "ping");
    EXPECT_EQ(commands[1], "pong");
}

TEST(PeerTest, BadMagicDisconnects) {
    Peer peer(1, "127.0.0.1", 9555, false);

    auto msg = build_message("ping", {});
    // Corrupt magic
    msg[0] = 0xFF;

    peer.receive_data(msg.data(), msg.size(),
        [](uint64_t, const std::string&, const std::vector<uint8_t>&) {});

    EXPECT_EQ(peer.state(), PeerState::DISCONNECTED);
}

TEST(PeerTest, BanScore) {
    Peer peer(1, "127.0.0.1", 9555, false);
    EXPECT_FALSE(peer.add_ban_score(50));
    EXPECT_FALSE(peer.add_ban_score(49));
    EXPECT_TRUE(peer.add_ban_score(1)); // total = 100 → banned
}

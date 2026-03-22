// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "peer.h"
#include "core/time.h"
#include "consensus/params.h"

namespace flow::net {

Peer::Peer(uint64_t id, const std::string& address, uint16_t port, bool inbound) {
    info_.id = id;
    info_.address = address;
    info_.port = port;
    info_.inbound = inbound;
    info_.connect_time = get_time();
    info_.last_recv_time = get_time();
}

void Peer::receive_data(const uint8_t* data, size_t len, MessageCallback msg_callback) {
    recv_buffer_.insert(recv_buffer_.end(), data, data + len);
    info_.last_recv_time = get_time();

    // Try to parse complete messages from the buffer
    while (try_parse_message(msg_callback)) {}
}

bool Peer::try_parse_message(MessageCallback& callback) {
    if (recv_buffer_.size() < HEADER_SIZE) return false;

    MessageHeader hdr = MessageHeader::deserialize(recv_buffer_.data());

    // Verify magic
    if (hdr.magic != consensus::MAINNET_MAGIC) {
        // Invalid magic — disconnect
        recv_buffer_.clear();
        info_.state = PeerState::DISCONNECTED;
        return false;
    }

    // Check if we have the full message
    size_t total = HEADER_SIZE + hdr.payload_size;
    if (recv_buffer_.size() < total) return false;

    // Extract payload
    std::vector<uint8_t> payload(
        recv_buffer_.begin() + HEADER_SIZE,
        recv_buffer_.begin() + total);

    // Verify checksum
    if (hdr.payload_size > 0) {
        uint32_t expected = compute_checksum(payload.data(), payload.size());
        if (hdr.checksum != expected) {
            // Bad checksum — skip this message
            recv_buffer_.erase(recv_buffer_.begin(), recv_buffer_.begin() + total);
            return true; // try next message
        }
    }

    // Remove parsed bytes from buffer
    recv_buffer_.erase(recv_buffer_.begin(), recv_buffer_.begin() + total);

    // Deliver the message
    callback(info_.id, hdr.command_str(), payload);
    return true;
}

std::vector<uint8_t> Peer::make_message(const std::string& command,
                                          const std::vector<uint8_t>& payload) {
    return build_message(command, payload);
}

bool Peer::add_ban_score(int32_t score) {
    info_.ban_score += score;
    return info_.ban_score >= 100;
}

} // namespace flow::net

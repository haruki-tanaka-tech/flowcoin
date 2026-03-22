// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Peer connection management.
// Each peer has a TCP connection, send/receive buffers, and state.

#pragma once

#include "protocol.h"
#include "core/types.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <deque>

namespace flow::net {

enum class PeerState {
    CONNECTING,
    CONNECTED,
    VERSION_SENT,
    ESTABLISHED,
    DISCONNECTED,
};

struct PeerInfo {
    uint64_t id;
    std::string address;
    uint16_t port;
    PeerState state{PeerState::CONNECTING};
    uint32_t protocol_version{0};
    uint64_t best_height{0};
    int64_t  connect_time{0};
    int64_t  last_recv_time{0};
    int32_t  ban_score{0};
    bool     inbound{false};
};

// Callback for when a complete message is received from a peer
using MessageCallback = std::function<void(uint64_t peer_id,
                                            const std::string& command,
                                            const std::vector<uint8_t>& payload)>;

// Callback for when a peer disconnects
using DisconnectCallback = std::function<void(uint64_t peer_id)>;

class Peer {
public:
    explicit Peer(uint64_t id, const std::string& address, uint16_t port, bool inbound);

    uint64_t id() const { return info_.id; }
    PeerState state() const { return info_.state; }
    void set_state(PeerState s) { info_.state = s; }
    const PeerInfo& info() const { return info_; }
    PeerInfo& info() { return info_; }

    // Feed raw bytes from the TCP connection into the parser.
    // Calls msg_callback for each complete message parsed.
    void receive_data(const uint8_t* data, size_t len, MessageCallback msg_callback);

    // Queue a message to send. Returns serialized bytes.
    std::vector<uint8_t> make_message(const std::string& command,
                                       const std::vector<uint8_t>& payload);

    // Add ban score. Returns true if peer should be banned (>= 100).
    bool add_ban_score(int32_t score);

private:
    PeerInfo info_;
    std::vector<uint8_t> recv_buffer_;

    bool try_parse_message(MessageCallback& callback);
};

} // namespace flow::net

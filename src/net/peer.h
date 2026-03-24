// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Individual peer connection state for the FlowCoin P2P network.
// Each Peer object tracks the TCP connection lifecycle, protocol
// handshake progress, misbehavior scoring, and a receive buffer
// for accumulating partial wire messages.

#ifndef FLOWCOIN_NET_PEER_H
#define FLOWCOIN_NET_PEER_H

#include "net/protocol.h"

#include <cstdint>
#include <string>
#include <vector>

namespace flow {

enum class PeerState {
    CONNECTING,        // TCP connection in progress
    VERSION_SENT,      // We sent VERSION, waiting for their VERSION
    HANDSHAKE_DONE,    // Both VERSION + VERACK exchanged
    DISCONNECTED,      // Connection closed
};

class Peer {
public:
    Peer(uint64_t id, const CNetAddr& addr, bool inbound);

    uint64_t id() const { return id_; }
    const CNetAddr& addr() const { return addr_; }
    bool is_inbound() const { return inbound_; }
    PeerState state() const { return state_; }
    void set_state(PeerState s) { state_ = s; }

    // Peer's reported chain height
    uint64_t start_height() const { return start_height_; }
    void set_start_height(uint64_t h) { start_height_ = h; }

    // Version info
    uint32_t protocol_version() const { return protocol_version_; }
    void set_version(uint32_t v) { protocol_version_ = v; }
    const std::string& user_agent() const { return user_agent_; }
    void set_user_agent(const std::string& ua) { user_agent_ = ua; }

    // Nonce for self-connection detection
    uint64_t nonce() const { return nonce_; }
    void set_nonce(uint64_t n) { nonce_ = n; }

    // Service flags
    uint64_t services() const { return services_; }
    void set_services(uint64_t s) { services_ = s; }

    // Ping tracking
    int64_t last_ping_time() const { return last_ping_time_; }
    void set_last_ping_time(int64_t t) { last_ping_time_ = t; }
    uint64_t ping_nonce() const { return ping_nonce_; }
    void set_ping_nonce(uint64_t n) { ping_nonce_ = n; }
    int64_t ping_latency_us() const { return ping_latency_us_; }
    void set_ping_latency_us(int64_t us) { ping_latency_us_ = us; }

    // Misbehavior tracking
    int misbehavior_score() const { return misbehavior_; }
    void add_misbehavior(int score) { misbehavior_ += score; }
    bool should_ban() const { return misbehavior_ >= 100; }

    // Connection timing
    int64_t connect_time() const { return connect_time_; }
    void set_connect_time(int64_t t) { connect_time_ = t; }
    int64_t last_recv_time() const { return last_recv_time_; }
    void set_last_recv_time(int64_t t) { last_recv_time_ = t; }
    int64_t last_send_time() const { return last_send_time_; }
    void set_last_send_time(int64_t t) { last_send_time_ = t; }

    // Whether we have received their version message
    bool version_received() const { return version_received_; }
    void set_version_received(bool v) { version_received_ = v; }

    // Whether we have received verack
    bool verack_received() const { return verack_received_; }
    void set_verack_received(bool v) { verack_received_ = v; }

    // Whether we have sent our version
    bool version_sent() const { return version_sent_; }
    void set_version_sent(bool v) { version_sent_ = v; }

    // Receive buffer for accumulating partial messages
    std::vector<uint8_t>& recv_buffer() { return recv_buf_; }
    const std::vector<uint8_t>& recv_buffer() const { return recv_buf_; }

    // libuv TCP handle
    void* tcp_handle() const { return tcp_handle_; }
    void set_tcp_handle(void* h) { tcp_handle_ = h; }

    // Messages received/sent counters
    uint64_t messages_recv() const { return messages_recv_; }
    void inc_messages_recv() { ++messages_recv_; }
    uint64_t messages_sent() const { return messages_sent_; }
    void inc_messages_sent() { ++messages_sent_; }

    // Bytes received/sent counters
    uint64_t bytes_recv() const { return bytes_recv_; }
    void add_bytes_recv(uint64_t n) { bytes_recv_ += n; }
    uint64_t bytes_sent() const { return bytes_sent_; }
    void add_bytes_sent(uint64_t n) { bytes_sent_ += n; }

private:
    uint64_t id_;
    CNetAddr addr_;
    bool inbound_;
    PeerState state_ = PeerState::CONNECTING;
    uint64_t start_height_ = 0;
    uint32_t protocol_version_ = 0;
    std::string user_agent_;
    uint64_t nonce_ = 0;
    uint64_t services_ = 0;
    int64_t last_ping_time_ = 0;
    uint64_t ping_nonce_ = 0;
    int64_t ping_latency_us_ = 0;
    int misbehavior_ = 0;
    int64_t connect_time_ = 0;
    int64_t last_recv_time_ = 0;
    int64_t last_send_time_ = 0;
    bool version_received_ = false;
    bool verack_received_ = false;
    bool version_sent_ = false;
    std::vector<uint8_t> recv_buf_;
    void* tcp_handle_ = nullptr;
    uint64_t messages_recv_ = 0;
    uint64_t messages_sent_ = 0;
    uint64_t bytes_recv_ = 0;
    uint64_t bytes_sent_ = 0;
};

} // namespace flow

#endif // FLOWCOIN_NET_PEER_H

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Individual peer connection state for the FlowCoin P2P network.
// Each Peer object tracks the TCP connection lifecycle, protocol
// handshake progress, misbehavior scoring, bandwidth usage, sync state,
// compact block support, fee filtering, inventory tracking, and
// request timeout detection.

#ifndef FLOWCOIN_NET_PEER_H
#define FLOWCOIN_NET_PEER_H

#include "net/protocol.h"
#include "util/types.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace flow {

enum class PeerState {
    CONNECTING,        // TCP connection in progress
    VERSION_SENT,      // We sent VERSION, waiting for their VERSION
    HANDSHAKE_DONE,    // Both VERSION + VERACK exchanged
    DISCONNECTED,      // Connection closed
};

// Service flag bitfield constants
enum PeerServices : uint64_t {
    PEER_NODE_NONE            = 0,
    PEER_NODE_NETWORK         = (1ULL << 0),   // Full node, can serve blocks
    PEER_NODE_BLOOM           = (1ULL << 2),   // Supports BIP37 bloom filters
    PEER_NODE_COMPACT_FILTERS = (1ULL << 6),   // Supports BIP157/158 compact filters
    PEER_NODE_NETWORK_LIMITED = (1ULL << 10),   // Pruned node, last 288 blocks only
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
    bool has_service(uint64_t flag) const { return (services_ & flag) != 0; }

    // Ping tracking
    int64_t last_ping_time() const { return last_ping_time_; }
    void set_last_ping_time(int64_t t) { last_ping_time_ = t; }
    uint64_t ping_nonce() const { return ping_nonce_; }
    void set_ping_nonce(uint64_t n) { ping_nonce_ = n; }
    int64_t ping_latency_us() const { return ping_latency_us_; }
    void set_ping_latency_us(int64_t us) { ping_latency_us_ = us; }
    int64_t min_ping_us() const { return min_ping_us_; }

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

    // -----------------------------------------------------------------------
    // Per-message-type counters
    // -----------------------------------------------------------------------

    // Record bytes sent/received for a specific message type
    void record_message_recv(const std::string& command, uint64_t bytes);
    void record_message_sent(const std::string& command, uint64_t bytes);

    // Get per-message-type stats: { command -> (count, bytes) }
    struct MsgStats {
        uint64_t count = 0;
        uint64_t bytes = 0;
    };
    const std::map<std::string, MsgStats>& recv_msg_stats() const { return recv_msg_stats_; }
    const std::map<std::string, MsgStats>& sent_msg_stats() const { return sent_msg_stats_; }

    // -----------------------------------------------------------------------
    // Sync state tracking
    // -----------------------------------------------------------------------

    // Last header height we synced with this peer
    uint64_t synced_headers() const { return synced_headers_; }
    void set_synced_headers(uint64_t h) { synced_headers_ = h; }

    // Last block height we synced with this peer
    uint64_t synced_blocks() const { return synced_blocks_; }
    void set_synced_blocks(uint64_t h) { synced_blocks_ = h; }

    // -----------------------------------------------------------------------
    // Fee filter
    // -----------------------------------------------------------------------

    // Minimum fee rate (satoshis/kB) for transaction relay from this peer
    int64_t fee_filter() const { return fee_filter_; }
    void set_fee_filter(int64_t rate) { fee_filter_ = rate; }

    // -----------------------------------------------------------------------
    // Compact block support
    // -----------------------------------------------------------------------

    bool supports_compact_blocks() const { return supports_cmpct_; }
    void set_supports_compact_blocks(bool v) { supports_cmpct_ = v; }

    uint64_t compact_block_version() const { return cmpct_version_; }
    void set_compact_block_version(uint64_t v) { cmpct_version_ = v; }

    // Whether this peer wants high-bandwidth compact block relay
    bool wants_cmpct_high_bandwidth() const { return cmpct_high_bandwidth_; }
    void set_wants_cmpct_high_bandwidth(bool v) { cmpct_high_bandwidth_ = v; }

    // -----------------------------------------------------------------------
    // Block announcement preference
    // -----------------------------------------------------------------------

    // Peer sent "sendheaders" — prefers headers announcements over inv
    bool prefers_headers() const { return prefers_headers_; }
    void set_prefers_headers(bool v) { prefers_headers_ = v; }

    // Peer sent "sendcmpct" — prefers compact block announcements
    bool prefers_compact_blocks() const { return prefers_cmpct_; }
    void set_prefers_compact_blocks(bool v) { prefers_cmpct_ = v; }

    // -----------------------------------------------------------------------
    // Inventory tracking (deduplication)
    // -----------------------------------------------------------------------

    // Check if we already announced this hash to this peer
    bool has_announced(const uint256& hash) const;
    void mark_announced(const uint256& hash);

    // Check if we have already received this hash from this peer
    bool has_received_inv(const uint256& hash) const;
    void mark_received_inv(const uint256& hash);

    // Clear old inventory entries to bound memory (keep most recent 50000)
    void prune_inventory();

    // -----------------------------------------------------------------------
    // getdata request tracking
    // -----------------------------------------------------------------------

    struct PendingRequest {
        uint256 hash;
        InvType type;
        int64_t request_time;
    };

    // Record an outstanding getdata request
    void add_pending_request(const uint256& hash, InvType type, int64_t now);

    // Remove a fulfilled request
    void fulfill_request(const uint256& hash);

    // Get all pending requests
    const std::map<uint256, PendingRequest>& pending_requests() const {
        return pending_requests_;
    }

    // Check for stalled requests (blocks > 2s, txs > 20s)
    std::vector<PendingRequest> get_stalled_requests(int64_t now) const;

    // Count of pending requests
    size_t pending_request_count() const { return pending_requests_.size(); }

    // -----------------------------------------------------------------------
    // Bandwidth tracking (rolling window)
    // -----------------------------------------------------------------------

    // Calculate bytes/second over the last measurement period
    double recv_bandwidth() const;
    double send_bandwidth() const;

    // Update bandwidth measurement
    void update_bandwidth(int64_t now);

    // -----------------------------------------------------------------------
    // Feeler connection flag
    // -----------------------------------------------------------------------

    bool is_feeler() const { return is_feeler_; }
    void set_is_feeler(bool v) { is_feeler_ = v; }

    // -----------------------------------------------------------------------
    // Eviction protection score (higher = more protected)
    // -----------------------------------------------------------------------

    double eviction_score() const;

    // -----------------------------------------------------------------------
    // Subnet for connection diversity
    // -----------------------------------------------------------------------

    // Get /16 subnet identifier for IPv4 (first 2 octets)
    uint16_t get_subnet_id() const;

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
    int64_t min_ping_us_ = INT64_MAX;
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

    // Per-message-type counters
    std::map<std::string, MsgStats> recv_msg_stats_;
    std::map<std::string, MsgStats> sent_msg_stats_;

    // Sync state
    uint64_t synced_headers_ = 0;
    uint64_t synced_blocks_ = 0;

    // Fee filter
    int64_t fee_filter_ = 0;

    // Compact block support
    bool supports_cmpct_ = false;
    uint64_t cmpct_version_ = 0;
    bool cmpct_high_bandwidth_ = false;

    // Announcement preferences
    bool prefers_headers_ = false;
    bool prefers_cmpct_ = false;

    // Inventory tracking
    std::set<uint256> announced_inv_;
    std::set<uint256> received_inv_;

    // Outstanding getdata requests
    std::map<uint256, PendingRequest> pending_requests_;

    // Bandwidth measurement
    uint64_t bw_recv_start_bytes_ = 0;
    uint64_t bw_send_start_bytes_ = 0;
    int64_t bw_start_time_ = 0;
    double bw_recv_rate_ = 0.0;
    double bw_send_rate_ = 0.0;

    // Feeler connection flag
    bool is_feeler_ = false;
};

} // namespace flow

#endif // FLOWCOIN_NET_PEER_H

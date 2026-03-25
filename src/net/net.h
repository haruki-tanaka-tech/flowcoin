// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Network manager: manages all P2P connections using libuv for async I/O.
// Handles listening for inbound connections, connecting to outbound peers,
// reading/writing wire protocol messages, and periodic maintenance tasks
// (ping, address relay, seed node connections).

#ifndef FLOWCOIN_NET_NET_H
#define FLOWCOIN_NET_NET_H

#include "net/addrman.h"
#include "net/banman.h"
#include "net/messages.h"
#include "net/peer.h"
#include "net/protocol.h"
#include "primitives/transaction.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

struct uv_loop_s;
typedef struct uv_loop_s uv_loop_t;
struct uv_tcp_s;
typedef struct uv_tcp_s uv_tcp_t;
struct uv_timer_s;
typedef struct uv_timer_s uv_timer_t;
struct uv_stream_s;
typedef struct uv_stream_s uv_stream_t;
struct uv_connect_s;
typedef struct uv_connect_s uv_connect_t;
struct uv_handle_s;
typedef struct uv_handle_s uv_handle_t;
struct uv_buf_t;
struct uv_write_s;
typedef struct uv_write_s uv_write_t;
struct uv_async_s;
typedef struct uv_async_s uv_async_t;

namespace flow {

class ChainState;

class NetManager {
public:
    NetManager(ChainState& chain, uint16_t port, uint32_t magic);
    ~NetManager();

    // Start listening for connections and connect to seeds
    bool start();

    // Stop all connections and shut down the event loop
    void stop();

    // Run the libuv event loop (blocking call, returns when stop() is called)
    void run();

    // Connect to a specific peer address
    void connect_to(const CNetAddr& addr);

    // Send raw bytes to a peer
    void send_to(Peer& peer, const std::vector<uint8_t>& data);

    // Disconnect a peer with a reason string
    void disconnect(Peer& peer, const std::string& reason);

    // Get all connected peers (snapshot)
    std::vector<Peer*> get_peers() const;

    // Alias for get_peers()
    std::vector<Peer*> connected_peers() const;

    // Number of connected peers
    size_t peer_count() const;

    // Number of outbound peers
    size_t outbound_count() const;

    // Number of inbound peers
    size_t inbound_count() const;

    // Address manager
    AddrMan& addrman() { return addrman_; }
    const AddrMan& addrman() const { return addrman_; }

    // Our random nonce for self-connection detection
    uint64_t local_nonce() const { return local_nonce_; }

    // Broadcast a message to all handshaked peers
    void broadcast(const std::string& command, const std::vector<uint8_t>& payload);

    // Broadcast a transaction to all connected peers via INV
    void broadcast_transaction(const CTransaction& tx);

    // Broadcast a block hash to all connected peers via INV
    void broadcast_block(const uint256& block_hash);

    // Manually add a peer by IP and port (for RPC addnode)
    bool add_node(const std::string& ip, uint16_t port);

    // Get the port we are listening on
    uint16_t port() const { return port_; }

    // Get the network magic bytes
    uint32_t magic() const { return magic_; }

    // Access chain state
    ChainState& chain() { return chain_; }

    // Ban manager
    BanMan& banman() { return banman_; }
    const BanMan& banman() const { return banman_; }

    // Get per-peer info for RPC getpeerinfo
    struct PeerInfo {
        uint64_t id;
        std::string addr;
        uint64_t services;
        int64_t last_send;
        int64_t last_recv;
        int64_t conntime;
        int64_t ping_time;      // microseconds
        int64_t min_ping;       // microseconds
        uint32_t version;
        std::string subver;
        bool inbound;
        uint64_t startingheight;
        int banscore;
        uint64_t synced_headers;
        uint64_t synced_blocks;
        uint64_t bytes_sent;
        uint64_t bytes_recv;
        double send_bandwidth;  // bytes/sec
        double recv_bandwidth;  // bytes/sec
        bool prefers_headers;
        bool compact_blocks;
        int64_t fee_filter;
    };
    std::vector<PeerInfo> get_peer_info() const;

    // Total bandwidth stats
    uint64_t total_bytes_sent() const { return total_bytes_sent_.load(); }
    uint64_t total_bytes_recv() const { return total_bytes_recv_.load(); }

    // Bandwidth management
    struct BandwidthStats {
        int64_t total_sent;
        int64_t total_received;
        double send_rate_kbps;
        double recv_rate_kbps;
        int64_t uptime_seconds;
        std::map<std::string, int64_t> sent_by_type;
        std::map<std::string, int64_t> recv_by_type;
    };

    BandwidthStats get_bandwidth_stats() const;

    // Maintenance
    void clean_expired_bans() { banman_.sweep(); }
    void save_peers(const std::string& path);
    void set_max_upload_rate(int64_t bytes_per_second);
    bool can_send(size_t bytes) const;

    // Network info for RPC
    struct NetworkInfo {
        uint32_t protocol_version;
        size_t connections;
        size_t connections_in;
        size_t connections_out;
        uint64_t total_bytes_sent;
        uint64_t total_bytes_recv;
        double send_rate;
        double recv_rate;
        int64_t uptime;
        size_t known_addresses;
        size_t banned_count;
    };
    NetworkInfo get_network_info() const;

    // Connect by hostname:port string (with DNS resolution)
    bool connect_to_host(const std::string& addr_str);

    // Full outbound connection management
    void maintain_outbound_connections();

    // Full inbound handling with eviction
    void on_new_inbound(uv_stream_t* server);

    // Process all pending network events
    void process_events();

    // Network thread main loop
    void network_thread_func();

    // Start a feeler connection (test reachability of a New table address)
    void start_feeler();

    // Set the data directory for peers.dat
    void set_data_dir(const std::string& dir) { data_dir_ = dir; }

    // Save/load peers.dat
    void save_peers();
    void load_peers();

private:
    ChainState& chain_;
    uint16_t port_;
    uint32_t magic_;
    uint64_t local_nonce_;

    uv_loop_t* loop_ = nullptr;
    uv_tcp_t* server_ = nullptr;
    uv_timer_t* timer_ = nullptr;
    uv_async_t* stop_async_ = nullptr;

    mutable std::mutex peers_mutex_;
    std::unordered_map<uint64_t, std::unique_ptr<Peer>> peers_;
    uint64_t next_peer_id_ = 1;

    MessageHandler handler_;
    AddrMan addrman_;
    BanMan banman_;

    std::atomic<bool> running_{false};
    std::atomic<uint64_t> total_bytes_sent_{0};
    std::atomic<uint64_t> total_bytes_recv_{0};

    std::string data_dir_;
    int64_t last_feeler_time_ = 0;
    int64_t last_peers_save_time_ = 0;
    int64_t last_cleanup_time_ = 0;
    int64_t last_dns_seed_time_ = 0;
    int64_t start_time_ = 0;
    int64_t max_upload_rate_ = 0;  // 0 = unlimited

    // Seed nodes (ip, port)
    static const std::vector<std::pair<std::string, uint16_t>> SEED_NODES;

    // libuv callbacks (must be static, context passed via handle->data)
    static void on_new_connection(uv_stream_t* server, int status);
    static void on_connect(uv_connect_t* req, int status);
    static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
    static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
    static void on_write(uv_write_t* req, int status);
    static void on_timer(uv_timer_t* timer);
    static void on_close(uv_handle_t* handle);
    static void on_stop_async(uv_async_t* handle);

    // Process received data for a peer: parse messages from the recv buffer
    void process_recv(Peer& peer);

    // Create a new peer entry and return a reference to it
    Peer& create_peer(const CNetAddr& addr, bool inbound, uv_tcp_t* handle);

    // Remove a peer by id
    void remove_peer(uint64_t peer_id);

    // Periodic maintenance: ping peers, connect to seeds, etc.
    void on_tick();

    // Connect to seed nodes on startup
    void connect_seeds();

    // Try to maintain target number of outbound connections
    void maintain_connections();

    // Eviction logic: select an inbound peer to evict when at capacity
    Peer* select_eviction_candidate();

    // Evict a peer to make room for a new inbound connection
    void evict_inbound_if_needed();

    // Peer rotation: disconnect idle peers
    void rotate_idle_peers(int64_t now);

    // Update bandwidth tracking for all peers
    void update_peer_bandwidth(int64_t now);

    // Connection diversity: check if we have too many peers from same subnet
    bool has_subnet_diversity(const CNetAddr& addr) const;

    // DNS seed resolution on startup
    void resolve_dns_seeds();

    // Compute eviction score for a peer (higher = more valuable)
    int compute_eviction_score(const Peer& peer) const;

    // Advanced eviction with protection groups
    Peer* select_eviction_candidate_advanced();
};

} // namespace flow

#endif // FLOWCOIN_NET_NET_H

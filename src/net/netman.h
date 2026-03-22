// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Network manager: TCP server + client connections using libuv.
// Listens on port 9333, manages peer connections, routes messages.

#pragma once

#include "peer.h"
#include "protocol.h"
#include "consensus/params.h"

#include <uv.h>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace flow::net {

// Callback when a complete message arrives from a peer
using OnMessage = std::function<void(uint64_t peer_id,
                                      const std::string& command,
                                      const std::vector<uint8_t>& payload)>;

// Callback when a peer connects or disconnects
using OnPeerEvent = std::function<void(uint64_t peer_id, bool connected)>;

struct NetConfig {
    std::string bind_addr{"0.0.0.0"};
    uint16_t port{consensus::MAINNET_PORT}; // 9333
    int max_inbound{64};
    int max_outbound{8};
    std::vector<std::string> seed_nodes; // ip:port
};

class NetManager {
public:
    explicit NetManager(const NetConfig& config);
    ~NetManager();

    NetManager(const NetManager&) = delete;
    NetManager& operator=(const NetManager&) = delete;

    // Set callbacks
    void set_on_message(OnMessage cb) { on_message_ = std::move(cb); }
    void set_on_peer_event(OnPeerEvent cb) { on_peer_event_ = std::move(cb); }

    // Start the network (spawns event loop thread)
    void start();

    // Stop the network
    void stop();

    // Connect to a peer (async — connection happens in event loop)
    void connect_to(const std::string& host, uint16_t port);

    // Send a message to a specific peer
    void send_to(uint64_t peer_id, const std::string& command,
                  const std::vector<uint8_t>& payload);

    // Broadcast a message to all established peers
    void broadcast(const std::string& command, const std::vector<uint8_t>& payload);

    // Get info about all connected peers
    std::vector<PeerInfo> get_peer_info() const;

    // Update a peer's state (e.g., after version handshake)
    void update_peer(uint64_t peer_id, std::function<void(Peer&)> fn);

    // Get number of connected peers
    size_t peer_count() const;

    bool is_running() const { return running_.load(); }

private:
    NetConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> next_peer_id_{1};

    // Event loop runs in its own thread
    std::thread net_thread_;
    uv_loop_s* loop_{nullptr};
    uv_tcp_s* server_{nullptr};
    uv_async_s* stop_async_{nullptr};
    uv_async_s* work_async_{nullptr};

    // Protected by mutex
    mutable std::mutex mu_;
    std::unordered_map<uint64_t, std::shared_ptr<Peer>> peers_;
    std::unordered_map<uint64_t, uv_tcp_t*> peer_handles_; // peer_id → tcp handle

    // Pending work queue (for cross-thread operations)
    std::mutex work_mu_;
    std::vector<std::function<void()>> work_queue_;

    // Callbacks
    OnMessage on_message_;
    OnPeerEvent on_peer_event_;

    // Reconnect: outbound peers that disconnected
    struct ReconnectEntry {
        std::string host;
        uint16_t port;
        int attempts{0};
        int64_t next_try{0};
    };
    std::vector<ReconnectEntry> reconnect_list_;

    void run_loop();
    void accept_connection(uv_tcp_s* client_handle);
    void remove_peer(uint64_t peer_id);
    void process_work_queue();

    // libuv callbacks (static, dispatch to instance via handle->data)
    static void on_new_connection(uv_stream_t* server, int status);
    static void on_alloc(uv_handle_t* handle, size_t suggested, uv_buf_t* buf);
    static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
    static void on_connect(uv_connect_t* req, int status);
    static void on_stop(uv_async_t* handle);
    static void on_work(uv_async_t* handle);
};

} // namespace flow::net

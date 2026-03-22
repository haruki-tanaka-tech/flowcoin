// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "netman.h"
#include "core/time.h"

#include <uv.h>
#include <spdlog/spdlog.h>

#include <cstring>

namespace flow::net {

// Per-connection context stored in uv_tcp_t.data
struct ConnContext {
    NetManager* mgr;
    uint64_t peer_id;
    uv_tcp_t handle;
};

NetManager::NetManager(const NetConfig& config) : config_(config) {}

NetManager::~NetManager() {
    stop();
}

void NetManager::start() {
    if (running_.load()) return;
    net_thread_ = std::thread([this]() { run_loop(); });
}

void NetManager::stop() {
    if (!running_.load()) return;
    if (stop_async_) {
        uv_async_send(stop_async_);
    }
    if (net_thread_.joinable()) {
        net_thread_.join();
    }
}

void NetManager::run_loop() {
    loop_ = new uv_loop_t;
    uv_loop_init(loop_);

    // Stop async handle
    stop_async_ = new uv_async_t;
    uv_async_init(loop_, stop_async_, on_stop);
    stop_async_->data = this;

    // Work queue async handle
    work_async_ = new uv_async_t;
    uv_async_init(loop_, work_async_, on_work);
    work_async_->data = this;

    // TCP server
    server_ = new uv_tcp_t;
    uv_tcp_init(loop_, server_);
    server_->data = this;

    struct sockaddr_in addr;
    uv_ip4_addr(config_.bind_addr.c_str(), config_.port, &addr);

    int rb = uv_tcp_bind(server_, reinterpret_cast<const struct sockaddr*>(&addr), 0);
    if (rb) {
        spdlog::error("P2P bind failed on port {}: {}", config_.port, uv_strerror(rb));
        uv_close(reinterpret_cast<uv_handle_t*>(server_), nullptr);
        server_ = nullptr;
    }

    if (server_) {
        int r = uv_listen(reinterpret_cast<uv_stream_t*>(server_), 128, on_new_connection);
        if (r) {
            spdlog::error("P2P listen failed on port {}: {}", config_.port, uv_strerror(r));
            uv_close(reinterpret_cast<uv_handle_t*>(server_), nullptr);
            server_ = nullptr;
        } else {
            spdlog::info("P2P listening on {}:{}", config_.bind_addr, config_.port);
        }
    }

    // Connect to seed nodes
    for (const auto& seed : config_.seed_nodes) {
        auto colon = seed.find(':');
        if (colon != std::string::npos) {
            std::string host = seed.substr(0, colon);
            uint16_t port = static_cast<uint16_t>(std::stoi(seed.substr(colon + 1)));
            connect_to(host, port);
        }
    }

    running_.store(true);
    uv_run(loop_, UV_RUN_DEFAULT);

    // Cleanup: close all handles, then run loop to process close callbacks
    uv_walk(loop_, [](uv_handle_t* h, void*) {
        if (!uv_is_closing(h)) {
            h->data = nullptr; // prevent double-free
            uv_close(h, nullptr);
        }
    }, nullptr);
    uv_run(loop_, UV_RUN_DEFAULT);

    uv_loop_close(loop_);
    delete loop_;
    loop_ = nullptr;
    server_ = nullptr;
    stop_async_ = nullptr;
    work_async_ = nullptr;
    running_.store(false);
}

void NetManager::on_new_connection(uv_stream_t* server, int status) {
    if (status < 0) return;
    auto* mgr = static_cast<NetManager*>(server->data);

    // Enforce connection limit
    if (mgr->peer_count() >= static_cast<size_t>(mgr->config_.max_inbound + mgr->config_.max_outbound)) {
        uv_tcp_t reject;
        uv_tcp_init(server->loop, &reject);
        uv_accept(server, reinterpret_cast<uv_stream_t*>(&reject));
        uv_close(reinterpret_cast<uv_handle_t*>(&reject), nullptr);
        spdlog::warn("P2P rejected connection: max peers reached ({})", mgr->peer_count());
        return;
    }

    auto* ctx = new ConnContext;
    ctx->mgr = mgr;
    ctx->peer_id = mgr->next_peer_id_++;
    uv_tcp_init(server->loop, &ctx->handle);
    ctx->handle.data = ctx;

    if (uv_accept(server, reinterpret_cast<uv_stream_t*>(&ctx->handle)) == 0) {
        // Get peer address
        struct sockaddr_in peer_addr;
        int namelen = sizeof(peer_addr);
        uv_tcp_getpeername(&ctx->handle,
                           reinterpret_cast<struct sockaddr*>(&peer_addr), &namelen);
        char ip[64];
        uv_ip4_name(&peer_addr, ip, sizeof(ip));
        uint16_t port = ntohs(peer_addr.sin_port);

        auto peer = std::make_shared<Peer>(ctx->peer_id, ip, port, true);
        peer->set_state(PeerState::CONNECTED);

        {
            std::lock_guard lock(mgr->mu_);
            mgr->peers_[ctx->peer_id] = peer;
            mgr->peer_handles_[ctx->peer_id] = &ctx->handle;
        }

        spdlog::info("P2P inbound connection from {}:{} (id={})", ip, port, ctx->peer_id);

        if (mgr->on_peer_event_) {
            mgr->on_peer_event_(ctx->peer_id, true);
        }

        uv_read_start(reinterpret_cast<uv_stream_t*>(&ctx->handle), on_alloc, on_read);
    } else {
        uv_close(reinterpret_cast<uv_handle_t*>(&ctx->handle),
                  [](uv_handle_t* h) { delete static_cast<ConnContext*>(h->data); });
    }
}

void NetManager::connect_to(const std::string& host, uint16_t port) {
    // Schedule connect in the event loop thread
    std::lock_guard lock(work_mu_);
    work_queue_.push_back([this, host, port]() {
        auto* ctx = new ConnContext;
        ctx->mgr = this;
        ctx->peer_id = next_peer_id_++;
        uv_tcp_init(loop_, &ctx->handle);
        ctx->handle.data = ctx;

        auto* req = new uv_connect_t;
        req->data = ctx;

        struct sockaddr_in addr;
        uv_ip4_addr(host.c_str(), port, &addr);

        auto peer = std::make_shared<Peer>(ctx->peer_id, host, port, false);
        peer->set_state(PeerState::CONNECTING);

        {
            std::lock_guard lock2(mu_);
            peers_[ctx->peer_id] = peer;
        }

        spdlog::info("P2P connecting to {}:{} (id={})", host, port, ctx->peer_id);

        uv_tcp_connect(req, &ctx->handle,
                        reinterpret_cast<const struct sockaddr*>(&addr), on_connect);
    });

    if (work_async_) uv_async_send(work_async_);
}

void NetManager::on_connect(uv_connect_t* req, int status) {
    auto* ctx = static_cast<ConnContext*>(req->data);
    delete req;

    if (status < 0) {
        spdlog::warn("P2P connect failed (id={}): {}", ctx->peer_id, uv_strerror(status));
        ctx->mgr->remove_peer(ctx->peer_id);
        uv_close(reinterpret_cast<uv_handle_t*>(&ctx->handle),
                  [](uv_handle_t* h) { delete static_cast<ConnContext*>(h->data); });
        return;
    }

    {
        std::lock_guard lock(ctx->mgr->mu_);
        auto it = ctx->mgr->peers_.find(ctx->peer_id);
        if (it != ctx->mgr->peers_.end()) {
            it->second->set_state(PeerState::CONNECTED);
        }
        ctx->mgr->peer_handles_[ctx->peer_id] = &ctx->handle;
    }

    spdlog::info("P2P connected (id={})", ctx->peer_id);

    if (ctx->mgr->on_peer_event_) {
        ctx->mgr->on_peer_event_(ctx->peer_id, true);
    }

    uv_read_start(reinterpret_cast<uv_stream_t*>(&ctx->handle), on_alloc, on_read);
}

void NetManager::on_alloc(uv_handle_t*, size_t suggested, uv_buf_t* buf) {
    buf->base = new char[suggested];
    buf->len = static_cast<unsigned int>(suggested);
}

void NetManager::on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    auto* ctx = static_cast<ConnContext*>(stream->data);

    if (nread < 0) {
        delete[] buf->base;
        spdlog::debug("P2P peer {} disconnected", ctx->peer_id);
        ctx->mgr->remove_peer(ctx->peer_id);
        if (ctx->mgr->on_peer_event_) {
            ctx->mgr->on_peer_event_(ctx->peer_id, false);
        }
        uv_close(reinterpret_cast<uv_handle_t*>(stream),
                  [](uv_handle_t* h) { delete static_cast<ConnContext*>(h->data); });
        return;
    }

    if (nread > 0) {
        std::shared_ptr<Peer> peer;
        {
            std::lock_guard lock(ctx->mgr->mu_);
            auto it = ctx->mgr->peers_.find(ctx->peer_id);
            if (it != ctx->mgr->peers_.end()) {
                peer = it->second;
            }
        }

        if (peer) {
            auto on_msg = ctx->mgr->on_message_;
            peer->receive_data(reinterpret_cast<const uint8_t*>(buf->base),
                               static_cast<size_t>(nread),
                               [&on_msg](uint64_t id, const std::string& cmd,
                                         const std::vector<uint8_t>& payload) {
                                   if (on_msg) on_msg(id, cmd, payload);
                               });
        }
    }

    delete[] buf->base;
}

static void on_write_done_net(uv_write_t* req, int) {
    auto* data = static_cast<std::vector<uint8_t>*>(req->data);
    delete data;
    delete req;
}

void NetManager::send_to(uint64_t peer_id, const std::string& command,
                           const std::vector<uint8_t>& payload) {
    auto msg_data = std::make_shared<std::vector<uint8_t>>(build_message(command, payload));

    std::lock_guard lock(work_mu_);
    work_queue_.push_back([this, peer_id, msg_data]() {
        uv_tcp_t* handle = nullptr;
        {
            std::lock_guard lock2(mu_);
            auto it = peer_handles_.find(peer_id);
            if (it != peer_handles_.end()) {
                handle = it->second;
            }
        }
        if (!handle) return;

        auto* buf_data = new std::vector<uint8_t>(*msg_data);
        uv_buf_t buf = uv_buf_init(reinterpret_cast<char*>(buf_data->data()),
                                     static_cast<unsigned int>(buf_data->size()));

        auto* req = new uv_write_t;
        req->data = buf_data;
        uv_write(req, reinterpret_cast<uv_stream_t*>(handle), &buf, 1, on_write_done_net);
    });
    if (work_async_) uv_async_send(work_async_);
}

void NetManager::broadcast(const std::string& command,
                            const std::vector<uint8_t>& payload) {
    std::vector<uint64_t> ids;
    {
        std::lock_guard lock(mu_);
        for (const auto& [id, peer] : peers_) {
            ids.push_back(id);
        }
    }
    for (auto id : ids) {
        send_to(id, command, payload);
    }
}

void NetManager::remove_peer(uint64_t peer_id) {
    std::lock_guard lock(mu_);
    peers_.erase(peer_id);
    peer_handles_.erase(peer_id);
}

void NetManager::update_peer(uint64_t peer_id, std::function<void(Peer&)> fn) {
    std::lock_guard lock(mu_);
    auto it = peers_.find(peer_id);
    if (it != peers_.end()) {
        fn(*it->second);
    }
}

std::vector<PeerInfo> NetManager::get_peer_info() const {
    std::lock_guard lock(mu_);
    std::vector<PeerInfo> result;
    result.reserve(peers_.size());
    for (const auto& [id, peer] : peers_) {
        result.push_back(peer->info());
    }
    return result;
}

size_t NetManager::peer_count() const {
    std::lock_guard lock(mu_);
    return peers_.size();
}

void NetManager::on_stop(uv_async_t* handle) {
    uv_stop(handle->loop);
}

void NetManager::on_work(uv_async_t* handle) {
    auto* mgr = static_cast<NetManager*>(handle->data);
    mgr->process_work_queue();
}

void NetManager::process_work_queue() {
    std::vector<std::function<void()>> work;
    {
        std::lock_guard lock(work_mu_);
        work.swap(work_queue_);
    }
    for (auto& fn : work) {
        fn();
    }
}

} // namespace flow::net

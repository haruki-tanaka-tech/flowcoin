// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// HTTP JSON-RPC server on localhost:9334 using libuv.
// Accepts POST requests with JSON-RPC body, returns JSON-RPC response.
// Localhost only by default — no external access.

#pragma once

#include "server.h"
#include <cstdint>
#include <string>
#include <atomic>

struct uv_loop_s;
struct uv_tcp_s;
struct uv_async_s;

namespace flow::rpc {

class HttpServer {
public:
    // Bind to addr:port. Default: 127.0.0.1:9334
    HttpServer(RpcServer& rpc, const std::string& bind_addr = "127.0.0.1",
               uint16_t port = 9334);
    ~HttpServer();

    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;

    // Start the server (runs the libuv event loop in a separate thread).
    void start();

    // Stop the server.
    void stop();

    bool is_running() const { return running_.load(); }

private:
    RpcServer& rpc_;
    std::string bind_addr_;
    uint16_t port_;
    std::atomic<bool> running_{false};

    uv_loop_s* loop_{nullptr};
    uv_tcp_s* tcp_{nullptr};
    uv_async_s* stop_handle_{nullptr};

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace flow::rpc

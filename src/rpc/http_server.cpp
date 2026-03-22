// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Minimal HTTP server for JSON-RPC using libuv.
// Parses just enough HTTP to extract the POST body.
// No TLS — localhost only.

#include "http_server.h"

#include <uv.h>
#include <cstring>
#include <string>
#include <thread>
#include <spdlog/spdlog.h>

namespace flow::rpc {

struct HttpServer::Impl {
    std::thread server_thread;
};

// Per-connection context
struct ClientContext {
    uv_tcp_t handle;
    RpcServer* rpc;
    std::string recv_buf;
};

static void on_close(uv_handle_t* handle) {
    auto* ctx = static_cast<ClientContext*>(handle->data);
    delete ctx;
}

static void on_write_done(uv_write_t* req, int) {
    auto* buf = static_cast<std::string*>(req->data);
    uv_handle_t* handle = reinterpret_cast<uv_handle_t*>(req->handle);
    delete buf;
    delete req;
    // Close connection after response (Connection: close)
    if (!uv_is_closing(handle)) {
        uv_close(handle, on_close);
    }
}

static void send_response(uv_stream_t* client, const std::string& json_body) {
    auto* response = new std::string();
    *response = "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: " + std::to_string(json_body.size()) + "\r\n"
                "Connection: close\r\n"
                "\r\n" + json_body;

    uv_buf_t buf = uv_buf_init(response->data(), static_cast<unsigned int>(response->size()));

    auto* req = new uv_write_t;
    req->data = response;
    uv_write(req, client, &buf, 1, on_write_done);
}

static void send_error(uv_stream_t* client, int http_code, const std::string& msg) {
    std::string body = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"" + msg + "\"}}";
    auto* response = new std::string();
    *response = "HTTP/1.1 " + std::to_string(http_code) + " Error\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: " + std::to_string(body.size()) + "\r\n"
                "Connection: close\r\n"
                "\r\n" + body;

    uv_buf_t buf = uv_buf_init(response->data(), static_cast<unsigned int>(response->size()));

    auto* req = new uv_write_t;
    req->data = response;
    uv_write(req, client, &buf, 1, on_write_done);
}

// Extract HTTP POST body from raw data.
// Returns empty string if not a complete POST request.
static std::string extract_body(const std::string& raw) {
    // Find end of headers
    auto header_end = raw.find("\r\n\r\n");
    if (header_end == std::string::npos) return "";

    size_t body_start = header_end + 4;

    // Find Content-Length
    auto cl_pos = raw.find("Content-Length:");
    if (cl_pos == std::string::npos) cl_pos = raw.find("content-length:");
    if (cl_pos == std::string::npos) {
        // No Content-Length — return whatever is after headers
        return raw.substr(body_start);
    }

    size_t val_start = cl_pos + 15; // skip "Content-Length:"
    while (val_start < raw.size() && raw[val_start] == ' ') val_start++;
    auto val_end = raw.find("\r\n", val_start);
    if (val_end == std::string::npos) return "";

    size_t content_length = std::stoul(raw.substr(val_start, val_end - val_start));

    // Check if we have the full body
    if (raw.size() < body_start + content_length) return "";

    return raw.substr(body_start, content_length);
}

static void alloc_buffer(uv_handle_t*, size_t suggested, uv_buf_t* buf) {
    buf->base = new char[suggested];
    buf->len = static_cast<unsigned int>(suggested);
}

static void on_read(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf) {
    auto* ctx = static_cast<ClientContext*>(client->data);

    if (nread < 0) {
        delete[] buf->base;
        uv_close(reinterpret_cast<uv_handle_t*>(client), on_close);
        return;
    }

    if (nread > 0) {
        ctx->recv_buf.append(buf->base, static_cast<size_t>(nread));
    }
    delete[] buf->base;

    // Check if we have a complete request
    std::string body = extract_body(ctx->recv_buf);
    if (body.empty()) return; // need more data

    // Check method is POST
    if (ctx->recv_buf.substr(0, 4) != "POST") {
        send_error(client, 405, "Method Not Allowed");
        uv_close(reinterpret_cast<uv_handle_t*>(client), on_close);
        return;
    }

    // Process JSON-RPC
    std::string response = ctx->rpc->handle_request(body);
    send_response(client, response);

    // Close after response (HTTP/1.0 style — simple)
    // The on_write_done callback will close
}

static void on_new_connection(uv_stream_t* server, int status) {
    if (status < 0) return;

    auto* ctx = new ClientContext;
    ctx->rpc = static_cast<RpcServer*>(server->data);

    uv_tcp_init(server->loop, &ctx->handle);
    ctx->handle.data = ctx;

    if (uv_accept(server, reinterpret_cast<uv_stream_t*>(&ctx->handle)) == 0) {
        uv_read_start(reinterpret_cast<uv_stream_t*>(&ctx->handle), alloc_buffer, on_read);
    } else {
        uv_close(reinterpret_cast<uv_handle_t*>(&ctx->handle), on_close);
    }
}

static void on_stop(uv_async_t* handle) {
    uv_stop(handle->loop);
}

HttpServer::HttpServer(RpcServer& rpc, const std::string& bind_addr, uint16_t port)
    : rpc_(rpc), bind_addr_(bind_addr), port_(port), impl_(std::make_unique<Impl>()) {}

HttpServer::~HttpServer() {
    stop();
}

void HttpServer::start() {
    if (running_.load()) return;

    impl_->server_thread = std::thread([this]() {
        loop_ = new uv_loop_t;
        uv_loop_init(loop_);

        tcp_ = new uv_tcp_t;
        uv_tcp_init(loop_, tcp_);
        tcp_->data = &rpc_;

        struct sockaddr_in addr;
        uv_ip4_addr(bind_addr_.c_str(), port_, &addr);
        uv_tcp_bind(tcp_, reinterpret_cast<const struct sockaddr*>(&addr), 0);

        int r = uv_listen(reinterpret_cast<uv_stream_t*>(tcp_), 128, on_new_connection);
        if (r) {
            spdlog::error("RPC listen failed: {}", uv_strerror(r));
            delete tcp_;
            uv_loop_close(loop_);
            delete loop_;
            return;
        }

        stop_handle_ = new uv_async_t;
        uv_async_init(loop_, stop_handle_, on_stop);

        running_.store(true);
        spdlog::info("RPC server listening on {}:{}", bind_addr_, port_);

        uv_run(loop_, UV_RUN_DEFAULT);

        // Cleanup
        uv_close(reinterpret_cast<uv_handle_t*>(tcp_), [](uv_handle_t* h) { delete reinterpret_cast<uv_tcp_t*>(h); });
        uv_close(reinterpret_cast<uv_handle_t*>(stop_handle_), [](uv_handle_t* h) { delete reinterpret_cast<uv_async_t*>(h); });
        uv_run(loop_, UV_RUN_DEFAULT); // process close callbacks
        uv_loop_close(loop_);
        delete loop_;
        loop_ = nullptr;
        tcp_ = nullptr;
        stop_handle_ = nullptr;
        running_.store(false);
    });
}

void HttpServer::stop() {
    if (!running_.load()) return;
    if (stop_handle_) {
        uv_async_send(stop_handle_);
    }
    if (impl_->server_thread.joinable()) {
        impl_->server_thread.join();
    }
}

} // namespace flow::rpc

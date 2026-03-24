// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// HTTP JSON-RPC server for FlowCoin using libuv.
// Supports Basic authentication, JSON-RPC 2.0 dispatch, batch requests,
// keep-alive connections, request timeouts, CORS headers, rate limiting,
// and .cookie-based authentication.

#ifndef FLOWCOIN_RPC_SERVER_H
#define FLOWCOIN_RPC_SERVER_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <json.hpp>
#include <uv.h>

namespace flow {

using json = nlohmann::json;

/// RPC method signature: takes JSON params, returns JSON result.
/// On error, throw std::runtime_error with a descriptive message.
using RpcMethod = std::function<json(const json& params)>;

class RpcServer {
public:
    RpcServer(uint16_t port, const std::string& user, const std::string& password);
    ~RpcServer();

    // Non-copyable
    RpcServer(const RpcServer&) = delete;
    RpcServer& operator=(const RpcServer&) = delete;

    /// Register an RPC method by name.
    void register_method(const std::string& name, RpcMethod method);

    /// Check if a method is registered.
    bool has_method(const std::string& name) const;

    /// Get list of all registered method names.
    std::vector<std::string> get_method_names() const;

    /// Get the number of registered methods.
    size_t method_count() const;

    /// Start the server on the given libuv event loop. Non-blocking.
    bool start(uv_loop_t* loop);

    /// Stop the server and close all connections.
    void stop();

    /// Check if the server is running.
    bool is_running() const { return running_; }

    /// Get the port the server is listening on.
    uint16_t port() const { return port_; }

    // -------------------------------------------------------------------
    // Configuration
    // -------------------------------------------------------------------

    /// Set the request timeout in seconds (default 30).
    void set_timeout(int seconds) { timeout_seconds_ = seconds; }

    /// Set the maximum request body size in bytes (default 8MB).
    void set_max_body_size(size_t bytes) { max_body_size_ = bytes; }

    /// Enable or disable CORS headers (default disabled).
    void set_cors_enabled(bool enabled) { cors_enabled_ = enabled; }

    /// Set allowed CORS origin (default "*").
    void set_cors_origin(const std::string& origin) { cors_origin_ = origin; }

    /// Set rate limit: max requests per second per IP (0 = no limit).
    void set_rate_limit(int max_per_second) { rate_limit_ = max_per_second; }

    /// Enable cookie-based authentication from a file.
    void set_cookie_auth(const std::string& cookie_path);

    /// Get server statistics.
    struct ServerStats {
        uint64_t total_requests;
        uint64_t successful_requests;
        uint64_t failed_requests;
        uint64_t auth_failures;
        uint64_t rate_limited;
        int64_t uptime_seconds;
    };
    ServerStats get_stats() const;

private:
    uint16_t port_;
    std::string user_;
    std::string password_;
    std::string auth_header_;  // Pre-computed "Basic base64(user:pass)"
    std::string cookie_auth_;  // Cookie-based auth string

    uv_tcp_t server_;
    bool running_ = false;
    std::unordered_map<std::string, RpcMethod> methods_;
    mutable std::mutex methods_mutex_;

    // Configuration
    int timeout_seconds_ = 30;
    size_t max_body_size_ = 8 * 1024 * 1024; // 8 MB
    bool cors_enabled_ = false;
    std::string cors_origin_ = "*";
    int rate_limit_ = 0; // 0 = no limit

    // Statistics
    mutable std::atomic<uint64_t> total_requests_{0};
    mutable std::atomic<uint64_t> successful_requests_{0};
    mutable std::atomic<uint64_t> failed_requests_{0};
    mutable std::atomic<uint64_t> auth_failures_{0};
    mutable std::atomic<uint64_t> rate_limited_{0};
    std::chrono::steady_clock::time_point start_time_;

    // Rate limiting state
    mutable std::mutex rate_mutex_;
    struct RateEntry {
        int64_t window_start;
        int count;
    };
    std::map<std::string, RateEntry> rate_state_;

    // Per-connection context for accumulating request data
    struct ClientContext {
        RpcServer* server;
        std::string buffer;
        std::string client_ip;
        std::chrono::steady_clock::time_point connect_time;
    };

    // libuv callbacks
    static void on_connection(uv_stream_t* server, int status);
    static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
    static void on_read(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf);
    static void on_write_done(uv_write_t* req, int status);
    static void on_close(uv_handle_t* handle);

    /// Process an HTTP request string, return an HTTP response string.
    std::string process_request(const std::string& request,
                                 const std::string& client_ip);

    /// Parse JSON-RPC request, dispatch to registered method, return JSON-RPC response.
    json dispatch(const json& request);

    /// Validate the Authorization header against stored credentials.
    bool check_auth(const std::string& request) const;

    /// Check rate limit for a client IP. Returns true if allowed.
    bool check_rate_limit(const std::string& client_ip);

    /// Build a complete HTTP response from a status code and body.
    std::string http_response(int code, const std::string& body) const;

    /// Send an HTTP response back to the client and close the connection.
    static void send_response(uv_stream_t* client, const std::string& response);

    /// Base64-encode a string (for auth header construction).
    static std::string base64_encode(const std::string& input);

    /// Extract an HTTP header value by name (case-insensitive).
    static std::string get_header(const std::string& request, const std::string& name);

    /// Extract the HTTP body (everything after \r\n\r\n).
    static std::string get_body(const std::string& request);

    /// Extract the HTTP method (GET, POST, etc.) from the request line.
    static std::string get_http_method(const std::string& request);

    /// Extract the request path from the request line.
    static std::string get_request_path(const std::string& request);

    /// Extract the client IP address from a libuv stream handle.
    static std::string get_client_ip(uv_stream_t* client);
};

} // namespace flow

#endif // FLOWCOIN_RPC_SERVER_H

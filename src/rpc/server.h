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
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "util/types.h"

#include <json.hpp>
#include <uv.h>

namespace flow {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// HttpRequest — parsed HTTP request
// ---------------------------------------------------------------------------

struct HttpRequest {
    std::string method;
    std::string path;
    std::string query;
    std::string http_version;
    std::string client_ip;
    std::map<std::string, std::string> headers;
    std::vector<uint8_t> body;

    std::string get_header(const std::string& name) const;
    bool has_header(const std::string& name) const;
    std::string content_type() const;
    size_t content_length() const;
    bool keep_alive() const;
    std::string auth_user() const;
    std::string auth_password() const;
};

// ---------------------------------------------------------------------------
// HttpResponse — HTTP response builder
// ---------------------------------------------------------------------------

class HttpResponse {
public:
    explicit HttpResponse(int status_code = 200);

    HttpResponse& set_status(int code);
    HttpResponse& set_header(const std::string& name, const std::string& value);
    HttpResponse& set_body(const std::string& body);
    HttpResponse& set_body(const std::vector<uint8_t>& body);
    HttpResponse& set_json(const nlohmann::json& j);
    HttpResponse& set_content_type(const std::string& type);
    HttpResponse& enable_cors();
    HttpResponse& set_keep_alive(bool enabled);

    std::vector<uint8_t> serialize() const;

    static HttpResponse ok(const nlohmann::json& j);
    static HttpResponse error(int code, const std::string& message);
    static HttpResponse not_found();
    static HttpResponse unauthorized();
    static HttpResponse method_not_allowed();
    static HttpResponse too_many_requests();
    static HttpResponse internal_error(const std::string& msg);
    static std::string status_text(int code);

private:
    int status_;
    std::map<std::string, std::string> headers_;
    std::vector<uint8_t> body_;
};

// ---------------------------------------------------------------------------
// HttpParser — stateful HTTP/1.1 parser for keep-alive connections
// ---------------------------------------------------------------------------

class HttpParser {
public:
    enum class State {
        READING_REQUEST_LINE,
        READING_HEADERS,
        READING_BODY,
        COMPLETE,
        ERROR
    };

    size_t feed(const uint8_t* data, size_t len);
    State state() const;
    bool is_complete() const;
    bool has_error() const;
    std::string error_message() const;
    HttpRequest get_request() const;
    void reset();

private:
    State state_ = State::READING_REQUEST_LINE;
    HttpRequest req_;
    std::string line_buffer_;
    size_t body_received_ = 0;
    size_t body_expected_ = 0;
    std::string error_;

    bool parse_request_line(const std::string& line);
    bool parse_header_line(const std::string& line);
};

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
    bool is_running() const { return running_.load(); }

    /// Get the port the server is listening on.
    uint16_t port() const { return port_; }

    // -------------------------------------------------------------------
    // Configuration
    // -------------------------------------------------------------------

    /// Set the request timeout in seconds (default 30).
    void set_timeout(int seconds);

    /// Set the maximum request body size in bytes (default 8MB).
    void set_max_body_size(size_t bytes);

    /// Enable or disable CORS headers (default disabled).
    void set_cors_enabled(bool enabled) { cors_enabled_ = enabled; }

    /// Set allowed CORS origin (default "*").
    void set_cors_origin(const std::string& origin);

    /// Set rate limit: max requests per second per IP (0 = no limit).
    void set_rate_limit(int max_per_second);

    /// Enable cookie-based authentication from a file.
    void set_cookie_auth(const std::string& cookie_path);

    /// Generate a .cookie file with random credentials in the given datadir.
    /// Sets file permissions to 0600 (owner-only). Returns true on success.
    bool generate_cookie(const std::string& datadir);

    /// Remove the .cookie file from the given datadir.
    static void remove_cookie(const std::string& datadir);

    /// Get the full path to the .cookie file for the given datadir.
    static std::string cookie_filepath(const std::string& datadir);

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
    std::atomic<bool> running_{false};
    std::unordered_map<std::string, RpcMethod> methods_;
    mutable std::mutex methods_mutex_;

    // Configuration
    int timeout_seconds_ = 30;
    size_t max_body_size_ = 256 * 1024 * 1024; // 256 MB
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

    // --- Request routing ---
    void route_request(const HttpRequest& req, HttpResponse& resp);
    void handle_rest_request(const HttpRequest& req, HttpResponse& resp);

    // --- Connection tracking ---
    struct RpcConnection {
        uint64_t id;
        std::string client_ip;
        int64_t connected_at;
        int requests_served;
        int64_t last_request_at;
        bool authenticated;
        bool keep_alive;
    };

    mutable std::mutex conn_mutex_;
    std::map<uint64_t, RpcConnection> active_connections_;
    int max_connections_ = 100;

    void track_connection(uint64_t id, const std::string& client_ip);
    void untrack_connection(uint64_t id);
    void update_connection(uint64_t id);
    std::vector<RpcConnection> get_connections() const;
    void set_max_connections(int max_conn);

    // --- Long polling ---
    struct LongPollContext {
        uint64_t target_height = 0;
        uint256 target_hash;
        int64_t timeout = 0;
        std::function<void(const json&)> callback;
    };

    mutable std::mutex poll_mutex_;
    std::vector<LongPollContext> long_polls_;

    void add_long_poll(LongPollContext ctx);
    void notify_new_block(uint64_t height, const uint256& hash);
    void expire_long_polls();

    // --- Whitelist / blacklist ---
    mutable std::mutex acl_mutex_;
    std::set<std::string> whitelist_;
    std::set<std::string> blacklist_;

    void add_whitelist(const std::string& ip);
    void remove_whitelist(const std::string& ip);
    void add_blacklist(const std::string& ip);
    void remove_blacklist(const std::string& ip);
    bool is_allowed(const std::string& ip) const;

    // --- Method introspection ---
    json build_help_text() const;
    json get_server_info() const;
};

} // namespace flow

#endif // FLOWCOIN_RPC_SERVER_H

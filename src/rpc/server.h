// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// HTTP JSON-RPC server for FlowCoin using libuv.
// Supports Basic authentication, JSON-RPC 2.0 dispatch, and non-blocking I/O.

#ifndef FLOWCOIN_RPC_SERVER_H
#define FLOWCOIN_RPC_SERVER_H

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>

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

    /// Start the server on the given libuv event loop. Non-blocking.
    bool start(uv_loop_t* loop);

    /// Stop the server and close all connections.
    void stop();

private:
    uint16_t port_;
    std::string user_;
    std::string password_;
    std::string auth_header_;  // Pre-computed "Basic base64(user:pass)"

    uv_tcp_t server_;
    bool running_ = false;
    std::unordered_map<std::string, RpcMethod> methods_;
    mutable std::mutex methods_mutex_;

    // Per-connection context for accumulating request data
    struct ClientContext {
        RpcServer* server;
        std::string buffer;
    };

    // libuv callbacks
    static void on_connection(uv_stream_t* server, int status);
    static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
    static void on_read(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf);
    static void on_write_done(uv_write_t* req, int status);
    static void on_close(uv_handle_t* handle);

    /// Process an HTTP request string, return an HTTP response string.
    std::string process_request(const std::string& request);

    /// Parse JSON-RPC request, dispatch to registered method, return JSON-RPC response.
    json dispatch(const json& request);

    /// Validate the Authorization header against stored credentials.
    bool check_auth(const std::string& request) const;

    /// Build a complete HTTP response from a status code and body.
    static std::string http_response(int code, const std::string& body);

    /// Send an HTTP response back to the client and close the connection.
    static void send_response(uv_stream_t* client, const std::string& response);

    /// Base64-encode a string (for auth header construction).
    static std::string base64_encode(const std::string& input);

    /// Extract an HTTP header value by name (case-insensitive).
    static std::string get_header(const std::string& request, const std::string& name);

    /// Extract the HTTP body (everything after \r\n\r\n).
    static std::string get_body(const std::string& request);
};

} // namespace flow

#endif // FLOWCOIN_RPC_SERVER_H

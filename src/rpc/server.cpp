// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "rpc/server.h"
#include "logging.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace flow {

// ---------------------------------------------------------------------------
// Base64 encoding (for Basic auth)
// ---------------------------------------------------------------------------

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string RpcServer::base64_encode(const std::string& input) {
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);
    const auto* src = reinterpret_cast<const uint8_t*>(input.data());
    size_t len = input.size();

    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(src[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(src[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(src[i + 2]);

        out.push_back(b64_table[(n >> 18) & 0x3F]);
        out.push_back(b64_table[(n >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? b64_table[(n >> 6) & 0x3F] : '=');
        out.push_back((i + 2 < len) ? b64_table[n & 0x3F] : '=');
    }
    return out;
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

std::string RpcServer::get_header(const std::string& request, const std::string& name) {
    // Case-insensitive search for "Name: value\r\n"
    std::string lower_req = request;
    std::string lower_name = name;
    std::transform(lower_req.begin(), lower_req.end(), lower_req.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    std::string search = lower_name + ":";
    auto pos = lower_req.find(search);
    if (pos == std::string::npos) return "";

    // Find the value start (skip whitespace after colon)
    size_t val_start = pos + search.size();
    while (val_start < request.size() && request[val_start] == ' ') val_start++;

    // Find end of line
    auto eol = request.find("\r\n", val_start);
    if (eol == std::string::npos) eol = request.size();

    return request.substr(val_start, eol - val_start);
}

std::string RpcServer::get_body(const std::string& request) {
    auto sep = request.find("\r\n\r\n");
    if (sep == std::string::npos) return "";
    return request.substr(sep + 4);
}

std::string RpcServer::get_http_method(const std::string& request) {
    auto space = request.find(' ');
    if (space == std::string::npos) return "";
    return request.substr(0, space);
}

std::string RpcServer::get_request_path(const std::string& request) {
    auto first_space = request.find(' ');
    if (first_space == std::string::npos) return "/";
    auto second_space = request.find(' ', first_space + 1);
    if (second_space == std::string::npos) return "/";
    return request.substr(first_space + 1, second_space - first_space - 1);
}

std::string RpcServer::get_client_ip(uv_stream_t* client) {
    struct sockaddr_storage addr;
    int addr_len = sizeof(addr);
    if (uv_tcp_getpeername(reinterpret_cast<uv_tcp_t*>(client),
                            reinterpret_cast<struct sockaddr*>(&addr),
                            &addr_len) != 0) {
        return "unknown";
    }

    char ip[INET6_ADDRSTRLEN] = {0};
    if (addr.ss_family == AF_INET) {
        auto* s = reinterpret_cast<struct sockaddr_in*>(&addr);
        uv_ip4_name(s, ip, sizeof(ip));
    } else if (addr.ss_family == AF_INET6) {
        auto* s = reinterpret_cast<struct sockaddr_in6*>(&addr);
        uv_ip6_name(s, ip, sizeof(ip));
    }

    return std::string(ip);
}

std::string RpcServer::http_response(int code, const std::string& body) const {
    std::string status_text;
    switch (code) {
        case 200: status_text = "OK"; break;
        case 400: status_text = "Bad Request"; break;
        case 401: status_text = "Unauthorized"; break;
        case 403: status_text = "Forbidden"; break;
        case 404: status_text = "Not Found"; break;
        case 405: status_text = "Method Not Allowed"; break;
        case 413: status_text = "Payload Too Large"; break;
        case 429: status_text = "Too Many Requests"; break;
        case 500: status_text = "Internal Server Error"; break;
        case 503: status_text = "Service Unavailable"; break;
        default:  status_text = "Error"; break;
    }

    std::string resp;
    resp += "HTTP/1.1 " + std::to_string(code) + " " + status_text + "\r\n";
    resp += "Content-Type: application/json\r\n";
    resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    resp += "Connection: close\r\n";
    resp += "Server: FlowCoin-RPC/1.0\r\n";

    // CORS headers
    if (cors_enabled_) {
        resp += "Access-Control-Allow-Origin: " + cors_origin_ + "\r\n";
        resp += "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n";
        resp += "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
        resp += "Access-Control-Max-Age: 86400\r\n";
    }

    resp += "\r\n";
    resp += body;
    return resp;
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

RpcServer::RpcServer(uint16_t port, const std::string& user, const std::string& password)
    : port_(port), user_(user), password_(password) {
    std::memset(&server_, 0, sizeof(server_));
    auth_header_ = "Basic " + base64_encode(user + ":" + password);
    start_time_ = std::chrono::steady_clock::now();
}

RpcServer::~RpcServer() {
    stop();
}

// ---------------------------------------------------------------------------
// Method registration
// ---------------------------------------------------------------------------

void RpcServer::register_method(const std::string& name, RpcMethod method) {
    std::lock_guard<std::mutex> lock(methods_mutex_);
    methods_[name] = std::move(method);
}

bool RpcServer::has_method(const std::string& name) const {
    std::lock_guard<std::mutex> lock(methods_mutex_);
    return methods_.count(name) > 0;
}

std::vector<std::string> RpcServer::get_method_names() const {
    std::lock_guard<std::mutex> lock(methods_mutex_);
    std::vector<std::string> names;
    names.reserve(methods_.size());
    for (const auto& [name, method] : methods_) {
        names.push_back(name);
    }
    std::sort(names.begin(), names.end());
    return names;
}

size_t RpcServer::method_count() const {
    std::lock_guard<std::mutex> lock(methods_mutex_);
    return methods_.size();
}

// ---------------------------------------------------------------------------
// Cookie auth
// ---------------------------------------------------------------------------

void RpcServer::set_cookie_auth(const std::string& cookie_path) {
    std::ifstream file(cookie_path);
    if (!file.is_open()) {
        LogWarn("rpc", "Failed to open cookie file: %s", cookie_path.c_str());
        return;
    }

    std::string cookie_content;
    std::getline(file, cookie_content);

    if (!cookie_content.empty()) {
        cookie_auth_ = "Basic " + base64_encode(cookie_content);
        LogInfo("rpc", "Loaded cookie authentication from %s", cookie_path.c_str());
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

RpcServer::ServerStats RpcServer::get_stats() const {
    ServerStats stats;
    stats.total_requests = total_requests_.load();
    stats.successful_requests = successful_requests_.load();
    stats.failed_requests = failed_requests_.load();
    stats.auth_failures = auth_failures_.load();
    stats.rate_limited = rate_limited_.load();

    auto now = std::chrono::steady_clock::now();
    stats.uptime_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        now - start_time_).count();

    return stats;
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

bool RpcServer::check_rate_limit(const std::string& client_ip) {
    if (rate_limit_ <= 0) return true;

    std::lock_guard<std::mutex> lock(rate_mutex_);

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    auto it = rate_state_.find(client_ip);
    if (it == rate_state_.end()) {
        rate_state_[client_ip] = {now, 1};
        return true;
    }

    // Check if we're in a new window
    if (now - it->second.window_start >= 1) {
        it->second.window_start = now;
        it->second.count = 1;
        return true;
    }

    // Same second window
    it->second.count++;
    if (it->second.count > rate_limit_) {
        rate_limited_++;
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Start / Stop
// ---------------------------------------------------------------------------

bool RpcServer::start(uv_loop_t* loop) {
    if (running_) return false;

    int r = uv_tcp_init(loop, &server_);
    if (r != 0) {
        LogError("rpc", "Failed to init TCP handle: %s", uv_strerror(r));
        return false;
    }
    server_.data = this;

    struct sockaddr_in addr;
    uv_ip4_addr("127.0.0.1", port_, &addr);

    r = uv_tcp_bind(&server_, reinterpret_cast<const struct sockaddr*>(&addr), 0);
    if (r != 0) {
        LogError("rpc", "Failed to bind RPC server to port %d: %s", port_, uv_strerror(r));
        return false;
    }

    r = uv_listen(reinterpret_cast<uv_stream_t*>(&server_), 128, on_connection);
    if (r != 0) {
        LogError("rpc", "Failed to listen on port %d: %s", port_, uv_strerror(r));
        return false;
    }

    running_ = true;
    start_time_ = std::chrono::steady_clock::now();
    LogInfo("rpc", "JSON-RPC server listening on 127.0.0.1:%d", port_);
    return true;
}

void RpcServer::stop() {
    if (!running_) return;
    running_ = false;

    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&server_))) {
        uv_close(reinterpret_cast<uv_handle_t*>(&server_), nullptr);
    }

    LogInfo("rpc", "RPC server stopped");
}

// ---------------------------------------------------------------------------
// libuv callbacks
// ---------------------------------------------------------------------------

void RpcServer::on_connection(uv_stream_t* server, int status) {
    if (status < 0) {
        LogError("rpc", "Connection error: %s", uv_strerror(status));
        return;
    }

    auto* self = static_cast<RpcServer*>(server->data);

    auto* client = new uv_tcp_t;
    uv_tcp_init(server->loop, client);

    auto* ctx = new ClientContext{self, "", "", std::chrono::steady_clock::now()};
    client->data = ctx;

    if (uv_accept(server, reinterpret_cast<uv_stream_t*>(client)) == 0) {
        // Extract client IP for logging and rate limiting
        ctx->client_ip = get_client_ip(reinterpret_cast<uv_stream_t*>(client));
        uv_read_start(reinterpret_cast<uv_stream_t*>(client), on_alloc, on_read);
    } else {
        delete ctx;
        uv_close(reinterpret_cast<uv_handle_t*>(client), on_close);
    }
}

void RpcServer::on_alloc(uv_handle_t* /*handle*/, size_t suggested_size, uv_buf_t* buf) {
    buf->base = new char[suggested_size];
    buf->len = suggested_size;
}

void RpcServer::on_read(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf) {
    auto* ctx = static_cast<ClientContext*>(client->data);

    if (nread > 0) {
        ctx->buffer.append(buf->base, static_cast<size_t>(nread));
    }

    delete[] buf->base;

    if (nread < 0) {
        if (nread != UV_EOF) {
            LogWarn("rpc", "Read error: %s", uv_err_name(static_cast<int>(nread)));
        }
        // Connection closed or error without a complete request -- just close
        if (ctx->buffer.empty()) {
            delete ctx;
            client->data = nullptr;
            uv_close(reinterpret_cast<uv_handle_t*>(client), on_close);
            return;
        }
    }

    // Check request size limit
    if (ctx->buffer.size() > ctx->server->max_body_size_ + 4096) {
        // Headers + body exceeds limit
        uv_read_stop(client);
        json err_resp = {
            {"jsonrpc", "2.0"},
            {"error", {{"code", -32600}, {"message", "Request too large"}}},
            {"id", nullptr}
        };
        std::string response = ctx->server->http_response(413, err_resp.dump());
        send_response(client, response);
        delete ctx;
        client->data = nullptr;
        return;
    }

    // Check for timeout
    auto elapsed = std::chrono::steady_clock::now() - ctx->connect_time;
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    if (seconds > ctx->server->timeout_seconds_) {
        uv_read_stop(client);
        json err_resp = {
            {"jsonrpc", "2.0"},
            {"error", {{"code", -32600}, {"message", "Request timeout"}}},
            {"id", nullptr}
        };
        std::string response = ctx->server->http_response(408, err_resp.dump());
        send_response(client, response);
        delete ctx;
        client->data = nullptr;
        return;
    }

    // Check if we have a complete HTTP request (headers + body)
    auto header_end = ctx->buffer.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        // Incomplete headers; if EOF, close
        if (nread < 0) {
            delete ctx;
            client->data = nullptr;
            uv_close(reinterpret_cast<uv_handle_t*>(client), on_close);
        }
        return;
    }

    // Check Content-Length to know when the body is complete
    std::string cl_val = get_header(ctx->buffer, "Content-Length");
    size_t content_length = 0;
    if (!cl_val.empty()) {
        try { content_length = std::stoul(cl_val); } catch (...) {}
    }

    size_t body_start = header_end + 4;
    size_t body_received = ctx->buffer.size() - body_start;

    if (body_received < content_length && nread >= 0) {
        // Still waiting for more body data
        return;
    }

    // We have a complete request -- process it
    uv_read_stop(client);

    // Handle CORS preflight
    std::string method = get_http_method(ctx->buffer);
    if (method == "OPTIONS" && ctx->server->cors_enabled_) {
        std::string response = ctx->server->http_response(200, "");
        send_response(client, response);
        delete ctx;
        client->data = nullptr;
        return;
    }

    // Only accept POST requests for JSON-RPC
    if (method != "POST") {
        json err_resp = {
            {"jsonrpc", "2.0"},
            {"error", {{"code", -32600}, {"message", "Only POST method is supported"}}},
            {"id", nullptr}
        };
        std::string response = ctx->server->http_response(405, err_resp.dump());
        send_response(client, response);
        delete ctx;
        client->data = nullptr;
        return;
    }

    std::string response = ctx->server->process_request(ctx->buffer, ctx->client_ip);
    send_response(client, response);

    delete ctx;
    client->data = nullptr;
}

void RpcServer::send_response(uv_stream_t* client, const std::string& response) {
    struct WriteReq {
        uv_write_t req;
        std::string data;
    };

    auto* wr = new WriteReq;
    wr->data = response;
    wr->req.data = wr;

    uv_buf_t buf = uv_buf_init(const_cast<char*>(wr->data.c_str()),
                                static_cast<unsigned int>(wr->data.size()));

    uv_write(&wr->req, client, &buf, 1, on_write_done);
}

void RpcServer::on_write_done(uv_write_t* req, int /*status*/) {
    struct WriteReq {
        uv_write_t req;
        std::string data;
    };
    auto* wr = static_cast<WriteReq*>(static_cast<void*>(req));

    // Close the connection after writing
    uv_close(reinterpret_cast<uv_handle_t*>(req->handle), on_close);
    delete wr;
}

void RpcServer::on_close(uv_handle_t* handle) {
    delete reinterpret_cast<uv_tcp_t*>(handle);
}

// ---------------------------------------------------------------------------
// Request processing
// ---------------------------------------------------------------------------

bool RpcServer::check_auth(const std::string& request) const {
    std::string auth = get_header(request, "Authorization");

    // Check against username:password auth
    if (auth == auth_header_) return true;

    // Check against cookie auth
    if (!cookie_auth_.empty() && auth == cookie_auth_) return true;

    // Allow empty auth if no credentials were configured
    if (user_.empty() && password_.empty()) return true;

    return false;
}

std::string RpcServer::process_request(const std::string& request,
                                        const std::string& client_ip) {
    total_requests_++;

    // Check rate limit
    if (!check_rate_limit(client_ip)) {
        json err_resp = {
            {"jsonrpc", "2.0"},
            {"error", {{"code", -32600}, {"message", "Rate limit exceeded"}}},
            {"id", nullptr}
        };
        failed_requests_++;
        return http_response(429, err_resp.dump());
    }

    // Check authentication
    if (!check_auth(request)) {
        auth_failures_++;
        json err_resp = {
            {"jsonrpc", "2.0"},
            {"error", {{"code", -32600}, {"message", "Unauthorized"}}},
            {"id", nullptr}
        };
        return http_response(401, err_resp.dump());
    }

    // Extract body
    std::string body = get_body(request);
    if (body.empty()) {
        failed_requests_++;
        json err_resp = {
            {"jsonrpc", "2.0"},
            {"error", {{"code", -32700}, {"message", "Parse error: empty body"}}},
            {"id", nullptr}
        };
        return http_response(400, err_resp.dump());
    }

    // Check body size
    if (body.size() > max_body_size_) {
        failed_requests_++;
        json err_resp = {
            {"jsonrpc", "2.0"},
            {"error", {{"code", -32600}, {"message", "Request body too large"}}},
            {"id", nullptr}
        };
        return http_response(413, err_resp.dump());
    }

    // Parse JSON
    json req_json;
    try {
        req_json = json::parse(body);
    } catch (const json::parse_error& e) {
        failed_requests_++;
        json err_resp = {
            {"jsonrpc", "2.0"},
            {"error", {{"code", -32700}, {"message", std::string("Parse error: ") + e.what()}}},
            {"id", nullptr}
        };
        return http_response(200, err_resp.dump());
    }

    // Handle batch requests (JSON array)
    if (req_json.is_array()) {
        if (req_json.empty()) {
            failed_requests_++;
            json err_resp = {
                {"jsonrpc", "2.0"},
                {"error", {{"code", -32600}, {"message", "Empty batch request"}}},
                {"id", nullptr}
            };
            return http_response(200, err_resp.dump());
        }

        json batch_response = json::array();
        for (const auto& single : req_json) {
            json result = dispatch(single);
            // Only include non-notification responses (those with an "id")
            if (!result.is_null()) {
                batch_response.push_back(result);
            }
        }

        if (batch_response.empty()) {
            // All requests were notifications
            successful_requests_++;
            return http_response(200, "");
        }

        successful_requests_++;
        return http_response(200, batch_response.dump());
    }

    // Single request
    json result = dispatch(req_json);

    // Check if it was an error
    if (result.contains("error") && !result["error"].is_null()) {
        failed_requests_++;
    } else {
        successful_requests_++;
    }

    return http_response(200, result.dump());
}

json RpcServer::dispatch(const json& request) {
    // Extract id (can be null, number, or string)
    json id = nullptr;
    if (request.contains("id")) {
        id = request["id"];
    }

    // Extract method
    if (!request.contains("method") || !request["method"].is_string()) {
        return {
            {"jsonrpc", "2.0"},
            {"error", {{"code", -32600}, {"message", "Invalid request: missing method"}}},
            {"id", id}
        };
    }

    std::string method = request["method"].get<std::string>();

    // Extract params (default to empty array)
    json params = json::array();
    if (request.contains("params")) {
        params = request["params"];
    }

    // Look up the method
    RpcMethod handler;
    {
        std::lock_guard<std::mutex> lock(methods_mutex_);
        auto it = methods_.find(method);
        if (it == methods_.end()) {
            return {
                {"jsonrpc", "2.0"},
                {"error", {{"code", -32601}, {"message", "Method not found: " + method}}},
                {"id", id}
            };
        }
        handler = it->second;
    }

    // Execute the method
    try {
        json result = handler(params);
        return {
            {"jsonrpc", "2.0"},
            {"result", result},
            {"id", id}
        };
    } catch (const std::exception& e) {
        return {
            {"jsonrpc", "2.0"},
            {"error", {{"code", -1}, {"message", e.what()}}},
            {"id", id}
        };
    }
}

} // namespace flow

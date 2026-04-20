// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "rpc/server.h"
#include "logging.h"
#include "util/strencodings.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <stdexcept>

#include <sys/stat.h>

namespace flow {

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 response formatting — bitcoind-compatible.
//
// Bitcoin Core writes its JSON-RPC reply as compact JSON with the field
// order `jsonrpc, result|error, id` and *omits* the unused half (no
// "error": null on success, no "result": null on failure). nlohmann::json
// uses an alphabetically-sorted map, so we build the response as a raw
// string to preserve field order.
// ---------------------------------------------------------------------------

static std::string jsonrpc_reply(const json& id, const json& result) {
    std::string s = "{\"jsonrpc\":\"2.0\",\"result\":";
    s += result.is_null() ? "null" : result.dump();
    s += ",\"id\":" + id.dump() + "}";
    return s;
}

static std::string jsonrpc_error(const json& id, int code, const std::string& msg) {
    json err = { {"code", code}, {"message", msg} };
    std::string s = "{\"jsonrpc\":\"2.0\",\"error\":";
    s += err.dump();
    s += ",\"id\":" + id.dump() + "}";
    return s;
}

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

    // If Transfer-Encoding: chunked, ignore Content-Length and return
    // everything after headers (the chunked decoder in process_request
    // will reassemble the body).
    std::string te = get_header(request, "Transfer-Encoding");
    if (te.find("chunked") != std::string::npos) {
        return request.substr(sep + 4);
    }

    // Respect Content-Length — don't read beyond it
    std::string cl = get_header(request, "Content-Length");
    if (!cl.empty()) {
        try {
            size_t content_length = std::stoul(cl);
            return request.substr(sep + 4, content_length);
        } catch (...) {}
    }
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

std::string RpcServer::cookie_filepath(const std::string& datadir) {
    std::string path = datadir;
    if (!path.empty() && path.back() != '/') path += "/";
    path += ".cookie";
    return path;
}

bool RpcServer::generate_cookie(const std::string& datadir) {
    // Generate 32 random bytes -> 64 hex characters
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    static const char hex_chars[] = "0123456789abcdef";
    std::string cookie_pass;
    cookie_pass.reserve(64);
    for (int i = 0; i < 32; ++i) {
        uint8_t byte = static_cast<uint8_t>(dist(gen));
        cookie_pass.push_back(hex_chars[(byte >> 4) & 0x0F]);
        cookie_pass.push_back(hex_chars[byte & 0x0F]);
    }

    std::string cookie_user = "__cookie__";
    std::string cookie_line = cookie_user + ":" + cookie_pass;

    std::string path = cookie_filepath(datadir);
    std::ofstream ofs(path);
    if (!ofs.is_open()) {
        LogWarn("rpc", "Failed to create cookie file: %s", path.c_str());
        return false;
    }

    ofs << cookie_line << "\n";
    ofs.close();

    // Set restrictive permissions (owner-only read/write)
    ::chmod(path.c_str(), 0600);

    // Update server auth to accept cookie credentials
    user_ = cookie_user;
    password_ = cookie_pass;
    auth_header_ = "Basic " + base64_encode(cookie_line);
    cookie_auth_ = auth_header_;

    LogInfo("rpc", "Generated cookie authentication: %s", path.c_str());
    return true;
}

void RpcServer::remove_cookie(const std::string& datadir) {
    std::string path = cookie_filepath(datadir);
    std::filesystem::remove(path);
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
        std::string response = ctx->server->http_response(413,
            jsonrpc_error(nullptr, -32600, "Request too large"));
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
        std::string response = ctx->server->http_response(408,
            jsonrpc_error(nullptr, -32600, "Request timeout"));
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

    // Check Content-Length or Transfer-Encoding to know when body is complete
    std::string cl_val = get_header(ctx->buffer, "Content-Length");
    std::string te_val = get_header(ctx->buffer, "Transfer-Encoding");
    bool is_chunked = (te_val.find("chunked") != std::string::npos);
    size_t content_length = 0;
    if (!cl_val.empty()) {
        try { content_length = std::stoul(cl_val); } catch (...) {}
    }

    size_t body_start = header_end + 4;
    size_t body_received = ctx->buffer.size() - body_start;

    if (is_chunked) {
        // For chunked encoding, wait for terminal chunk "0\r\n\r\n"
        if (ctx->buffer.find("\r\n0\r\n", body_start) == std::string::npos) {
            if (nread >= 0) return;  // still receiving chunks
        }
    } else if (content_length > 0 && body_received < content_length && nread >= 0) {
        // Still waiting for more body data (Content-Length mode)
        return;
    } else if (content_length == 0 && !is_chunked && body_received == 0 && nread >= 0) {
        // No body expected and none received — proceed
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
        std::string response = ctx->server->http_response(405,
            jsonrpc_error(nullptr, -32600, "Only POST method is supported"));
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
        failed_requests_++;
        return http_response(429,
            jsonrpc_error(nullptr, -32600, "Rate limit exceeded"));
    }

    // Check authentication
    if (!check_auth(request)) {
        auth_failures_++;
        return http_response(401,
            jsonrpc_error(nullptr, -32600, "Unauthorized"));
    }

    // Extract body
    std::string body = get_body(request);

    // Handle chunked transfer encoding (cgminer/libcurl sends this)
    // Chunked format: hex_size\r\n chunk_data\r\n ... 0\r\n\r\n
    if (body.size() > 4 && body[0] != '{' && body[0] != '[') {
        std::string decoded;
        size_t pos = 0;
        while (pos < body.size()) {
            // Find end of chunk size line
            auto crlf = body.find("\r\n", pos);
            if (crlf == std::string::npos) break;
            // Parse chunk size (hex)
            std::string size_str = body.substr(pos, crlf - pos);
            size_t chunk_size = 0;
            try { chunk_size = std::stoul(size_str, nullptr, 16); } catch (...) { break; }
            if (chunk_size == 0) break;  // terminal chunk
            pos = crlf + 2;  // skip \r\n
            if (pos + chunk_size > body.size()) break;
            decoded += body.substr(pos, chunk_size);
            pos += chunk_size + 2;  // skip chunk data + \r\n
        }
        if (!decoded.empty()) body = decoded;
    }
    if (body.empty()) {
        failed_requests_++;
        return http_response(400,
            jsonrpc_error(nullptr, -32700, "Parse error: empty body"));
    }

    // Check body size
    if (body.size() > max_body_size_) {
        failed_requests_++;
        return http_response(413,
            jsonrpc_error(nullptr, -32600, "Request body too large"));
    }

    // Parse JSON
    json req_json;
    try {
        // Trim trailing whitespace/newlines (cgminer sends \n after JSON)
        std::string trimmed = body;
        while (!trimmed.empty() && (trimmed.back() == '\n' || trimmed.back() == '\r' || trimmed.back() == ' ' || trimmed.back() == '\t'))
            trimmed.pop_back();
        req_json = json::parse(trimmed);
    } catch (const json::parse_error& e) {
        failed_requests_++;
        return http_response(200,
            jsonrpc_error(nullptr, -32700, std::string("Parse error: ") + e.what()));
    }

    // Handle batch requests (JSON array)
    if (req_json.is_array()) {
        if (req_json.empty()) {
            failed_requests_++;
            return http_response(200,
                jsonrpc_error(nullptr, -32600, "Empty batch request"));
        }

        std::vector<std::string> batch_response;
        for (const auto& single : req_json) {
            std::string result = dispatch(single);
            if (!result.empty()) batch_response.push_back(std::move(result));
        }

        if (batch_response.empty()) {
            // All requests were notifications
            successful_requests_++;
            return http_response(200, "");
        }

        successful_requests_++;
        // Batch response is an array of pre-formatted JSON-RPC strings.
        std::string out = "[";
        for (size_t i = 0; i < batch_response.size(); ++i) {
            if (i) out += ",";
            out += batch_response[i];
        }
        out += "]";
        return http_response(200, out);
    }

    // Single request
    std::string result = dispatch(req_json);

    // Rough success/failure classification based on response contents.
    if (result.find("\"error\":") != std::string::npos) {
        failed_requests_++;
    } else {
        successful_requests_++;
    }

    return http_response(200, result);
}

std::string RpcServer::dispatch(const json& request) {
    // Extract id (can be null, number, or string)
    json id = nullptr;
    if (request.contains("id")) {
        id = request["id"];
    }

    // Extract method
    if (!request.contains("method") || !request["method"].is_string()) {
        return jsonrpc_error(id, -32600, "Invalid request: missing method");
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
            return jsonrpc_error(id, -32601, "Method not found: " + method);
        }
        handler = it->second;
    }

    // Execute the method
    try {
        json result = handler(params);
        return jsonrpc_reply(id, result);
    } catch (const std::exception& e) {
        return jsonrpc_error(id, -1, e.what());
    }
}

// ===========================================================================
// Full HTTP/1.1 request parser
// ===========================================================================

std::string HttpRequest::get_header(const std::string& name) const {
    // Case-insensitive header lookup
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    for (const auto& [key, value] : headers) {
        std::string lower_key = key;
        std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (lower_key == lower_name) {
            return value;
        }
    }
    return "";
}

bool HttpRequest::has_header(const std::string& name) const {
    return !get_header(name).empty();
}

std::string HttpRequest::content_type() const {
    return get_header("Content-Type");
}

size_t HttpRequest::content_length() const {
    std::string val = get_header("Content-Length");
    if (val.empty()) return 0;
    try {
        return std::stoul(val);
    } catch (...) {
        return 0;
    }
}

bool HttpRequest::keep_alive() const {
    std::string conn = get_header("Connection");
    std::string lower_conn = conn;
    std::transform(lower_conn.begin(), lower_conn.end(), lower_conn.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (http_version == "HTTP/1.1") {
        // HTTP/1.1 defaults to keep-alive unless "Connection: close"
        return lower_conn != "close";
    }
    // HTTP/1.0 defaults to close unless "Connection: keep-alive"
    return lower_conn == "keep-alive";
}

std::string HttpRequest::auth_user() const {
    std::string auth = get_header("Authorization");
    if (auth.empty()) return "";

    // Parse Basic auth: "Basic base64(user:pass)"
    if (auth.substr(0, 6) != "Basic ") return "";

    // We'd need to decode base64, but for simplicity return the raw token
    // The server already handles auth checking via the existing mechanism
    return auth.substr(6);
}

std::string HttpRequest::auth_password() const {
    // Same as auth_user - actual parsing happens in the auth check
    return auth_user();
}

// ===========================================================================
// HTTP response builder
// ===========================================================================

HttpResponse::HttpResponse(int status_code) : status_(status_code) {
    headers_["Server"] = "FlowCoin-RPC/1.0";
    headers_["Content-Type"] = "application/json";
}

HttpResponse& HttpResponse::set_status(int code) {
    status_ = code;
    return *this;
}

HttpResponse& HttpResponse::set_header(const std::string& name,
                                        const std::string& value) {
    headers_[name] = value;
    return *this;
}

HttpResponse& HttpResponse::set_body(const std::string& body) {
    body_.assign(body.begin(), body.end());
    return *this;
}

HttpResponse& HttpResponse::set_body(const std::vector<uint8_t>& body) {
    body_ = body;
    return *this;
}

HttpResponse& HttpResponse::set_json(const nlohmann::json& j) {
    std::string s = j.dump();
    body_.assign(s.begin(), s.end());
    headers_["Content-Type"] = "application/json";
    return *this;
}

HttpResponse& HttpResponse::set_content_type(const std::string& type) {
    headers_["Content-Type"] = type;
    return *this;
}

HttpResponse& HttpResponse::enable_cors() {
    headers_["Access-Control-Allow-Origin"] = "*";
    headers_["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS";
    headers_["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
    headers_["Access-Control-Max-Age"] = "86400";
    return *this;
}

HttpResponse& HttpResponse::set_keep_alive(bool enabled) {
    headers_["Connection"] = enabled ? "keep-alive" : "close";
    return *this;
}

std::vector<uint8_t> HttpResponse::serialize() const {
    std::string response;
    response += "HTTP/1.1 " + std::to_string(status_) + " " +
                status_text(status_) + "\r\n";

    // Add Content-Length if not already set
    auto cl_it = headers_.find("Content-Length");
    bool has_cl = (cl_it != headers_.end());

    for (const auto& [name, value] : headers_) {
        response += name + ": " + value + "\r\n";
    }

    if (!has_cl) {
        response += "Content-Length: " + std::to_string(body_.size()) + "\r\n";
    }

    response += "\r\n";

    std::vector<uint8_t> result(response.begin(), response.end());
    result.insert(result.end(), body_.begin(), body_.end());
    return result;
}

HttpResponse HttpResponse::ok(const nlohmann::json& j) {
    HttpResponse resp(200);
    resp.set_json(j);
    return resp;
}

HttpResponse HttpResponse::error(int code, const std::string& message) {
    HttpResponse resp(code);
    nlohmann::json j = {
        {"jsonrpc", "2.0"},
        {"error", {{"code", code}, {"message", message}}},
        {"id", nullptr}
    };
    resp.set_json(j);
    return resp;
}

HttpResponse HttpResponse::not_found() {
    return error(404, "Not found");
}

HttpResponse HttpResponse::unauthorized() {
    HttpResponse resp(401);
    resp.set_header("WWW-Authenticate", "Basic realm=\"FlowCoin RPC\"");
    nlohmann::json j = {
        {"jsonrpc", "2.0"},
        {"error", {{"code", -32600}, {"message", "Unauthorized"}}},
        {"id", nullptr}
    };
    resp.set_json(j);
    return resp;
}

HttpResponse HttpResponse::method_not_allowed() {
    return error(405, "Method not allowed");
}

HttpResponse HttpResponse::too_many_requests() {
    return error(429, "Rate limit exceeded");
}

HttpResponse HttpResponse::internal_error(const std::string& msg) {
    return error(500, msg);
}

std::string HttpResponse::status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 413: return "Payload Too Large";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 503: return "Service Unavailable";
        default:  return "Unknown";
    }
}

// ===========================================================================
// HTTP parser (stateful, for keep-alive connections)
// ===========================================================================

size_t HttpParser::feed(const uint8_t* data, size_t len) {
    size_t consumed = 0;

    for (size_t i = 0; i < len; ++i) {
        char c = static_cast<char>(data[i]);
        consumed++;

        switch (state_) {
        case State::READING_REQUEST_LINE:
            if (c == '\n') {
                // Remove trailing \r if present
                if (!line_buffer_.empty() && line_buffer_.back() == '\r') {
                    line_buffer_.pop_back();
                }
                if (!parse_request_line(line_buffer_)) {
                    state_ = State::PARSE_ERROR;
                    error_ = "Invalid request line";
                    return consumed;
                }
                line_buffer_.clear();
                state_ = State::READING_HEADERS;
            } else {
                line_buffer_ += c;
                if (line_buffer_.size() > 8192) {
                    state_ = State::PARSE_ERROR;
                    error_ = "Request line too long";
                    return consumed;
                }
            }
            break;

        case State::READING_HEADERS:
            if (c == '\n') {
                if (!line_buffer_.empty() && line_buffer_.back() == '\r') {
                    line_buffer_.pop_back();
                }
                if (line_buffer_.empty()) {
                    // Empty line = end of headers
                    body_expected_ = req_.content_length();
                    if (body_expected_ > 0) {
                        state_ = State::READING_BODY;
                        body_received_ = 0;
                        req_.body.reserve(body_expected_);
                    } else {
                        state_ = State::COMPLETE;
                        return consumed;
                    }
                } else {
                    if (!parse_header_line(line_buffer_)) {
                        state_ = State::PARSE_ERROR;
                        error_ = "Invalid header line";
                        return consumed;
                    }
                    line_buffer_.clear();
                }
            } else {
                line_buffer_ += c;
                if (line_buffer_.size() > 8192) {
                    state_ = State::PARSE_ERROR;
                    error_ = "Header line too long";
                    return consumed;
                }
            }
            break;

        case State::READING_BODY:
            req_.body.push_back(data[i]);
            body_received_++;
            if (body_received_ >= body_expected_) {
                state_ = State::COMPLETE;
                return consumed;
            }
            break;

        case State::COMPLETE:
        case State::PARSE_ERROR:
            return consumed;
        }
    }

    return consumed;
}

HttpParser::State HttpParser::state() const {
    return state_;
}

bool HttpParser::is_complete() const {
    return state_ == State::COMPLETE;
}

bool HttpParser::has_error() const {
    return state_ == State::PARSE_ERROR;
}

std::string HttpParser::error_message() const {
    return error_;
}

HttpRequest HttpParser::get_request() const {
    return req_;
}

void HttpParser::reset() {
    state_ = State::READING_REQUEST_LINE;
    req_ = HttpRequest();
    line_buffer_.clear();
    body_received_ = 0;
    body_expected_ = 0;
    error_.clear();
}

bool HttpParser::parse_request_line(const std::string& line) {
    // Parse "METHOD PATH HTTP/VERSION"
    size_t first_space = line.find(' ');
    if (first_space == std::string::npos) return false;

    size_t second_space = line.find(' ', first_space + 1);
    if (second_space == std::string::npos) return false;

    req_.method = line.substr(0, first_space);
    std::string full_path = line.substr(first_space + 1,
                                        second_space - first_space - 1);
    req_.http_version = line.substr(second_space + 1);

    // Split path and query string
    size_t qmark = full_path.find('?');
    if (qmark != std::string::npos) {
        req_.path = full_path.substr(0, qmark);
        req_.query = full_path.substr(qmark + 1);
    } else {
        req_.path = full_path;
    }

    // Validate method
    if (req_.method != "GET" && req_.method != "POST" &&
        req_.method != "OPTIONS" && req_.method != "HEAD" &&
        req_.method != "PUT" && req_.method != "DELETE") {
        return false;
    }

    return true;
}

bool HttpParser::parse_header_line(const std::string& line) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) return false;

    std::string name = line.substr(0, colon);
    std::string value = line.substr(colon + 1);

    // Trim leading whitespace from value
    size_t start = value.find_first_not_of(' ');
    if (start != std::string::npos) {
        value = value.substr(start);
    }

    req_.headers[name] = value;
    return true;
}

// ===========================================================================
// Request routing: handle both JSON-RPC and REST on same port
// ===========================================================================

void RpcServer::route_request(const HttpRequest& req, HttpResponse& resp) {
    // CORS preflight
    if (req.method == "OPTIONS" && cors_enabled_) {
        resp.set_status(200);
        resp.enable_cors();
        resp.set_body("");
        return;
    }

    // REST endpoints
    if (req.method == "GET" && req.path.substr(0, 6) == "/rest/") {
        handle_rest_request(req, resp);
        return;
    }

    // JSON-RPC: POST to /
    if (req.method == "POST" && (req.path == "/" || req.path.empty())) {
        std::string body_str(req.body.begin(), req.body.end());
        std::string raw_request = req.method + " " + req.path + " " +
                                  req.http_version + "\r\n";
        for (const auto& [name, value] : req.headers) {
            raw_request += name + ": " + value + "\r\n";
        }
        raw_request += "\r\n";
        raw_request += body_str;

        std::string result = process_request(raw_request, req.client_ip);
        resp.set_status(200);
        resp.set_body(result);
        return;
    }

    // Everything else: 404
    resp = HttpResponse::not_found();
}

void RpcServer::handle_rest_request(const HttpRequest& req, HttpResponse& resp) {
    // Parse the REST path: /rest/<resource>[/<id>][.json]
    std::string rest_path = req.path.substr(5);  // remove "/rest"

    // Remove .json suffix if present
    std::string format = "json";
    size_t dot = rest_path.rfind('.');
    if (dot != std::string::npos) {
        format = rest_path.substr(dot + 1);
        rest_path = rest_path.substr(0, dot);
    }

    if (format != "json") {
        resp = HttpResponse::error(400, "Only JSON format is supported");
        return;
    }

    // Route to specific REST handlers
    if (rest_path == "/chaininfo" || rest_path == "/chaininfo/") {
        // Delegate to getblockchaininfo RPC method
        std::lock_guard<std::mutex> lock(methods_mutex_);
        auto it = methods_.find("getblockchaininfo");
        if (it != methods_.end()) {
            try {
                json result = it->second(json::array());
                resp = HttpResponse::ok(result);
            } catch (const std::exception& e) {
                resp = HttpResponse::internal_error(e.what());
            }
        } else {
            resp = HttpResponse::not_found();
        }
    } else if (rest_path == "/mempool/info" || rest_path == "/mempool/info/") {
        std::lock_guard<std::mutex> lock(methods_mutex_);
        auto it = methods_.find("getmempoolinfo");
        if (it != methods_.end()) {
            try {
                json result = it->second(json::array());
                resp = HttpResponse::ok(result);
            } catch (const std::exception& e) {
                resp = HttpResponse::internal_error(e.what());
            }
        } else {
            resp = HttpResponse::not_found();
        }
    } else {
        resp = HttpResponse::not_found();
    }
}

// ===========================================================================
// Connection tracking
// ===========================================================================

void RpcServer::track_connection(uint64_t id, const std::string& client_ip) {
    std::lock_guard<std::mutex> lock(conn_mutex_);

    RpcConnection conn;
    conn.id = id;
    conn.client_ip = client_ip;
    conn.connected_at = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    conn.requests_served = 0;
    conn.last_request_at = conn.connected_at;
    conn.authenticated = false;
    conn.keep_alive = false;

    active_connections_[id] = conn;
}

void RpcServer::untrack_connection(uint64_t id) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    active_connections_.erase(id);
}

void RpcServer::update_connection(uint64_t id) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    auto it = active_connections_.find(id);
    if (it != active_connections_.end()) {
        it->second.requests_served++;
        it->second.last_request_at = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

std::vector<RpcServer::RpcConnection> RpcServer::get_connections() const {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    std::vector<RpcConnection> result;
    result.reserve(active_connections_.size());
    for (const auto& [id, conn] : active_connections_) {
        result.push_back(conn);
    }
    return result;
}

// ===========================================================================
// Long polling support
// ===========================================================================

void RpcServer::add_long_poll(LongPollContext ctx) {
    std::lock_guard<std::mutex> lock(poll_mutex_);
    long_polls_.push_back(std::move(ctx));
}

void RpcServer::notify_new_block(uint64_t height, const uint256& hash) {
    std::lock_guard<std::mutex> lock(poll_mutex_);

    auto it = long_polls_.begin();
    while (it != long_polls_.end()) {
        bool should_notify = false;

        // Notify if height reached
        if (it->target_height > 0 && height >= it->target_height) {
            should_notify = true;
        }

        // Notify if specific hash appeared
        if (!it->target_hash.is_null() && it->target_hash == hash) {
            should_notify = true;
        }

        if (should_notify && it->callback) {
            json response = {
                {"height", height},
                {"hash", hex_encode(hash.data(), 32)}
            };
            try {
                it->callback(response);
            } catch (...) {
                // Swallow callback exceptions
            }
            it = long_polls_.erase(it);
        } else {
            ++it;
        }
    }
}

void RpcServer::expire_long_polls() {
    std::lock_guard<std::mutex> lock(poll_mutex_);

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    auto it = long_polls_.begin();
    while (it != long_polls_.end()) {
        if (it->timeout > 0 && now > it->timeout) {
            // Timed out: send empty response
            if (it->callback) {
                try {
                    it->callback(json::object());
                } catch (...) {}
            }
            it = long_polls_.erase(it);
        } else {
            ++it;
        }
    }
}

// ===========================================================================
// Server configuration helpers
// ===========================================================================

void RpcServer::set_max_connections(int max_conn) {
    max_connections_ = max_conn;
}

void RpcServer::set_cors_origin(const std::string& origin) {
    cors_origin_ = origin;
    cors_enabled_ = true;
}

void RpcServer::set_rate_limit(int requests_per_second) {
    rate_limit_ = requests_per_second;
}

void RpcServer::set_timeout(int seconds) {
    timeout_seconds_ = seconds;
}

void RpcServer::set_max_body_size(size_t bytes) {
    max_body_size_ = bytes;
}

// ===========================================================================
// Whitelist / blacklist
// ===========================================================================

void RpcServer::add_whitelist(const std::string& ip) {
    std::lock_guard<std::mutex> lock(acl_mutex_);
    whitelist_.insert(ip);
}

void RpcServer::remove_whitelist(const std::string& ip) {
    std::lock_guard<std::mutex> lock(acl_mutex_);
    whitelist_.erase(ip);
}

void RpcServer::add_blacklist(const std::string& ip) {
    std::lock_guard<std::mutex> lock(acl_mutex_);
    blacklist_.insert(ip);
}

void RpcServer::remove_blacklist(const std::string& ip) {
    std::lock_guard<std::mutex> lock(acl_mutex_);
    blacklist_.erase(ip);
}

bool RpcServer::is_allowed(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(acl_mutex_);

    // If blacklist is non-empty and ip is in it, deny
    if (!blacklist_.empty() && blacklist_.count(ip) > 0) {
        return false;
    }

    // If whitelist is non-empty, only allow listed IPs
    if (!whitelist_.empty()) {
        return whitelist_.count(ip) > 0;
    }

    // By default, allow (localhost-only binding provides the security)
    return true;
}

// ===========================================================================
// Method introspection
// ===========================================================================

json RpcServer::build_help_text() const {
    std::lock_guard<std::mutex> lock(methods_mutex_);

    json help = json::array();
    for (const auto& [name, method] : methods_) {
        help.push_back(name);
    }
    std::sort(help.begin(), help.end());
    return help;
}

json RpcServer::get_server_info() const {
    auto stats = get_stats();

    json info = {
        {"version", "1.0.0"},
        {"port", port_},
        {"running", running_.load()},
        {"uptime_seconds", stats.uptime_seconds},
        {"total_requests", stats.total_requests},
        {"successful_requests", stats.successful_requests},
        {"failed_requests", stats.failed_requests},
        {"auth_failures", stats.auth_failures},
        {"rate_limited", stats.rate_limited},
        {"method_count", method_count()},
        {"cors_enabled", cors_enabled_},
        {"rate_limit", rate_limit_},
        {"max_body_size", max_body_size_},
        {"timeout_seconds", timeout_seconds_}
    };

    // Connection info
    auto conns = get_connections();
    info["active_connections"] = static_cast<int>(conns.size());

    return info;
}

} // namespace flow

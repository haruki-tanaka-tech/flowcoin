// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "miner/rpc_client.h"

#include <cstring>
#include <sstream>
#include <vector>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
using socket_t = SOCKET;
static constexpr socket_t INVALID_SOCK = INVALID_SOCKET;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
using socket_t = int;
static constexpr socket_t INVALID_SOCK = -1;
#endif

namespace flow::miner {

// =========================================================================
// Base64 encoder (minimal, no padding required for HTTP Basic auth)
// =========================================================================

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const std::string& input) {
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);

    uint32_t val = 0;
    int bits = -6;
    for (uint8_t c : input) {
        val = (val << 8) | c;
        bits += 8;
        while (bits >= 0) {
            out.push_back(b64_table[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6) {
        out.push_back(b64_table[((val << 8) >> (bits + 8)) & 0x3F]);
    }
    while (out.size() % 4) {
        out.push_back('=');
    }
    return out;
}

// =========================================================================
// Socket helpers
// =========================================================================

static void close_socket(socket_t s) {
#ifdef _WIN32
    closesocket(s);
#else
    ::close(s);
#endif
}

static bool set_timeout(socket_t s, int timeout_ms) {
#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(timeout_ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
    return true;
}

// =========================================================================
// RPCClient implementation
// =========================================================================

RPCClient::RPCClient(const std::string& host, int port,
                     const std::string& user, const std::string& password)
    : host_(host), port_(port)
{
    auth_base64_ = base64_encode(user + ":" + password);
}

std::string RPCClient::http_post(const std::string& body) {
    // Resolve host
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port_);
    int rc = getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &result);
    if (rc != 0 || !result) {
        return {};
    }

    socket_t sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCK) {
        freeaddrinfo(result);
        return {};
    }

    set_timeout(sock, 30000);

    if (connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen)) != 0) {
        close_socket(sock);
        freeaddrinfo(result);
        return {};
    }
    freeaddrinfo(result);

    // Build HTTP request
    std::ostringstream req;
    req << "POST / HTTP/1.1\r\n"
        << "Host: " << host_ << ":" << port_ << "\r\n"
        << "Authorization: Basic " << auth_base64_ << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n"
        << "\r\n"
        << body;

    std::string request = req.str();
    const char* send_ptr = request.c_str();
    size_t remaining = request.size();

    while (remaining > 0) {
        auto sent = send(sock, send_ptr, static_cast<int>(remaining), 0);
        if (sent <= 0) {
            close_socket(sock);
            return {};
        }
        send_ptr += sent;
        remaining -= static_cast<size_t>(sent);
    }

    // Read response
    std::string response;
    char buf[4096];
    for (;;) {
        auto n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        response.append(buf, static_cast<size_t>(n));
    }
    close_socket(sock);

    // Extract body (after \r\n\r\n)
    auto hdr_end = response.find("\r\n\r\n");
    if (hdr_end == std::string::npos) {
        return {};
    }
    return response.substr(hdr_end + 4);
}

std::string RPCClient::call(const std::string& method, const std::string& params) {
    static int id_counter = 0;

    std::ostringstream json;
    json << "{\"jsonrpc\":\"1.0\",\"id\":" << (++id_counter)
         << ",\"method\":\"" << method
         << "\",\"params\":" << params << "}";

    std::string body = http_post(json.str());
    if (body.empty()) return {};

    // Extract "result" value from response
    // Simple approach: find "result": and grab everything until matching close
    auto pos = body.find("\"result\"");
    if (pos == std::string::npos) return {};

    pos = body.find(':', pos + 8);
    if (pos == std::string::npos) return {};
    ++pos;

    // Skip whitespace
    while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t'))
        ++pos;

    if (pos >= body.size()) return {};

    // Determine the type and extract accordingly
    char ch = body[pos];

    if (ch == '"') {
        // String value
        size_t start = pos + 1;
        size_t end = body.find('"', start);
        if (end == std::string::npos) return {};
        return body.substr(start, end - start);
    }

    if (ch == '{' || ch == '[') {
        // Object or array — find matching brace
        char open = ch;
        char close_ch = (ch == '{') ? '}' : ']';
        int depth = 1;
        size_t i = pos + 1;
        bool in_string = false;
        while (i < body.size() && depth > 0) {
            if (body[i] == '"' && (i == 0 || body[i - 1] != '\\'))
                in_string = !in_string;
            if (!in_string) {
                if (body[i] == open) ++depth;
                else if (body[i] == close_ch) --depth;
            }
            ++i;
        }
        return body.substr(pos, i - pos);
    }

    if (ch == 'n') {
        // null
        return "null";
    }

    // Numeric or boolean — read until comma, }, or end
    size_t end = body.find_first_of(",}", pos);
    if (end == std::string::npos) end = body.size();
    std::string val = body.substr(pos, end - pos);
    // Trim whitespace
    while (!val.empty() && (val.back() == ' ' || val.back() == '\t' ||
           val.back() == '\n' || val.back() == '\r'))
        val.pop_back();
    return val;
}

// =========================================================================
// JSON helpers
// =========================================================================

std::string RPCClient::json_get_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return {};

    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return {};
    ++pos;

    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
        ++pos;

    if (pos >= json.size() || json[pos] != '"') return {};
    size_t start = pos + 1;
    size_t end = json.find('"', start);
    if (end == std::string::npos) return {};
    return json.substr(start, end - start);
}

int64_t RPCClient::json_get_int(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return 0;

    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return 0;
    ++pos;

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
        ++pos;

    try {
        return std::stoll(json.substr(pos));
    } catch (...) {
        return 0;
    }
}

double RPCClient::json_get_double(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return 0.0;

    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return 0.0;
    ++pos;

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
        ++pos;

    try {
        return std::stod(json.substr(pos));
    } catch (...) {
        return 0.0;
    }
}

// =========================================================================
// Convenience methods
// =========================================================================

int64_t RPCClient::get_block_count() {
    std::string result = call("getblockcount");
    if (result.empty()) return -1;
    try {
        return std::stoll(result);
    } catch (...) {
        return -1;
    }
}

std::string RPCClient::get_best_block_hash() {
    return call("getbestblockhash");
}

RPCClient::BlockTemplate RPCClient::get_block_template() {
    BlockTemplate tmpl{};
    tmpl.valid = false;

    std::string result = call("getblocktemplate");
    if (result.empty() || result == "null") return tmpl;

    tmpl.height       = static_cast<uint64_t>(json_get_int(result, "height"));
    tmpl.prev_hash    = json_get_string(result, "previousblockhash");
    tmpl.nbits        = static_cast<uint32_t>(json_get_int(result, "nbits"));

    // Validate essential fields
    tmpl.valid = true;

    return tmpl;
}

std::string RPCClient::submit_block(const std::string& hex_block) {
    return call("submitblock", "[\"" + hex_block + "\"]");
}

std::string RPCClient::get_new_address() {
    return call("getnewaddress");
}

bool RPCClient::is_connected() {
    int64_t count = get_block_count();
    return count >= 0;
}

} // namespace flow::miner

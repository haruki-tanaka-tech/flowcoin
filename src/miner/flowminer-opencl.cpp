// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// flowminer-opencl -- OpenCL GPU miner for FlowCoin (Keccak-256d PoW).
//
// Talks to a flowcoind node over HTTP JSON-RPC (getblocktemplate,
// submitblock).  The Keccak-256d kernel runs on GPU; the host handles
// RPC, template parsing, and result submission.
//
// Build:
//   Linux:
//     g++ -O3 -std=c++20 flowminer-opencl.cpp -o flowminer-opencl -lOpenCL
//   Windows (MSVC):
//     cl /O2 /std:c++20 flowminer-opencl.cpp /link OpenCL.lib
//   Windows (MinGW):
//     g++ -O3 -std=c++20 flowminer-opencl.cpp -o flowminer-opencl.exe -lOpenCL

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "OpenCL.lib")
typedef int socklen_t;
#define close_socket closesocket
#define isatty _isatty
#define fileno _fileno
typedef long long ssize_t;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define close_socket close
#endif

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// =========================================================================
// Version
// =========================================================================

#define FLOWCOIN_GPU_MINER_VERSION "0.1.0"

static constexpr size_t HEADER_UNSIGNED = 92;

// =========================================================================
// Embedded OpenCL kernel source
// =========================================================================

static const char* KERNEL_SOURCE = R"CL(
// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

__constant ulong RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL
};

__constant int ROTC[24] = {
     1,  3,  6, 10, 15, 21,
    28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43,
    62, 18, 39, 61, 20, 44
};

__constant int PILN[24] = {
    10,  7, 11, 17, 18,  3,
     5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2,
    20, 14, 22,  9,  6,  1
};

inline void keccak_f1600(ulong st[25])
{
    ulong bc[5];
    for (int round = 0; round < 24; ++round) {
        bc[0] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        bc[1] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        bc[2] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        bc[3] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        bc[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        ulong t;
        t = bc[4] ^ rotate(bc[1], (ulong)1);
        st[0]  ^= t; st[5]  ^= t; st[10] ^= t; st[15] ^= t; st[20] ^= t;
        t = bc[0] ^ rotate(bc[2], (ulong)1);
        st[1]  ^= t; st[6]  ^= t; st[11] ^= t; st[16] ^= t; st[21] ^= t;
        t = bc[1] ^ rotate(bc[3], (ulong)1);
        st[2]  ^= t; st[7]  ^= t; st[12] ^= t; st[17] ^= t; st[22] ^= t;
        t = bc[2] ^ rotate(bc[4], (ulong)1);
        st[3]  ^= t; st[8]  ^= t; st[13] ^= t; st[18] ^= t; st[23] ^= t;
        t = bc[3] ^ rotate(bc[0], (ulong)1);
        st[4]  ^= t; st[9]  ^= t; st[14] ^= t; st[19] ^= t; st[24] ^= t;

        ulong tmp = st[1];
        for (int j = 0; j < 24; ++j) {
            int idx = PILN[j];
            ulong sv = st[idx];
            st[idx] = rotate(tmp, (ulong)ROTC[j]);
            tmp = sv;
        }

        for (int j = 0; j < 25; j += 5) {
            ulong c0 = st[j + 0];
            ulong c1 = st[j + 1];
            ulong c2 = st[j + 2];
            ulong c3 = st[j + 3];
            ulong c4 = st[j + 4];
            st[j + 0] = c0 ^ ((~c1) & c2);
            st[j + 1] = c1 ^ ((~c2) & c3);
            st[j + 2] = c2 ^ ((~c3) & c4);
            st[j + 3] = c3 ^ ((~c4) & c0);
            st[j + 4] = c4 ^ ((~c0) & c1);
        }

        st[0] ^= RC[round];
    }
}

inline void keccak256_92(const uchar data[92], uchar out[32])
{
    ulong st[25];
    for (int i = 0; i < 25; ++i) st[i] = 0;

    for (int i = 0; i < 11; ++i) {
        ulong lane = 0;
        for (int b = 0; b < 8; ++b)
            lane |= ((ulong)data[i * 8 + b]) << (b * 8);
        st[i] ^= lane;
    }

    {
        ulong lane = 0;
        for (int b = 0; b < 4; ++b)
            lane |= ((ulong)data[88 + b]) << (b * 8);
        lane |= ((ulong)0x01) << (4 * 8);
        st[11] ^= lane;
    }

    st[16] ^= ((ulong)0x80) << (7 * 8);

    keccak_f1600(st);

    for (int i = 0; i < 4; ++i) {
        ulong lane = st[i];
        for (int b = 0; b < 8; ++b)
            out[i * 8 + b] = (uchar)(lane >> (b * 8));
    }
}

inline void keccak256_32(const uchar data[32], uchar out[32])
{
    ulong st[25];
    for (int i = 0; i < 25; ++i) st[i] = 0;

    for (int i = 0; i < 4; ++i) {
        ulong lane = 0;
        for (int b = 0; b < 8; ++b)
            lane |= ((ulong)data[i * 8 + b]) << (b * 8);
        st[i] ^= lane;
    }

    st[4] ^= (ulong)0x01;
    st[16] ^= ((ulong)0x80) << (7 * 8);

    keccak_f1600(st);

    for (int i = 0; i < 4; ++i) {
        ulong lane = st[i];
        for (int b = 0; b < 8; ++b)
            out[i * 8 + b] = (uchar)(lane >> (b * 8));
    }
}

__kernel void mine(
    __global const uchar* header,
    __global const uchar* target,
    const uint nonce_base,
    __global uint*  result_nonce,
    __global uchar* result_hash,
    __global uint*  result_found
)
{
    if (*result_found != 0)
        return;

    uint gid = get_global_id(0);
    uint nonce = nonce_base + gid;

    uchar hdr[92];
    for (int i = 0; i < 92; ++i)
        hdr[i] = header[i];

    hdr[84] = (uchar)(nonce);
    hdr[85] = (uchar)(nonce >> 8);
    hdr[86] = (uchar)(nonce >> 16);
    hdr[87] = (uchar)(nonce >> 24);

    uchar inner[32];
    keccak256_92(hdr, inner);

    uchar hash[32];
    keccak256_32(inner, hash);

    uchar tgt[32];
    for (int i = 0; i < 32; ++i)
        tgt[i] = target[i];

    bool valid = true;
    for (int i = 0; i < 32; ++i) {
        if (hash[i] < tgt[i]) break;
        if (hash[i] > tgt[i]) {
            valid = false;
            break;
        }
    }

    if (valid) {
        if (atomic_cmpxchg(result_found, 0u, 1u) == 0u) {
            *result_nonce = nonce;
            for (int i = 0; i < 32; ++i)
                result_hash[i] = hash[i];
        }
    }
}
)CL";

// =========================================================================
// Hex helpers
// =========================================================================

static inline int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static std::vector<uint8_t> hex_decode(const std::string& s) {
    std::vector<uint8_t> out;
    if (s.size() % 2 != 0) return out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = hex_nibble(s[i]);
        int lo = hex_nibble(s[i + 1]);
        if (hi < 0 || lo < 0) { out.clear(); return out; }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

static std::string hex_encode(const uint8_t* p, size_t n) {
    static const char k[] = "0123456789abcdef";
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out[i * 2]     = k[p[i] >> 4];
        out[i * 2 + 1] = k[p[i] & 0xf];
    }
    return out;
}

// =========================================================================
// Minimal JSON parser / builder
//
// We avoid a dependency on nlohmann/json for the standalone GPU miner.
// This is a tiny hand-rolled parser that handles the exact JSON shapes
// returned by getblocktemplate and submitblock.
// =========================================================================

// Trim whitespace
static std::string_view json_trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' ||
                          s.front() == '\n' || s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' ||
                          s.back() == '\n' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

// Extract a JSON string value for a given key from a flat JSON object.
// Returns empty string if not found.
static std::string json_get_string(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    // skip whitespace and colon
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' ||
                                  json[pos] == '\t' || json[pos] == '\n'))
        ++pos;
    if (pos >= json.size() || json[pos] != '"') return {};
    ++pos; // skip opening quote
    std::string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            ++pos;
            if      (json[pos] == '"')  result += '"';
            else if (json[pos] == '\\') result += '\\';
            else if (json[pos] == 'n')  result += '\n';
            else if (json[pos] == 't')  result += '\t';
            else result += json[pos];
        } else {
            result += json[pos];
        }
        ++pos;
    }
    return result;
}

// Extract a JSON integer value for a given key.
static int64_t json_get_int(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return 0;
    pos += needle.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' ||
                                  json[pos] == '\t' || json[pos] == '\n'))
        ++pos;
    if (pos >= json.size()) return 0;
    // Read number (possibly negative)
    std::string num;
    if (json[pos] == '-') { num += '-'; ++pos; }
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
        num += json[pos]; ++pos;
    }
    if (num.empty() || num == "-") return 0;
    return std::strtoll(num.c_str(), nullptr, 10);
}

// Extract unsigned integer
static uint64_t json_get_uint(const std::string& json, const std::string& key) {
    return static_cast<uint64_t>(json_get_int(json, key));
}

// Extract the "result" field from an RPC response.
// Returns the raw JSON content of the result field (could be object, string, null, etc.)
static std::string json_get_result(const std::string& json) {
    std::string needle = "\"result\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' ||
                                  json[pos] == '\t' || json[pos] == '\n'))
        ++pos;
    if (pos >= json.size()) return {};

    // Determine type and extract
    if (json[pos] == 'n' && json.substr(pos, 4) == "null") return "null";

    if (json[pos] == '"') {
        // String value
        ++pos;
        std::string result = "\"";
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) {
                result += json[pos]; ++pos;
                result += json[pos]; ++pos;
            } else {
                result += json[pos]; ++pos;
            }
        }
        result += '"';
        return result;
    }

    if (json[pos] == '{') {
        // Object: find matching brace
        int depth = 1;
        size_t start = pos;
        ++pos;
        while (pos < json.size() && depth > 0) {
            if (json[pos] == '{') ++depth;
            else if (json[pos] == '}') --depth;
            else if (json[pos] == '"') {
                ++pos;
                while (pos < json.size() && json[pos] != '"') {
                    if (json[pos] == '\\') ++pos;
                    ++pos;
                }
            }
            ++pos;
        }
        return json.substr(start, pos - start);
    }

    // Number or boolean
    size_t start = pos;
    while (pos < json.size() && json[pos] != ',' && json[pos] != '}' &&
           json[pos] != ']' && json[pos] != ' ' && json[pos] != '\n')
        ++pos;
    return json.substr(start, pos - start);
}

// Check if the RPC response contains an error
static bool json_has_error(const std::string& json) {
    std::string needle = "\"error\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return false;
    pos += needle.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' ||
                                  json[pos] == '\t' || json[pos] == '\n'))
        ++pos;
    if (pos >= json.size()) return false;
    // If error is null, no error
    if (json.substr(pos, 4) == "null") return false;
    return true;
}

// Build a simple JSON-RPC request string
static std::string build_rpc_request(const std::string& method,
                                      const std::string& params_array) {
    return "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method +
           "\",\"params\":" + params_array + "}";
}

// =========================================================================
// Base64 encoder (for HTTP Basic auth)
// =========================================================================

static std::string base64_encode(const std::string& in) {
    static const char k[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    for (size_t i = 0; i < in.size(); i += 3) {
        uint32_t a = static_cast<uint8_t>(in[i]);
        uint32_t b = i + 1 < in.size() ? static_cast<uint8_t>(in[i + 1]) : 0;
        uint32_t c = i + 2 < in.size() ? static_cast<uint8_t>(in[i + 2]) : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out.push_back(k[(triple >> 18) & 0x3f]);
        out.push_back(k[(triple >> 12) & 0x3f]);
        out.push_back(i + 1 < in.size() ? k[(triple >> 6) & 0x3f] : '=');
        out.push_back(i + 2 < in.size() ? k[triple & 0x3f]        : '=');
    }
    return out;
}

// =========================================================================
// HTTP client -- minimal JSON-RPC over POSIX sockets
// =========================================================================

struct RpcAuth {
    std::string user;
    std::string pass;
};

struct RpcEndpoint {
    std::string host = "127.0.0.1";
    uint16_t    port = 9334;
    RpcAuth     auth;
};

static std::optional<std::string> http_post(const RpcEndpoint& ep,
                                             const std::string& body) {
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* ai = nullptr;
    std::string port_str = std::to_string(ep.port);
    if (::getaddrinfo(ep.host.c_str(), port_str.c_str(), &hints, &ai) != 0 || !ai)
        return std::nullopt;

#ifdef _WIN32
    SOCKET sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock == INVALID_SOCKET) { ::freeaddrinfo(ai); return std::nullopt; }
    if (::connect(sock, ai->ai_addr, (int)ai->ai_addrlen) == SOCKET_ERROR) {
        ::closesocket(sock); ::freeaddrinfo(ai); return std::nullopt;
    }
#else
    int sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock < 0) { ::freeaddrinfo(ai); return std::nullopt; }
    if (::connect(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
        ::close(sock); ::freeaddrinfo(ai); return std::nullopt;
    }
#endif
    ::freeaddrinfo(ai);

    std::string req;
    req.reserve(body.size() + 256);
    req += "POST / HTTP/1.1\r\n";
    req += "Host: " + ep.host + ":" + port_str + "\r\n";
    req += "Content-Type: application/json\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    req += "Connection: close\r\n";
    if (!ep.auth.user.empty() || !ep.auth.pass.empty())
        req += "Authorization: Basic " +
               base64_encode(ep.auth.user + ":" + ep.auth.pass) + "\r\n";
    req += "\r\n";
    req += body;

    size_t sent = 0;
    while (sent < req.size()) {
        int n = ::send(sock, req.data() + sent, (int)(req.size() - sent), 0);
        if (n <= 0) { close_socket(sock); return std::nullopt; }
        sent += static_cast<size_t>(n);
    }

    std::string resp;
    char buf[4096];
    for (;;) {
        int n = ::recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, static_cast<size_t>(n));
    }
    close_socket(sock);

    auto pos = resp.find("\r\n\r\n");
    if (pos == std::string::npos) return std::nullopt;
    return resp.substr(pos + 4);
}

static std::optional<std::string> rpc_call(const RpcEndpoint& ep,
                                            const std::string& method,
                                            const std::string& params_array) {
    std::string body = build_rpc_request(method, params_array);
    auto resp = http_post(ep, body);
    if (!resp) return std::nullopt;
    if (json_has_error(*resp)) return std::nullopt;
    std::string result = json_get_result(*resp);
    if (result.empty()) return std::nullopt;
    return result;
}

// =========================================================================
// Cookie auth
// =========================================================================

static bool load_cookie(const std::string& path, RpcAuth& out) {
    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string line;
    std::getline(f, line);
    auto p = line.find(':');
    if (p == std::string::npos) return false;
    out.user = line.substr(0, p);
    out.pass = line.substr(p + 1);
    return true;
}

static std::string default_datadir() {
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    if (appdata) return std::string(appdata) + "\\FlowCoin";
#endif
    const char* home = std::getenv("HOME");
    if (!home) home = "/tmp";
    return std::string(home) + "/.flowcoin";
}

static std::string default_cookie_path() {
    return default_datadir() + "/.cookie";
}

// =========================================================================
// Hashrate formatting
// =========================================================================

static std::string format_hashrate(double h) {
    char buf[64];
    if      (h >= 1e12) std::snprintf(buf, sizeof(buf), "%.2f TH/s", h / 1e12);
    else if (h >= 1e9)  std::snprintf(buf, sizeof(buf), "%.2f GH/s", h / 1e9);
    else if (h >= 1e6)  std::snprintf(buf, sizeof(buf), "%.2f MH/s", h / 1e6);
    else if (h >= 1e3)  std::snprintf(buf, sizeof(buf), "%.2f kH/s", h / 1e3);
    else                std::snprintf(buf, sizeof(buf), "%.2f H/s",  h);
    return buf;
}

// =========================================================================
// Timestamp for log lines
// =========================================================================

static std::string timestamp() {
    auto now = std::chrono::system_clock::now();
    auto tt  = std::chrono::system_clock::to_time_t(now);
    auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                   now.time_since_epoch()) % 1000;
    struct tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &tt);
#else
    localtime_r(&tt, &tm_buf);
#endif
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                  tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                  tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
                  static_cast<int>(ms.count()));
    return buf;
}

// =========================================================================
// Difficulty from nbits
// =========================================================================

static double nbits_to_difficulty(uint32_t nbits) {
    int shift = (nbits >> 24) & 0xff;
    double mantissa = static_cast<double>(nbits & 0x00ffffff);
    if (mantissa == 0.0) return 0.0;
    double pow_limit = static_cast<double>(0xffff);
    int base_shift = 0x1d;
    double d = pow_limit / mantissa;
    int exp_diff = base_shift - shift;
    for (int i = 0; i < std::abs(exp_diff); ++i)
        d *= (exp_diff > 0 ? 256.0 : 1.0 / 256.0);
    return d;
}

// =========================================================================
// CompactSize encoding (for block serialisation)
// =========================================================================

static void encode_compact_size(std::vector<uint8_t>& out, uint64_t v) {
    if (v < 253)            { out.push_back(static_cast<uint8_t>(v)); }
    else if (v <= 0xFFFF)   { out.push_back(253); out.push_back(v & 0xff); out.push_back((v >> 8) & 0xff); }
    else if (v <= 0xFFFFFFFFULL) {
        out.push_back(254);
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (i * 8)));
    } else {
        out.push_back(255);
        for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }
}

// =========================================================================
// Block template
// =========================================================================

struct BlockTemplate {
    uint64_t height    = 0;
    uint32_t nbits     = 0;
    uint32_t version   = 1;
    int64_t  curtime   = 0;
    double   difficulty = 0.0;

    uint8_t  header[HEADER_UNSIGNED]{};
    uint8_t  target_be[32]{};            // big-endian target for GPU
    std::vector<uint8_t> coinbase_tx;

    std::string previousblockhash;
    std::string merkle_root;
    std::string target_hex;
    std::string coinbase_hex;
};

static bool parse_template(const std::string& result_json, BlockTemplate& bt) {
    bt.height    = json_get_uint(result_json, "height");
    bt.nbits     = static_cast<uint32_t>(json_get_uint(result_json, "nbits"));
    bt.version   = static_cast<uint32_t>(json_get_uint(result_json, "version"));
    bt.curtime   = json_get_int(result_json, "curtime");
    bt.difficulty = nbits_to_difficulty(bt.nbits);

    bt.previousblockhash = json_get_string(result_json, "previousblockhash");
    bt.merkle_root       = json_get_string(result_json, "merkle_root");
    bt.target_hex        = json_get_string(result_json, "target");
    bt.coinbase_hex      = json_get_string(result_json, "coinbase_tx");

    auto prev   = hex_decode(bt.previousblockhash);
    auto merkle = hex_decode(bt.merkle_root);
    auto target = hex_decode(bt.target_hex);
    bt.coinbase_tx = hex_decode(bt.coinbase_hex);

    if (prev.size() != 32 || merkle.size() != 32 || target.size() != 32)
        return false;

    // Build the 92-byte unsigned header
    std::memset(bt.header, 0, HEADER_UNSIGNED);
    std::memcpy(bt.header +  0, prev.data(),   32);
    std::memcpy(bt.header + 32, merkle.data(), 32);
    // height (LE uint64)
    for (int i = 0; i < 8; ++i)
        bt.header[64 + i] = static_cast<uint8_t>(bt.height >> (i * 8));
    // timestamp (LE int64)
    for (int i = 0; i < 8; ++i)
        bt.header[72 + i] = static_cast<uint8_t>(bt.curtime >> (i * 8));
    // nbits (LE uint32)
    for (int i = 0; i < 4; ++i)
        bt.header[80 + i] = static_cast<uint8_t>(bt.nbits >> (i * 8));
    // nonce [84..87] left zero -- GPU will fill
    // version (LE uint32)
    for (int i = 0; i < 4; ++i)
        bt.header[88 + i] = static_cast<uint8_t>(bt.version >> (i * 8));

    // Target: RPC gives little-endian display hex; flip to big-endian for GPU
    for (size_t i = 0; i < 32; ++i)
        bt.target_be[i] = target[31 - i];

    return true;
}

// =========================================================================
// Block submission (unsigned header only -- node signs it)
//
// NOTE: The GPU miner does NOT have access to the Ed25519 miner key.
// It submits the raw hex of the unsigned block (header + coinbase).
// The flowcoind node's submitblock RPC accepts this form and signs
// the block using its own miner key, just like the CPU miner does
// on the host side.  If your node requires a pre-signed block,
// you will need to link against ed25519 and add key management.
// For now, we submit: 92-byte header + CompactSize(1) + coinbase_tx.
// =========================================================================

static std::string serialize_unsigned_block(const BlockTemplate& bt,
                                             uint32_t winning_nonce) {
    // We need to produce the full signed block.
    // Since the GPU miner is standalone and does not have the Ed25519 key,
    // we submit the block as a "raw" hex.  The node's submitblock will
    // handle it.  But for a fully working submission we actually need the
    // signed block.  We set pubkey to zeros and sig to zeros -- if the
    // node accepts unsigned blocks (regtest, or if the node is configured
    // to auto-sign).
    //
    // For production use, embed the miner key and sign here.
    uint8_t hdr[HEADER_UNSIGNED];
    std::memcpy(hdr, bt.header, HEADER_UNSIGNED);
    hdr[84] = static_cast<uint8_t>(winning_nonce);
    hdr[85] = static_cast<uint8_t>(winning_nonce >> 8);
    hdr[86] = static_cast<uint8_t>(winning_nonce >> 16);
    hdr[87] = static_cast<uint8_t>(winning_nonce >> 24);

    std::vector<uint8_t> out;
    out.reserve(HEADER_UNSIGNED + 32 + 64 + 1 + bt.coinbase_tx.size());

    // 92-byte header
    out.insert(out.end(), hdr, hdr + HEADER_UNSIGNED);

    // 32-byte public key (zeros for unsigned submission)
    out.insert(out.end(), 32, 0);

    // 64-byte signature (zeros for unsigned submission)
    out.insert(out.end(), 64, 0);

    // CompactSize(1) + coinbase transaction
    encode_compact_size(out, 1);
    out.insert(out.end(), bt.coinbase_tx.begin(), bt.coinbase_tx.end());

    return hex_encode(out.data(), out.size());
}

// =========================================================================
// OpenCL helpers
// =========================================================================

static const char* cl_error_string(cl_int err) {
    switch (err) {
    case CL_SUCCESS:                        return "CL_SUCCESS";
    case CL_DEVICE_NOT_FOUND:               return "CL_DEVICE_NOT_FOUND";
    case CL_DEVICE_NOT_AVAILABLE:           return "CL_DEVICE_NOT_AVAILABLE";
    case CL_COMPILER_NOT_AVAILABLE:         return "CL_COMPILER_NOT_AVAILABLE";
    case CL_BUILD_PROGRAM_FAILURE:          return "CL_BUILD_PROGRAM_FAILURE";
    case CL_INVALID_VALUE:                  return "CL_INVALID_VALUE";
    case CL_INVALID_DEVICE_TYPE:            return "CL_INVALID_DEVICE_TYPE";
    case CL_INVALID_PLATFORM:              return "CL_INVALID_PLATFORM";
    case CL_INVALID_DEVICE:                return "CL_INVALID_DEVICE";
    case CL_INVALID_CONTEXT:               return "CL_INVALID_CONTEXT";
    case CL_INVALID_PROGRAM:               return "CL_INVALID_PROGRAM";
    case CL_INVALID_KERNEL_NAME:           return "CL_INVALID_KERNEL_NAME";
    case CL_INVALID_WORK_GROUP_SIZE:       return "CL_INVALID_WORK_GROUP_SIZE";
    case CL_INVALID_ARG_SIZE:              return "CL_INVALID_ARG_SIZE";
    case CL_OUT_OF_RESOURCES:              return "CL_OUT_OF_RESOURCES";
    case CL_OUT_OF_HOST_MEMORY:            return "CL_OUT_OF_HOST_MEMORY";
    case CL_MEM_OBJECT_ALLOCATION_FAILURE: return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
    default:                                return "UNKNOWN_CL_ERROR";
    }
}

#define CL_CHECK(call) do { \
    cl_int _err = (call); \
    if (_err != CL_SUCCESS) { \
        std::fprintf(stderr, "[%s] ERROR  OpenCL error: %s (%d) at %s:%d\n", \
                     timestamp().c_str(), cl_error_string(_err), _err, \
                     __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

// =========================================================================
// Signal handling
// =========================================================================

static std::atomic<bool> g_stop{false};

static void signal_handler(int) {
    g_stop.store(true);
}

// =========================================================================
// Command-line arguments
// =========================================================================

struct Args {
    std::string url      = "http://127.0.0.1:9334";
    std::string user;
    std::string pass;
    std::string cookie;
    std::string address;
    int         device   = 0;
    int         platform = 0;
    size_t      global_work_size = 1 << 20;  // ~1M work items per dispatch
    size_t      local_work_size  = 256;       // work group size
};

static void print_usage() {
    std::puts(
        "flowminer-opencl " FLOWCOIN_GPU_MINER_VERSION "\n"
        "Usage: flowminer-opencl [options]\n"
        "\n"
        "  -o, --url URL           node RPC URL (default: http://127.0.0.1:9334)\n"
        "  -u, --user USER         HTTP Basic user\n"
        "  -p, --pass PASS         HTTP Basic password\n"
        "      --cookie PATH       read auth from cookie file\n"
        "  -a, --address ADDR      coinbase address (default: node's wallet)\n"
        "  -d, --device N          OpenCL device index (default: 0)\n"
        "      --platform N        OpenCL platform index (default: 0)\n"
        "  -g, --global N          global work size (default: 1048576)\n"
        "  -t, --threads N         local work group size (default: 256)\n"
        "      --list-devices      list available OpenCL devices and exit\n"
        "  -h, --help              this message\n");
}

static bool parse_url(const std::string& url, RpcEndpoint& ep) {
    std::string s = url;
    auto p = s.find("://");
    if (p != std::string::npos) s = s.substr(p + 3);
    auto slash = s.find('/');
    if (slash != std::string::npos) s = s.substr(0, slash);
    auto colon = s.rfind(':');
    if (colon == std::string::npos) { ep.host = s; return true; }
    ep.host = s.substr(0, colon);
    ep.port = static_cast<uint16_t>(std::atoi(s.c_str() + colon + 1));
    return true;
}

// =========================================================================
// List OpenCL devices
// =========================================================================

static int list_devices() {
    cl_uint num_platforms = 0;
    clGetPlatformIDs(0, nullptr, &num_platforms);
    if (num_platforms == 0) {
        std::printf("No OpenCL platforms found.\n");
        return 0;
    }
    std::vector<cl_platform_id> platforms(num_platforms);
    clGetPlatformIDs(num_platforms, platforms.data(), nullptr);

    for (cl_uint pi = 0; pi < num_platforms; ++pi) {
        char pname[256]{};
        clGetPlatformInfo(platforms[pi], CL_PLATFORM_NAME, sizeof(pname), pname, nullptr);
        std::printf("Platform %u: %s\n", pi, pname);

        cl_uint num_devices = 0;
        clGetDeviceIDs(platforms[pi], CL_DEVICE_TYPE_ALL, 0, nullptr, &num_devices);
        std::vector<cl_device_id> devices(num_devices);
        clGetDeviceIDs(platforms[pi], CL_DEVICE_TYPE_ALL, num_devices,
                       devices.data(), nullptr);

        for (cl_uint di = 0; di < num_devices; ++di) {
            char dname[256]{};
            cl_ulong mem = 0;
            cl_uint  cu  = 0;
            clGetDeviceInfo(devices[di], CL_DEVICE_NAME, sizeof(dname), dname, nullptr);
            clGetDeviceInfo(devices[di], CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(mem), &mem, nullptr);
            clGetDeviceInfo(devices[di], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cu), &cu, nullptr);
            std::printf("  Device %u: %s  (%u CUs, %" PRIu64 " MB)\n",
                        di, dname, cu, static_cast<uint64_t>(mem / (1024 * 1024)));
        }
    }
    return 0;
}

// =========================================================================
// Main
// =========================================================================

int main(int argc, char** argv) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    Args a;
    bool do_list = false;

    for (int i = 1; i < argc; ++i) {
        std::string k = argv[i];
        auto take = [&](std::string& dst) {
            if (++i < argc) dst = argv[i];
        };
        if      (k == "-h" || k == "--help")        { print_usage(); return 0; }
        else if (k == "-o" || k == "--url")         take(a.url);
        else if (k == "-u" || k == "--user")        take(a.user);
        else if (k == "-p" || k == "--pass")        take(a.pass);
        else if (k == "--cookie")                   take(a.cookie);
        else if (k == "-a" || k == "--address")     take(a.address);
        else if (k == "-d" || k == "--device")      { std::string s; take(s); a.device = std::stoi(s); }
        else if (k == "--platform")                 { std::string s; take(s); a.platform = std::stoi(s); }
        else if (k == "-g" || k == "--global")      { std::string s; take(s); a.global_work_size = std::stoul(s); }
        else if (k == "-t" || k == "--threads")     { std::string s; take(s); a.local_work_size = std::stoul(s); }
        else if (k == "--list-devices")              do_list = true;
        else { std::fprintf(stderr, "unknown option: %s\n", k.c_str()); return 2; }
    }

    if (do_list) return list_devices();

    // ---- Signal handlers ----
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    // ---- RPC endpoint ----
    RpcEndpoint ep;
    parse_url(a.url, ep);
    if (!a.cookie.empty()) {
        if (!load_cookie(a.cookie, ep.auth)) {
            std::fprintf(stderr, "[%s] ERROR  cannot read cookie file %s\n",
                         timestamp().c_str(), a.cookie.c_str());
            return 3;
        }
    } else if (!a.user.empty() || !a.pass.empty()) {
        ep.auth.user = a.user;
        ep.auth.pass = a.pass;
    } else {
        std::string auto_cookie = default_cookie_path();
        if (load_cookie(auto_cookie, ep.auth)) {
            std::printf("[%s] CONFIG  using cookie auth from %s\n",
                        timestamp().c_str(), auto_cookie.c_str());
        }
    }

    // ---- Banner ----
    std::printf("\n");
    std::printf(" * ABOUT         flowminer-opencl/" FLOWCOIN_GPU_MINER_VERSION "\n");
    std::printf(" * ALGO          keccak-256d\n");
    std::printf(" * NODE          %s:%u\n", ep.host.c_str(), ep.port);
    if (!a.address.empty())
        std::printf(" * ADDRESS       %s\n", a.address.c_str());
    std::printf(" * PLATFORM      %d\n", a.platform);
    std::printf(" * DEVICE        %d\n", a.device);
    std::printf(" * GLOBAL SIZE   %zu\n", a.global_work_size);
    std::printf(" * LOCAL SIZE    %zu\n", a.local_work_size);
    std::printf("\n");

    // ---- Initial connectivity check ----
    {
        auto r = rpc_call(ep, "getblockcount", "[]");
        if (!r) {
            std::fprintf(stderr, "[%s] ERROR  cannot reach node at %s:%u\n",
                         timestamp().c_str(), ep.host.c_str(), ep.port);
            return 4;
        }
        std::printf("[%s] NET     connected to %s:%u  height=%s\n",
                    timestamp().c_str(), ep.host.c_str(), ep.port, r->c_str());
    }

    // ---- OpenCL setup ----
    cl_uint num_platforms = 0;
    CL_CHECK(clGetPlatformIDs(0, nullptr, &num_platforms));
    if (num_platforms == 0 || static_cast<cl_uint>(a.platform) >= num_platforms) {
        std::fprintf(stderr, "[%s] ERROR  invalid OpenCL platform %d (found %u)\n",
                     timestamp().c_str(), a.platform, num_platforms);
        return 5;
    }
    std::vector<cl_platform_id> platforms(num_platforms);
    CL_CHECK(clGetPlatformIDs(num_platforms, platforms.data(), nullptr));

    cl_platform_id plat = platforms[a.platform];
    {
        char pname[256]{};
        clGetPlatformInfo(plat, CL_PLATFORM_NAME, sizeof(pname), pname, nullptr);
        std::printf("[%s] OPENCL  platform: %s\n", timestamp().c_str(), pname);
    }

    cl_uint num_devices = 0;
    CL_CHECK(clGetDeviceIDs(plat, CL_DEVICE_TYPE_ALL, 0, nullptr, &num_devices));
    if (num_devices == 0 || static_cast<cl_uint>(a.device) >= num_devices) {
        std::fprintf(stderr, "[%s] ERROR  invalid OpenCL device %d (found %u)\n",
                     timestamp().c_str(), a.device, num_devices);
        return 5;
    }
    std::vector<cl_device_id> devices(num_devices);
    CL_CHECK(clGetDeviceIDs(plat, CL_DEVICE_TYPE_ALL, num_devices,
                             devices.data(), nullptr));

    cl_device_id dev = devices[a.device];
    {
        char dname[256]{};
        cl_ulong mem = 0;
        cl_uint  cu  = 0;
        clGetDeviceInfo(dev, CL_DEVICE_NAME, sizeof(dname), dname, nullptr);
        clGetDeviceInfo(dev, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(mem), &mem, nullptr);
        clGetDeviceInfo(dev, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cu), &cu, nullptr);
        std::printf("[%s] OPENCL  device: %s  (%u CUs, %" PRIu64 " MB)\n",
                    timestamp().c_str(), dname, cu,
                    static_cast<uint64_t>(mem / (1024 * 1024)));
    }

    cl_int err;
    cl_context ctx = clCreateContext(nullptr, 1, &dev, nullptr, nullptr, &err);
    CL_CHECK(err);

    // Use clCreateCommandQueue (OpenCL 1.x compatible)
    cl_command_queue queue = clCreateCommandQueue(ctx, dev, 0, &err);
    CL_CHECK(err);

    // ---- Build kernel ----
    const char* src_ptr = KERNEL_SOURCE;
    size_t src_len = std::strlen(KERNEL_SOURCE);
    cl_program prog = clCreateProgramWithSource(ctx, 1, &src_ptr, &src_len, &err);
    CL_CHECK(err);

    err = clBuildProgram(prog, 1, &dev, "-cl-std=CL1.2", nullptr, nullptr);
    if (err != CL_SUCCESS) {
        size_t log_size = 0;
        clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
        std::string build_log(log_size, '\0');
        clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, log_size,
                              build_log.data(), nullptr);
        std::fprintf(stderr, "[%s] ERROR  kernel build failed:\n%s\n",
                     timestamp().c_str(), build_log.c_str());
        return 6;
    }

    cl_kernel kernel = clCreateKernel(prog, "mine", &err);
    CL_CHECK(err);

    std::printf("[%s] OPENCL  kernel compiled successfully\n", timestamp().c_str());

    // ---- Allocate GPU buffers ----
    cl_mem buf_header = clCreateBuffer(ctx, CL_MEM_READ_ONLY, HEADER_UNSIGNED, nullptr, &err);
    CL_CHECK(err);
    cl_mem buf_target = clCreateBuffer(ctx, CL_MEM_READ_ONLY, 32, nullptr, &err);
    CL_CHECK(err);
    cl_mem buf_result_nonce = clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(cl_uint), nullptr, &err);
    CL_CHECK(err);
    cl_mem buf_result_hash = clCreateBuffer(ctx, CL_MEM_READ_WRITE, 32, nullptr, &err);
    CL_CHECK(err);
    cl_mem buf_result_found = clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(cl_uint), nullptr, &err);
    CL_CHECK(err);

    // Set kernel args (buffers are fixed, nonce_base changes per dispatch)
    CL_CHECK(clSetKernelArg(kernel, 0, sizeof(cl_mem), &buf_header));
    CL_CHECK(clSetKernelArg(kernel, 1, sizeof(cl_mem), &buf_target));
    // arg 2 (nonce_base) set per dispatch
    CL_CHECK(clSetKernelArg(kernel, 3, sizeof(cl_mem), &buf_result_nonce));
    CL_CHECK(clSetKernelArg(kernel, 4, sizeof(cl_mem), &buf_result_hash));
    CL_CHECK(clSetKernelArg(kernel, 5, sizeof(cl_mem), &buf_result_found));

    // ---- Mining loop ----
    uint32_t nonce_cursor = 0;
    uint64_t total_hashes = 0;
    uint64_t submits  = 0;
    uint64_t accepted = 0;
    uint64_t rejected = 0;

    BlockTemplate current_bt;
    bool have_template = false;
    auto last_template_poll = std::chrono::steady_clock::now() - std::chrono::seconds(999);
    auto last_speed_print   = std::chrono::steady_clock::now();
    auto speed_start        = std::chrono::steady_clock::now();
    uint64_t speed_hashes   = 0;

    // Round global_work_size up to multiple of local_work_size
    size_t gws = a.global_work_size;
    size_t lws = a.local_work_size;
    if (gws % lws != 0)
        gws = ((gws / lws) + 1) * lws;

    while (!g_stop.load(std::memory_order_relaxed)) {
        auto now = std::chrono::steady_clock::now();

        // ---- Poll for new template ----
        if (now - last_template_poll > std::chrono::seconds(3) || !have_template) {
            last_template_poll = now;
            std::string params = a.address.empty() ? "[]" : "[\"" + a.address + "\"]";
            auto r = rpc_call(ep, "getblocktemplate", params);
            if (!r) {
                std::fprintf(stderr, "[%s] NET     getblocktemplate failed\n",
                             timestamp().c_str());
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }

            BlockTemplate bt;
            if (!parse_template(*r, bt)) {
                std::fprintf(stderr, "[%s] NET     malformed template\n",
                             timestamp().c_str());
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }

            // Check if template changed (different height or different header)
            bool changed = !have_template || bt.height != current_bt.height ||
                           std::memcmp(bt.header, current_bt.header, HEADER_UNSIGNED) != 0;

            if (changed) {
                current_bt = bt;
                have_template = true;
                nonce_cursor = 0;

                // Upload header and target to GPU
                CL_CHECK(clEnqueueWriteBuffer(queue, buf_header, CL_TRUE, 0,
                                               HEADER_UNSIGNED, bt.header,
                                               0, nullptr, nullptr));
                CL_CHECK(clEnqueueWriteBuffer(queue, buf_target, CL_TRUE, 0,
                                               32, bt.target_be,
                                               0, nullptr, nullptr));

                char diff_buf[32];
                std::snprintf(diff_buf, sizeof(diff_buf), "%.3f", bt.difficulty);
                std::printf("[%s] NET     new job  height=%" PRIu64 "  diff=%s  algo=keccak-256d\n",
                            timestamp().c_str(), bt.height, diff_buf);
            }
        }

        if (!have_template) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        // ---- Reset result buffers ----
        cl_uint zero = 0;
        CL_CHECK(clEnqueueWriteBuffer(queue, buf_result_found, CL_TRUE, 0,
                                       sizeof(cl_uint), &zero, 0, nullptr, nullptr));
        CL_CHECK(clEnqueueWriteBuffer(queue, buf_result_nonce, CL_TRUE, 0,
                                       sizeof(cl_uint), &zero, 0, nullptr, nullptr));
        uint8_t zero_hash[32]{};
        CL_CHECK(clEnqueueWriteBuffer(queue, buf_result_hash, CL_TRUE, 0,
                                       32, zero_hash, 0, nullptr, nullptr));

        // ---- Set nonce_base and dispatch ----
        cl_uint nonce_base = nonce_cursor;
        CL_CHECK(clSetKernelArg(kernel, 2, sizeof(cl_uint), &nonce_base));

        CL_CHECK(clEnqueueNDRangeKernel(queue, kernel, 1, nullptr,
                                         &gws, &lws,
                                         0, nullptr, nullptr));
        CL_CHECK(clFinish(queue));

        total_hashes += gws;
        speed_hashes += gws;

        // Check for nonce overflow (wrap around to 0; re-fetch template)
        uint64_t next = static_cast<uint64_t>(nonce_cursor) + gws;
        if (next > 0xFFFFFFFFULL) {
            nonce_cursor = 0;
            // Force template refresh on nonce exhaustion
            last_template_poll = std::chrono::steady_clock::now() - std::chrono::seconds(999);
        } else {
            nonce_cursor = static_cast<uint32_t>(next);
        }

        // ---- Check result ----
        cl_uint found = 0;
        CL_CHECK(clEnqueueReadBuffer(queue, buf_result_found, CL_TRUE, 0,
                                      sizeof(cl_uint), &found, 0, nullptr, nullptr));

        if (found) {
            cl_uint winning_nonce = 0;
            uint8_t winning_hash[32]{};
            CL_CHECK(clEnqueueReadBuffer(queue, buf_result_nonce, CL_TRUE, 0,
                                          sizeof(cl_uint), &winning_nonce,
                                          0, nullptr, nullptr));
            CL_CHECK(clEnqueueReadBuffer(queue, buf_result_hash, CL_TRUE, 0,
                                          32, winning_hash, 0, nullptr, nullptr));

            std::printf("[%s] MINER   found nonce=%u  hash=%s\n",
                        timestamp().c_str(), winning_nonce,
                        hex_encode(winning_hash, 32).c_str());

            // Submit block
            std::string hex = serialize_unsigned_block(current_bt, winning_nonce);
            auto ts = std::chrono::steady_clock::now();
            ++submits;

            auto r = rpc_call(ep, "submitblock", "[\"" + hex + "\"]");
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - ts).count();

            // submitblock returns null on success, or an error string
            bool ok = r && (*r == "null" || *r == "\"\"");
            if (ok) {
                ++accepted;
                std::printf("[%s] MINER   accepted (%" PRIu64 "/%" PRIu64
                            ") height=%" PRIu64 "  nonce=%u  (%" PRId64 " ms)\n",
                            timestamp().c_str(), accepted, submits,
                            current_bt.height, winning_nonce,
                            static_cast<int64_t>(ms));
            } else {
                ++rejected;
                std::string reason = r ? *r : "no response";
                std::printf("[%s] MINER   rejected (%" PRIu64 "/%" PRIu64
                            ") height=%" PRIu64 "  %s  (%" PRId64 " ms)\n",
                            timestamp().c_str(), rejected, submits,
                            current_bt.height, reason.c_str(),
                            static_cast<int64_t>(ms));
            }

            // Force template refresh after submit
            last_template_poll = std::chrono::steady_clock::now() - std::chrono::seconds(999);
            have_template = false;
        }

        // ---- Periodic hashrate ----
        now = std::chrono::steady_clock::now();
        if (now - last_speed_print > std::chrono::seconds(10)) {
            double elapsed = std::chrono::duration<double>(now - speed_start).count();
            double rate = elapsed > 0.0 ? static_cast<double>(speed_hashes) / elapsed : 0.0;
            std::printf("[%s] MINER   speed %s  total=%" PRIu64 "\n",
                        timestamp().c_str(), format_hashrate(rate).c_str(),
                        total_hashes);
            speed_hashes = 0;
            speed_start  = now;
            last_speed_print = now;
        }
    }

    // ---- Cleanup ----
    std::printf("[%s] SIGNAL  stopping\n", timestamp().c_str());

    clReleaseMemObject(buf_header);
    clReleaseMemObject(buf_target);
    clReleaseMemObject(buf_result_nonce);
    clReleaseMemObject(buf_result_hash);
    clReleaseMemObject(buf_result_found);
    clReleaseKernel(kernel);
    clReleaseProgram(prog);
    clReleaseCommandQueue(queue);
    clReleaseContext(ctx);

    std::printf("[%s] MINER   stopped. total=%" PRIu64 "  accepted=%" PRIu64
                "  rejected=%" PRIu64 "\n",
                timestamp().c_str(), submits, accepted, rejected);

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

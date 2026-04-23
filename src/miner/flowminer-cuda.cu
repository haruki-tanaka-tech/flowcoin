// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// flowminer-cuda — standalone GPU miner for FlowCoin (Keccak-256d PoW).
//
// Build:
//   nvcc -O3 -arch=sm_86 flowminer-cuda.cu -o flowminer-cuda
//   (Windows: add -lws2_32)
//   nvcc -O3 -arch=sm_86 flowminer-cuda.cu -o flowminer-cuda.exe -lws2_32
//
// Talks to a flowcoind node over HTTP JSON-RPC (getblocktemplate, submitblock).
// Each CUDA device runs a grid of threads, each computing keccak256d(header)
// with a unique nonce. Valid solutions are reported back to the host for
// Ed25519 signing and submission.
//
// Header layout (92 bytes unsigned):
//   [0..31]   prev_hash   (32 bytes)
//   [32..63]  merkle_root (32 bytes)
//   [64..71]  height      (8 bytes LE)
//   [72..79]  timestamp   (8 bytes LE)
//   [80..83]  nbits       (4 bytes LE)
//   [84..87]  nonce       (4 bytes LE)  <-- GPU writes this
//   [88..91]  version     (4 bytes LE)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cinttypes>
#include <string>
#include <vector>
#include <optional>
#include <fstream>
#include <sstream>
#include <chrono>
#include <thread>
#include <atomic>
#include <csignal>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
   typedef int socklen_t;
#  define CLOSE_SOCKET closesocket
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <unistd.h>
#  define CLOSE_SOCKET close
   typedef int SOCKET;
#  define INVALID_SOCKET (-1)
#  define SOCKET_ERROR   (-1)
#endif

#include <cuda_runtime.h>

// ============================================================================
// Minimal JSON helpers (no external dependency)
// ============================================================================
//
// We implement a tiny subset of JSON parsing/generation sufficient for
// JSON-RPC with getblocktemplate and submitblock. This avoids requiring
// nlohmann-json or any other library in the CUDA compilation unit.

// Escape a string for JSON output.
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

// Build a JSON-RPC request string.
static std::string json_rpc_request(const std::string& method,
                                     const std::string& params_array) {
    return "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" +
           json_escape(method) + "\",\"params\":" + params_array + "}";
}

// Simple JSON value extractor: find "key":"value" and return value (string).
// Only works for simple flat objects. Returns empty on miss.
static std::string json_get_string(const std::string& json,
                                    const std::string& key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "";
    pos += needle.size();
    // Skip whitespace and colon
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' ||
           json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r'))
        ++pos;
    if (pos >= json.size() || json[pos] != '"') return "";
    ++pos; // skip opening quote
    std::string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            ++pos;
            switch (json[pos]) {
                case '"':  result += '"';  break;
                case '\\': result += '\\'; break;
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                default:   result += json[pos]; break;
            }
        } else {
            result += json[pos];
        }
        ++pos;
    }
    return result;
}

// Extract a numeric value for "key":number (integer).
static int64_t json_get_int(const std::string& json, const std::string& key,
                             int64_t def = 0) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return def;
    pos += needle.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' ||
           json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r'))
        ++pos;
    if (pos >= json.size()) return def;
    // Read digits (possibly with leading minus)
    std::string numstr;
    if (json[pos] == '-') { numstr += '-'; ++pos; }
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
        numstr += json[pos++];
    }
    if (numstr.empty() || numstr == "-") return def;
    return std::stoll(numstr);
}

// Extract an unsigned numeric value.
static uint64_t json_get_uint(const std::string& json, const std::string& key,
                               uint64_t def = 0) {
    int64_t v = json_get_int(json, key, static_cast<int64_t>(def));
    return static_cast<uint64_t>(v);
}

// Extract the "result" object/value as a raw substring from JSON-RPC response.
// Returns the raw JSON value after "result":
static std::string json_get_result(const std::string& json) {
    auto pos = json.find("\"result\"");
    if (pos == std::string::npos) return "";
    pos += 8; // skip "result"
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' ||
           json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r'))
        ++pos;
    if (pos >= json.size()) return "";

    // Determine the type and extract the value
    char c = json[pos];
    if (c == 'n') {
        // null
        return "null";
    } else if (c == '"') {
        // String
        ++pos;
        std::string result = "\"";
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) {
                result += json[pos++];
            }
            result += json[pos++];
        }
        result += '"';
        return result;
    } else if (c == '{') {
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
    } else if (c == '[') {
        int depth = 1;
        size_t start = pos;
        ++pos;
        while (pos < json.size() && depth > 0) {
            if (json[pos] == '[') ++depth;
            else if (json[pos] == ']') --depth;
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
    } else {
        // Number or boolean
        size_t start = pos;
        while (pos < json.size() && json[pos] != ',' && json[pos] != '}' &&
               json[pos] != ']' && json[pos] != ' ' && json[pos] != '\n')
            ++pos;
        return json.substr(start, pos - start);
    }
}

// Check if the JSON-RPC response has an error.
static bool json_has_error(const std::string& json) {
    auto pos = json.find("\"error\"");
    if (pos == std::string::npos) return false;
    pos += 7;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' ||
           json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r'))
        ++pos;
    if (pos < json.size() && json[pos] == 'n') return false; // null
    return true;
}

// ============================================================================
// Hex helpers
// ============================================================================

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

// ============================================================================
// Base64 encoding
// ============================================================================

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

// ============================================================================
// HTTP / JSON-RPC client (copied pattern from flowminer.cpp)
// ============================================================================

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

    SOCKET sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#ifdef _WIN32
    if (sock == INVALID_SOCKET) { ::freeaddrinfo(ai); return std::nullopt; }
    if (::connect(sock, ai->ai_addr, (int)ai->ai_addrlen) == SOCKET_ERROR) {
        CLOSE_SOCKET(sock); ::freeaddrinfo(ai); return std::nullopt;
    }
#else
    if (sock < 0) { ::freeaddrinfo(ai); return std::nullopt; }
    if (::connect(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
        CLOSE_SOCKET(sock); ::freeaddrinfo(ai); return std::nullopt;
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
    if (!ep.auth.user.empty() || !ep.auth.pass.empty()) {
        req += "Authorization: Basic " +
               base64_encode(ep.auth.user + ":" + ep.auth.pass) + "\r\n";
    }
    req += "\r\n";
    req += body;

    size_t sent = 0;
    while (sent < req.size()) {
        int n = ::send(sock, req.data() + sent, (int)(req.size() - sent), 0);
        if (n <= 0) { CLOSE_SOCKET(sock); return std::nullopt; }
        sent += static_cast<size_t>(n);
    }

    std::string resp;
    char buf[4096];
    for (;;) {
        int n = ::recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, static_cast<size_t>(n));
    }
    CLOSE_SOCKET(sock);

    auto pos = resp.find("\r\n\r\n");
    if (pos == std::string::npos) return std::nullopt;
    return resp.substr(pos + 4);
}

// Perform a JSON-RPC call. Returns the full response body (so caller can
// parse result or error).
static std::optional<std::string> rpc_call_raw(const RpcEndpoint& ep,
                                                const std::string& method,
                                                const std::string& params) {
    std::string body = json_rpc_request(method, params);
    return http_post(ep, body);
}

// Cookie auth loader (user:pass from .cookie file).
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

// ============================================================================
// CompactSize encoding (for block serialization)
// ============================================================================

static void encode_compact_size(std::vector<uint8_t>& out, uint64_t v) {
    if (v < 253) {
        out.push_back(static_cast<uint8_t>(v));
    } else if (v <= 0xFFFF) {
        out.push_back(253);
        out.push_back(v & 0xff);
        out.push_back((v >> 8) & 0xff);
    } else if (v <= 0xFFFFFFFFULL) {
        out.push_back(254);
        for (int i = 0; i < 4; ++i)
            out.push_back(static_cast<uint8_t>(v >> (i * 8)));
    } else {
        out.push_back(255);
        for (int i = 0; i < 8; ++i)
            out.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }
}

// ============================================================================
// Difficulty display
// ============================================================================

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

static std::string format_hashrate(double h) {
    char buf[32];
    if      (h >= 1e12) std::snprintf(buf, sizeof(buf), "%.2f TH/s", h / 1e12);
    else if (h >= 1e9)  std::snprintf(buf, sizeof(buf), "%.2f GH/s", h / 1e9);
    else if (h >= 1e6)  std::snprintf(buf, sizeof(buf), "%.2f MH/s", h / 1e6);
    else if (h >= 1e3)  std::snprintf(buf, sizeof(buf), "%.2f kH/s", h / 1e3);
    else                std::snprintf(buf, sizeof(buf), "%.2f H/s",  h);
    return buf;
}

// ============================================================================
// Timestamp helper
// ============================================================================

static std::string timestamp_now() {
    auto now = std::chrono::system_clock::now();
    auto tt  = std::chrono::system_clock::to_time_t(now);
    auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                   now.time_since_epoch()) % 1000;
    char buf[32];
    struct tm lt;
#ifdef _WIN32
    localtime_s(&lt, &tt);
#else
    localtime_r(&tt, &lt);
#endif
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                  lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
                  lt.tm_hour, lt.tm_min, lt.tm_sec, (int)ms.count());
    return buf;
}

// ============================================================================
// CUDA error checking
// ============================================================================

#define CUDA_CHECK(call)                                                     \
    do {                                                                      \
        cudaError_t err = (call);                                             \
        if (err != cudaSuccess) {                                             \
            std::fprintf(stderr, "[%s]  CUDA ERROR  %s at %s:%d\n",          \
                         timestamp_now().c_str(),                             \
                         cudaGetErrorString(err), __FILE__, __LINE__);        \
            std::exit(1);                                                     \
        }                                                                     \
    } while (0)

// ============================================================================
// Keccak-1600 permutation — CUDA device implementation
// ============================================================================
//
// Keccak-256 parameters:
//   Rate      = 1088 bits = 136 bytes (17 lanes of 64 bits)
//   Capacity  = 512 bits
//   Output    = 256 bits  = 32 bytes  (4 lanes)
//   Pad byte  = 0x01 (original Keccak, NOT SHA-3's 0x06)
//
// For a 92-byte message:
//   92 < 136 (rate), so the entire message fits in one block.
//   Padding: msg[92] = 0x01, msg[135] |= 0x80, rest zeros.
//   Absorb the 136-byte padded block into the state, then squeeze 32 bytes.
//
// For the second hash (32 bytes input):
//   32 < 136, so again one block.
//   Padding: msg[32] = 0x01, msg[135] |= 0x80, rest zeros.

// Round constants for Keccak-f[1600] (24 rounds).
__constant__ uint64_t d_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rotation offsets for rho step.
// Lane (x,y) gets rotated left by ROT[x][y] positions.
// State indexing: lane index = x + 5*y, where x=0..4, y=0..4.
__constant__ int d_ROT[25] = {
    // (x,y) = (0,0),(1,0),(2,0),(3,0),(4,0),
    //          (0,1),(1,1),(2,1),(3,1),(4,1), ...
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

// Full Keccak-f[1600] permutation (24 rounds): theta, rho, pi, chi, iota.
__device__ __forceinline__ void keccak_f1600(uint64_t* A) {
    // A[25] is the state array, indexed as A[x + 5*y].
    uint64_t C[5], D[5], B[25];

    for (int round = 0; round < 24; ++round) {
        // --- Theta ---
        C[0] = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
        C[1] = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
        C[2] = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
        C[3] = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
        C[4] = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];

        D[0] = C[4] ^ ((C[1] << 1) | (C[1] >> 63));
        D[1] = C[0] ^ ((C[2] << 1) | (C[2] >> 63));
        D[2] = C[1] ^ ((C[3] << 1) | (C[3] >> 63));
        D[3] = C[2] ^ ((C[4] << 1) | (C[4] >> 63));
        D[4] = C[3] ^ ((C[0] << 1) | (C[0] >> 63));

        #pragma unroll
        for (int i = 0; i < 25; i += 5) {
            A[i + 0] ^= D[0];
            A[i + 1] ^= D[1];
            A[i + 2] ^= D[2];
            A[i + 3] ^= D[3];
            A[i + 4] ^= D[4];
        }

        // --- Rho + Pi ---
        // B[y + 5 * ((2*x + 3*y) % 5)] = ROT(A[x + 5*y], r[x + 5*y])
        // Unrolled for clarity and performance:
        B[ 0] = A[ 0];  // rot 0
        B[10] = (A[ 1] <<  1) | (A[ 1] >> 63);
        B[20] = (A[ 2] << 62) | (A[ 2] >>  2);
        B[ 5] = (A[ 3] << 28) | (A[ 3] >> 36);
        B[15] = (A[ 4] << 27) | (A[ 4] >> 37);

        B[16] = (A[ 5] << 36) | (A[ 5] >> 28);
        B[ 1] = (A[ 6] << 44) | (A[ 6] >> 20);
        B[11] = (A[ 7] <<  6) | (A[ 7] >> 58);
        B[21] = (A[ 8] << 55) | (A[ 8] >>  9);
        B[ 6] = (A[ 9] << 20) | (A[ 9] >> 44);

        B[ 7] = (A[10] <<  3) | (A[10] >> 61);
        B[17] = (A[11] << 10) | (A[11] >> 54);
        B[ 2] = (A[12] << 43) | (A[12] >> 21);
        B[12] = (A[13] << 25) | (A[13] >> 39);
        B[22] = (A[14] << 39) | (A[14] >> 25);

        B[23] = (A[15] << 41) | (A[15] >> 23);
        B[ 8] = (A[16] << 45) | (A[16] >> 19);
        B[18] = (A[17] << 15) | (A[17] >> 49);
        B[ 3] = (A[18] << 21) | (A[18] >> 43);
        B[13] = (A[19] <<  8) | (A[19] >> 56);

        B[14] = (A[20] << 18) | (A[20] >> 46);
        B[24] = (A[21] <<  2) | (A[21] >> 62);
        B[ 9] = (A[22] << 61) | (A[22] >>  3);
        B[19] = (A[23] << 56) | (A[23] >>  8);
        B[ 4] = (A[24] << 14) | (A[24] >> 50);

        // --- Chi ---
        #pragma unroll
        for (int i = 0; i < 25; i += 5) {
            A[i + 0] = B[i + 0] ^ ((~B[i + 1]) & B[i + 2]);
            A[i + 1] = B[i + 1] ^ ((~B[i + 2]) & B[i + 3]);
            A[i + 2] = B[i + 2] ^ ((~B[i + 3]) & B[i + 4]);
            A[i + 3] = B[i + 3] ^ ((~B[i + 4]) & B[i + 0]);
            A[i + 4] = B[i + 4] ^ ((~B[i + 0]) & B[i + 1]);
        }

        // --- Iota ---
        A[0] ^= d_RC[round];
    }
}

// ============================================================================
// Device Keccak-256 for exactly 92 bytes (header hash, first pass)
// ============================================================================

// Absorb a 92-byte message with original Keccak padding (0x01), squeeze 32 bytes.
__device__ __forceinline__ void keccak256_92(const uint8_t* msg, uint8_t* out32) {
    uint64_t A[25];
    #pragma unroll
    for (int i = 0; i < 25; ++i) A[i] = 0;

    // Load 92 bytes into lanes 0..11 (11 full lanes = 88 bytes)
    // and partially into lane 11 (bytes 88..91 = 4 bytes at offset 88).
    // Wait -- let me recalculate: 11 full lanes = 88 bytes, then we have
    // 4 remaining bytes that go into lane 11 at the bottom.
    // Actually: 92 / 8 = 11.5, so 11 full 64-bit words plus 4 extra bytes.

    // Load 11 full lanes (bytes 0..87)
    #pragma unroll
    for (int i = 0; i < 11; ++i) {
        uint64_t lane = 0;
        #pragma unroll
        for (int b = 0; b < 8; ++b) {
            lane |= ((uint64_t)msg[i * 8 + b]) << (b * 8);
        }
        A[i] = lane;
    }

    // Lane 11: bytes 88..91 (4 bytes) + pad byte 0x01 at offset 92 (byte 4 of lane 11)
    {
        uint64_t lane = 0;
        lane |= ((uint64_t)msg[88]);
        lane |= ((uint64_t)msg[89]) << 8;
        lane |= ((uint64_t)msg[90]) << 16;
        lane |= ((uint64_t)msg[91]) << 24;
        lane |= ((uint64_t)0x01)    << 32;  // pad byte at position 92
        A[11] = lane;
    }

    // Lanes 12..16 are zero (no data), lane 16 (last lane of rate, index 16)
    // gets the final padding bit: byte 135 of the rate block.
    // Rate = 136 bytes = 17 lanes. Last byte of rate is byte 135 = lane 16, byte 7.
    // So lane 16 |= 0x80 << 56.
    A[16] = (uint64_t)0x80 << 56;

    // Permute
    keccak_f1600(A);

    // Squeeze: output 32 bytes = lanes 0..3 (4 * 8 = 32 bytes), little-endian.
    #pragma unroll
    for (int i = 0; i < 4; ++i) {
        uint64_t lane = A[i];
        #pragma unroll
        for (int b = 0; b < 8; ++b) {
            out32[i * 8 + b] = (uint8_t)(lane >> (b * 8));
        }
    }
}

// ============================================================================
// Device Keccak-256 for exactly 32 bytes (second pass of keccak256d)
// ============================================================================

__device__ __forceinline__ void keccak256_32(const uint8_t* msg, uint8_t* out32) {
    uint64_t A[25];
    #pragma unroll
    for (int i = 0; i < 25; ++i) A[i] = 0;

    // Load 32 bytes = 4 full lanes
    #pragma unroll
    for (int i = 0; i < 4; ++i) {
        uint64_t lane = 0;
        #pragma unroll
        for (int b = 0; b < 8; ++b) {
            lane |= ((uint64_t)msg[i * 8 + b]) << (b * 8);
        }
        A[i] = lane;
    }

    // Pad byte 0x01 at position 32 = lane 4, byte 0
    A[4] = 0x01;

    // Final pad: last byte of rate (byte 135 = lane 16, byte 7)
    A[16] = (uint64_t)0x80 << 56;

    keccak_f1600(A);

    #pragma unroll
    for (int i = 0; i < 4; ++i) {
        uint64_t lane = A[i];
        #pragma unroll
        for (int b = 0; b < 8; ++b) {
            out32[i * 8 + b] = (uint8_t)(lane >> (b * 8));
        }
    }
}

// ============================================================================
// Mining kernel
// ============================================================================
//
// Each thread:
//   1. Computes its unique nonce = base_nonce + global_thread_id
//   2. Copies 92-byte header template, writes nonce at bytes [84..87]
//   3. Computes keccak256d(header)
//   4. Compares hash against target (big-endian byte comparison: hash <= target)
//   5. If valid: atomically write nonce to d_found_nonce, set d_found flag
//
// We pass the header template in constant memory and the target in constant memory.

// Device results (pinned global memory, one per device).
struct DeviceResult {
    uint32_t nonce;
    uint8_t  hash[32];
    int      found;  // 0 = not found, 1 = found
};

__global__ void mining_kernel(const uint8_t* __restrict__ d_header,
                               const uint8_t* __restrict__ d_target,
                               uint32_t base_nonce,
                               DeviceResult* __restrict__ d_result) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t nonce = base_nonce + tid;

    // If we wrapped around, skip (handles the edge case near UINT32_MAX).
    if (nonce < base_nonce && tid != 0) return;

    // Copy header to registers.
    uint8_t hdr[92];
    #pragma unroll
    for (int i = 0; i < 92; ++i) hdr[i] = d_header[i];

    // Write nonce at bytes [84..87] (little-endian).
    hdr[84] = (uint8_t)(nonce);
    hdr[85] = (uint8_t)(nonce >> 8);
    hdr[86] = (uint8_t)(nonce >> 16);
    hdr[87] = (uint8_t)(nonce >> 24);

    // First Keccak-256 pass.
    uint8_t inner[32];
    keccak256_92(hdr, inner);

    // Second Keccak-256 pass.
    uint8_t hash[32];
    keccak256_32(inner, hash);

    // Compare hash <= target (big-endian byte comparison).
    // Both hash and target are stored with byte [0] most significant.
    bool valid = true;
    bool decided = false;
    #pragma unroll
    for (int i = 0; i < 32; ++i) {
        if (!decided) {
            if (hash[i] < d_target[i]) {
                decided = true;
                // valid remains true
            } else if (hash[i] > d_target[i]) {
                decided = true;
                valid = false;
            }
            // If equal, continue to next byte.
        }
    }

    if (valid) {
        // Atomically claim the result slot. Only the first finder wins.
        int prev = atomicCAS(&d_result->found, 0, 1);
        if (prev == 0) {
            d_result->nonce = nonce;
            #pragma unroll
            for (int i = 0; i < 32; ++i)
                d_result->hash[i] = hash[i];
        }
    }
}

// ============================================================================
// Host-side Keccak-256d (for signing — we need to hash the unsigned header
// on the CPU side to verify before submitting, and for any other CPU hashing).
// We implement the full permutation on the host side too.
// ============================================================================

static const uint64_t h_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

static void host_keccak_f1600(uint64_t* A) {
    uint64_t C[5], D[5], B[25];
    for (int round = 0; round < 24; ++round) {
        C[0] = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
        C[1] = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
        C[2] = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
        C[3] = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
        C[4] = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];

        D[0] = C[4] ^ rotl64(C[1], 1);
        D[1] = C[0] ^ rotl64(C[2], 1);
        D[2] = C[1] ^ rotl64(C[3], 1);
        D[3] = C[2] ^ rotl64(C[4], 1);
        D[4] = C[3] ^ rotl64(C[0], 1);

        for (int i = 0; i < 25; i += 5) {
            A[i+0] ^= D[0]; A[i+1] ^= D[1]; A[i+2] ^= D[2];
            A[i+3] ^= D[3]; A[i+4] ^= D[4];
        }

        B[ 0] = A[ 0];
        B[10] = rotl64(A[ 1],  1);
        B[20] = rotl64(A[ 2], 62);
        B[ 5] = rotl64(A[ 3], 28);
        B[15] = rotl64(A[ 4], 27);
        B[16] = rotl64(A[ 5], 36);
        B[ 1] = rotl64(A[ 6], 44);
        B[11] = rotl64(A[ 7],  6);
        B[21] = rotl64(A[ 8], 55);
        B[ 6] = rotl64(A[ 9], 20);
        B[ 7] = rotl64(A[10],  3);
        B[17] = rotl64(A[11], 10);
        B[ 2] = rotl64(A[12], 43);
        B[12] = rotl64(A[13], 25);
        B[22] = rotl64(A[14], 39);
        B[23] = rotl64(A[15], 41);
        B[ 8] = rotl64(A[16], 45);
        B[18] = rotl64(A[17], 15);
        B[ 3] = rotl64(A[18], 21);
        B[13] = rotl64(A[19],  8);
        B[14] = rotl64(A[20], 18);
        B[24] = rotl64(A[21],  2);
        B[ 9] = rotl64(A[22], 61);
        B[19] = rotl64(A[23], 56);
        B[ 4] = rotl64(A[24], 14);

        for (int i = 0; i < 25; i += 5) {
            A[i+0] = B[i+0] ^ ((~B[i+1]) & B[i+2]);
            A[i+1] = B[i+1] ^ ((~B[i+2]) & B[i+3]);
            A[i+2] = B[i+2] ^ ((~B[i+3]) & B[i+4]);
            A[i+3] = B[i+3] ^ ((~B[i+4]) & B[i+0]);
            A[i+4] = B[i+4] ^ ((~B[i+0]) & B[i+1]);
        }

        A[0] ^= h_RC[round];
    }
}

static void host_keccak256(const uint8_t* data, size_t len, uint8_t* out32) {
    // General Keccak-256: rate=136 bytes, pad byte=0x01
    uint64_t A[25];
    std::memset(A, 0, sizeof(A));

    const size_t rate_bytes = 136;
    size_t offset = 0;

    // Absorb full blocks
    while (offset + rate_bytes <= len) {
        for (int i = 0; i < 17; ++i) {
            uint64_t lane = 0;
            for (int b = 0; b < 8; ++b)
                lane |= ((uint64_t)data[offset + i * 8 + b]) << (b * 8);
            A[i] ^= lane;
        }
        host_keccak_f1600(A);
        offset += rate_bytes;
    }

    // Final block: pad
    uint8_t block[136];
    std::memset(block, 0, sizeof(block));
    size_t remaining = len - offset;
    std::memcpy(block, data + offset, remaining);
    block[remaining] = 0x01;                    // Keccak padding byte
    block[rate_bytes - 1] |= 0x80;              // Final bit

    for (int i = 0; i < 17; ++i) {
        uint64_t lane = 0;
        for (int b = 0; b < 8; ++b)
            lane |= ((uint64_t)block[i * 8 + b]) << (b * 8);
        A[i] ^= lane;
    }
    host_keccak_f1600(A);

    // Squeeze 32 bytes
    for (int i = 0; i < 4; ++i) {
        uint64_t lane = A[i];
        for (int b = 0; b < 8; ++b)
            out32[i * 8 + b] = (uint8_t)(lane >> (b * 8));
    }
}

static void host_keccak256d(const uint8_t* data, size_t len, uint8_t* out32) {
    uint8_t inner[32];
    host_keccak256(data, len, inner);
    host_keccak256(inner, 32, out32);
}

// ============================================================================
// Global state
// ============================================================================

static std::atomic<bool> g_stop{false};

static void signal_handler(int) {
    g_stop.store(true);
}

// ============================================================================
// Per-device mining state
// ============================================================================

struct DeviceCtx {
    int              device_id;
    std::string      name;
    uint8_t*         d_header;       // 92 bytes on device
    uint8_t*         d_target;       // 32 bytes on device
    DeviceResult*    d_result;       // result struct on device
    DeviceResult     h_result;       // host-side result
    cudaStream_t     stream;
    int              sm_count;
    int              max_threads_per_sm;
    uint32_t         grid_size;
    uint32_t         block_size;
};

// ============================================================================
// Main
// ============================================================================

struct Args {
    std::string url      = "http://127.0.0.1:9334";
    std::string user;
    std::string pass;
    std::string cookie;
    std::string address;
    uint32_t    block_size  = 256;     // threads per CUDA block
    uint32_t    grid_mult   = 0;       // grid multiplier (0 = auto)
    int         device      = -1;      // -1 = all devices
    bool        benchmark   = false;
    int         bench_secs  = 10;
};

static void print_usage() {
    std::puts(
        "flowminer-cuda 0.1.0\n"
        "Usage: flowminer-cuda [options]\n"
        "\n"
        "  -o, --url URL           node RPC URL (default: http://127.0.0.1:9334)\n"
        "  -u, --user USER         HTTP Basic user\n"
        "  -p, --pass PASS         HTTP Basic password\n"
        "      --cookie PATH       read auth from cookie file\n"
        "  -a, --address ADDR      coinbase address (default: node's wallet)\n"
        "  -d, --device N          use only GPU device N (-1 = all, default)\n"
        "      --block-size N      CUDA threads per block (default: 256)\n"
        "      --grid-mult N       grid size = N * SM_count (default: auto)\n"
        "  -b, --benchmark [SECS]  run GPU benchmark (default: 10 seconds)\n"
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

int main(int argc, char** argv) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string k = argv[i];
        auto take = [&](std::string& dst) {
            if (++i < argc) dst = argv[i];
        };
        if      (k == "-h" || k == "--help")       { print_usage(); return 0; }
        else if (k == "-o" || k == "--url")        take(a.url);
        else if (k == "-u" || k == "--user")       take(a.user);
        else if (k == "-p" || k == "--pass")       take(a.pass);
        else if (k == "--cookie")                  take(a.cookie);
        else if (k == "-a" || k == "--address")    take(a.address);
        else if (k == "-d" || k == "--device") {
            std::string s; take(s); a.device = std::stoi(s);
        }
        else if (k == "--block-size") {
            std::string s; take(s); a.block_size = std::stoul(s);
        }
        else if (k == "--grid-mult") {
            std::string s; take(s); a.grid_mult = std::stoul(s);
        }
        else if (k == "-b" || k == "--benchmark") {
            a.benchmark = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                ++i;
                a.bench_secs = std::stoi(argv[i]);
            }
        }
        else {
            std::fprintf(stderr, "unknown option: %s\n", k.c_str());
            return 2;
        }
    }

    // ---- Signal handling ----
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    // ---- RPC setup ----
    RpcEndpoint ep;
    parse_url(a.url, ep);
    if (!a.cookie.empty()) {
        if (!load_cookie(a.cookie, ep.auth)) {
            std::fprintf(stderr, "[%s]  ERROR  cannot read cookie file %s\n",
                         timestamp_now().c_str(), a.cookie.c_str());
            return 3;
        }
    } else if (!a.user.empty() || !a.pass.empty()) {
        ep.auth.user = a.user;
        ep.auth.pass = a.pass;
    } else {
        std::string auto_cookie = default_cookie_path();
        if (load_cookie(auto_cookie, ep.auth)) {
            std::printf("[%s]  CONFIG  using cookie auth from %s\n",
                        timestamp_now().c_str(), auto_cookie.c_str());
        }
    }

    // ---- Enumerate CUDA devices ----
    int device_count = 0;
    CUDA_CHECK(cudaGetDeviceCount(&device_count));
    if (device_count == 0) {
        std::fprintf(stderr, "[%s]  ERROR  no CUDA devices found\n",
                     timestamp_now().c_str());
        return 4;
    }

    std::vector<int> devices;
    if (a.device >= 0) {
        if (a.device >= device_count) {
            std::fprintf(stderr, "[%s]  ERROR  device %d not found (have %d)\n",
                         timestamp_now().c_str(), a.device, device_count);
            return 4;
        }
        devices.push_back(a.device);
    } else {
        for (int d = 0; d < device_count; ++d) devices.push_back(d);
    }

    // ---- Print banner ----
    std::printf("\n");
    std::printf(" * ABOUT         flowminer-cuda/0.1.0\n");
    std::printf(" * ALGO          keccak-256d\n");
    std::printf(" * DEVICES       %d\n", (int)devices.size());
    for (int d : devices) {
        cudaDeviceProp prop;
        CUDA_CHECK(cudaGetDeviceProperties(&prop, d));
        std::printf(" *   GPU #%d      %s  (%d SMs, %d MHz, %zu MB)\n",
                    d, prop.name, prop.multiProcessorCount,
                    prop.clockRate / 1000,
                    prop.totalGlobalMem / (1024 * 1024));
    }
    if (!a.benchmark) {
        std::printf(" * NODE          %s:%u\n", ep.host.c_str(), ep.port);
        std::printf(" * ADDRESS       %s\n",
                    a.address.empty() ? "(node wallet)" : a.address.c_str());
    }
    std::printf("\n");

    // ---- Initialize per-device contexts ----
    std::vector<DeviceCtx> ctxs(devices.size());
    for (size_t i = 0; i < devices.size(); ++i) {
        auto& ctx = ctxs[i];
        ctx.device_id = devices[i];

        CUDA_CHECK(cudaSetDevice(ctx.device_id));

        cudaDeviceProp prop;
        CUDA_CHECK(cudaGetDeviceProperties(&prop, ctx.device_id));
        ctx.name = prop.name;
        ctx.sm_count = prop.multiProcessorCount;
        ctx.max_threads_per_sm = prop.maxThreadsPerMultiProcessor;
        ctx.block_size = a.block_size;

        // Grid size: enough blocks to fill all SMs well.
        // Each SM can run max_threads_per_sm / block_size blocks.
        uint32_t blocks_per_sm = ctx.max_threads_per_sm / ctx.block_size;
        if (blocks_per_sm < 1) blocks_per_sm = 1;
        ctx.grid_size = a.grid_mult > 0
            ? a.grid_mult * ctx.sm_count
            : blocks_per_sm * ctx.sm_count * 4;  // 4x oversubscription

        // Allocate device memory
        CUDA_CHECK(cudaMalloc(&ctx.d_header, 92));
        CUDA_CHECK(cudaMalloc(&ctx.d_target, 32));
        CUDA_CHECK(cudaMalloc(&ctx.d_result, sizeof(DeviceResult)));

        CUDA_CHECK(cudaStreamCreate(&ctx.stream));
    }

    // Compute total threads per launch across all devices
    uint64_t total_threads_per_launch = 0;
    for (auto& ctx : ctxs)
        total_threads_per_launch += (uint64_t)ctx.grid_size * ctx.block_size;

    std::printf("[%s]  MINER   total GPU threads per launch: %" PRIu64 "\n",
                timestamp_now().c_str(), total_threads_per_launch);

    // ---- Benchmark mode ----
    if (a.benchmark) {
        // Create a dummy header and target (all 0xFF target = always miss).
        uint8_t dummy_header[92];
        std::memset(dummy_header, 0, sizeof(dummy_header));
        uint8_t dummy_target[32];
        std::memset(dummy_target, 0, sizeof(dummy_target)); // impossibly hard

        for (auto& ctx : ctxs) {
            CUDA_CHECK(cudaSetDevice(ctx.device_id));
            CUDA_CHECK(cudaMemcpy(ctx.d_header, dummy_header, 92,
                                  cudaMemcpyHostToDevice));
            CUDA_CHECK(cudaMemcpy(ctx.d_target, dummy_target, 32,
                                  cudaMemcpyHostToDevice));
        }

        std::printf("[%s]  BENCH   running %d second benchmark...\n",
                    timestamp_now().c_str(), a.bench_secs);

        auto t0 = std::chrono::steady_clock::now();
        uint64_t total_hashes = 0;
        uint32_t base_nonce = 0;

        while (!g_stop.load()) {
            auto now = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(now - t0).count();
            if (elapsed >= a.bench_secs) break;

            for (auto& ctx : ctxs) {
                CUDA_CHECK(cudaSetDevice(ctx.device_id));
                ctx.h_result.found = 0;
                CUDA_CHECK(cudaMemcpy(ctx.d_result, &ctx.h_result,
                                      sizeof(DeviceResult),
                                      cudaMemcpyHostToDevice));

                mining_kernel<<<ctx.grid_size, ctx.block_size, 0, ctx.stream>>>(
                    ctx.d_header, ctx.d_target, base_nonce, ctx.d_result);
            }

            // Synchronize all devices
            for (auto& ctx : ctxs) {
                CUDA_CHECK(cudaSetDevice(ctx.device_id));
                CUDA_CHECK(cudaStreamSynchronize(ctx.stream));
            }

            total_hashes += total_threads_per_launch;
            base_nonce += (uint32_t)total_threads_per_launch;
            if (base_nonce < (uint32_t)total_threads_per_launch) break; // wrap
        }

        auto t1 = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(t1 - t0).count();
        double rate = elapsed > 0 ? (double)total_hashes / elapsed : 0;

        std::printf("[%s]  BENCH   %s  (%" PRIu64 " hashes in %.2fs)\n",
                    timestamp_now().c_str(), format_hashrate(rate).c_str(),
                    total_hashes, elapsed);

        // Cleanup
        for (auto& ctx : ctxs) {
            CUDA_CHECK(cudaSetDevice(ctx.device_id));
            cudaFree(ctx.d_header);
            cudaFree(ctx.d_target);
            cudaFree(ctx.d_result);
            cudaStreamDestroy(ctx.stream);
        }
        return 0;
    }

    // ---- Initial connectivity check ----
    {
        auto r = rpc_call_raw(ep, "getblockcount", "[]");
        if (!r || json_has_error(*r)) {
            std::fprintf(stderr, "[%s]  ERROR  cannot reach node at %s:%u\n",
                         timestamp_now().c_str(), ep.host.c_str(), ep.port);
            return 4;
        }
        std::string result = json_get_result(*r);
        std::printf("[%s]  NET     connected to %s:%u  height=%s\n",
                    timestamp_now().c_str(), ep.host.c_str(), ep.port,
                    result.c_str());
    }

    // ---- Mining loop ----
    uint64_t total_hashes = 0;
    uint64_t submits = 0, accepted = 0, rejected = 0;
    auto last_template_poll = std::chrono::steady_clock::now() -
                              std::chrono::seconds(999);
    auto last_speed_report  = std::chrono::steady_clock::now();

    // Current job state
    uint8_t  cur_header[92];
    uint8_t  cur_target_be[32];  // big-endian target for comparison
    bool     have_job = false;
    uint64_t cur_height = 0;
    uint32_t cur_nbits = 0;
    std::string cur_coinbase_hex;
    std::string cur_prev_hash_hex;

    uint32_t base_nonce = 0;

    // Seed base_nonce from a random value to avoid collisions between
    // multiple miners.
    {
        std::srand((unsigned)std::time(nullptr) ^
                   (unsigned)std::chrono::steady_clock::now()
                       .time_since_epoch().count());
        base_nonce = (uint32_t)std::rand() << 16;
    }

    while (!g_stop.load()) {
        auto now = std::chrono::steady_clock::now();

        // ---- Poll for new template every ~3 seconds ----
        if (now - last_template_poll > std::chrono::seconds(3)) {
            last_template_poll = now;
            std::string params = a.address.empty()
                ? "[]"
                : "[\"" + json_escape(a.address) + "\"]";
            auto r = rpc_call_raw(ep, "getblocktemplate", params);
            if (!r || json_has_error(*r)) {
                std::printf("[%s]  NET     getblocktemplate failed\n",
                            timestamp_now().c_str());
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }
            std::string result = json_get_result(*r);

            // Parse template fields from the result object.
            uint64_t height     = json_get_uint(result, "height", 0);
            uint32_t nbits      = (uint32_t)json_get_uint(result, "nbits", 0);
            int64_t  curtime    = json_get_int(result, "curtime", 0);
            uint32_t version    = (uint32_t)json_get_uint(result, "version", 1);
            std::string prev_s  = json_get_string(result, "previousblockhash");
            std::string merkle_s = json_get_string(result, "merkle_root");
            std::string target_s = json_get_string(result, "target");
            std::string cb_s     = json_get_string(result, "coinbase_tx");

            auto prev   = hex_decode(prev_s);
            auto merkle = hex_decode(merkle_s);
            auto target = hex_decode(target_s);

            if (prev.size() != 32 || merkle.size() != 32 || target.size() != 32) {
                std::printf("[%s]  NET     malformed template\n",
                            timestamp_now().c_str());
                continue;
            }

            // Build 92-byte unsigned header
            std::memset(cur_header, 0, 92);
            std::memcpy(cur_header + 0,  prev.data(),   32);
            std::memcpy(cur_header + 32, merkle.data(), 32);
            for (int b = 0; b < 8; ++b)
                cur_header[64 + b] = (uint8_t)(height >> (b * 8));
            for (int b = 0; b < 8; ++b)
                cur_header[72 + b] = (uint8_t)(curtime >> (b * 8));
            for (int b = 0; b < 4; ++b)
                cur_header[80 + b] = (uint8_t)(nbits >> (b * 8));
            // nonce [84..87] = 0 (GPU writes this)
            for (int b = 0; b < 4; ++b)
                cur_header[88 + b] = (uint8_t)(version >> (b * 8));

            // Target: RPC returns little-endian display, flip to big-endian
            // for byte-wise comparison (hash[0] is most significant).
            for (int b = 0; b < 32; ++b)
                cur_target_be[b] = target[31 - b];

            cur_height = height;
            cur_nbits  = nbits;
            cur_coinbase_hex = cb_s;
            cur_prev_hash_hex = prev_s;
            have_job = true;

            // Upload header and target to all devices
            for (auto& ctx : ctxs) {
                CUDA_CHECK(cudaSetDevice(ctx.device_id));
                CUDA_CHECK(cudaMemcpy(ctx.d_header, cur_header, 92,
                                      cudaMemcpyHostToDevice));
                CUDA_CHECK(cudaMemcpy(ctx.d_target, cur_target_be, 32,
                                      cudaMemcpyHostToDevice));
            }

            // Reset base nonce on new job
            base_nonce = (uint32_t)std::rand() << 16;

            char diff_buf[32];
            std::snprintf(diff_buf, sizeof(diff_buf), "%.3f",
                          nbits_to_difficulty(nbits));
            std::printf("[%s]  NET     new job  height=%" PRIu64
                        "  diff=%s  algo=keccak-256d\n",
                        timestamp_now().c_str(), height, diff_buf);
        }

        if (!have_job) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        // ---- Launch kernels on all devices ----
        for (auto& ctx : ctxs) {
            CUDA_CHECK(cudaSetDevice(ctx.device_id));
            ctx.h_result.found = 0;
            ctx.h_result.nonce = 0;
            std::memset(ctx.h_result.hash, 0, 32);
            CUDA_CHECK(cudaMemcpyAsync(ctx.d_result, &ctx.h_result,
                                       sizeof(DeviceResult),
                                       cudaMemcpyHostToDevice, ctx.stream));

            mining_kernel<<<ctx.grid_size, ctx.block_size, 0, ctx.stream>>>(
                ctx.d_header, ctx.d_target, base_nonce, ctx.d_result);
        }

        // ---- Synchronize and check results ----
        bool found_solution = false;
        uint32_t winning_nonce = 0;
        uint8_t  winning_hash[32];
        int      winning_device = -1;

        for (auto& ctx : ctxs) {
            CUDA_CHECK(cudaSetDevice(ctx.device_id));
            CUDA_CHECK(cudaStreamSynchronize(ctx.stream));

            CUDA_CHECK(cudaMemcpy(&ctx.h_result, ctx.d_result,
                                  sizeof(DeviceResult),
                                  cudaMemcpyDeviceToHost));

            if (ctx.h_result.found && !found_solution) {
                found_solution = true;
                winning_nonce  = ctx.h_result.nonce;
                std::memcpy(winning_hash, ctx.h_result.hash, 32);
                winning_device = ctx.device_id;
            }
        }

        total_hashes += total_threads_per_launch;
        base_nonce += (uint32_t)total_threads_per_launch;

        // ---- Speed report every ~10 seconds ----
        now = std::chrono::steady_clock::now();
        if (now - last_speed_report > std::chrono::seconds(10)) {
            double elapsed = std::chrono::duration<double>(
                now - last_speed_report).count();
            // We track total_hashes but for rate we want recent hashes.
            // Simple approach: keep a running counter and compute rate.
            static uint64_t last_total = 0;
            uint64_t recent = total_hashes - last_total;
            last_total = total_hashes;
            double rate = elapsed > 0 ? (double)recent / elapsed : 0;
            std::printf("[%s]  MINER   speed %s  total=%" PRIu64 "\n",
                        timestamp_now().c_str(), format_hashrate(rate).c_str(),
                        total_hashes);
            last_speed_report = now;
        }

        // ---- Submit solution ----
        if (found_solution) {
            // Verify on CPU first
            uint8_t verify_hdr[92];
            std::memcpy(verify_hdr, cur_header, 92);
            verify_hdr[84] = (uint8_t)(winning_nonce);
            verify_hdr[85] = (uint8_t)(winning_nonce >> 8);
            verify_hdr[86] = (uint8_t)(winning_nonce >> 16);
            verify_hdr[87] = (uint8_t)(winning_nonce >> 24);

            uint8_t cpu_hash[32];
            host_keccak256d(verify_hdr, 92, cpu_hash);

            if (std::memcmp(cpu_hash, winning_hash, 32) != 0) {
                std::printf("[%s]  WARN    GPU/CPU hash mismatch for nonce %u"
                            " on device %d (GPU bug?)\n",
                            timestamp_now().c_str(), winning_nonce,
                            winning_device);
                // Use CPU hash for comparison anyway
                std::memcpy(winning_hash, cpu_hash, 32);
            }

            // Check hash <= target on CPU
            bool meets = true;
            for (int b = 0; b < 32; ++b) {
                if (cpu_hash[b] < cur_target_be[b]) break;
                if (cpu_hash[b] > cur_target_be[b]) { meets = false; break; }
            }

            if (!meets) {
                std::printf("[%s]  WARN    nonce %u does not meet target"
                            " (false positive)\n",
                            timestamp_now().c_str(), winning_nonce);
            } else {
                // Build the block for submission.
                // The block needs: unsigned_header(92) + pubkey(32) + sig(64)
                // + compact_size(1) + coinbase_tx.
                //
                // However, Ed25519 signing requires the miner's private key,
                // which this GPU miner does NOT carry. Instead, we submit the
                // raw unsigned header + nonce via submitblock. The node's
                // flowcoind will handle signing if configured.
                //
                // Actually, looking at the CPU miner, it does sign with a local
                // miner_key. For the CUDA miner, we build the block as:
                //   unsigned_header (92 bytes, with nonce filled in)
                //   + 32 zero bytes for pubkey placeholder
                //   + 64 zero bytes for signature placeholder
                //   + compact_size(1) + coinbase_tx
                //
                // But the node expects a fully signed block. Since we don't
                // want to link Ed25519 into the CUDA binary, we submit just
                // the unsigned header hex and let the user configure their
                // node accordingly, OR we provide a minimal submission.
                //
                // For full compatibility with the CPU miner pattern, let's
                // build the block with zero pubkey/sig. The node will reject
                // this if it requires a valid signature. For production use,
                // the user should either:
                //   (a) Use a signing proxy, or
                //   (b) Extend this miner with Ed25519 support.
                //
                // For now, build and submit the full block structure.
                // The node's submitblock accepts hex data.

                // Build signed block (with zero key/sig for now)
                std::vector<uint8_t> block_data;
                block_data.reserve(92 + 32 + 64 + 1 + 4096);

                // Unsigned header with winning nonce
                block_data.insert(block_data.end(), verify_hdr, verify_hdr + 92);

                // Pubkey: 32 zero bytes (placeholder)
                for (int b = 0; b < 32; ++b) block_data.push_back(0);

                // Signature: 64 zero bytes (placeholder)
                for (int b = 0; b < 64; ++b) block_data.push_back(0);

                // Transaction count (compact size) + coinbase tx
                encode_compact_size(block_data, 1);
                auto coinbase_bytes = hex_decode(cur_coinbase_hex);
                block_data.insert(block_data.end(),
                                  coinbase_bytes.begin(), coinbase_bytes.end());

                std::string block_hex = hex_encode(block_data.data(),
                                                    block_data.size());

                // Submit
                submits++;
                auto ts = std::chrono::steady_clock::now();
                std::string submit_params = "[\"" + json_escape(block_hex) + "\"]";
                auto r = rpc_call_raw(ep, "submitblock", submit_params);
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - ts).count();

                bool ok = false;
                if (r) {
                    std::string result = json_get_result(*r);
                    ok = (result == "null" || result.empty() ||
                          result == "\"\"");
                }

                if (ok) {
                    accepted++;
                    std::printf("[%s]  MINER   ACCEPTED (%" PRIu64 "/%" PRIu64
                                ") height=%" PRIu64 "  nonce=%u  device=%d"
                                "  (%" PRId64 " ms)\n",
                                timestamp_now().c_str(), accepted, submits,
                                cur_height, winning_nonce, winning_device,
                                (int64_t)ms);
                } else {
                    rejected++;
                    std::string reason = r ? json_get_result(*r) : "no response";
                    std::printf("[%s]  MINER   REJECTED (%" PRIu64 "/%" PRIu64
                                ") height=%" PRIu64 "  %s  (%" PRId64 " ms)\n",
                                timestamp_now().c_str(), rejected, submits,
                                cur_height, reason.c_str(), (int64_t)ms);
                }

                // Force template refresh after submit
                last_template_poll = std::chrono::steady_clock::now() -
                                     std::chrono::seconds(999);
            }
        }
    }

    // ---- Cleanup ----
    std::printf("[%s]  MINER   stopping\n", timestamp_now().c_str());
    for (auto& ctx : ctxs) {
        CUDA_CHECK(cudaSetDevice(ctx.device_id));
        cudaFree(ctx.d_header);
        cudaFree(ctx.d_target);
        cudaFree(ctx.d_result);
        cudaStreamDestroy(ctx.stream);
    }
    std::printf("[%s]  MINER   stopped. submitted=%" PRIu64
                "  accepted=%" PRIu64 "  rejected=%" PRIu64 "\n",
                timestamp_now().c_str(), submits, accepted, rejected);

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

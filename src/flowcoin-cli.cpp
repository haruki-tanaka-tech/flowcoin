// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// flowcoin-cli: Command-line RPC client for flowcoind.
// Sends JSON-RPC 2.0 requests over HTTP to the daemon and prints results.
// Supports automatic cookie authentication, pretty-printed JSON output,
// testnet/regtest port selection, and config file reading.
//
// Usage: flowcoin-cli [options] <command> [params...]
//
// Examples:
//   flowcoin-cli getblockcount
//   flowcoin-cli getblockhash 0
//   flowcoin-cli sendtoaddress fl1q... 1.5
//   flowcoin-cli -testnet getblockcount

#include "version.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// ============================================================================
// Exit codes
// ============================================================================

static constexpr int EXIT_OK          = 0;
static constexpr int EXIT_RPC_ERROR   = 1;
static constexpr int EXIT_CONN_ERROR  = 2;
static constexpr int EXIT_USAGE_ERROR = 3;

// RPC error codes
static constexpr int RPC_IN_WARMUP   = -28;

// ============================================================================
// CLI options
// ============================================================================

struct CliOptions {
    std::string rpc_host  = "127.0.0.1";
    uint16_t rpc_port     = 0;   // 0 = use default for network
    bool port_set         = false;
    std::string rpc_user;
    std::string rpc_pass;
    std::string rpc_cookiefile;
    std::string config_file;
    std::string datadir;
    bool testnet          = false;
    bool regtest          = false;
    bool help             = false;
    bool version          = false;
    bool stdin_rpc        = false;   // -stdin: read extra args from stdin
    bool stdin_rpcpass    = false;   // -stdinrpcpass: read password from stdin
    bool rpcwait          = false;   // -rpcwait: retry until server starts
    int rpcwait_timeout   = 0;      // -rpcwaittimeout=N
    bool named_args       = false;   // -named: pass params as key=value
    int timeout_seconds   = 30;

    // CLI commands (handled specially, not forwarded as RPC methods)
    bool cli_getinfo      = false;   // -getinfo
    bool cli_netinfo      = false;   // -netinfo

    std::string method;
    std::vector<std::string> params;
};

// ============================================================================
// Base64 encoding (for HTTP Basic auth)
// ============================================================================

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const std::string& input) {
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

// ============================================================================
// String utilities
// ============================================================================

static bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static std::string get_arg_value(const std::string& arg) {
    auto eq = arg.find('=');
    if (eq != std::string::npos) return arg.substr(eq + 1);
    return "";
}

static std::string trim_ws(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

/// Strip leading dashes from an option string and return the canonical form.
/// Converts "--rpcport=9334" or "-rpcport=9334" to "rpcport=9334".
static std::string strip_dashes(const std::string& arg) {
    if (arg.size() >= 2 && arg[0] == '-' && arg[1] == '-') {
        return arg.substr(2);
    }
    if (arg.size() >= 1 && arg[0] == '-') {
        return arg.substr(1);
    }
    return arg;
}

// ============================================================================
// JSON escaping (minimal, for building JSON-RPC requests without json.hpp)
// ============================================================================

static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x",
                                 static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out.push_back(c);
                }
        }
    }
    return out;
}

// ============================================================================
// JSON pretty printer (simple recursive formatter)
// ============================================================================

static std::string json_pretty(const std::string& json, int indent = 2) {
    std::string result;
    result.reserve(json.size() * 2);

    int level = 0;
    bool in_string = false;
    bool escape_next = false;

    auto add_indent = [&]() {
        result.push_back('\n');
        for (int i = 0; i < level * indent; ++i) {
            result.push_back(' ');
        }
    };

    for (size_t i = 0; i < json.size(); ++i) {
        char c = json[i];

        if (escape_next) {
            result.push_back(c);
            escape_next = false;
            continue;
        }

        if (c == '\\' && in_string) {
            result.push_back(c);
            escape_next = true;
            continue;
        }

        if (c == '"') {
            in_string = !in_string;
            result.push_back(c);
            continue;
        }

        if (in_string) {
            result.push_back(c);
            continue;
        }

        // Skip whitespace outside strings
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            continue;
        }

        switch (c) {
            case '{':
            case '[':
                result.push_back(c);
                // Check if the next non-whitespace char is the closing bracket
                {
                    size_t j = i + 1;
                    while (j < json.size() && (json[j] == ' ' || json[j] == '\n' ||
                           json[j] == '\r' || json[j] == '\t')) {
                        ++j;
                    }
                    if (j < json.size() && ((c == '{' && json[j] == '}') ||
                                            (c == '[' && json[j] == ']'))) {
                        result.push_back(json[j]);
                        i = j;
                        continue;
                    }
                }
                ++level;
                add_indent();
                break;

            case '}':
            case ']':
                --level;
                add_indent();
                result.push_back(c);
                break;

            case ',':
                result.push_back(c);
                add_indent();
                break;

            case ':':
                result.push_back(':');
                result.push_back(' ');
                break;

            default:
                result.push_back(c);
                break;
        }
    }

    return result;
}

// ============================================================================
// Config file / cookie reading
// ============================================================================

static std::string get_default_datadir() {
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    if (appdata && appdata[0] != '\0')
        return std::string(appdata) + "\\FlowCoin";
    const char* userprofile = std::getenv("USERPROFILE");
    if (userprofile && userprofile[0] != '\0')
        return std::string(userprofile) + "\\FlowCoin";
    return "FlowCoin";
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    if (home && home[0] != '\0')
        return std::string(home) + "/Library/Application Support/FlowCoin";
    return ".flowcoin";
#else
    const char* home = std::getenv("HOME");
    if (home && home[0] != '\0')
        return std::string(home) + "/.flowcoin";
    return ".flowcoin";
#endif
}

static bool read_cookie(const std::string& cookie_path,
                        std::string& user, std::string& pass) {
    std::ifstream ifs(cookie_path);
    if (!ifs.is_open()) return false;

    std::string line;
    if (!std::getline(ifs, line)) return false;

    auto colon = line.find(':');
    if (colon == std::string::npos) return false;

    user = line.substr(0, colon);
    pass = trim_ws(line.substr(colon + 1));
    return !user.empty() && !pass.empty();
}

static void read_config_file(const std::string& path, CliOptions& opts) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) return;

    std::string line;
    while (std::getline(ifs, line)) {
        line = trim_ws(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = trim_ws(line.substr(0, eq));
        std::string val = trim_ws(line.substr(eq + 1));

        if (key == "rpcuser" && opts.rpc_user.empty()) {
            opts.rpc_user = val;
        } else if (key == "rpcpassword" && opts.rpc_pass.empty()) {
            opts.rpc_pass = val;
        } else if (key == "rpcport" && !opts.port_set) {
            try { opts.rpc_port = static_cast<uint16_t>(std::stoi(val)); opts.port_set = true; } catch (...) {}
        } else if (key == "rpcconnect" && opts.rpc_host == "127.0.0.1") {
            opts.rpc_host = val;
        } else if (key == "testnet" && (val == "1" || val == "true")) {
            opts.testnet = true;
        } else if (key == "regtest" && (val == "1" || val == "true")) {
            opts.regtest = true;
        }
    }
}

// ============================================================================
// TCP HTTP client
// ============================================================================

/// Send an HTTP POST and return the full response (headers + body).
/// Returns empty string on connection failure.
static std::string http_request(const std::string& host, uint16_t port,
                                 const std::string& user, const std::string& pass,
                                 const std::string& body, int timeout_sec,
                                 bool suppress_errors = false) {
    // Resolve hostname
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;   // Support both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    int gai_err = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (gai_err != 0) {
        if (!suppress_errors) {
            std::cerr << "error: could not resolve " << host << ": "
                      << gai_strerror(gai_err) << std::endl;
        }
        return "";
    }

    // Create socket
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        if (!suppress_errors) {
            std::cerr << "error: socket creation failed: " << strerror(errno) << std::endl;
        }
        freeaddrinfo(res);
        return "";
    }

    // Set timeouts
#ifdef _WIN32
    DWORD tv_ms = static_cast<DWORD>(timeout_sec) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
#else
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    // Connect
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        if (!suppress_errors) {
            std::cerr << "error: could not connect to " << host << ":" << port
                      << " — " << strerror(errno) << std::endl;
        }
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        freeaddrinfo(res);
        return "";
    }
    freeaddrinfo(res);

    // Build HTTP request
    std::string auth = "Basic " + base64_encode(user + ":" + pass);

    std::ostringstream req;
    req << "POST / HTTP/1.1\r\n";
    req << "Host: " << host << "\r\n";
    req << "Authorization: " << auth << "\r\n";
    req << "Content-Type: application/json\r\n";
    req << "Content-Length: " << body.size() << "\r\n";
    req << "Connection: close\r\n";
    req << "\r\n";
    req << body;

    std::string request = req.str();

    // Send
    ssize_t total_sent = 0;
    while (total_sent < static_cast<ssize_t>(request.size())) {
        ssize_t n = send(sock, request.data() + total_sent,
                         request.size() - static_cast<size_t>(total_sent), 0);
        if (n < 0) {
            if (!suppress_errors) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    std::cerr << "error: send timeout" << std::endl;
                } else {
                    std::cerr << "error: send failed: " << strerror(errno) << std::endl;
                }
            }
#ifdef _WIN32
            closesocket(sock);
#else
            close(sock);
#endif
            return "";
        }
        total_sent += n;
    }

    // Receive response
    std::string response;
    char buf[8192];
    while (true) {
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        response.append(buf, static_cast<size_t>(n));
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    return response;
}

// ============================================================================
// HTTP response parsing
// ============================================================================

static int extract_http_status(const std::string& response) {
    // HTTP/1.1 200 OK\r\n...
    auto sp1 = response.find(' ');
    if (sp1 == std::string::npos) return 0;
    auto sp2 = response.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) sp2 = response.find('\r', sp1 + 1);
    if (sp2 == std::string::npos) return 0;
    try {
        return std::stoi(response.substr(sp1 + 1, sp2 - sp1 - 1));
    } catch (...) {
        return 0;
    }
}

static std::string extract_body(const std::string& response) {
    auto pos = response.find("\r\n\r\n");
    if (pos == std::string::npos) return response;
    return response.substr(pos + 4);
}

// ============================================================================
// Simple JSON result/error extraction
// Avoids depending on json.hpp in the CLI binary.
// ============================================================================

/// Find a top-level key in a JSON object string.
/// Returns the value string (may be a nested object/array/string/number).
static std::string json_extract_value(const std::string& json,
                                       const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";

    // Find the colon after the key
    auto colon = json.find(':', pos + search.size());
    if (colon == std::string::npos) return "";

    // Skip whitespace after colon
    size_t start = colon + 1;
    while (start < json.size() && (json[start] == ' ' || json[start] == '\t' ||
           json[start] == '\r' || json[start] == '\n')) {
        ++start;
    }
    if (start >= json.size()) return "";

    // Determine the value type and find its end
    char first = json[start];

    if (first == '"') {
        // String value: find closing quote (handle escapes)
        size_t end = start + 1;
        while (end < json.size()) {
            if (json[end] == '\\') {
                end += 2;  // Skip escaped char
            } else if (json[end] == '"') {
                return json.substr(start, end - start + 1);
            } else {
                ++end;
            }
        }
        return json.substr(start);
    }

    if (first == '{' || first == '[') {
        // Object or array: find matching closing bracket
        char open = first;
        char close_ch = (first == '{') ? '}' : ']';
        int depth = 1;
        size_t end = start + 1;
        bool in_str = false;
        while (end < json.size() && depth > 0) {
            if (json[end] == '\\' && in_str) {
                ++end;
            } else if (json[end] == '"') {
                in_str = !in_str;
            } else if (!in_str) {
                if (json[end] == open) ++depth;
                if (json[end] == close_ch) --depth;
            }
            ++end;
        }
        return json.substr(start, end - start);
    }

    // Primitive value (number, boolean, null): find delimiter
    size_t end = start;
    while (end < json.size() && json[end] != ',' && json[end] != '}' &&
           json[end] != ']' && json[end] != '\r' && json[end] != '\n') {
        ++end;
    }
    return trim_ws(json.substr(start, end - start));
}

/// Unquote a JSON string value.
static std::string json_unquote(const std::string& s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

/// Check if a JSON value is "null".
static bool json_is_null(const std::string& s) {
    std::string trimmed = trim_ws(s);
    return trimmed == "null";
}

// ============================================================================
// Usage / help (Bitcoin Core format)
// ============================================================================

static void print_usage() {
    std::cout << "FlowCoin Core RPC client version v" << CLIENT_VERSION_STRING << "\n";
    std::cout << "\n";
    std::cout << "Usage: flowcoin-cli [options] <command> [params]\n";
    std::cout << "or:    flowcoin-cli [options] -named <command> [name=value]...\n";
    std::cout << "or:    flowcoin-cli [options] help\n";
    std::cout << "or:    flowcoin-cli [options] help <command>\n";
    std::cout << "\n";
    std::cout << "Options:\n";
    std::cout << "\n";
    std::cout << "  -conf=<file>\n";
    std::cout << "       Specify configuration file. Relative paths will be prefixed by datadir\n";
    std::cout << "       location. (default: flowcoin.conf)\n";
    std::cout << "\n";
    std::cout << "  -datadir=<dir>\n";
    std::cout << "       Specify data directory\n";
    std::cout << "\n";
    std::cout << "  -help\n";
    std::cout << "       Print this help message and exit\n";
    std::cout << "\n";
    std::cout << "  -rpcconnect=<ip>\n";
    std::cout << "       Send commands to node running on <ip> (default: 127.0.0.1)\n";
    std::cout << "\n";
    std::cout << "  -rpccookiefile=<loc>\n";
    std::cout << "       Location of the auth cookie. (default: data dir)\n";
    std::cout << "\n";
    std::cout << "  -rpcpassword=<pw>\n";
    std::cout << "       Password for JSON-RPC connections\n";
    std::cout << "\n";
    std::cout << "  -rpcport=<port>\n";
    std::cout << "       Connect to JSON-RPC on <port> (default: 9334)\n";
    std::cout << "\n";
    std::cout << "  -rpcuser=<user>\n";
    std::cout << "       Username for JSON-RPC connections\n";
    std::cout << "\n";
    std::cout << "  -rpcwait\n";
    std::cout << "       Wait for RPC server to start\n";
    std::cout << "\n";
    std::cout << "  -stdin\n";
    std::cout << "       Read extra arguments from standard input, one per line until EOF/Ctrl-D\n";
    std::cout << "\n";
    std::cout << "  -stdinrpcpass\n";
    std::cout << "       Read RPC password from standard input as a single line.\n";
    std::cout << "\n";
    std::cout << "  -version\n";
    std::cout << "       Print version and exit\n";
    std::cout << "\n";
    std::cout << "CLI Commands:\n";
    std::cout << "\n";
    std::cout << "  -getinfo\n";
    std::cout << "       Get general information from the remote server.\n";
    std::cout << "\n";
    std::cout << "  -netinfo\n";
    std::cout << "       Get network peer connection information from the remote server.\n";
}

// ============================================================================
// Argument parsing (supports both -option and --option like Bitcoin Core)
// ============================================================================

static CliOptions parse_cli_args(int argc, char* argv[]) {
    CliOptions opts;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];

        // Strip leading dashes to get the canonical option name
        // We accept both -option and --option
        if (a.size() >= 1 && a[0] == '-') {
            std::string canon = strip_dashes(a);

            // Boolean flags (no value)
            if (canon == "help" || canon == "h" || canon == "?") {
                opts.help = true;
                continue;
            }
            if (canon == "version") {
                opts.version = true;
                continue;
            }
            if (canon == "testnet") {
                opts.testnet = true;
                continue;
            }
            if (canon == "regtest") {
                opts.regtest = true;
                continue;
            }
            if (canon == "stdin") {
                opts.stdin_rpc = true;
                continue;
            }
            if (canon == "stdinrpcpass") {
                opts.stdin_rpcpass = true;
                continue;
            }
            if (canon == "rpcwait") {
                opts.rpcwait = true;
                continue;
            }
            if (canon == "named") {
                opts.named_args = true;
                continue;
            }
            if (canon == "getinfo") {
                opts.cli_getinfo = true;
                continue;
            }
            if (canon == "netinfo") {
                opts.cli_netinfo = true;
                continue;
            }

            // Options with values (key=value)
            if (starts_with(canon, "rpcconnect=")) {
                opts.rpc_host = get_arg_value(a);
            } else if (starts_with(canon, "rpcport=")) {
                try { opts.rpc_port = static_cast<uint16_t>(std::stoi(get_arg_value(a))); opts.port_set = true; } catch (...) {}
            } else if (starts_with(canon, "rpcuser=")) {
                opts.rpc_user = get_arg_value(a);
            } else if (starts_with(canon, "rpcpassword=")) {
                opts.rpc_pass = get_arg_value(a);
            } else if (starts_with(canon, "rpccookiefile=")) {
                opts.rpc_cookiefile = get_arg_value(a);
            } else if (starts_with(canon, "conf=")) {
                opts.config_file = get_arg_value(a);
            } else if (starts_with(canon, "datadir=")) {
                opts.datadir = get_arg_value(a);
            } else if (starts_with(canon, "timeout=")) {
                try { opts.timeout_seconds = std::stoi(get_arg_value(a)); } catch (...) {}
            } else if (starts_with(canon, "rpcwaittimeout=")) {
                try { opts.rpcwait_timeout = std::stoi(get_arg_value(a)); } catch (...) {}
            } else {
                // Unknown option — might be a negative number parameter
                if (opts.method.empty()) {
                    continue;  // Skip unknown options before the method name
                }
                opts.params.push_back(a);
            }
        } else {
            if (opts.method.empty()) {
                opts.method = a;
            } else {
                opts.params.push_back(a);
            }
        }
    }

    return opts;
}

// ============================================================================
// Build JSON-RPC params array from CLI arguments
// ============================================================================

static std::string build_params_json(const std::vector<std::string>& params) {
    std::ostringstream ss;
    ss << "[";
    for (size_t i = 0; i < params.size(); ++i) {
        if (i > 0) ss << ", ";

        const std::string& p = params[i];

        // Detect type: boolean
        if (p == "true" || p == "false" || p == "null") {
            ss << p;
            continue;
        }

        // Detect type: number (integer or float)
        bool is_number = false;
        bool has_dot = false;
        if (!p.empty()) {
            size_t start = (p[0] == '-') ? 1 : 0;
            if (start < p.size()) {
                is_number = true;
                for (size_t j = start; j < p.size(); ++j) {
                    if (p[j] == '.') {
                        if (has_dot) { is_number = false; break; }
                        has_dot = true;
                    } else if (p[j] < '0' || p[j] > '9') {
                        is_number = false;
                        break;
                    }
                }
            }
        }

        if (is_number) {
            ss << p;
        } else if (p.front() == '{' || p.front() == '[') {
            // Already JSON — pass through
            ss << p;
        } else {
            // String: quote and escape
            ss << "\"" << json_escape(p) << "\"";
        }
    }
    ss << "]";
    return ss.str();
}

/// Build a JSON object from key=value pairs (for -named mode).
static std::string build_named_params_json(const std::vector<std::string>& params) {
    std::ostringstream ss;
    ss << "{";
    bool first = true;
    for (const auto& p : params) {
        auto eq = p.find('=');
        if (eq == std::string::npos) continue;

        std::string key = p.substr(0, eq);
        std::string val = p.substr(eq + 1);

        if (!first) ss << ", ";
        first = false;

        ss << "\"" << json_escape(key) << "\": ";

        // Try to detect type
        if (val == "true" || val == "false" || val == "null") {
            ss << val;
        } else {
            // Try number
            bool is_number = false;
            bool has_dot = false;
            if (!val.empty()) {
                size_t start = (val[0] == '-') ? 1 : 0;
                if (start < val.size()) {
                    is_number = true;
                    for (size_t j = start; j < val.size(); ++j) {
                        if (val[j] == '.') {
                            if (has_dot) { is_number = false; break; }
                            has_dot = true;
                        } else if (val[j] < '0' || val[j] > '9') {
                            is_number = false;
                            break;
                        }
                    }
                }
            }
            if (is_number) {
                ss << val;
            } else if (!val.empty() && (val.front() == '{' || val.front() == '[')) {
                ss << val;
            } else {
                ss << "\"" << json_escape(val) << "\"";
            }
        }
    }
    ss << "}";
    return ss.str();
}

// ============================================================================
// JSON-RPC call helper
// ============================================================================

/// Make a single JSON-RPC call and return the raw JSON body.
/// On connection failure returns empty string.
static std::string rpc_call_raw(const std::string& host, uint16_t port,
                                 const std::string& user, const std::string& pass,
                                 const std::string& method, const std::string& params_json,
                                 int timeout_sec, bool suppress_errors = false) {
    std::ostringstream body;
    body << "{\"jsonrpc\":\"2.0\",\"method\":\""
         << json_escape(method)
         << "\",\"params\":" << params_json
         << ",\"id\":1}";

    std::string response = http_request(host, port, user, pass,
                                         body.str(), timeout_sec, suppress_errors);
    if (response.empty()) return "";
    return extract_body(response);
}

// ============================================================================
// CLI command: -getinfo
// ============================================================================

static int cmd_getinfo(const CliOptions& opts, const std::string& host, uint16_t port,
                        const std::string& user, const std::string& pass) {
    // Call getblockchaininfo
    std::string chain_body = rpc_call_raw(host, port, user, pass,
                                           "getblockchaininfo", "[]", opts.timeout_seconds);
    // Call getnetworkinfo
    std::string net_body = rpc_call_raw(host, port, user, pass,
                                         "getnetworkinfo", "[]", opts.timeout_seconds);
    // Call getwalletinfo (may fail if no wallet loaded)
    std::string wallet_body = rpc_call_raw(host, port, user, pass,
                                            "getwalletinfo", "[]", opts.timeout_seconds, true);

    if (chain_body.empty() && net_body.empty()) {
        std::cerr << "error: could not connect to " << host << ":" << port << std::endl;
        std::cerr << "Is flowcoind running?" << std::endl;
        return EXIT_CONN_ERROR;
    }

    // Extract fields from chain info
    std::string chain_result = json_extract_value(chain_body, "result");
    std::string chain_err = json_extract_value(chain_body, "error");
    if (!json_is_null(chain_err) && !chain_err.empty()) {
        std::string err_code = json_extract_value(chain_err, "code");
        std::string err_msg = json_extract_value(chain_err, "message");
        int code = 0;
        try { code = std::stoi(err_code); } catch (...) {}
        if (code == RPC_IN_WARMUP) {
            std::cerr << "error code: " << err_code << "\n";
            std::cerr << "error message:\n";
            std::cerr << json_unquote(err_msg) << std::endl;
            return 28;
        }
        std::cerr << "error code: " << err_code << "\n";
        std::cerr << "error message:\n";
        std::cerr << json_unquote(err_msg) << std::endl;
        return EXIT_RPC_ERROR;
    }

    std::string chain_name = json_unquote(json_extract_value(chain_result, "chain"));
    std::string blocks = json_extract_value(chain_result, "blocks");
    std::string headers = json_extract_value(chain_result, "headers");
    std::string difficulty = json_extract_value(chain_result, "difficulty");
    std::string bestblockhash = json_unquote(json_extract_value(chain_result, "bestblockhash"));

    // Extract fields from network info
    std::string net_result = json_extract_value(net_body, "result");
    std::string version_str = json_extract_value(net_result, "version");
    std::string subversion = json_unquote(json_extract_value(net_result, "subversion"));
    std::string protocolversion = json_extract_value(net_result, "protocolversion");
    std::string connections = json_extract_value(net_result, "connections");

    // Extract fields from wallet info (optional)
    std::string wallet_result = json_extract_value(wallet_body, "result");
    std::string balance;
    std::string keypoolsize;
    std::string paytxfee;
    if (!json_is_null(wallet_result) && !wallet_result.empty()) {
        balance = json_extract_value(wallet_result, "balance");
        keypoolsize = json_extract_value(wallet_result, "keypoolsize");
        paytxfee = json_extract_value(wallet_result, "paytxfee");
    }

    // Collect fields as "key": value lines (values already formatted)
    std::vector<std::string> fields;
    if (!version_str.empty()) fields.push_back("  \"version\": " + version_str);
    if (!protocolversion.empty()) fields.push_back("  \"protocolversion\": " + protocolversion);
    if (!balance.empty()) fields.push_back("  \"balance\": " + balance);
    if (!blocks.empty()) fields.push_back("  \"blocks\": " + blocks);
    if (!headers.empty()) fields.push_back("  \"headers\": " + headers);
    if (!bestblockhash.empty()) fields.push_back("  \"bestblockhash\": \"" + bestblockhash + "\"");
    if (!difficulty.empty()) fields.push_back("  \"difficulty\": " + difficulty);
    if (!connections.empty()) fields.push_back("  \"connections\": " + connections);
    if (!chain_name.empty()) fields.push_back("  \"chain\": \"" + chain_name + "\"");
    if (!keypoolsize.empty()) fields.push_back("  \"keypoolsize\": " + keypoolsize);
    if (!paytxfee.empty()) fields.push_back("  \"paytxfee\": " + paytxfee);
    if (!subversion.empty()) fields.push_back("  \"subversion\": \"" + subversion + "\"");

    // Print as valid JSON with correct comma placement
    std::cout << "{\n";
    for (size_t i = 0; i < fields.size(); ++i) {
        std::cout << fields[i];
        if (i + 1 < fields.size()) std::cout << ",";
        std::cout << "\n";
    }
    std::cout << "}" << std::endl;

    return EXIT_OK;
}

// ============================================================================
// CLI command: -netinfo
// ============================================================================

static int cmd_netinfo(const CliOptions& opts, const std::string& host, uint16_t port,
                        const std::string& user, const std::string& pass) {
    std::string peer_body = rpc_call_raw(host, port, user, pass,
                                          "getpeerinfo", "[]", opts.timeout_seconds);
    if (peer_body.empty()) {
        std::cerr << "error: could not connect to " << host << ":" << port << std::endl;
        std::cerr << "Is flowcoind running?" << std::endl;
        return EXIT_CONN_ERROR;
    }

    std::string peer_err = json_extract_value(peer_body, "error");
    if (!json_is_null(peer_err) && !peer_err.empty()) {
        std::string err_code = json_extract_value(peer_err, "code");
        std::string err_msg = json_extract_value(peer_err, "message");
        int code = 0;
        try { code = std::stoi(err_code); } catch (...) {}
        if (code == RPC_IN_WARMUP) {
            std::cerr << "error code: " << err_code << "\n";
            std::cerr << "error message:\n";
            std::cerr << json_unquote(err_msg) << std::endl;
            return 28;
        }
        std::cerr << "error code: " << err_code << "\n";
        std::cerr << "error message:\n";
        std::cerr << json_unquote(err_msg) << std::endl;
        return EXIT_RPC_ERROR;
    }

    std::string peer_result = json_extract_value(peer_body, "result");

    // Print the peer info as formatted JSON (the result is an array of peer objects)
    if (peer_result.empty() || json_is_null(peer_result)) {
        std::cout << "No peers connected." << std::endl;
    } else {
        std::cout << "Peer connections:" << std::endl;
        std::cout << json_pretty(peer_result) << std::endl;
    }

    return EXIT_OK;
}

// ============================================================================
// Process a JSON-RPC response body (shared by normal and rpcwait paths)
// Returns exit code.
// ============================================================================

static int process_rpc_response(const std::string& json_body) {
    std::string error_val = json_extract_value(json_body, "error");
    std::string result_val = json_extract_value(json_body, "result");

    // Check for errors — Bitcoin Core format
    if (!json_is_null(error_val) && !error_val.empty()) {
        std::string err_msg = json_extract_value(error_val, "message");
        std::string err_code = json_extract_value(error_val, "code");

        int code = 0;
        if (!err_code.empty()) {
            try { code = std::stoi(err_code); } catch (...) {}
        }

        if (!err_msg.empty()) {
            // Bitcoin Core format:
            // error code: -28
            // error message:
            // Loading block index...
            std::cerr << "error code: " << err_code << "\n";
            std::cerr << "error message:\n";
            std::cerr << json_unquote(err_msg) << std::endl;
        } else {
            std::cerr << "error: " << error_val << std::endl;
        }

        // Special exit code for warmup
        if (code == RPC_IN_WARMUP) {
            return 28;
        }

        return EXIT_RPC_ERROR;
    }

    // Print the result
    if (result_val.empty() || json_is_null(result_val)) {
        // Some methods return null on success (like stop)
        return EXIT_OK;
    }

    // If result is a simple string, unquote it
    if (result_val.front() == '"') {
        std::cout << json_unquote(result_val) << std::endl;
    }
    // If result is an object or array, pretty-print it
    else if (result_val.front() == '{' || result_val.front() == '[') {
        std::cout << json_pretty(result_val) << std::endl;
    }
    // Numbers, booleans: print directly
    else {
        std::cout << result_val << std::endl;
    }

    return EXIT_OK;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        std::cerr << "error: WSAStartup failed" << std::endl;
        return 1;
    }
#endif

    CliOptions opts = parse_cli_args(argc, argv);

    if (opts.help) {
        print_usage();
        return EXIT_OK;
    }

    if (opts.version) {
        std::cout << "FlowCoin Core RPC client version v" << CLIENT_VERSION_STRING << std::endl;
        return EXIT_OK;
    }

    // -stdinrpcpass: read password from stdin before anything else
    if (opts.stdin_rpcpass) {
        std::string pw;
        if (std::getline(std::cin, pw)) {
            opts.rpc_pass = trim_ws(pw);
        }
    }

    // A CLI command or a regular RPC method is required
    if (opts.method.empty() && !opts.cli_getinfo && !opts.cli_netinfo) {
        print_usage();
        return EXIT_USAGE_ERROR;
    }

    // Determine data directory for cookie file
    std::string datadir = opts.datadir;
    if (datadir.empty()) {
        datadir = get_default_datadir();
    }
    if (opts.testnet) datadir += "/testnet";
    if (opts.regtest) datadir += "/regtest";

    // Load config file
    std::string conf_path = opts.config_file;
    if (conf_path.empty()) {
        conf_path = datadir + "/flowcoin.conf";
    } else if (conf_path[0] != '/'
#ifdef _WIN32
               && !(conf_path.size() >= 2 && conf_path[1] == ':')
#endif
              ) {
        // Relative path: prefix with datadir
        conf_path = datadir + "/" + conf_path;
    }
    read_config_file(conf_path, opts);

    // Apply network-specific port defaults (only if user didn't set port)
    if (!opts.port_set) {
        if (opts.testnet) {
            opts.rpc_port = 19334;
        } else if (opts.regtest) {
            opts.rpc_port = 19443;
        } else {
            opts.rpc_port = 9334;
        }
    }

    // Cookie file path
    std::string cookie_path;
    if (!opts.rpc_cookiefile.empty()) {
        cookie_path = opts.rpc_cookiefile;
    } else {
        cookie_path = datadir;
        if (!cookie_path.empty() && cookie_path.back() != '/') cookie_path += "/";
        cookie_path += ".cookie";
    }

    // Try cookie auth if no user/password specified
    if (opts.rpc_user.empty() || opts.rpc_pass.empty()) {
        std::string cookie_user, cookie_pass;
        if (read_cookie(cookie_path, cookie_user, cookie_pass)) {
            if (opts.rpc_user.empty()) opts.rpc_user = cookie_user;
            if (opts.rpc_pass.empty()) opts.rpc_pass = cookie_pass;
        }
    }

    // Final fallback for auth
    if (opts.rpc_user.empty()) opts.rpc_user = "flowcoin";
    if (opts.rpc_pass.empty()) opts.rpc_pass = "flowcoin";

    // -stdin: read extra arguments from stdin, one per line
    if (opts.stdin_rpc) {
        std::string line;
        while (std::getline(std::cin, line)) {
            line = trim_ws(line);
            if (!line.empty()) {
                opts.params.push_back(line);
            }
        }
    }

    int exit_code = EXIT_OK;

    // Handle CLI commands (-getinfo, -netinfo)
    if (opts.cli_getinfo) {
        if (opts.rpcwait) {
            auto start_time = std::chrono::steady_clock::now();
            while (true) {
                int rc = cmd_getinfo(opts, opts.rpc_host, opts.rpc_port,
                                      opts.rpc_user, opts.rpc_pass);
                if (rc != EXIT_CONN_ERROR && rc != 28) {
                    exit_code = rc;
                    break;
                }
                if (opts.rpcwait_timeout > 0) {
                    auto elapsed = std::chrono::steady_clock::now() - start_time;
                    if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count()
                        >= opts.rpcwait_timeout) {
                        std::cerr << "error: timeout waiting for RPC server" << std::endl;
                        exit_code = EXIT_CONN_ERROR;
                        break;
                    }
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        } else {
            exit_code = cmd_getinfo(opts, opts.rpc_host, opts.rpc_port,
                                     opts.rpc_user, opts.rpc_pass);
        }
    } else if (opts.cli_netinfo) {
        if (opts.rpcwait) {
            auto start_time = std::chrono::steady_clock::now();
            while (true) {
                int rc = cmd_netinfo(opts, opts.rpc_host, opts.rpc_port,
                                      opts.rpc_user, opts.rpc_pass);
                if (rc != EXIT_CONN_ERROR && rc != 28) {
                    exit_code = rc;
                    break;
                }
                if (opts.rpcwait_timeout > 0) {
                    auto elapsed = std::chrono::steady_clock::now() - start_time;
                    if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count()
                        >= opts.rpcwait_timeout) {
                        std::cerr << "error: timeout waiting for RPC server" << std::endl;
                        exit_code = EXIT_CONN_ERROR;
                        break;
                    }
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        } else {
            exit_code = cmd_netinfo(opts, opts.rpc_host, opts.rpc_port,
                                     opts.rpc_user, opts.rpc_pass);
        }
    } else {
        // Regular RPC method call

        // Build params
        std::string params_json;
        if (opts.named_args) {
            params_json = build_named_params_json(opts.params);
        } else {
            params_json = build_params_json(opts.params);
        }

        // Build JSON-RPC request
        std::ostringstream body;
        body << "{\"jsonrpc\":\"2.0\",\"method\":\""
             << json_escape(opts.method)
             << "\",\"params\":" << params_json
             << ",\"id\":1}";

        std::string response;

        if (opts.rpcwait) {
            // -rpcwait: retry until server starts
            auto start_time = std::chrono::steady_clock::now();
            bool got_response = false;
            while (true) {
                response = http_request(
                    opts.rpc_host, opts.rpc_port,
                    opts.rpc_user, opts.rpc_pass,
                    body.str(), opts.timeout_seconds, true);

                if (!response.empty()) {
                    // Got a response. Check if it's a warmup error.
                    std::string wait_body = extract_body(response);
                    std::string error_val = json_extract_value(wait_body, "error");
                    if (!json_is_null(error_val) && !error_val.empty()) {
                        std::string err_code = json_extract_value(error_val, "code");
                        int code = 0;
                        try { code = std::stoi(err_code); } catch (...) {}
                        if (code == RPC_IN_WARMUP) {
                            // Server is starting up, keep waiting
                            if (opts.rpcwait_timeout > 0) {
                                auto elapsed = std::chrono::steady_clock::now() - start_time;
                                if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count()
                                    >= opts.rpcwait_timeout) {
                                    std::cerr << "error: timeout waiting for RPC server" << std::endl;
                                    exit_code = EXIT_CONN_ERROR;
                                    got_response = false;
                                    break;
                                }
                            }
                            std::this_thread::sleep_for(std::chrono::seconds(1));
                            continue;
                        }
                    }
                    // Server responded with something other than warmup
                    got_response = true;
                    break;
                }

                // No response — check timeout
                if (opts.rpcwait_timeout > 0) {
                    auto elapsed = std::chrono::steady_clock::now() - start_time;
                    if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count()
                        >= opts.rpcwait_timeout) {
                        std::cerr << "error: timeout waiting for RPC server" << std::endl;
                        exit_code = EXIT_CONN_ERROR;
                        break;
                    }
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            if (got_response) {
                std::string json_body = extract_body(response);
                exit_code = process_rpc_response(json_body);
            }
        } else {
            // Normal (non-rpcwait) path: send single request
            response = http_request(
                opts.rpc_host, opts.rpc_port,
                opts.rpc_user, opts.rpc_pass,
                body.str(), opts.timeout_seconds);

            if (response.empty()) {
                std::cerr << "error: could not connect to " << opts.rpc_host
                          << ":" << opts.rpc_port << std::endl;
                std::cerr << "Is flowcoind running?" << std::endl;
                exit_code = EXIT_CONN_ERROR;
            } else {
                // Check HTTP status
                int http_status = extract_http_status(response);
                if (http_status == 401) {
                    std::cerr << "error: authentication failed (check rpcuser/rpcpassword "
                              << "or .cookie file)" << std::endl;
                    exit_code = EXIT_RPC_ERROR;
                } else if (http_status == 403) {
                    std::cerr << "error: forbidden (check RPC bind settings)" << std::endl;
                    exit_code = EXIT_RPC_ERROR;
                } else {
                    std::string json_body = extract_body(response);
                    if (json_body.empty()) {
                        std::cerr << "error: empty response body (HTTP " << http_status << ")" << std::endl;
                        exit_code = EXIT_RPC_ERROR;
                    } else {
                        exit_code = process_rpc_response(json_body);
                    }
                }
            }
        }
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return exit_code;
}

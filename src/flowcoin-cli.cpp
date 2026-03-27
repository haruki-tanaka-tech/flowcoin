// Copyright (c) 2026 The FlowCoin Developers
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
//   flowcoin-cli --testnet getblockcount

#include "version.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
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

// ============================================================================
// CLI options
// ============================================================================

struct CliOptions {
    std::string rpc_host  = "127.0.0.1";
    uint16_t rpc_port     = 9334;
    std::string rpc_user;
    std::string rpc_pass;
    std::string config_file;
    std::string datadir;
    bool testnet          = false;
    bool regtest          = false;
    bool help             = false;
    bool version          = false;
    bool stdin_rpc        = false;   // read params from stdin (for piping)
    int timeout_seconds   = 30;

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
    const char* home = std::getenv("HOME");
    if (!home || home[0] == '\0') return ".flowcoin";
    return std::string(home) + "/.flowcoin";
}

static bool read_cookie(const std::string& datadir,
                        std::string& user, std::string& pass) {
    std::string path = datadir;
    if (!path.empty() && path.back() != '/') path += "/";
    path += ".cookie";

    std::ifstream ifs(path);
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
        } else if (key == "rpcport" && opts.rpc_port == 9334) {
            try { opts.rpc_port = static_cast<uint16_t>(std::stoi(val)); } catch (...) {}
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

static std::string http_request(const std::string& host, uint16_t port,
                                 const std::string& user, const std::string& pass,
                                 const std::string& body, int timeout_sec) {
    // Resolve hostname
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;   // Support both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    int gai_err = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (gai_err != 0) {
        std::cerr << "error: could not resolve " << host << ": "
                  << gai_strerror(gai_err) << std::endl;
        return "";
    }

    // Create socket
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        std::cerr << "error: socket creation failed: " << strerror(errno) << std::endl;
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
        std::cerr << "error: could not connect to " << host << ":" << port
                  << " — " << strerror(errno) << std::endl;
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
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::cerr << "error: send timeout" << std::endl;
            } else {
                std::cerr << "error: send failed: " << strerror(errno) << std::endl;
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
// Usage / help
// ============================================================================

static void print_usage() {
    std::cout << CLIENT_NAME << " CLI v" << CLIENT_VERSION_STRING << "\n\n";
    std::cout << "Usage: flowcoin-cli [options] <method> [params...]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --rpcconnect=<ip>      Connect to RPC server (default: 127.0.0.1)\n";
    std::cout << "  --rpcport=<port>       RPC port (default: 9334, testnet: 19334, regtest: 29334)\n";
    std::cout << "  --rpcuser=<user>       RPC username (reads from .cookie if not set)\n";
    std::cout << "  --rpcpassword=<pass>   RPC password (reads from .cookie if not set)\n";
    std::cout << "  --conf=<file>          Config file path (default: ~/.flowcoin/flowcoin.conf)\n";
    std::cout << "  --datadir=<dir>        Data directory (for finding .cookie file)\n";
    std::cout << "  --testnet              Use testnet ports\n";
    std::cout << "  --regtest              Use regtest ports\n";
    std::cout << "  --timeout=<secs>       RPC timeout in seconds (default: 30)\n";
    std::cout << "  --stdin                Read method params from stdin (JSON array)\n";
    std::cout << "  --help, -h             Print this help message\n";
    std::cout << "  --version              Print version\n";
    std::cout << "\nExamples:\n";
    std::cout << "  flowcoin-cli getblockcount\n";
    std::cout << "  flowcoin-cli getblockhash 0\n";
    std::cout << "  flowcoin-cli getblock <hash> 2\n";
    std::cout << "  flowcoin-cli sendtoaddress fl1q... 1.5\n";
    std::cout << "  flowcoin-cli --testnet getblockcount\n";
    std::cout << "  echo '[0]' | flowcoin-cli --stdin getblockhash\n";
}

// ============================================================================
// Argument parsing
// ============================================================================

static CliOptions parse_cli_args(int argc, char* argv[]) {
    CliOptions opts;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];

        if (a == "--help" || a == "-h" || a == "-?") {
            opts.help = true;
            continue;
        }
        if (a == "--version") {
            opts.version = true;
            continue;
        }
        if (a == "--testnet") {
            opts.testnet = true;
            continue;
        }
        if (a == "--regtest") {
            opts.regtest = true;
            continue;
        }
        if (a == "--stdin") {
            opts.stdin_rpc = true;
            continue;
        }

        if (starts_with(a, "--rpcconnect=")) {
            opts.rpc_host = get_arg_value(a);
        } else if (starts_with(a, "--rpcport=")) {
            try { opts.rpc_port = static_cast<uint16_t>(std::stoi(get_arg_value(a))); } catch (...) {}
        } else if (starts_with(a, "--rpcuser=")) {
            opts.rpc_user = get_arg_value(a);
        } else if (starts_with(a, "--rpcpassword=")) {
            opts.rpc_pass = get_arg_value(a);
        } else if (starts_with(a, "--conf=")) {
            opts.config_file = get_arg_value(a);
        } else if (starts_with(a, "--datadir=")) {
            opts.datadir = get_arg_value(a);
        } else if (starts_with(a, "--timeout=")) {
            try { opts.timeout_seconds = std::stoi(get_arg_value(a)); } catch (...) {}
        } else if (a[0] == '-' && a.size() > 1) {
            std::cerr << "Unknown option: " << a << std::endl;
            // Don't exit — it might be a negative number param
            if (opts.method.empty()) {
                continue;  // Skip unknown options before the method name
            }
            opts.params.push_back(a);
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

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    CliOptions opts = parse_cli_args(argc, argv);

    if (opts.help) {
        print_usage();
        return EXIT_OK;
    }

    if (opts.version) {
        std::cout << CLIENT_NAME << " CLI v" << CLIENT_VERSION_STRING << std::endl;
        return EXIT_OK;
    }

    if (opts.method.empty()) {
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
    }
    read_config_file(conf_path, opts);

    // Apply network-specific port defaults
    if (opts.testnet && opts.rpc_port == 9334) {
        opts.rpc_port = 19334;
    } else if (opts.regtest && opts.rpc_port == 9334) {
        opts.rpc_port = 29334;
    }

    // Try cookie auth if no user/password specified
    if (opts.rpc_user.empty() || opts.rpc_pass.empty()) {
        std::string cookie_user, cookie_pass;
        if (read_cookie(datadir, cookie_user, cookie_pass)) {
            if (opts.rpc_user.empty()) opts.rpc_user = cookie_user;
            if (opts.rpc_pass.empty()) opts.rpc_pass = cookie_pass;
        }
    }

    // Final fallback for auth
    if (opts.rpc_user.empty()) opts.rpc_user = "flowcoin";
    if (opts.rpc_pass.empty()) opts.rpc_pass = "flowcoin";

    // Build params
    std::string params_json;
    if (opts.stdin_rpc) {
        // Read params from stdin
        std::string line;
        std::getline(std::cin, line);
        line = trim_ws(line);
        if (line.empty() || line == "[]") {
            params_json = "[]";
        } else if (line.front() == '[') {
            params_json = line;
        } else {
            params_json = "[" + line + "]";
        }
    } else {
        params_json = build_params_json(opts.params);
    }

    // Build JSON-RPC request
    std::ostringstream body;
    body << "{\"jsonrpc\":\"2.0\",\"method\":\""
         << json_escape(opts.method)
         << "\",\"params\":" << params_json
         << ",\"id\":1}";

    // Send HTTP request
    std::string response = http_request(
        opts.rpc_host, opts.rpc_port,
        opts.rpc_user, opts.rpc_pass,
        body.str(), opts.timeout_seconds);

    if (response.empty()) {
        std::cerr << "error: no response from server at "
                  << opts.rpc_host << ":" << opts.rpc_port << std::endl;
        std::cerr << "Is flowcoind running?" << std::endl;
        return EXIT_CONN_ERROR;
    }

    // Check HTTP status
    int http_status = extract_http_status(response);
    if (http_status == 401) {
        std::cerr << "error: authentication failed (check rpcuser/rpcpassword "
                  << "or .cookie file)" << std::endl;
        return EXIT_RPC_ERROR;
    }
    if (http_status == 403) {
        std::cerr << "error: forbidden (check RPC bind settings)" << std::endl;
        return EXIT_RPC_ERROR;
    }

    // Extract HTTP body
    std::string json_body = extract_body(response);
    if (json_body.empty()) {
        std::cerr << "error: empty response body (HTTP " << http_status << ")" << std::endl;
        return EXIT_RPC_ERROR;
    }

    // Parse the JSON-RPC response
    std::string error_val = json_extract_value(json_body, "error");
    std::string result_val = json_extract_value(json_body, "result");

    // Check for errors
    if (!json_is_null(error_val) && !error_val.empty()) {
        // Extract error message if it's an object
        std::string err_msg = json_extract_value(error_val, "message");
        std::string err_code = json_extract_value(error_val, "code");

        if (!err_msg.empty()) {
            std::cerr << "error";
            if (!err_code.empty()) {
                std::cerr << " (code " << err_code << ")";
            }
            std::cerr << ": " << json_unquote(err_msg) << std::endl;
        } else {
            // Print the raw error
            std::cerr << "error: " << error_val << std::endl;
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

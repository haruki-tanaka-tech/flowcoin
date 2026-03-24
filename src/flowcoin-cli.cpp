// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// flowcoin-cli: Command-line RPC client for flowcoind.
// Sends JSON-RPC requests over HTTP to the daemon and prints the result.
//
// Usage: flowcoin-cli [options] <method> [params...]
// Options: --rpcconnect, --rpcport, --rpcuser, --rpcpassword

#include "version.h"

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// ---------------------------------------------------------------------------
// Base64 encoding (for HTTP Basic auth)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Simple TCP client for one-shot HTTP request
// ---------------------------------------------------------------------------

static std::string http_request(const std::string& host, uint16_t port,
                                 const std::string& user, const std::string& pass,
                                 const std::string& body) {
    // Resolve hostname
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
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
        std::cerr << "error: socket creation failed" << std::endl;
        freeaddrinfo(res);
        return "";
    }

    // Set a 10-second timeout on reads
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Connect
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        std::cerr << "error: could not connect to " << host << ":" << port
                  << std::endl;
        close(sock);
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
            std::cerr << "error: send failed" << std::endl;
            close(sock);
            return "";
        }
        total_sent += n;
    }

    // Receive response
    std::string response;
    char buf[4096];
    while (true) {
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        response.append(buf, static_cast<size_t>(n));
    }

    close(sock);
    return response;
}

// ---------------------------------------------------------------------------
// Parse JSON-RPC response
// ---------------------------------------------------------------------------

static std::string extract_body(const std::string& response) {
    auto pos = response.find("\r\n\r\n");
    if (pos == std::string::npos) return response;
    return response.substr(pos + 4);
}

// Very simple JSON value extraction (avoids dependency on json.hpp in CLI)
// Only handles the outer result/error structure.
static bool is_json_null(const std::string& s) {
    // Check if the trimmed value is "null"
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return false;
    return s.compare(start, 4, "null") == 0;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

static void print_usage() {
    std::cout << "FlowCoin CLI v" << CLIENT_VERSION_STRING << "\n\n";
    std::cout << "Usage: flowcoin-cli [options] <method> [params...]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --rpcconnect=<ip>      Connect to RPC server (default: 127.0.0.1)\n";
    std::cout << "  --rpcport=<port>       RPC port (default: 9334)\n";
    std::cout << "  --rpcuser=<user>       RPC username (default: flowcoin)\n";
    std::cout << "  --rpcpassword=<pass>   RPC password (default: flowcoin)\n";
    std::cout << "  --help                 Print this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  flowcoin-cli getblockcount\n";
    std::cout << "  flowcoin-cli getblockhash 0\n";
    std::cout << "  flowcoin-cli sendtoaddress fl1q... 1.5\n";
}

static bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static std::string get_arg_value(const std::string& arg) {
    auto eq = arg.find('=');
    if (eq != std::string::npos) return arg.substr(eq + 1);
    return "";
}

int main(int argc, char* argv[]) {
    std::string rpc_host = "127.0.0.1";
    uint16_t rpc_port = 9334;
    std::string rpc_user = "flowcoin";
    std::string rpc_pass = "flowcoin";

    // Collect non-option arguments
    std::vector<std::string> args;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];

        if (a == "--help" || a == "-h") {
            print_usage();
            return 0;
        }

        if (starts_with(a, "--rpcconnect=")) {
            rpc_host = get_arg_value(a);
        } else if (starts_with(a, "--rpcport=")) {
            rpc_port = static_cast<uint16_t>(std::stoi(get_arg_value(a)));
        } else if (starts_with(a, "--rpcuser=")) {
            rpc_user = get_arg_value(a);
        } else if (starts_with(a, "--rpcpassword=")) {
            rpc_pass = get_arg_value(a);
        } else if (a[0] == '-') {
            std::cerr << "Unknown option: " << a << std::endl;
            return 1;
        } else {
            args.push_back(a);
        }
    }

    if (args.empty()) {
        print_usage();
        return 1;
    }

    std::string method = args[0];

    // Build JSON-RPC request
    // params array: try to parse numbers and booleans, otherwise treat as strings
    std::ostringstream params;
    params << "[";
    for (size_t i = 1; i < args.size(); ++i) {
        if (i > 1) params << ", ";

        const std::string& p = args[i];

        // Try to detect if it's a number
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

        if (p == "true" || p == "false" || p == "null") {
            params << p;
        } else if (is_number) {
            params << p;
        } else {
            // String parameter: quote it
            params << "\"" << p << "\"";
        }
    }
    params << "]";

    std::ostringstream body;
    body << "{\"jsonrpc\":\"2.0\",\"method\":\"" << method
         << "\",\"params\":" << params.str() << ",\"id\":1}";

    // Send HTTP request
    std::string response = http_request(rpc_host, rpc_port, rpc_user, rpc_pass,
                                         body.str());

    if (response.empty()) {
        std::cerr << "error: no response from server at "
                  << rpc_host << ":" << rpc_port << std::endl;
        std::cerr << "Is flowcoind running?" << std::endl;
        return 1;
    }

    // Extract HTTP body
    std::string json_body = extract_body(response);

    if (json_body.empty()) {
        std::cerr << "error: empty response body" << std::endl;
        return 1;
    }

    // Check for HTTP-level auth errors
    if (response.find("401") != std::string::npos) {
        std::cerr << "error: authentication failed (check rpcuser/rpcpassword)"
                  << std::endl;
        return 1;
    }

    // Simple parsing: look for "error" field.
    // If "error":null, print the "result" field.
    // If "error":{ ... }, print the error.
    //
    // For proper output, we look for the key patterns in the JSON string.
    // This avoids pulling in the json.hpp dependency for the CLI binary.

    // Find "error": position
    auto error_pos = json_body.find("\"error\"");
    auto result_pos = json_body.find("\"result\"");

    if (error_pos != std::string::npos) {
        // Check if error is null
        auto colon = json_body.find(':', error_pos + 7);
        if (colon != std::string::npos) {
            auto after_colon = json_body.find_first_not_of(" \t", colon + 1);
            if (after_colon != std::string::npos &&
                json_body.compare(after_colon, 4, "null") == 0) {
                // No error -- print the result
                if (result_pos != std::string::npos) {
                    auto rcolon = json_body.find(':', result_pos + 8);
                    if (rcolon != std::string::npos) {
                        // Extract everything between result: and the next
                        // top-level comma or closing brace.
                        // Simple approach: print from after the colon to
                        // before the ,"error" or ,"id"
                        size_t val_start = rcolon + 1;
                        // Skip whitespace
                        while (val_start < json_body.size() &&
                               (json_body[val_start] == ' ' ||
                                json_body[val_start] == '\t')) {
                            val_start++;
                        }

                        // Find where the result value ends
                        // Look for ,\"error\" or ,\"id\"
                        size_t val_end = json_body.find(",\"error\"", val_start);
                        if (val_end == std::string::npos) {
                            val_end = json_body.find(",\"id\"", val_start);
                        }
                        if (val_end == std::string::npos) {
                            val_end = json_body.rfind('}');
                        }

                        if (val_end != std::string::npos) {
                            std::string result_val = json_body.substr(
                                val_start, val_end - val_start);
                            // Trim trailing whitespace
                            auto last = result_val.find_last_not_of(" \t\r\n");
                            if (last != std::string::npos) {
                                result_val = result_val.substr(0, last + 1);
                            }
                            // Remove surrounding quotes if it's a simple string
                            if (result_val.size() >= 2 &&
                                result_val.front() == '"' &&
                                result_val.back() == '"') {
                                result_val = result_val.substr(
                                    1, result_val.size() - 2);
                            }
                            std::cout << result_val << std::endl;
                            return 0;
                        }
                    }
                }
                // Fallback: print the whole body
                std::cout << json_body << std::endl;
                return 0;
            } else {
                // There is an error -- print it
                std::cerr << "error: " << json_body << std::endl;
                return 1;
            }
        }
    }

    // Fallback: just print the raw response body
    std::cout << json_body << std::endl;
    return 0;
}

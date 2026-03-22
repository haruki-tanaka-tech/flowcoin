// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// FlowCoin CLI — sends JSON-RPC requests to a running flowcoind via HTTP.
// Default: http://127.0.0.1:9334

#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <string>

using json = nlohmann::json;

static std::string http_post(const std::string& host, uint16_t port,
                              const std::string& body) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(sock);
        return "";
    }

    // Set receive timeout (2 seconds)
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    std::string request =
        "POST / HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n"
        "\r\n" + body;

    send(sock, request.data(), request.size(), 0);

    std::string response;
    char buf[4096];
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0) {
        response.append(buf, static_cast<size_t>(n));
    }
    close(sock);

    // Extract body from HTTP response
    auto header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos) return response;
    return response.substr(header_end + 4);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: flowcoin-cli [options] <method> [params...]\n"
                  << "Options:\n"
                  << "  -rpcport=PORT  RPC port (default: 9334)\n"
                  << "  -rpchost=HOST  RPC host (default: 127.0.0.1)\n"
                  << "\nMethods:\n"
                  << "  getblockcount          Get current block height\n"
                  << "  getbestblockhash       Get tip block hash\n"
                  << "  getblock <hash>        Get block by hash\n"
                  << "  gettraininginfo        Get model training status\n"
                  << "  getmempoolinfo         Get mempool status\n"
                  << "  getnewaddress          Generate new wallet address\n"
                  << "  listaddresses          List all wallet addresses\n"
                  << "  importprivkey <hex>     Import a private key\n"
                  << "  dumpwallet             Export all private keys\n";
        return 1;
    }

    std::string host = "127.0.0.1";
    uint16_t port = 9334;

    // Parse options
    int method_idx = 1;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.starts_with("-rpcport=")) {
            port = static_cast<uint16_t>(std::stoi(arg.substr(9)));
            method_idx = i + 1;
        } else if (arg.starts_with("-rpchost=")) {
            host = arg.substr(9);
            method_idx = i + 1;
        } else {
            method_idx = i;
            break;
        }
    }

    if (method_idx >= argc) {
        std::cerr << "Error: no method specified\n";
        return 1;
    }

    std::string method = argv[method_idx];

    json request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", method},
        {"params", json::array()},
    };

    for (int i = method_idx + 1; i < argc; ++i) {
        request["params"].push_back(argv[i]);
    }

    std::string response_body = http_post(host, port, request.dump());

    if (response_body.empty()) {
        std::cerr << "Error: could not connect to flowcoind at "
                  << host << ":" << port << "\n";
        return 1;
    }

    try {
        json response = json::parse(response_body);
        if (response.contains("error") && !response["error"].is_null()) {
            std::cerr << "Error: " << response["error"]["message"] << "\n";
            return 1;
        }
        if (response.contains("result")) {
            if (response["result"].is_string()) {
                std::cout << response["result"].get<std::string>() << "\n";
            } else {
                std::cout << response["result"].dump(2) << "\n";
            }
        }
    } catch (const json::exception& e) {
        std::cerr << "Error parsing response: " << e.what() << "\n";
        std::cerr << "Raw: " << response_body << "\n";
        return 1;
    }

    return 0;
}

// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// FlowCoin CLI — sends JSON-RPC requests to a running flowcoind via HTTP.
// Default: http://127.0.0.1:9334

#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

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
    int n;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0) {
        response.append(buf, static_cast<size_t>(n));
    }
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

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
                  << "\n  Wallet:\n"
                  << "  getbalance             Total wallet balance\n"
                  << "  getbalance <address>   Balance of a specific address\n"
                  << "  listunspent            List all unspent outputs\n"
                  << "  getnewaddress          Generate new wallet address\n"
                  << "  sendtoaddress <addr> <amount>  Send FLOW to address\n"
                  << "  listaddresses          List all wallet addresses\n"
                  << "  importprivkey <hex>    Import a private key\n"
                  << "  dumpwallet             Export all private keys\n"
                  << "\n  Network:\n"
                  << "  getnetworkinfo         Network status\n"
                  << "  getpeerinfo            Connected peers\n"
                  << "  getconnectioncount     Number of connections\n"
                  << "  addnode <ip:port>      Connect to a peer\n";
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
            auto& r = response["result"];

            if (r.is_string()) {
                std::cout << r.get<std::string>() << "\n";
            } else if (r.is_number()) {
                if (r.is_number_float()) {
                    std::cout << r.get<double>() << "\n";
                } else {
                    std::cout << r.get<int64_t>() << "\n";
                }
            } else if (method == "getpeerinfo" && r.is_array()) {
                // Table format for peers
                std::cout << "  ID  ADDR                        DIR    HEIGHT  VER\n";
                for (const auto& p : r) {
                    std::string dir = p.value("inbound", false) ? "in " : "out";
                    printf("  %-3d %-27s %-4s   %-7d %d\n",
                        p.value("id", 0),
                        p.value("addr", std::string("?")).c_str(),
                        dir.c_str(),
                        p.value("height", 0),
                        p.value("version", 0));
                }
                std::cout << "Total: " << r.size() << " peers\n";
            } else if (method == "listaddresses" && r.is_array()) {
                for (const auto& a : r) {
                    std::string used = a.value("used", false) ? "*" : " ";
                    printf("  %s %s\n", used.c_str(),
                        a.value("address", std::string("?")).c_str());
                }
                std::cout << "Total: " << r.size() << " addresses\n";
            } else if (method == "listunspent" && r.is_array()) {
                printf("  %-16s %4s  %12s  %s\n", "TXID", "VOUT", "AMOUNT", "ADDRESS");
                for (const auto& u : r) {
                    std::string txid = u.value("txid", std::string("?"));
                    printf("  %-16s %4d  %12.8f  %s\n",
                        txid.substr(0, 16).c_str(),
                        u.value("vout", 0),
                        u.value("amount", 0.0),
                        u.value("address", std::string("?")).c_str());
                }
                double total = 0;
                for (const auto& u : r) total += u.value("amount", 0.0);
                printf("Total: %zu UTXOs, %.8f FLOW\n", r.size(), total);
            } else if (method == "getbalance" && r.is_object()) {
                if (r.contains("address")) {
                    printf("%s: %.8f FLOW (%d UTXOs)\n",
                        r.value("address", std::string("?")).c_str(),
                        r.value("balance", 0.0),
                        r.value("utxo_count", 0));
                } else {
                    printf("%.8f FLOW (%d UTXOs)\n",
                        r.value("balance", 0.0),
                        r.value("utxo_count", 0));
                }
            } else if (method == "getnetworkinfo" && r.is_object()) {
                printf("Network:     %s\n", r.value("network", std::string("?")).c_str());
                printf("Protocol:    %d\n", r.value("protocol_version", 0));
                printf("P2P port:    %d\n", r.value("p2p_port", 0));
                printf("RPC port:    %d\n", r.value("rpc_port", 0));
                printf("Connections: %d\n", r.value("connections", 0));
            } else if (method == "gettraininginfo" && r.is_object()) {
                printf("Height:      %d\n", r.value("height", 0));
                printf("Val loss:    %.4f\n", r.value("val_loss", 0.0));
                printf("d_model:     %d\n", r.value("d_model", 0));
                printf("n_layers:    %d\n", r.value("n_layers", 0));
                printf("n_experts:   %d\n", r.value("n_experts", 0));
                printf("Improving:   %d blocks\n", r.value("improving_blocks", 0));
            } else {
                std::cout << r.dump(2) << "\n";
            }
        }
    } catch (const json::exception& e) {
        std::cerr << "Error parsing response: " << e.what() << "\n";
        std::cerr << "Raw: " << response_body << "\n";
        return 1;
    }

    return 0;
}

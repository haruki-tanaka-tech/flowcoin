// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Minimal JSON-RPC client for the standalone miner.
// Uses raw TCP sockets -- no curl, no external dependencies.

#pragma once
#include <string>
#include <cstdint>

namespace flow::miner {

class RPCClient {
public:
    RPCClient(const std::string& host, int port,
              const std::string& user, const std::string& password);

    // Make a JSON-RPC call, return result as JSON string.
    std::string call(const std::string& method, const std::string& params = "[]");

    // Convenience methods
    int64_t get_block_count();
    std::string get_best_block_hash();

    struct BlockTemplate {
        uint64_t height;
        std::string prev_hash;
        uint32_t nbits;
        bool valid;
    };
    BlockTemplate get_block_template();

    // Submit a block (hex-encoded)
    std::string submit_block(const std::string& hex_block);

    // Get a new wallet address
    std::string get_new_address();

    bool is_connected();

private:
    std::string host_;
    int port_;
    std::string auth_base64_;

    std::string http_post(const std::string& body);

    static std::string json_get_string(const std::string& json, const std::string& key);
    static int64_t json_get_int(const std::string& json, const std::string& key);
    static double json_get_double(const std::string& json, const std::string& key);
};

} // namespace flow::miner

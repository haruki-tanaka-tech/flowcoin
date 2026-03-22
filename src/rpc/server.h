// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// JSON-RPC server for FlowCoin.
// Listens on localhost:9554, dispatches methods to handlers.

#pragma once

#include "core/types.h"
#include <nlohmann/json.hpp>

#include <functional>
#include <string>
#include <unordered_map>

namespace flow::rpc {

using json = nlohmann::json;
using RpcHandler = std::function<json(const json& params)>;

class RpcServer {
public:
    // Register an RPC method handler.
    void register_method(const std::string& method, RpcHandler handler);

    // Process a JSON-RPC request string. Returns JSON-RPC response string.
    std::string handle_request(const std::string& request_body);

private:
    std::unordered_map<std::string, RpcHandler> handlers_;

    json make_response(const json& id, const json& result);
    json make_error(const json& id, int code, const std::string& message);
};

} // namespace flow::rpc

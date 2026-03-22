// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "server.h"

namespace flow::rpc {

void RpcServer::register_method(const std::string& method, RpcHandler handler) {
    handlers_[method] = std::move(handler);
}

std::string RpcServer::handle_request(const std::string& request_body) {
    json request;
    try {
        request = json::parse(request_body);
    } catch (const json::exception&) {
        return make_error(nullptr, -32700, "Parse error").dump();
    }

    // Validate JSON-RPC structure
    if (!request.contains("method") || !request["method"].is_string()) {
        json id = request.value("id", json(nullptr));
        return make_error(id, -32600, "Invalid Request").dump();
    }

    std::string method = request["method"];
    json id = request.value("id", json(nullptr));
    json params = request.value("params", json::array());

    // Find handler
    auto it = handlers_.find(method);
    if (it == handlers_.end()) {
        return make_error(id, -32601, "Method not found: " + method).dump();
    }

    // Execute handler
    try {
        json result = it->second(params);
        return make_response(id, result).dump();
    } catch (const std::exception& e) {
        return make_error(id, -32000, e.what()).dump();
    }
}

json RpcServer::make_response(const json& id, const json& result) {
    return {
        {"jsonrpc", "2.0"},
        {"id", id},
        {"result", result},
    };
}

json RpcServer::make_error(const json& id, int code, const std::string& message) {
    return {
        {"jsonrpc", "2.0"},
        {"id", id},
        {"error", {
            {"code", code},
            {"message", message},
        }},
    };
}

} // namespace flow::rpc

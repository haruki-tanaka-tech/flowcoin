// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Central RPC registration: registers all RPC methods from all modules
// with the server. Provides a help system with method categories,
// parameter descriptions, and usage examples.

#ifndef FLOWCOIN_RPC_REGISTER_H
#define FLOWCOIN_RPC_REGISTER_H

#include <map>
#include <string>
#include <vector>

namespace flow {

class RpcServer;
class ChainState;
class Wallet;
class NetManager;
class Mempool;

// ---------------------------------------------------------------------------
// Node context: aggregates all subsystems for RPC access
// ---------------------------------------------------------------------------

struct NodeContext {
    ChainState* chain = nullptr;
    Wallet* wallet = nullptr;
    NetManager* net = nullptr;
    Mempool* mempool = nullptr;
    std::string datadir;
    int64_t start_time = 0;
};

// ---------------------------------------------------------------------------
// Central registration
// ---------------------------------------------------------------------------

/// Register all RPC methods with the server.
/// This is the single entry point that calls all individual registration
/// functions for blockchain, wallet, mining, network, utility,
/// raw transaction, and debug RPCs.
void register_all_rpcs(RpcServer& server, NodeContext& node);

// ---------------------------------------------------------------------------
// Help system
// ---------------------------------------------------------------------------

/// Detailed help entry for a single RPC method.
struct RpcMethodHelp {
    std::string name;
    std::string category;
    std::string summary;
    std::string params;      // parameter description
    std::string result;      // result description
    std::string examples;    // example usage
};

/// Register a help entry for an RPC method.
void register_help(const RpcMethodHelp& help);

/// Get help for a specific method. Returns false if method not found.
bool get_method_help(const std::string& name, RpcMethodHelp& help);

/// List all registered methods grouped by category.
std::map<std::string, std::vector<std::string>> list_methods_by_category();

/// Get all registered method names.
std::vector<std::string> list_all_methods();

/// Get all help entries for a category.
std::vector<RpcMethodHelp> get_category_help(const std::string& category);

/// Get the number of registered help entries.
size_t help_entry_count();

/// Format a help entry as a human-readable string.
std::string format_help(const RpcMethodHelp& help);

/// Format the full help listing (all methods by category).
std::string format_help_all();

} // namespace flow

#endif // FLOWCOIN_RPC_REGISTER_H

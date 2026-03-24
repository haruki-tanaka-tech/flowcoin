// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Node initialization and shutdown.
// Parses command-line arguments, sets up data directories, initializes
// all subsystems (chain, wallet, network, RPC), and runs the event loop.

#ifndef FLOWCOIN_INIT_H
#define FLOWCOIN_INIT_H

#include "config.h"
#include "consensus/params.h"

#include <cstdint>
#include <memory>
#include <string>

struct uv_loop_s;
typedef struct uv_loop_s uv_loop_t;

namespace flow {

class ChainState;
class Wallet;
class NetManager;
class RpcServer;

struct NodeConfig {
    std::string datadir      = "data";
    uint16_t port            = consensus::MAINNET_PORT;
    uint16_t rpc_port        = consensus::MAINNET_RPC_PORT;
    std::string rpc_user     = "flowcoin";
    std::string rpc_password = "flowcoin";
    bool testnet             = false;
    bool regtest             = false;
    bool daemon              = false;
};

/// Parse command-line arguments into a NodeConfig.
/// Recognized flags: --datadir, --port, --rpcport, --rpcuser, --rpcpassword,
/// --testnet, --regtest, --daemon, --help
NodeConfig parse_args(int argc, char* argv[]);

/// Print usage information to stdout.
void print_usage();

class Node {
public:
    explicit Node(const NodeConfig& config);
    ~Node();

    // Non-copyable
    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;

    /// Initialize all subsystems. Returns true on success.
    bool init();

    /// Run the node (blocking). Returns when shutdown() is called.
    void run();

    /// Trigger a graceful shutdown.
    void shutdown();

    /// Access subsystems (for signal handler integration).
    ChainState* chain_state()  { return chain_.get(); }
    Wallet*     wallet()       { return wallet_.get(); }
    NetManager* net_manager()  { return net_.get(); }
    RpcServer*  rpc_server()   { return rpc_.get(); }

private:
    NodeConfig config_;
    Config file_config_;

    std::unique_ptr<ChainState> chain_;
    std::unique_ptr<Wallet>     wallet_;
    std::unique_ptr<NetManager> net_;
    std::unique_ptr<RpcServer>  rpc_;

    uv_loop_t* loop_ = nullptr;

    /// Apply network-specific settings (testnet/regtest ports, magic, etc.).
    void apply_network_config();

    /// Ensure data directory exists.
    bool ensure_datadir();

    /// Load and merge the configuration file (datadir/flowcoin.conf).
    void load_config_file();

    /// Register all RPC methods.
    void register_rpcs();
};

} // namespace flow

#endif // FLOWCOIN_INIT_H

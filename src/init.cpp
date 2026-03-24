// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "init.h"
#include "logging.h"
#include "version.h"

#include "chain/chainstate.h"
#include "wallet/wallet.h"
#include "net/net.h"
#include "rpc/server.h"
#include "rpc/blockchain.h"
#include "rpc/wallet.h"
#include "rpc/mining.h"
#include "rpc/net.h"
#include "consensus/params.h"

#include <uv.h>

#include <cstring>
#include <filesystem>
#include <iostream>
#include <thread>

namespace flow {

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

static bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static std::string get_arg_value(const std::string& arg) {
    auto eq = arg.find('=');
    if (eq != std::string::npos) {
        return arg.substr(eq + 1);
    }
    return "";
}

NodeConfig parse_args(int argc, char* argv[]) {
    NodeConfig cfg;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_usage();
            std::exit(0);
        }

        if (starts_with(arg, "--datadir=")) {
            cfg.datadir = get_arg_value(arg);
        } else if (starts_with(arg, "--port=")) {
            cfg.port = static_cast<uint16_t>(std::stoi(get_arg_value(arg)));
        } else if (starts_with(arg, "--rpcport=")) {
            cfg.rpc_port = static_cast<uint16_t>(std::stoi(get_arg_value(arg)));
        } else if (starts_with(arg, "--rpcuser=")) {
            cfg.rpc_user = get_arg_value(arg);
        } else if (starts_with(arg, "--rpcpassword=")) {
            cfg.rpc_password = get_arg_value(arg);
        } else if (arg == "--testnet") {
            cfg.testnet = true;
        } else if (arg == "--regtest") {
            cfg.regtest = true;
        } else if (arg == "--daemon") {
            cfg.daemon = true;
        } else if (arg == "--datadir" && i + 1 < argc) {
            cfg.datadir = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            cfg.port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--rpcport" && i + 1 < argc) {
            cfg.rpc_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--rpcuser" && i + 1 < argc) {
            cfg.rpc_user = argv[++i];
        } else if (arg == "--rpcpassword" && i + 1 < argc) {
            cfg.rpc_password = argv[++i];
        }
    }

    return cfg;
}

void print_usage() {
    std::cout << CLIENT_NAME << " v" << CLIENT_VERSION_STRING << "\n\n";
    std::cout << "Usage: flowcoind [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --datadir=<dir>        Data directory (default: data)\n";
    std::cout << "  --port=<port>          P2P listen port (default: 9333)\n";
    std::cout << "  --rpcport=<port>       RPC listen port (default: 9334)\n";
    std::cout << "  --rpcuser=<user>       RPC authentication username (default: flowcoin)\n";
    std::cout << "  --rpcpassword=<pass>   RPC authentication password (default: flowcoin)\n";
    std::cout << "  --testnet              Use testnet network\n";
    std::cout << "  --regtest              Use regtest network\n";
    std::cout << "  --daemon               Run in background\n";
    std::cout << "  --help, -h             Print this help message\n";
}

// ---------------------------------------------------------------------------
// Node implementation
// ---------------------------------------------------------------------------

Node::Node(const NodeConfig& config)
    : config_(config) {
}

Node::~Node() {
    shutdown();
}

void Node::apply_network_config() {
    if (config_.testnet) {
        if (config_.port == consensus::MAINNET_PORT) {
            config_.port = consensus::TESTNET_PORT;
        }
        if (config_.rpc_port == consensus::MAINNET_RPC_PORT) {
            config_.rpc_port = consensus::TESTNET_RPC_PORT;
        }
    } else if (config_.regtest) {
        if (config_.port == consensus::MAINNET_PORT) {
            config_.port = consensus::REGTEST_PORT;
        }
        if (config_.rpc_port == consensus::MAINNET_RPC_PORT) {
            config_.rpc_port = consensus::REGTEST_RPC_PORT;
        }
    }
}

bool Node::ensure_datadir() {
    try {
        std::filesystem::create_directories(config_.datadir);
        std::filesystem::create_directories(config_.datadir + "/blocks");
        return true;
    } catch (const std::filesystem::filesystem_error& e) {
        LogError("init", "Failed to create data directory '%s': %s",
                 config_.datadir.c_str(), e.what());
        return false;
    }
}

void Node::load_config_file() {
    std::string conf_path = config_.datadir + "/flowcoin.conf";
    if (file_config_.load(conf_path)) {
        LogInfo("init", "Loaded configuration from %s", conf_path.c_str());

        // Configuration file values are overridden by command-line arguments.
        // Only apply config file values if the corresponding command-line
        // argument was not provided (defaults still in place).
        if (config_.rpc_user == "flowcoin" && file_config_.has("rpcuser")) {
            config_.rpc_user = file_config_.get("rpcuser");
        }
        if (config_.rpc_password == "flowcoin" && file_config_.has("rpcpassword")) {
            config_.rpc_password = file_config_.get("rpcpassword");
        }
        if (file_config_.has("port")) {
            // Only override if default
            if (config_.port == consensus::MAINNET_PORT ||
                config_.port == consensus::TESTNET_PORT ||
                config_.port == consensus::REGTEST_PORT) {
                config_.port = static_cast<uint16_t>(
                    file_config_.get_int("port", config_.port));
            }
        }
        if (file_config_.has("rpcport")) {
            if (config_.rpc_port == consensus::MAINNET_RPC_PORT ||
                config_.rpc_port == consensus::TESTNET_RPC_PORT ||
                config_.rpc_port == consensus::REGTEST_RPC_PORT) {
                config_.rpc_port = static_cast<uint16_t>(
                    file_config_.get_int("rpcport", config_.rpc_port));
            }
        }
        if (file_config_.get_bool("testnet")) {
            config_.testnet = true;
        }
        if (file_config_.get_bool("regtest")) {
            config_.regtest = true;
        }
    }
}

bool Node::init() {
    // Apply network-specific configuration
    apply_network_config();

    // Ensure data directory exists
    if (!ensure_datadir()) {
        return false;
    }

    // Initialize logging
    std::string log_path = config_.datadir + "/debug.log";
    log_init(log_path);
    LogInfo("init", "%s v%s starting up", CLIENT_NAME, CLIENT_VERSION_STRING);

    // Load config file (may override defaults)
    load_config_file();

    // Re-apply network config in case config file changed testnet/regtest
    apply_network_config();

    // Determine network magic
    uint32_t magic = consensus::MAINNET_MAGIC;
    if (config_.testnet) {
        magic = consensus::TESTNET_MAGIC;
        LogInfo("init", "Using testnet");
    } else if (config_.regtest) {
        magic = consensus::REGTEST_MAGIC;
        LogInfo("init", "Using regtest");
    }

    // 1. Initialize ChainState
    LogInfo("init", "Initializing chain state in %s", config_.datadir.c_str());
    chain_ = std::make_unique<ChainState>(config_.datadir);
    if (!chain_->init()) {
        LogError("init", "Failed to initialize chain state");
        return false;
    }
    LogInfo("init", "Chain initialized at height %lu",
            (unsigned long)chain_->height());

    // 2. Initialize Wallet
    std::string wallet_path = config_.datadir + "/wallet.dat";
    LogInfo("init", "Initializing wallet at %s", wallet_path.c_str());
    wallet_ = std::make_unique<Wallet>(wallet_path, chain_->utxo_set());
    if (!wallet_->init()) {
        LogError("init", "Failed to initialize wallet");
        return false;
    }
    LogInfo("init", "Wallet initialized");

    // 3. Initialize NetManager
    LogInfo("init", "Starting P2P network on port %u", config_.port);
    net_ = std::make_unique<NetManager>(*chain_, config_.port, magic);
    if (!net_->start()) {
        LogError("init", "Failed to start network manager");
        return false;
    }
    LogInfo("init", "Network manager started");

    // 4. Initialize RPC server
    LogInfo("init", "Starting RPC server on port %u", config_.rpc_port);

    // Create libuv loop for RPC (we'll share the net's loop via run())
    loop_ = uv_default_loop();

    rpc_ = std::make_unique<RpcServer>(config_.rpc_port,
                                        config_.rpc_user,
                                        config_.rpc_password);

    // Register all RPC methods
    register_rpcs();

    if (!rpc_->start(loop_)) {
        LogError("init", "Failed to start RPC server");
        return false;
    }

    LogInfo("init", "Initialization complete");
    return true;
}

void Node::register_rpcs() {
    register_blockchain_rpcs(*rpc_, *chain_);
    register_wallet_rpcs(*rpc_, *wallet_, *chain_, *net_);
    register_mining_rpcs(*rpc_, *chain_, *net_);
    register_net_rpcs(*rpc_, *net_);

    // stop: graceful shutdown via RPC
    rpc_->register_method("stop", [this](const json& /*params*/) -> json {
        LogInfo("rpc", "Shutdown requested via RPC");
        shutdown();
        return "FlowCoin server stopping";
    });

    // getinfo: basic node info
    rpc_->register_method("getinfo", [this](const json& /*params*/) -> json {
        json j;
        j["version"]     = CLIENT_VERSION_STRING;
        j["blocks"]      = static_cast<int64_t>(chain_->height());
        j["connections"]  = static_cast<int64_t>(net_->peer_count());
        j["testnet"]     = config_.testnet;
        j["regtest"]     = config_.regtest;
        return j;
    });

    // help: list available methods
    rpc_->register_method("help", [](const json& /*params*/) -> json {
        json methods = json::array();
        methods.push_back("getblockcount");
        methods.push_back("getbestblockhash");
        methods.push_back("getblockhash <height>");
        methods.push_back("getblock <hash> [verbosity]");
        methods.push_back("getblockheader <hash>");
        methods.push_back("getblockchaininfo");
        methods.push_back("gettxout <txid> <vout>");
        methods.push_back("getnewaddress");
        methods.push_back("getbalance");
        methods.push_back("listunspent");
        methods.push_back("sendtoaddress <address> <amount>");
        methods.push_back("listtransactions [count] [skip]");
        methods.push_back("validateaddress <address>");
        methods.push_back("getblocktemplate [coinbase_address]");
        methods.push_back("submitblock <hex>");
        methods.push_back("getmininginfo");
        methods.push_back("getpeerinfo");
        methods.push_back("getconnectioncount");
        methods.push_back("addnode <ip:port> [add|remove|onetry]");
        methods.push_back("getnetworkinfo");
        methods.push_back("getinfo");
        methods.push_back("stop");
        methods.push_back("help");
        return methods;
    });
}

void Node::run() {
    LogInfo("init", "Node running. Press Ctrl+C to stop.");

    // Run the network manager's event loop on its own thread
    // and run the RPC event loop on the main thread.
    // Actually, the NetManager has its own loop created in start().
    // We run its loop in a separate thread and the RPC loop on main.
    std::thread net_thread([this]() {
        net_->run();
    });

    // Run the RPC/main event loop
    uv_run(loop_, UV_RUN_DEFAULT);

    // When the RPC loop exits, wait for the network thread
    net_->stop();
    if (net_thread.joinable()) {
        net_thread.join();
    }

    LogInfo("init", "Node stopped");
}

void Node::shutdown() {
    LogInfo("init", "Shutting down...");

    // Stop RPC server
    if (rpc_) {
        rpc_->stop();
    }

    // Stop the RPC event loop
    if (loop_) {
        uv_stop(loop_);
    }

    // Stop network manager
    if (net_) {
        net_->stop();
    }

    // Flush logging
    log_shutdown();
}

} // namespace flow

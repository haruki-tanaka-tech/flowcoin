// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Node initialization and shutdown.
// Parses command-line arguments, sets up data directories, initializes
// all subsystems (chain, wallet, network, RPC), and runs the event loop.
// Modeled after Bitcoin Core's init.cpp: a 12-step deterministic sequence
// that creates and wires all subsystems.

#ifndef FLOWCOIN_INIT_H
#define FLOWCOIN_INIT_H

#include "config.h"
#include "consensus/params.h"
#include "node/context.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

struct uv_loop_s;
typedef struct uv_loop_s uv_loop_t;

namespace flow {

class ChainState;
class Wallet;
class NetManager;
class RpcServer;

// ============================================================================
// AppArgs: parsed command-line arguments
// ============================================================================

struct AppArgs {
    // -- Data directory and config ---
    std::string datadir;
    std::string config_file;

    // -- Daemon mode ---
    bool daemon        = false;
    bool print_help    = false;
    bool print_version = false;

    // -- Network selection ---
    bool testnet       = false;
    bool regtest       = false;

    // -- Chain options ---
    bool reindex              = false;
    bool reindex_chainstate   = false;
    bool prune                = false;
    uint64_t prune_target     = 0;     // MB (0 = disabled)
    std::string assume_valid;          // block hash to skip sig checks below

    // -- RPC options ---
    std::string rpc_user;
    std::string rpc_password;
    std::string rpc_bind      = "127.0.0.1";
    uint16_t rpc_port         = 0;     // 0 = use network default
    bool server               = true;  // enable RPC

    // -- P2P network options ---
    std::string bind_addr;
    uint16_t port             = 0;     // 0 = use network default
    int max_connections       = defaults::MAX_CONNECTIONS;
    std::vector<std::string> addnodes;
    std::vector<std::string> connect_only;  // -connect (whitelist-only connections)
    bool listen               = defaults::LISTEN;
    bool discover             = defaults::DISCOVER;
    bool dns_seed             = defaults::DNS_SEED;

    // -- Logging options ---
    std::string log_file;
    std::string log_level     = "info";
    std::vector<std::string> log_categories;
    bool print_to_console     = false;

    // -- Wallet options ---
    std::string wallet_file;
    bool no_wallet            = false;

    // -- Performance options ---
    int db_cache              = defaults::DB_CACHE_MB;    // MB
    int par                   = defaults::PAR_THREADS;    // 0 = auto

    // -- Debug/testing ---
    int64_t mock_time         = 0;     // override system clock (testing)
};

// ============================================================================
// Argument parsing
// ============================================================================

/// Parse command-line arguments into an AppArgs structure.
/// Handles --key=value and --key value forms, as well as bare --flag.
AppArgs parse_args(int argc, char* argv[]);

/// Print full help text to stdout.
void print_help();

/// Print version information to stdout.
void print_version();

// ============================================================================
// NodeConfig (backward-compatible wrapper used by flowcoind.cpp)
// ============================================================================

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

// ============================================================================
// Full initialization sequence (12 steps)
// ============================================================================

namespace init {

/// Full initialization: runs all 12 steps in order.
/// Returns false if any step fails.
bool app_init(NodeContext& node, const AppArgs& args);

/// Step 1: Create/verify data directory, set canonical paths.
bool step1_setup_data_dir(NodeContext& node, const AppArgs& args);

/// Step 2: Validate parameters (port ranges, conflicting options).
bool step2_parameter_validation(const AppArgs& args);

/// Step 3: Lock the data directory to prevent concurrent instances.
bool step3_lock_data_dir(NodeContext& node);

/// Step 4: Initialize logging subsystem (open file, set level, categories).
bool step4_initialize_logging(NodeContext& node, const AppArgs& args);

/// Step 5: Write PID file for daemon management.
bool step5_create_pid_file(NodeContext& node);

/// Step 6: Create chain state (ChainDB, BlockStore, UTXOSet, ModelState).
bool step6_initialize_chain(NodeContext& node, const AppArgs& args);

/// Step 7: Create and initialize wallet (or skip if --nowallet).
bool step7_initialize_wallet(NodeContext& node, const AppArgs& args);

/// Step 8: Create network manager, configure seeds/addnodes/maxconnections.
bool step8_initialize_network(NodeContext& node, const AppArgs& args);

/// Step 9: Create RPC server, register all methods.
bool step9_initialize_rpc(NodeContext& node, const AppArgs& args);

/// Step 10: Load block index from ChainDB, verify tip, replay if needed.
bool step10_load_chain(NodeContext& node, const AppArgs& args);

/// Step 11: Start listening for P2P connections, begin IBD if needed.
bool step11_start_network(NodeContext& node);

/// Step 12: Start the HTTP RPC server.
bool step12_start_rpc(NodeContext& node);

/// Graceful shutdown: stops all subsystems in reverse order.
void app_shutdown(NodeContext& node);

} // namespace init

// ============================================================================
// Node class (backward-compatible wrapper for existing flowcoind.cpp)
// ============================================================================

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

    /// Access subsystems
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

// ============================================================================
// System utilities for daemon management
// ============================================================================

namespace sys {

/// Fork the process into background (Unix daemonization).
/// Returns true on success (in the child process).
/// Returns false on failure.
bool daemonize();

/// Install default signal handlers (SIGINT, SIGTERM -> graceful shutdown).
void install_default_handlers();

/// Get the default data directory path (~/.flowcoin).
std::string get_default_datadir();

/// Expand ~ to the user's home directory in a path.
std::string expand_path(const std::string& path);

/// Get the number of available CPU cores.
int get_num_cores();

/// Get the available system memory in bytes.
uint64_t get_available_memory();

/// Get the current process ID.
int get_pid();

/// Check if a file descriptor refers to a terminal.
bool is_terminal(int fd);

} // namespace sys

} // namespace flow

#endif // FLOWCOIN_INIT_H

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
#include "mempool/mempool.h"

#include <uv.h>

#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

using json = nlohmann::json;

namespace flow {

// ============================================================================
// String utility helpers (file-local)
// ============================================================================

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

[[maybe_unused]] static std::string trim_ws(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// ============================================================================
// Argument parsing
// ============================================================================

AppArgs parse_args(int argc, char* argv[]) {
    AppArgs args;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];

        // Help and version
        if (a == "--help" || a == "-h" || a == "-?") {
            args.print_help = true;
            continue;
        }
        if (a == "--version" || a == "-v") {
            args.print_version = true;
            continue;
        }

        // Lambda: get the value for a --key=value or --key <value> argument
        auto next_val = [&](const std::string& prefix) -> std::string {
            if (starts_with(a, prefix + "=")) {
                return get_arg_value(a);
            }
            if (a == prefix && i + 1 < argc) {
                return argv[++i];
            }
            return "";
        };

        // Data directory and config
        if (starts_with(a, "--datadir")) {
            args.datadir = next_val("--datadir");
        } else if (starts_with(a, "--conf")) {
            args.config_file = next_val("--conf");
        }
        // Daemon mode
        else if (a == "--daemon" || a == "-daemon") {
            args.daemon = true;
        }
        // Network selection
        else if (a == "--testnet") {
            args.testnet = true;
        } else if (a == "--regtest") {
            args.regtest = true;
        }
        // Chain options
        else if (a == "--reindex") {
            args.reindex = true;
        } else if (a == "--reindex-chainstate") {
            args.reindex_chainstate = true;
        } else if (starts_with(a, "--prune")) {
            args.prune = true;
            std::string val = next_val("--prune");
            if (!val.empty()) {
                try { args.prune_target = std::stoull(val); } catch (...) {}
            }
        } else if (starts_with(a, "--assumevalid")) {
            args.assume_valid = next_val("--assumevalid");
        }
        // RPC options
        else if (starts_with(a, "--rpcuser")) {
            args.rpc_user = next_val("--rpcuser");
        } else if (starts_with(a, "--rpcpassword")) {
            args.rpc_password = next_val("--rpcpassword");
        } else if (starts_with(a, "--rpcbind")) {
            args.rpc_bind = next_val("--rpcbind");
        } else if (starts_with(a, "--rpcport")) {
            std::string val = next_val("--rpcport");
            if (!val.empty()) {
                try { args.rpc_port = static_cast<uint16_t>(std::stoi(val)); } catch (...) {}
            }
        } else if (a == "--noserver" || a == "--norpc") {
            args.server = false;
        }
        // P2P network options
        else if (starts_with(a, "--bind")) {
            args.bind_addr = next_val("--bind");
        } else if (starts_with(a, "--port")) {
            std::string val = next_val("--port");
            if (!val.empty()) {
                try { args.port = static_cast<uint16_t>(std::stoi(val)); } catch (...) {}
            }
        } else if (starts_with(a, "--maxconnections")) {
            std::string val = next_val("--maxconnections");
            if (!val.empty()) {
                try { args.max_connections = std::stoi(val); } catch (...) {}
            }
        } else if (starts_with(a, "--addnode")) {
            std::string val = next_val("--addnode");
            if (!val.empty()) args.addnodes.push_back(val);
        } else if (starts_with(a, "--connect")) {
            std::string val = next_val("--connect");
            if (!val.empty()) args.connect_only.push_back(val);
        } else if (a == "--nolisten") {
            args.listen = false;
        } else if (a == "--nodiscover") {
            args.discover = false;
        } else if (a == "--nodnsseed") {
            args.dns_seed = false;
        }
        // Logging options
        else if (starts_with(a, "--logfile")) {
            args.log_file = next_val("--logfile");
        } else if (starts_with(a, "--loglevel")) {
            args.log_level = next_val("--loglevel");
        } else if (starts_with(a, "--debug")) {
            std::string val = next_val("--debug");
            if (!val.empty()) args.log_categories.push_back(val);
        } else if (a == "--printtoconsole") {
            args.print_to_console = true;
        }
        // Wallet options
        else if (starts_with(a, "--wallet")) {
            args.wallet_file = next_val("--wallet");
        } else if (a == "--nowallet" || a == "--disablewallet") {
            args.no_wallet = true;
        }
        // Performance options
        else if (starts_with(a, "--dbcache")) {
            std::string val = next_val("--dbcache");
            if (!val.empty()) {
                try { args.db_cache = std::stoi(val); } catch (...) {}
            }
        } else if (starts_with(a, "--par")) {
            std::string val = next_val("--par");
            if (!val.empty()) {
                try { args.par = std::stoi(val); } catch (...) {}
            }
        }
        // Debug/testing
        else if (starts_with(a, "--mocktime")) {
            std::string val = next_val("--mocktime");
            if (!val.empty()) {
                try { args.mock_time = std::stoll(val); } catch (...) {}
            }
        }
        // Unknown options: warn but continue
        else if (a[0] == '-') {
            std::cerr << "Warning: unknown option '" << a << "'" << std::endl;
        }
    }

    return args;
}

void print_help() {
    std::cout << CLIENT_NAME << " v" << CLIENT_VERSION_STRING << "\n";
    std::cout << flow::version::COPYRIGHT << "\n\n";
    std::cout << "Usage: flowcoind [options]\n\n";
    std::cout << "Options:\n\n";
    std::cout << "General:\n";
    std::cout << "  --help, -h             Print this help message and exit\n";
    std::cout << "  --version, -v          Print version and exit\n";
    std::cout << "  --datadir=<dir>        Data directory (default: ~/.flowcoin)\n";
    std::cout << "  --conf=<file>          Config file path (default: <datadir>/flowcoin.conf)\n";
    std::cout << "  --daemon               Run in background as a daemon\n\n";
    std::cout << "Network:\n";
    std::cout << "  --testnet              Use testnet (port " << consensus::TESTNET_PORT << ")\n";
    std::cout << "  --regtest              Use regtest (port " << consensus::REGTEST_PORT << ")\n";
    std::cout << "  --port=<port>          P2P listen port (default: " << consensus::MAINNET_PORT << ")\n";
    std::cout << "  --bind=<addr>          Bind to address (default: 0.0.0.0)\n";
    std::cout << "  --maxconnections=<n>   Maximum connections (default: 125)\n";
    std::cout << "  --addnode=<ip:port>    Add a peer to connect to\n";
    std::cout << "  --connect=<ip:port>    Connect only to these peers\n";
    std::cout << "  --nolisten             Don't accept incoming connections\n";
    std::cout << "  --nodiscover           Don't discover other nodes\n";
    std::cout << "  --nodnsseed            Don't query DNS seeds\n\n";
    std::cout << "RPC:\n";
    std::cout << "  --rpcuser=<user>       RPC username\n";
    std::cout << "  --rpcpassword=<pass>   RPC password\n";
    std::cout << "  --rpcport=<port>       RPC port (default: " << consensus::MAINNET_RPC_PORT << ")\n";
    std::cout << "  --rpcbind=<addr>       RPC bind address (default: 127.0.0.1)\n";
    std::cout << "  --noserver             Disable the RPC server\n\n";
    std::cout << "Wallet:\n";
    std::cout << "  --wallet=<file>        Wallet file path\n";
    std::cout << "  --nowallet             Run without a wallet\n\n";
    std::cout << "Chain:\n";
    std::cout << "  --reindex              Rebuild block index from blk files\n";
    std::cout << "  --reindex-chainstate   Rebuild UTXO set from blocks\n";
    std::cout << "  --prune=<n>            Prune to <n> MB of block data\n";
    std::cout << "  --assumevalid=<hash>   Skip sig verification below this hash\n\n";
    std::cout << "Logging:\n";
    std::cout << "  --logfile=<path>       Log file path (default: <datadir>/debug.log)\n";
    std::cout << "  --loglevel=<level>     Log level: trace/debug/info/warn/error (default: info)\n";
    std::cout << "  --debug=<category>     Enable debug category (net/mempool/validation/rpc/wallet/mining/sync/db/eval)\n";
    std::cout << "  --printtoconsole       Also print log output to stdout\n\n";
    std::cout << "Performance:\n";
    std::cout << "  --dbcache=<n>          Database cache size in MB (default: 450)\n";
    std::cout << "  --par=<n>              Script verification threads (0=auto, default: 0)\n\n";
    std::cout << "Testing:\n";
    std::cout << "  --mocktime=<epoch>     Override system time (for testing)\n";
}

void print_version() {
    std::cout << CLIENT_NAME << " v" << CLIENT_VERSION_STRING << "\n";
    std::cout << flow::version::COPYRIGHT << "\n";
    std::cout << flow::version::LICENSE << "\n";
    std::cout << "Protocol version: " << consensus::PROTOCOL_VERSION << "\n";
    std::cout << flow::version::URL << "\n";
}

// ============================================================================
// System utilities
// ============================================================================

namespace sys {

bool daemonize() {
#ifdef _WIN32
    return false;  // Not supported on Windows
#else
    // First fork
    pid_t pid = ::fork();
    if (pid < 0) return false;
    if (pid > 0) ::_exit(0);  // Parent exits

    // Create new session
    if (::setsid() < 0) return false;

    // Second fork (prevent acquiring a controlling terminal)
    pid = ::fork();
    if (pid < 0) return false;
    if (pid > 0) ::_exit(0);  // First child exits

    // Set file creation mask
    ::umask(0022);

    // Change working directory to root
    if (::chdir("/") < 0) {
        // Non-fatal, continue
    }

    // Redirect stdin/stdout/stderr to /dev/null
    int devnull = ::open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        ::dup2(devnull, STDIN_FILENO);
        ::dup2(devnull, STDOUT_FILENO);
        ::dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) ::close(devnull);
    }

    return true;
#endif
}

static NodeContext* g_signal_node = nullptr;

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        if (g_signal_node) {
            g_signal_node->interrupt();
        }
        get_shutdown_state().request_shutdown();
    }
}

void install_default_handlers() {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    // Ignore SIGPIPE (broken pipe from network writes)
    signal(SIGPIPE, SIG_IGN);

    // Ignore SIGHUP by default (daemon mode)
    signal(SIGHUP, SIG_IGN);
}

std::string get_default_datadir() {
    const char* home = std::getenv("HOME");
    if (!home || home[0] == '\0') {
        return ".flowcoin";
    }
    return std::string(home) + "/.flowcoin";
}

std::string expand_path(const std::string& path) {
    if (path.empty()) return path;
    if (path[0] == '~') {
        const char* home = std::getenv("HOME");
        if (home && home[0] != '\0') {
            return std::string(home) + path.substr(1);
        }
    }
    return path;
}

int get_num_cores() {
    int n = static_cast<int>(std::thread::hardware_concurrency());
    return (n > 0) ? n : 1;
}

uint64_t get_available_memory() {
    // Try to read from /proc/meminfo on Linux
    std::ifstream meminfo("/proc/meminfo");
    if (meminfo.is_open()) {
        std::string line;
        while (std::getline(meminfo, line)) {
            if (starts_with(line, "MemAvailable:")) {
                std::istringstream iss(line);
                std::string label;
                uint64_t kb;
                iss >> label >> kb;
                return kb * 1024;
            }
        }
    }
    // Fallback: assume 4 GB
    return 4ULL * 1024 * 1024 * 1024;
}

int get_pid() {
    return static_cast<int>(::getpid());
}

bool is_terminal(int fd) {
    return ::isatty(fd) != 0;
}

} // namespace sys

// ============================================================================
// 12-step initialization sequence
// ============================================================================

namespace init {

bool step1_setup_data_dir(NodeContext& node, const AppArgs& args) {
    LogInfo("init", "Step 1: Setting up data directory");

    // Determine data directory
    if (!args.datadir.empty()) {
        node.datadir = sys::expand_path(args.datadir);
    } else {
        node.datadir = sys::get_default_datadir();
    }

    // Apply network subdirectory
    node.testnet = args.testnet;
    node.regtest = args.regtest;
    node.datadir += node.get_network_subdir();

    // Resolve to absolute path
    try {
        std::filesystem::path p(node.datadir);
        if (p.is_relative()) {
            node.datadir = std::filesystem::absolute(p).string();
        }
        // Normalize the path
        node.datadir = std::filesystem::weakly_canonical(p).string();
    } catch (...) {
        // Keep the path as-is if canonicalization fails
    }

    // Ensure the data directory exists
    if (!node.ensure_datadir()) {
        LogError("init", "Cannot create data directory '%s'", node.datadir.c_str());
        return false;
    }

    LogInfo("init", "Data directory: %s", node.datadir.c_str());
    return true;
}

bool step2_parameter_validation(const AppArgs& args) {
    LogInfo("init", "Step 2: Validating parameters");

    // Cannot use both testnet and regtest
    if (args.testnet && args.regtest) {
        LogError("init", "Cannot use both --testnet and --regtest");
        return false;
    }

    // Port range validation
    if (args.port > 0 && args.port < 1024) {
        LogWarn("init", "Port %u is in the privileged range (< 1024)", args.port);
    }
    if (args.rpc_port > 0 && args.rpc_port < 1024) {
        LogWarn("init", "RPC port %u is in the privileged range (< 1024)", args.rpc_port);
    }

    // Port conflict check
    if (args.port > 0 && args.rpc_port > 0 && args.port == args.rpc_port) {
        LogError("init", "P2P port and RPC port cannot be the same (%u)", args.port);
        return false;
    }

    // Max connections sanity
    if (args.max_connections < 0) {
        LogError("init", "Invalid maxconnections value: %d", args.max_connections);
        return false;
    }
    if (args.max_connections > 10000) {
        LogWarn("init", "Very high maxconnections (%d), this may cause issues",
                args.max_connections);
    }

    // DB cache sanity
    if (args.db_cache < 4) {
        LogError("init", "dbcache must be at least 4 MB (got %d)", args.db_cache);
        return false;
    }
    if (args.db_cache > 16384) {
        LogWarn("init", "Very large dbcache (%d MB), ensure sufficient RAM", args.db_cache);
    }

    // Prune target validation
    if (args.prune && args.prune_target > 0 && args.prune_target < 550) {
        LogError("init", "Prune target must be at least 550 MB (got %lu)",
                 static_cast<unsigned long>(args.prune_target));
        return false;
    }

    // Reindex + prune conflict
    if (args.reindex && args.prune) {
        LogWarn("init", "Reindex with pruning enabled — all blocks will be re-downloaded");
    }

    // Connect-only + listen conflict
    if (!args.connect_only.empty() && args.listen) {
        LogInfo("init", "Using --connect disables listening by default");
    }

    // Parallel threads validation
    if (args.par < 0 || args.par > 256) {
        LogError("init", "Invalid --par value: %d (must be 0-256)", args.par);
        return false;
    }

    LogInfo("init", "Parameter validation passed");
    return true;
}

bool step3_lock_data_dir(NodeContext& node) {
    LogInfo("init", "Step 3: Locking data directory");
    if (!node.lock_datadir()) {
        return false;
    }
    return true;
}

bool step4_initialize_logging(NodeContext& node, const AppArgs& args) {
    LogInfo("init", "Step 4: Initializing logging");

    LogConfig log_cfg;

    // Determine log file path
    if (!args.log_file.empty()) {
        log_cfg.log_file = args.log_file;
    } else {
        log_cfg.log_file = node.log_path();
    }

    // Set log level
    log_cfg.min_level = parse_log_level(args.log_level);

    // Set log categories
    if (!args.log_categories.empty()) {
        uint32_t mask = 0;
        for (const auto& cat : args.log_categories) {
            if (cat == "all" || cat == "1") {
                mask = LOGCAT_ALL;
                break;
            }
            uint32_t c = parse_log_category(cat);
            if (c != 0) {
                mask |= c;
            } else {
                std::cerr << "Warning: unknown log category '" << cat << "'" << std::endl;
            }
        }
        if (mask != 0) {
            log_cfg.enabled_categories = mask;
        }
    }

    // Console output
    log_cfg.print_to_console = args.print_to_console || sys::is_terminal(STDOUT_FILENO);

    log_init_config(log_cfg);

    LogInfo("init", "Logging initialized: file=%s level=%s",
            log_cfg.log_file.c_str(),
            log_level_name(log_cfg.min_level));

    return true;
}

bool step5_create_pid_file(NodeContext& node) {
    LogInfo("init", "Step 5: Creating PID file");
    return node.write_pid_file();
}

bool step6_initialize_chain(NodeContext& node, const AppArgs& args) {
    LogInfo("init", "Step 6: Initializing chain state");

    try {
        node.chain = std::make_unique<ChainState>(node.datadir);
        if (!node.chain->init()) {
            LogError("init", "ChainState::init() failed");
            return false;
        }
    } catch (const std::exception& e) {
        LogError("init", "Chain initialization error: %s", e.what());
        return false;
    }

    LogInfo("init", "Chain initialized at height %lu",
            static_cast<unsigned long>(node.chain->height()));

    // PoW: no eval engine needed

    // Initialize mempool
    try {
        node.mempool = std::make_unique<Mempool>(node.chain->utxo_set());
    } catch (const std::exception& e) {
        LogError("init", "Mempool creation error: %s", e.what());
        return false;
    }

    (void)args;  // Some args (reindex, assume_valid) are reserved for future use
    return true;
}

bool step7_initialize_wallet(NodeContext& node, const AppArgs& args) {
    LogInfo("init", "Step 7: Initializing wallet");

    if (args.no_wallet) {
        LogInfo("init", "Wallet disabled (--nowallet)");
        return true;
    }

    std::string wp;
    if (!args.wallet_file.empty()) {
        wp = args.wallet_file;
    } else {
        wp = node.wallet_path();
    }

    try {
        node.wallet = std::make_unique<Wallet>(wp, node.chain->utxo_set());
        if (!node.wallet->init()) {
            LogError("init", "Wallet::init() failed for '%s'", wp.c_str());
            return false;
        }
    } catch (const std::exception& e) {
        LogError("init", "Wallet error: %s", e.what());
        return false;
    }

    LogInfo("init", "Wallet initialized at %s", wp.c_str());
    return true;
}

bool step8_initialize_network(NodeContext& node, const AppArgs& args) {
    LogInfo("init", "Step 8: Initializing network manager");

    uint16_t p2p_port = args.port;
    if (p2p_port == 0) {
        p2p_port = node.get_port();
    }

    // Store port in config for other subsystems
    node.config.set("port", static_cast<int64_t>(p2p_port));
    node.config.set("maxconnections", static_cast<int64_t>(args.max_connections));

    try {
        node.net = std::make_unique<NetManager>(
            *node.chain, p2p_port, node.get_magic());
    } catch (const std::exception& e) {
        LogError("init", "Network initialization error: %s", e.what());
        return false;
    }

    // Store addnode and connect-only lists in config for later use
    for (const auto& addr : args.addnodes) {
        node.config.set("addnode", addr);
    }
    for (const auto& addr : args.connect_only) {
        node.config.set("connect", addr);
    }

    // Store network flags
    if (!args.listen) node.config.set("listen", false);
    if (!args.discover) node.config.set("discover", false);
    if (!args.dns_seed) node.config.set("dnsseed", false);

    LogInfo("init", "Network manager created for %s (port %u, max %d connections)",
            node.get_network_name(), p2p_port, args.max_connections);
    return true;
}

bool step9_initialize_rpc(NodeContext& node, const AppArgs& args) {
    LogInfo("init", "Step 9: Initializing RPC server");

    if (!args.server) {
        LogInfo("init", "RPC server disabled (--noserver)");
        return true;
    }

    uint16_t rpc_port = args.rpc_port;
    if (rpc_port == 0) {
        rpc_port = node.get_rpc_port();
    }

    // Determine RPC credentials
    std::string rpc_user = args.rpc_user;
    std::string rpc_pass = args.rpc_password;

    // If no user/password specified, try reading from config file
    if (rpc_user.empty()) {
        rpc_user = node.config.get_rpc_user();
    }
    if (rpc_pass.empty()) {
        rpc_pass = node.config.get_rpc_password();
    }

    // If still no credentials, try cookie auth
    if (rpc_user.empty() || rpc_pass.empty()) {
        std::string cookie_user, cookie_pass;
        if (node.config.read_cookie(node.datadir, cookie_user, cookie_pass)) {
            rpc_user = cookie_user;
            rpc_pass = cookie_pass;
            LogInfo("init", "Using cookie authentication for RPC");
        } else {
            // Generate a new cookie
            node.config.generate_cookie(node.datadir);
            if (node.config.read_cookie(node.datadir, cookie_user, cookie_pass)) {
                rpc_user = cookie_user;
                rpc_pass = cookie_pass;
                LogInfo("init", "Generated cookie authentication for RPC");
            } else {
                // Fallback to defaults
                rpc_user = "flowcoin";
                rpc_pass = "flowcoin";
                LogWarn("init", "Using default RPC credentials — set rpcuser/rpcpassword in flowcoin.conf");
            }
        }
    }

    // Store RPC config
    node.config.set("rpcport", static_cast<int64_t>(rpc_port));
    node.config.set("rpcuser", rpc_user);
    node.config.set("rpcpassword", rpc_pass);

    try {
        node.rpc = std::make_unique<RpcServer>(rpc_port, rpc_user, rpc_pass);
    } catch (const std::exception& e) {
        LogError("init", "RPC server creation error: %s", e.what());
        return false;
    }

    // Register all RPC methods
    register_blockchain_rpcs(*node.rpc, *node.chain);
    if (node.wallet) {
        register_wallet_rpcs(*node.rpc, *node.wallet, *node.chain, *node.net);
    }
    register_mining_rpcs(*node.rpc, *node.chain, *node.net);
    register_net_rpcs(*node.rpc, *node.net);

    // Built-in RPC methods
    node.rpc->register_method("stop", [&node](const json& /*params*/) -> json {
        LogInfo("rpc", "Shutdown requested via RPC");
        node.interrupt();
        return "FlowCoin server stopping";
    });

    node.rpc->register_method("getinfo", [&node](const json& /*params*/) -> json {
        json j;
        j["version"]      = CLIENT_VERSION_STRING;
        j["protocolversion"] = static_cast<int>(consensus::PROTOCOL_VERSION);
        j["blocks"]       = static_cast<int64_t>(node.chain_height());
        j["connections"]  = static_cast<int64_t>(node.peer_count());
        j["testnet"]      = node.testnet;
        j["regtest"]      = node.regtest;
        j["network"]      = node.get_network_name();
        j["difficulty"]   = 1.0;
        j["paytxfee"]     = 0.0;
        j["relayfee"]     = static_cast<double>(consensus::MIN_RELAY_FEE) / 1e8;
        j["warnings"]     = "";
        return j;
    });

    node.rpc->register_method("uptime", [&node](const json& /*params*/) -> json {
        return node.uptime();
    });

    node.rpc->register_method("help", [](const json& /*params*/) -> json {
        json methods = json::array();
        methods.push_back("== Blockchain ==");
        methods.push_back("getblockcount");
        methods.push_back("getbestblockhash");
        methods.push_back("getblockhash <height>");
        methods.push_back("getblock <hash> [verbosity]");
        methods.push_back("getblockheader <hash>");
        methods.push_back("getblockchaininfo");
        methods.push_back("gettxout <txid> <vout>");
        methods.push_back("");
        methods.push_back("== Wallet ==");
        methods.push_back("getnewaddress");
        methods.push_back("getbalance");
        methods.push_back("listunspent");
        methods.push_back("sendtoaddress <address> <amount>");
        methods.push_back("listtransactions [count] [skip]");
        methods.push_back("validateaddress <address>");
        methods.push_back("");
        methods.push_back("== Mining ==");
        methods.push_back("getblocktemplate [coinbase_address]");
        methods.push_back("submitblock <hex>");
        methods.push_back("getmininginfo");
        methods.push_back("");
        methods.push_back("== Network ==");
        methods.push_back("getpeerinfo");
        methods.push_back("getconnectioncount");
        methods.push_back("addnode <ip:port> [add|remove|onetry]");
        methods.push_back("getnetworkinfo");
        methods.push_back("");
        methods.push_back("== Control ==");
        methods.push_back("getinfo");
        methods.push_back("uptime");
        methods.push_back("stop");
        methods.push_back("help");
        return methods;
    });

    LogInfo("init", "RPC server created (port %u)", rpc_port);
    return true;
}

bool step10_load_chain(NodeContext& node, const AppArgs& args) {
    LogInfo("init", "Step 10: Loading chain data");

    // The chain was already loaded in step 6 (ChainState::init() loads the block index).
    // This step verifies consistency and applies any additional chain-level configuration.

    uint64_t height = node.chain->height();
    LogInfo("init", "Chain tip at height %lu", static_cast<unsigned long>(height));

    // Check if we're in IBD
    if (height < consensus::IBD_MIN_BLOCKS_BEHIND) {
        node.is_ibd.store(true);
        LogInfo("init", "Node is in Initial Block Download mode");
    } else {
        node.is_ibd.store(false);
        LogInfo("init", "Node is synced");
    }

    // Apply assume-valid if specified
    if (!args.assume_valid.empty()) {
        LogInfo("init", "Assume-valid hash: %s", args.assume_valid.c_str());
    }

    // Apply reindex if requested
    if (args.reindex) {
        LogInfo("init", "Reindex requested — this will take a while");
        // Reindexing is handled by ChainState internally
    }

    return true;
}

bool step11_start_network(NodeContext& node) {
    LogInfo("init", "Step 11: Starting P2P network");

    if (!node.net) {
        LogWarn("init", "Network manager not initialized, skipping");
        return true;
    }

    if (!node.net->start()) {
        LogError("init", "Failed to start P2P network");
        return false;
    }

    LogInfo("init", "P2P network started on %s", node.get_network_name());
    return true;
}

bool step12_start_rpc(NodeContext& node) {
    LogInfo("init", "Step 12: Starting RPC server");

    if (!node.rpc) {
        LogInfo("init", "RPC server disabled, skipping");
        return true;
    }

    node.loop = uv_default_loop();
    if (!node.rpc->start(node.loop)) {
        LogError("init", "Failed to start RPC server");
        return false;
    }

    LogInfo("init", "RPC server started");
    return true;
}

bool app_init(NodeContext& node, const AppArgs& args) {
    LogInfo("init", "%s v%s initializing...", CLIENT_NAME, CLIENT_VERSION_STRING);
    LogInfo("init", "Network: %s", args.testnet ? "testnet" : (args.regtest ? "regtest" : "mainnet"));
    LogInfo("init", "PID: %d", sys::get_pid());
    LogInfo("init", "CPU cores: %d", sys::get_num_cores());

    // Load config file if specified or from default location
    if (!args.config_file.empty()) {
        if (node.config.load(args.config_file)) {
            LogInfo("init", "Loaded config from %s", args.config_file.c_str());
        } else {
            LogWarn("init", "Could not load config file '%s'", args.config_file.c_str());
        }
    }

    // Execute all 12 steps
    if (!step1_setup_data_dir(node, args)) return false;

    // Try loading config from data directory if not already loaded
    if (args.config_file.empty()) {
        std::string conf_path = node.config_path();
        if (node.config.load(conf_path)) {
            LogInfo("init", "Loaded config from %s", conf_path.c_str());
        }
    }

    if (!step2_parameter_validation(args))      return false;
    if (!step3_lock_data_dir(node))             return false;
    if (!step4_initialize_logging(node, args))  return false;
    if (!step5_create_pid_file(node))           return false;
    if (!step6_initialize_chain(node, args))    return false;
    if (!step7_initialize_wallet(node, args))   return false;
    if (!step8_initialize_network(node, args))  return false;
    if (!step9_initialize_rpc(node, args))      return false;
    if (!step10_load_chain(node, args))         return false;
    if (!step11_start_network(node))            return false;
    if (!step12_start_rpc(node))                return false;

    // Set the signal handler target
    sys::g_signal_node = &node;

    LogInfo("init", "Initialization complete (%d subsystems)",
            static_cast<int>(node.subsystems.size()));
    return true;
}

void app_shutdown(NodeContext& node) {
    LogInfo("init", "Beginning shutdown sequence...");

    node.stop();

    // Remove cookie file
    Config::remove_cookie(node.datadir);

    LogInfo("init", "Shutdown complete");
}

} // namespace init

// ============================================================================
// Node class (backward-compatible implementation)
// ============================================================================

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
        std::filesystem::create_directories(config_.datadir + "/model");
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
        if (config_.rpc_user == "flowcoin" && file_config_.has("rpcuser")) {
            config_.rpc_user = file_config_.get("rpcuser");
        }
        if (config_.rpc_password == "flowcoin" && file_config_.has("rpcpassword")) {
            config_.rpc_password = file_config_.get("rpcpassword");
        }
        if (file_config_.has("port")) {
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

    loop_ = uv_default_loop();

    rpc_ = std::make_unique<RpcServer>(config_.rpc_port,
                                        config_.rpc_user,
                                        config_.rpc_password);

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

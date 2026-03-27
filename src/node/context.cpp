// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "node/context.h"
#include "logging.h"
#include "version.h"
#include "consensus/params.h"
#include "consensus/validation.h"

#include "chain/chainstate.h"
#include "chain/utxo.h"
#include "hash/keccak.h"
#include "wallet/wallet.h"
#include "net/net.h"
#include "rpc/server.h"
#include "mempool/mempool.h"
#include "net/sync.h"
#include "primitives/block.h"

#include <uv.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <direct.h>
#include <process.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace flow {

// Forward declarations for utility functions defined later in this file
static void log_system_info();
static bool validate_network_selection(bool testnet, bool regtest);
static void log_network_config(const NodeContext&);
static void log_datadir_inventory(const std::string& datadir);
static std::string format_bytes(uint64_t bytes);
static std::string format_duration(int64_t seconds);

// ============================================================================
// SubsystemState names
// ============================================================================

const char* subsystem_state_name(SubsystemState s) {
    switch (s) {
        case SubsystemState::UNINITIALIZED: return "UNINITIALIZED";
        case SubsystemState::INITIALIZING:  return "INITIALIZING";
        case SubsystemState::RUNNING:       return "RUNNING";
        case SubsystemState::STOPPING:      return "STOPPING";
        case SubsystemState::STOPPED:       return "STOPPED";
        case SubsystemState::FAILED:        return "FAILED";
    }
    return "UNKNOWN";
}

// ============================================================================
// Current time in microseconds
// ============================================================================

static int64_t now_us() {
    auto tp = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        tp.time_since_epoch()).count();
}

static int64_t now_unix() {
    return static_cast<int64_t>(std::time(nullptr));
}

// ============================================================================
// NodeContext construction / destruction
// ============================================================================

NodeContext::NodeContext()
    : start_time(now_unix()) {
}

NodeContext::~NodeContext() {
    // Ensure everything is cleaned up
    if (!shutdown_requested.load()) {
        interrupt();
    }
    stop();
    unlock_datadir();
    remove_pid_file();
}

// ============================================================================
// Pre-flight checks (run before subsystem initialization)
// ============================================================================

/// Verify that critical system resources are available.
static bool check_system_resources() {
#ifndef _WIN32
    // Check available file descriptors (POSIX only)
    struct rlimit rl;
    if (::getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        if (rl.rlim_cur < 256) {
            LogWarn("node", "Low file descriptor limit: %lu (recommend >= 1024)",
                    static_cast<unsigned long>(rl.rlim_cur));
            rl.rlim_cur = std::min(static_cast<rlim_t>(4096), rl.rlim_max);
            if (::setrlimit(RLIMIT_NOFILE, &rl) == 0) {
                LogInfo("node", "Raised file descriptor limit to %lu",
                        static_cast<unsigned long>(rl.rlim_cur));
            }
        } else {
            LogDebug("node", "File descriptor limit: %lu",
                     static_cast<unsigned long>(rl.rlim_cur));
        }
    }
#endif

    // Check available disk space (at least 1 GB recommended)
    // This is checked again later after the data directory is set up.

    // Check available memory (at least 512 MB recommended)
    std::ifstream meminfo("/proc/meminfo");
    if (meminfo.is_open()) {
        std::string line;
        while (std::getline(meminfo, line)) {
            if (line.compare(0, 13, "MemAvailable:") == 0) {
                std::istringstream iss(line.substr(13));
                int64_t kb;
                iss >> kb;
                int64_t mb = kb / 1024;
                if (mb < 512) {
                    LogWarn("node", "Low available memory: %lld MB (recommend >= 512 MB)",
                            static_cast<long long>(mb));
                } else {
                    LogDebug("node", "Available memory: %lld MB",
                             static_cast<long long>(mb));
                }
                break;
            }
        }
    }

    return true;
}

/// Verify libuv is working correctly.
static bool check_libuv() {
    uv_loop_t test_loop;
    int err = uv_loop_init(&test_loop);
    if (err != 0) {
        LogError("node", "libuv initialization failed: %s", uv_strerror(err));
        return false;
    }
    uv_loop_close(&test_loop);
    LogDebug("node", "libuv %s verified", uv_version_string());
    return true;
}

/// Verify filesystem permissions on the data directory.
static bool check_datadir_permissions(const std::string& datadir) {
    // Check the directory exists and is writable
    if (!std::filesystem::exists(datadir)) {
        // Will be created later — this is OK
        return true;
    }

    // Try creating a test file to verify write access
    std::string test_path = datadir + "/.write_test";
    {
        std::ofstream test(test_path);
        if (!test.is_open()) {
            LogError("node", "Data directory '%s' is not writable", datadir.c_str());
            return false;
        }
        test << "test\n";
    }
    std::filesystem::remove(test_path);
    LogDebug("node", "Data directory permissions OK: %s", datadir.c_str());
    return true;
}

/// Run all pre-flight checks. Returns false if a critical check fails.
static bool run_preflight_checks(const std::string& datadir) {
    LogInfo("node", "Running pre-flight checks...");

    if (!check_system_resources()) {
        LogError("node", "System resource check failed");
        return false;
    }

    if (!check_libuv()) {
        LogError("node", "libuv check failed");
        return false;
    }

    if (!check_datadir_permissions(datadir)) {
        return false;
    }

    LogInfo("node", "Pre-flight checks passed");
    return true;
}

// ============================================================================
// Network parameter accessors
// ============================================================================

uint32_t NodeContext::get_magic() const {
    if (regtest) return consensus::REGTEST_MAGIC;
    if (testnet) return consensus::TESTNET_MAGIC;
    return consensus::MAINNET_MAGIC;
}

uint16_t NodeContext::get_port() const {
    if (regtest) return consensus::REGTEST_PORT;
    if (testnet) return consensus::TESTNET_PORT;
    return consensus::MAINNET_PORT;
}

uint16_t NodeContext::get_rpc_port() const {
    if (regtest) return consensus::REGTEST_RPC_PORT;
    if (testnet) return consensus::TESTNET_RPC_PORT;
    return consensus::MAINNET_RPC_PORT;
}

const char* NodeContext::get_hrp() const {
    if (regtest) return consensus::REGTEST_HRP;
    if (testnet) return consensus::TESTNET_HRP;
    return consensus::MAINNET_HRP;
}

const char* NodeContext::get_network_name() const {
    if (regtest) return "regtest";
    if (testnet) return "testnet";
    return "mainnet";
}

std::string NodeContext::get_network_subdir() const {
    if (regtest) return "/regtest";
    if (testnet) return "/testnet";
    return "";
}

// ============================================================================
// Lifecycle: init
// ============================================================================

bool NodeContext::init() {
    LogInfo("node", "NodeContext::init() — preparing subsystems");

    // Log system diagnostics
    log_system_info();

    // Validate network selection
    if (!validate_network_selection(testnet, regtest)) {
        return false;
    }

    // Log network config
    log_network_config(*this);

    // Run pre-flight checks
    if (!run_preflight_checks(datadir)) {
        return false;
    }

    // Register all subsystems for tracking
    size_t idx_chain   = register_subsystem("chain");
    size_t idx_mempool = register_subsystem("mempool");
    size_t idx_wallet  = register_subsystem("wallet");
    size_t idx_net     = register_subsystem("net");
    size_t idx_sync    = register_subsystem("sync");
    size_t idx_rpc     = register_subsystem("rpc");

    // 1. Chain
    mark_init_start(idx_chain);
    set_subsystem_state(idx_chain, SubsystemState::INITIALIZING);
    try {
        chain = std::make_unique<ChainState>(datadir);
        if (!chain->init()) {
            LogError("node", "ChainState::init() failed");
            set_subsystem_state(idx_chain, SubsystemState::FAILED);
            return false;
        }
    } catch (const std::exception& e) {
        LogError("node", "ChainState exception: %s", e.what());
        set_subsystem_state(idx_chain, SubsystemState::FAILED);
        return false;
    }
    set_subsystem_state(idx_chain, SubsystemState::RUNNING);
    mark_init_end(idx_chain);
    LogInfo("node", "Chain initialized at height %lu",
            static_cast<unsigned long>(chain->height()));

    // 2. Mempool
    mark_init_start(idx_mempool);
    set_subsystem_state(idx_mempool, SubsystemState::INITIALIZING);
    try {
        mempool = std::make_unique<Mempool>(chain->utxo_set());
    } catch (const std::exception& e) {
        LogError("node", "Mempool creation failed: %s", e.what());
        set_subsystem_state(idx_mempool, SubsystemState::FAILED);
        return false;
    }
    set_subsystem_state(idx_mempool, SubsystemState::RUNNING);
    mark_init_end(idx_mempool);
    LogInfo("node", "Mempool initialized");

    // 3. PoW: no eval engine needed
    {
        constexpr int idx_eval = 2;
        (void)idx_eval;
    }

    // 4. Wallet
    mark_init_start(idx_wallet);
    set_subsystem_state(idx_wallet, SubsystemState::INITIALIZING);
    if (!config.get_bool("nowallet")) {
        try {
            wallet = std::make_unique<Wallet>(wallet_path(), chain->utxo_set());
            if (!wallet->init()) {
                LogError("node", "Wallet::init() failed");
                set_subsystem_state(idx_wallet, SubsystemState::FAILED);
                return false;
            }
            LogInfo("node", "Wallet initialized at %s", wallet_path().c_str());
        } catch (const std::exception& e) {
            LogError("node", "Wallet exception: %s", e.what());
            set_subsystem_state(idx_wallet, SubsystemState::FAILED);
            return false;
        }
    } else {
        LogInfo("node", "Wallet disabled (--nowallet)");
    }
    set_subsystem_state(idx_wallet, SubsystemState::RUNNING);
    mark_init_end(idx_wallet);

    // 5. Network
    mark_init_start(idx_net);
    set_subsystem_state(idx_net, SubsystemState::INITIALIZING);
    {
        uint16_t p2p_port = static_cast<uint16_t>(
            config.get_int("port", get_port()));
        net = std::make_unique<NetManager>(*chain, p2p_port, get_magic());
        net->set_data_dir(datadir);
    }
    set_subsystem_state(idx_net, SubsystemState::RUNNING);
    mark_init_end(idx_net);
    LogInfo("node", "Network manager created (port %u)",
            static_cast<unsigned>(config.get_int("port", get_port())));

    // 6. Sync manager — created but not started until start()
    mark_init_start(idx_sync);
    set_subsystem_state(idx_sync, SubsystemState::INITIALIZING);
    // SyncManager is constructed with chain + net references
    // It will be fully started in start()
    set_subsystem_state(idx_sync, SubsystemState::RUNNING);
    mark_init_end(idx_sync);

    // 7. RPC server
    mark_init_start(idx_rpc);
    set_subsystem_state(idx_rpc, SubsystemState::INITIALIZING);
    {
        uint16_t rpc_port = static_cast<uint16_t>(
            config.get_int("rpcport", get_rpc_port()));
        std::string rpc_user = config.get("rpcuser", "flowcoin");
        std::string rpc_pass = config.get("rpcpassword", "flowcoin");

        rpc = std::make_unique<RpcServer>(rpc_port, rpc_user, rpc_pass);
    }
    set_subsystem_state(idx_rpc, SubsystemState::RUNNING);
    mark_init_end(idx_rpc);
    LogInfo("node", "RPC server created (port %u)",
            static_cast<unsigned>(config.get_int("rpcport", get_rpc_port())));

    log_init_timings();

    // Log data directory inventory
    log_datadir_inventory(datadir);

    // Initialize performance counters
    perf.reset();

    LogInfo("node", "All subsystems initialized");
    return true;
}

// ============================================================================
// Lifecycle: start
// ============================================================================

bool NodeContext::start() {
    LogInfo("node", "Starting services...");
    int64_t start_begin = now_us();

    // ---- Start P2P networking ----
    if (net) {
        LogInfo("node", "Starting P2P network layer...");
        int64_t t0 = now_us();

        // Configure addnodes from config
        auto addnodes = config.get_multi("addnode");
        if (!addnodes.empty()) {
            LogInfo("node", "  %zu addnode entries configured", addnodes.size());
            for (const auto& addr : addnodes) {
                LogDebug("node", "  addnode: %s", addr.c_str());
            }
        }

        // Configure connect-only from config
        auto connect_only = config.get_multi("connect");
        if (!connect_only.empty()) {
            LogInfo("node", "  %zu connect-only entries (no other outbound)",
                    connect_only.size());
        }

        // Check if listening is enabled
        bool should_listen = config.get_bool("listen", true);
        if (!should_listen) {
            LogInfo("node", "  Listening disabled (--nolisten)");
        }

        // Check if discovery is enabled
        bool should_discover = config.get_bool("discover", true);
        if (!should_discover) {
            LogInfo("node", "  Peer discovery disabled (--nodiscover)");
        }

        // Check if DNS seeding is enabled
        bool should_dns_seed = config.get_bool("dnsseed", true);
        if (!should_dns_seed) {
            LogInfo("node", "  DNS seeding disabled (--nodnsseed)");
        }

        if (!net->start()) {
            LogError("node", "Failed to start P2P network");
            return false;
        }

        int64_t t1 = now_us();
        LogInfo("node", "P2P network started (%.1f ms)",
                static_cast<double>(t1 - t0) / 1000.0);
    } else {
        LogWarn("node", "No network manager — node is offline");
    }

    // ---- Start RPC server ----
    if (rpc) {
        LogInfo("node", "Starting RPC server...");
        int64_t t0 = now_us();

        loop = uv_default_loop();
        if (!loop) {
            LogError("node", "Failed to get default libuv event loop");
            return false;
        }

        if (!rpc->start(loop)) {
            LogError("node", "Failed to start RPC server");
            return false;
        }

        int64_t t1 = now_us();
        LogInfo("node", "RPC server started on port %u (%.1f ms)",
                static_cast<unsigned>(config.get_int("rpcport", get_rpc_port())),
                static_cast<double>(t1 - t0) / 1000.0);
    } else {
        LogInfo("node", "RPC server disabled");
    }

    // ---- Determine IBD status ----
    if (chain) {
        uint64_t height = chain->height();
        // Check if we're far behind the expected tip
        is_ibd.store(height < consensus::IBD_MIN_BLOCKS_BEHIND);
        if (is_ibd.load()) {
            LogInfo("node", "Initial Block Download mode active (height=%lu, need >=%lu)",
                    static_cast<unsigned long>(height),
                    static_cast<unsigned long>(consensus::IBD_MIN_BLOCKS_BEHIND));
        }
    }

    // ---- Register wallet for tip notifications ----
    if (wallet && chain) {
        on_tip_changed([this](uint64_t height, const uint8_t* /*hash*/) {
            // Notify wallet of new block for balance updates
            LogDebug("node", "Tip changed to height %lu — wallet notified",
                     static_cast<unsigned long>(height));
        });
        LogDebug("node", "Wallet registered for tip notifications");
    }

    // ---- Startup complete ----
    int64_t start_end = now_us();
    double total_ms = static_cast<double>(start_end - start_begin) / 1000.0;

    LogInfo("node", "=== %s v%s started ===", CLIENT_NAME, CLIENT_VERSION_STRING);
    LogInfo("node", "  Network:       %s", get_network_name());
    LogInfo("node", "  Chain height:  %lu", static_cast<unsigned long>(chain_height()));
    LogInfo("node", "  Peers:         %lu", static_cast<unsigned long>(peer_count()));
    LogInfo("node", "  IBD:           %s", is_ibd.load() ? "yes" : "no");
    LogInfo("node", "  Start time:    %.1f ms", total_ms);

    return true;
}

// ============================================================================
// Lifecycle: interrupt
// ============================================================================

void NodeContext::interrupt() {
    bool expected = false;
    if (shutdown_requested.compare_exchange_strong(expected, true)) {
        LogInfo("node", "Shutdown requested");
        get_shutdown_state().request_shutdown();

        // Stop the main libuv event loop (RPC) so main thread unblocks
        // net->stop() is called later from main thread in flowcoind.cpp
        if (loop) {
            uv_stop(loop);
        }
    }
}

// ============================================================================
// Lifecycle: stop
// ============================================================================

void NodeContext::stop() {
    LogInfo("node", "Stopping all subsystems (reverse init order)...");

    int64_t stop_begin = now_us();

    // Assign stop indices (same order as init registration)
    // We stop in reverse order for clean dependency teardown.

    // --- 7. RPC Server ---
    // Must stop first so no new requests arrive during teardown.
    if (rpc) {
        LogInfo("node", "[7/7] Stopping RPC server...");
        int64_t t0 = now_us();
        rpc->stop();
        int64_t t1 = now_us();
        LogInfo("node", "RPC server stopped (%.1f ms)",
                static_cast<double>(t1 - t0) / 1000.0);
    }

    // --- 6. Sync Manager ---
    // Stop sync before net so no new block/header requests are made.
    // SyncManager is managed as part of the net module, no separate stop needed.
    LogDebug("node", "[6/7] Sync manager stopped (embedded in net)");

    // --- 5. Network ---
    // Close all peer connections, stop listening.
    if (net) {
        LogInfo("node", "[5/7] Stopping P2P network...");
        int64_t t0 = now_us();
        net->stop();
        int64_t t1 = now_us();
        LogInfo("node", "P2P network stopped (%.1f ms, %lu peers disconnected)",
                static_cast<double>(t1 - t0) / 1000.0,
                static_cast<unsigned long>(perf.bytes_sent.load() > 0 ? peer_count() : 0));
    }

    // --- 4. Wallet ---
    // Flush wallet DB to ensure all pending writes are persisted.
    if (wallet) {
        LogInfo("node", "[4/7] Flushing wallet...");
        int64_t t0 = now_us();
        // Wallet destructor handles DB flush, but we log it explicitly
        // to track timing. The unique_ptr will be released when NodeContext
        // is destroyed.
        int64_t t1 = now_us();
        LogInfo("node", "Wallet flushed (%.1f ms)",
                static_cast<double>(t1 - t0) / 1000.0);
    }

    // --- 2. Mempool ---
    // The mempool is purely in-memory; no persistence needed.
    // Transactions will need to be re-relayed after restart.
    if (mempool) {
        size_t pool_size = mempool->size();
        size_t pool_bytes = mempool->bytes();
        LogInfo("node", "[2/7] Mempool cleared (%lu txs, %s discarded)",
                static_cast<unsigned long>(pool_size),
                format_bytes(pool_bytes).c_str());
    }

    // --- 1. Chain ---
    // Chain state is persisted via SQLite (WAL mode); the RAII destructor
    // will close the database and flush any pending WAL pages.
    if (chain) {
        LogInfo("node", "[1/7] Closing chain state...");
        int64_t t0 = now_us();
        // ChainState destructor handles DB close
        int64_t t1 = now_us();
        LogInfo("node", "Chain state closed (%.1f ms)",
                static_cast<double>(t1 - t0) / 1000.0);
    }

    // Clean up lock and PID files
    unlock_datadir();
    remove_pid_file();

    // Remove cookie file
    Config::remove_cookie(datadir);

    int64_t stop_end = now_us();
    double total_ms = static_cast<double>(stop_end - stop_begin) / 1000.0;

    // Log final performance stats
    LogInfo("node", "=== Final Performance Summary ===");
    LogInfo("node", "  Uptime:            %s", format_duration(uptime()).c_str());
    LogInfo("node", "  Blocks validated:  %lu",
            static_cast<unsigned long>(perf.blocks_validated.load()));
    LogInfo("node", "  Txs validated:     %lu",
            static_cast<unsigned long>(perf.txs_validated.load()));
    LogInfo("node", "  RPC requests:      %lu",
            static_cast<unsigned long>(perf.rpc_requests.load()));
    LogInfo("node", "  Bytes sent:        %s",
            format_bytes(perf.bytes_sent.load()).c_str());
    LogInfo("node", "  Bytes received:    %s",
            format_bytes(perf.bytes_recv.load()).c_str());
    LogInfo("node", "  Shutdown duration: %.1f ms", total_ms);

    // Log stats
    auto lstats = log_get_stats();
    LogInfo("node", "=== Log Summary ===");
    LogInfo("node", "  Total entries: %lu", static_cast<unsigned long>(log_get_total_entries()));
    LogInfo("node", "  Warnings:      %lu", static_cast<unsigned long>(lstats.warn_count));
    LogInfo("node", "  Errors:        %lu", static_cast<unsigned long>(lstats.error_count));

    LogInfo("node", "All subsystems stopped. Goodbye.");

    // Flush and close the log file as the very last step
    log_flush();
}

// ============================================================================
// Status queries
// ============================================================================

int64_t NodeContext::uptime() const {
    return now_unix() - start_time;
}

bool NodeContext::is_synced() const {
    return !is_ibd.load();
}

uint64_t NodeContext::chain_height() const {
    if (chain) return chain->height();
    return 0;
}

size_t NodeContext::peer_count() const {
    if (net) return net->peer_count();
    return 0;
}

size_t NodeContext::mempool_size() const {
    if (mempool) return mempool->size();
    return 0;
}

size_t NodeContext::mempool_bytes() const {
    if (mempool) return mempool->bytes();
    return 0;
}

std::string NodeContext::status_summary() const {
    std::ostringstream ss;
    ss << CLIENT_NAME << " v" << CLIENT_VERSION_STRING
       << " (" << get_network_name() << ")\n"
       << "  Uptime:      " << uptime() << "s\n"
       << "  Height:      " << chain_height() << "\n"
       << "  Peers:       " << peer_count() << "\n"
       << "  Mempool:     " << mempool_size() << " txs ("
       << mempool_bytes() / 1024 << " KB)\n"
       << "  IBD:         " << (is_ibd.load() ? "yes" : "no") << "\n"
       << "  Shutdown:    " << (shutdown_requested.load() ? "requested" : "no") << "\n";
    return ss.str();
}

// ============================================================================
// Subsystem tracking
// ============================================================================

size_t NodeContext::register_subsystem(const std::string& name) {
    std::lock_guard<std::mutex> lock(subsystems_mutex);
    SubsystemEntry entry;
    entry.name = name;
    subsystems.push_back(entry);
    return subsystems.size() - 1;
}

void NodeContext::set_subsystem_state(size_t index, SubsystemState state) {
    std::lock_guard<std::mutex> lock(subsystems_mutex);
    if (index < subsystems.size()) {
        subsystems[index].state = state;
    }
}

void NodeContext::mark_init_start(size_t index) {
    std::lock_guard<std::mutex> lock(subsystems_mutex);
    if (index < subsystems.size()) {
        subsystems[index].init_start_us = now_us();
    }
}

void NodeContext::mark_init_end(size_t index) {
    std::lock_guard<std::mutex> lock(subsystems_mutex);
    if (index < subsystems.size()) {
        subsystems[index].init_end_us = now_us();
    }
}

void NodeContext::mark_stop_start(size_t index) {
    std::lock_guard<std::mutex> lock(subsystems_mutex);
    if (index < subsystems.size()) {
        subsystems[index].stop_start_us = now_us();
    }
}

void NodeContext::mark_stop_end(size_t index) {
    std::lock_guard<std::mutex> lock(subsystems_mutex);
    if (index < subsystems.size()) {
        subsystems[index].stop_end_us = now_us();
    }
}

void NodeContext::log_init_timings() const {
    std::lock_guard<std::mutex> lock(subsystems_mutex);
    LogInfo("node", "=== Subsystem initialization timings ===");
    double total_ms = 0.0;
    for (const auto& entry : subsystems) {
        double ms = entry.init_duration_ms();
        total_ms += ms;
        LogInfo("node", "  %-16s %8.2f ms  [%s]",
                entry.name.c_str(), ms,
                subsystem_state_name(entry.state));
    }
    LogInfo("node", "  %-16s %8.2f ms", "TOTAL", total_ms);
}

void NodeContext::log_stop_timings() const {
    std::lock_guard<std::mutex> lock(subsystems_mutex);
    LogInfo("node", "=== Subsystem shutdown timings ===");
    double total_ms = 0.0;
    for (const auto& entry : subsystems) {
        double ms = entry.stop_duration_ms();
        if (ms > 0.0) {
            total_ms += ms;
            LogInfo("node", "  %-16s %8.2f ms", entry.name.c_str(), ms);
        }
    }
    LogInfo("node", "  %-16s %8.2f ms", "TOTAL", total_ms);
}

// ============================================================================
// Lock file management
// ============================================================================

bool NodeContext::lock_datadir() {
    lock_file_path = datadir_path(".lock");

#ifdef _WIN32
    lockfile_handle = CreateFileA(lock_file_path.c_str(), GENERIC_READ | GENERIC_WRITE,
                                   0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (lockfile_handle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_SHARING_VIOLATION) {
            LogError("node", "Cannot obtain lock on data directory '%s'. "
                     "FlowCoin is probably already running.",
                     datadir.c_str());
        } else {
            LogError("node", "Lock file error: %lu", err);
        }
        return false;
    }

    // Write our PID to the lock file
    char pid_buf[32];
    int len = std::snprintf(pid_buf, sizeof(pid_buf), "%d\n", static_cast<int>(_getpid()));
    if (len > 0) {
        DWORD written;
        WriteFile(lockfile_handle, pid_buf, static_cast<DWORD>(len), &written, nullptr);
    }
    return true;
}
#else
    lockfile_fd = ::open(lock_file_path.c_str(),
                         O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (lockfile_fd < 0) {
        LogError("node", "Cannot open lock file '%s': %s",
                 lock_file_path.c_str(), strerror(errno));
        return false;
    }

    // Try to get an exclusive non-blocking lock
    if (::flock(lockfile_fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK) {
            LogError("node", "Cannot obtain lock on data directory '%s'. "
                     "FlowCoin is probably already running.",
                     datadir.c_str());
        } else {
            LogError("node", "Lock file error: %s", strerror(errno));
        }
        ::close(lockfile_fd);
        lockfile_fd = -1;
        return false;
    }

    // Write our PID to the lock file
    char pid_buf[32];
    int len = std::snprintf(pid_buf, sizeof(pid_buf), "%d\n", getpid());
    if (len > 0) {
        // Ignore write errors — the lock itself is what matters
        if (::write(lockfile_fd, pid_buf, static_cast<size_t>(len)) < 0) {}
    }

    LogInfo("node", "Data directory locked: %s", lock_file_path.c_str());
    return true;
#endif // !_WIN32
}

void NodeContext::unlock_datadir() {
#ifdef _WIN32
    if (lockfile_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(lockfile_handle);
        lockfile_handle = INVALID_HANDLE_VALUE;

        // Remove the lock file
        if (!lock_file_path.empty()) {
            DeleteFileA(lock_file_path.c_str());
            lock_file_path.clear();
        }
    }
#else
    if (lockfile_fd >= 0) {
        ::flock(lockfile_fd, LOCK_UN);
        ::close(lockfile_fd);
        lockfile_fd = -1;

        // Remove the lock file
        if (!lock_file_path.empty()) {
            ::unlink(lock_file_path.c_str());
            lock_file_path.clear();
        }
    }
#endif
}

// ============================================================================
// PID file management
// ============================================================================

bool NodeContext::write_pid_file() {
    pid_file_path = datadir_path("flowcoind.pid");

    std::ofstream f(pid_file_path);
    if (!f.is_open()) {
        LogError("node", "Cannot write PID file '%s': %s",
                 pid_file_path.c_str(), strerror(errno));
        return false;
    }
#ifdef _WIN32
    int current_pid = static_cast<int>(_getpid());
#else
    int current_pid = static_cast<int>(getpid());
#endif
    f << current_pid << "\n";
    f.close();

    LogInfo("node", "PID file written: %s (pid=%d)", pid_file_path.c_str(), current_pid);
    return true;
}

void NodeContext::remove_pid_file() {
    if (!pid_file_path.empty()) {
        std::remove(pid_file_path.c_str());
        pid_file_path.clear();
    }
}

// ============================================================================
// Data directory helpers
// ============================================================================

bool NodeContext::ensure_datadir() {
    try {
        std::filesystem::create_directories(datadir);
        std::filesystem::create_directories(blocks_dir());
        return true;
    } catch (const std::filesystem::filesystem_error& e) {
        LogError("node", "Failed to create data directory '%s': %s",
                 datadir.c_str(), e.what());
        return false;
    }
}

std::string NodeContext::datadir_path(const std::string& filename) const {
    if (datadir.empty()) return filename;
    if (datadir.back() == '/') return datadir + filename;
    return datadir + "/" + filename;
}

std::string NodeContext::blocks_dir() const {
    return datadir_path("blocks");
}

std::string NodeContext::wallet_path() const {
    std::string custom = config.get("walletfile");
    if (!custom.empty()) return custom;
    return datadir_path("wallet.dat");
}

std::string NodeContext::log_path() const {
    std::string custom = config.get("logfile");
    if (!custom.empty()) return custom;
    return datadir_path("debug.log");
}

std::string NodeContext::config_path() const {
    return datadir_path("flowcoin.conf");
}

std::string NodeContext::cookie_path() const {
    return datadir_path(".cookie");
}

// ============================================================================
// Network parameter validation helpers
// ============================================================================

/// Validate that network selection (testnet/regtest/mainnet) is consistent.
static bool validate_network_selection(bool testnet, bool regtest) {
    if (testnet && regtest) {
        LogError("node", "Cannot use both testnet and regtest simultaneously");
        return false;
    }
    return true;
}

/// Log the full network configuration for diagnostics.
static void log_network_config(const NodeContext& ctx) {
    LogInfo("node", "Network configuration:");
    LogInfo("node", "  Network:     %s", ctx.get_network_name());
    LogInfo("node", "  Magic:       0x%08x", ctx.get_magic());
    LogInfo("node", "  P2P port:    %u", ctx.get_port());
    LogInfo("node", "  RPC port:    %u", ctx.get_rpc_port());
    LogInfo("node", "  HRP:         %s", ctx.get_hrp());
    LogInfo("node", "  Data dir:    %s", ctx.datadir.c_str());
}

// ============================================================================
// Startup diagnostics
// ============================================================================

/// Log system information at startup for debugging.
static void log_system_info() {
    // CPU cores
    unsigned int cores = std::thread::hardware_concurrency();
    LogInfo("node", "System: %u CPU cores", cores);

    // Available memory
    std::ifstream meminfo("/proc/meminfo");
    if (meminfo.is_open()) {
        std::string line;
        while (std::getline(meminfo, line)) {
            if (line.compare(0, 9, "MemTotal:") == 0) {
                std::istringstream iss(line.substr(9));
                int64_t kb;
                iss >> kb;
                LogInfo("node", "System: %lld MB total memory",
                        static_cast<long long>(kb / 1024));
                break;
            }
        }
    }

    // Kernel version
    std::ifstream osrel("/proc/version");
    if (osrel.is_open()) {
        std::string version;
        std::getline(osrel, version);
        if (version.size() > 120) version = version.substr(0, 120) + "...";
        LogInfo("node", "System: %s", version.c_str());
    }

    // Current working directory
    char cwd[PATH_MAX];
    if (::getcwd(cwd, sizeof(cwd)) != nullptr) {
        LogInfo("node", "Working directory: %s", cwd);
    }
}

// ============================================================================
// Data directory inventory
// ============================================================================

/// Log the sizes of key files in the data directory.
static void log_datadir_inventory(const std::string& datadir) {
    LogInfo("node", "Data directory inventory:");

    struct FileEntry {
        const char* name;
        std::string path;
    };

    std::vector<FileEntry> files = {
        {"wallet.dat",    datadir + "/wallet.dat"},
        {"flowcoin.conf", datadir + "/flowcoin.conf"},
        {"debug.log",     datadir + "/debug.log"},
        {".cookie",       datadir + "/.cookie"},
        {".lock",         datadir + "/.lock"},
        {"flowcoind.pid", datadir + "/flowcoind.pid"},
    };

    for (const auto& f : files) {
        try {
            if (std::filesystem::exists(f.path)) {
                auto sz = std::filesystem::file_size(f.path);
                if (sz < 1024) {
                    LogInfo("node", "  %-20s %lu B", f.name,
                            static_cast<unsigned long>(sz));
                } else if (sz < 1024 * 1024) {
                    LogInfo("node", "  %-20s %.1f KB", f.name,
                            static_cast<double>(sz) / 1024.0);
                } else {
                    LogInfo("node", "  %-20s %.1f MB", f.name,
                            static_cast<double>(sz) / (1024.0 * 1024.0));
                }
            }
        } catch (...) {
            // Ignore errors when checking file sizes
        }
    }

    // Count block files
    std::string blocks_dir = datadir + "/blocks";
    if (std::filesystem::exists(blocks_dir)) {
        int count = 0;
        uint64_t total_size = 0;
        try {
            for (const auto& entry : std::filesystem::directory_iterator(blocks_dir)) {
                if (entry.is_regular_file()) {
                    ++count;
                    total_size += entry.file_size();
                }
            }
        } catch (...) {}
        LogInfo("node", "  blocks/            %d files, %.1f MB total",
                count, static_cast<double>(total_size) / (1024.0 * 1024.0));
    }

}

// ============================================================================
// Time formatting helpers
// ============================================================================

/// Format a duration in seconds to a human-readable string.
static std::string format_duration(int64_t seconds) {
    if (seconds < 60) {
        return std::to_string(seconds) + "s";
    }
    if (seconds < 3600) {
        return std::to_string(seconds / 60) + "m " +
               std::to_string(seconds % 60) + "s";
    }
    if (seconds < 86400) {
        int64_t h = seconds / 3600;
        int64_t m = (seconds % 3600) / 60;
        return std::to_string(h) + "h " + std::to_string(m) + "m";
    }
    int64_t d = seconds / 86400;
    int64_t h = (seconds % 86400) / 3600;
    return std::to_string(d) + "d " + std::to_string(h) + "h";
}

/// Format a byte count to a human-readable string.
static std::string format_bytes(uint64_t bytes) {
    if (bytes < 1024) {
        return std::to_string(bytes) + " B";
    }
    if (bytes < 1024 * 1024) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.1f KB", static_cast<double>(bytes) / 1024.0);
        return buf;
    }
    if (bytes < 1024ULL * 1024 * 1024) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.1f MB",
                      static_cast<double>(bytes) / (1024.0 * 1024.0));
        return buf;
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.2f GB",
                  static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
    return buf;
}

// ============================================================================
// Extended status summary with formatting
// ============================================================================

std::string NodeContext::extended_status() const {
    auto health = check_health();
    std::ostringstream ss;

    ss << "=== " << CLIENT_NAME << " v" << CLIENT_VERSION_STRING
       << " Status ===\n\n";

    ss << "Network:       " << get_network_name() << "\n";
    ss << "Uptime:        " << format_duration(uptime()) << "\n";
    ss << "Chain height:  " << chain_height() << "\n";
    ss << "Peers:         " << peer_count() << "\n";
    ss << "Mempool:       " << mempool_size() << " txs ("
       << format_bytes(mempool_bytes()) << ")\n";
    ss << "IBD:           " << (is_ibd.load() ? "yes" : "no") << "\n";
    ss << "Disk free:     " << health.disk_free_mb << " MB\n";
    ss << "Memory (RSS):  " << health.rss_mb << " MB\n\n";

    ss << "Subsystems:\n";
    ss << "  Chain:       " << (health.chain_ok ? "OK" : "FAILED") << "\n";
    ss << "  Wallet:      " << (health.wallet_ok ? "OK" : "disabled") << "\n";
    ss << "  Network:     " << (health.net_ok ? "OK" : "FAILED") << "\n";
    ss << "  RPC:         " << (health.rpc_ok ? "OK" : "disabled") << "\n";
    ss << "  Mempool:     " << (health.mempool_ok ? "OK" : "FAILED") << "\n";
    ss << "  Disk space:  " << (health.disk_space_ok ? "OK" : "LOW") << "\n";

    return ss.str();
}

// ============================================================================
// Chain tip notification
// ============================================================================

size_t NodeContext::on_tip_changed(TipChangedCallback callback) {
    std::lock_guard<std::mutex> lock(tip_cb_mutex_);
    size_t id = next_tip_cb_id_++;
    tip_callbacks_.emplace_back(id, std::move(callback));
    return id;
}

void NodeContext::remove_tip_callback(size_t id) {
    std::lock_guard<std::mutex> lock(tip_cb_mutex_);
    tip_callbacks_.erase(
        std::remove_if(tip_callbacks_.begin(), tip_callbacks_.end(),
                       [id](const auto& p) { return p.first == id; }),
        tip_callbacks_.end());
}

void NodeContext::notify_tip_changed(uint64_t height, const uint8_t* block_hash) {
    std::lock_guard<std::mutex> lock(tip_cb_mutex_);
    for (const auto& [id, cb] : tip_callbacks_) {
        try {
            cb(height, block_hash);
        } catch (const std::exception& e) {
            LogWarn("node", "Tip callback %zu threw: %s", id, e.what());
        }
    }
}

// ============================================================================
// Health monitoring
// ============================================================================

NodeContext::HealthStatus NodeContext::check_health() const {
    HealthStatus status;

    // Chain health
    if (chain) {
        status.chain_ok = true;
        status.chain_height = static_cast<int64_t>(chain->height());
    }

    // Wallet health
    if (wallet) {
        status.wallet_ok = true;
    }

    // Network health
    if (net) {
        status.net_ok = true;
        status.peer_count = static_cast<int64_t>(net->peer_count());
    }

    // RPC health
    if (rpc) {
        status.rpc_ok = true;
    }

    // Mempool health
    if (mempool) {
        status.mempool_ok = true;
        status.mempool_txs = static_cast<int64_t>(mempool->size());
    }

    // PoW: no eval engine

    // Disk space
    status.disk_free_mb = get_disk_free_mb();
    status.disk_space_ok = status.disk_free_mb > 100;  // Warn below 100 MB

    // Memory usage
    status.rss_mb = get_rss_mb();

    return status;
}

int64_t NodeContext::get_rss_mb() {
    // Read from /proc/self/status on Linux
    std::ifstream status_file("/proc/self/status");
    if (!status_file.is_open()) return 0;

    std::string line;
    while (std::getline(status_file, line)) {
        if (line.compare(0, 6, "VmRSS:") == 0) {
            std::istringstream iss(line.substr(6));
            int64_t kb;
            iss >> kb;
            return kb / 1024;
        }
    }
    return 0;
}

int64_t NodeContext::get_disk_free_mb() const {
    if (datadir.empty()) return 0;

    try {
        auto info = std::filesystem::space(datadir);
        return static_cast<int64_t>(info.available / (1024 * 1024));
    } catch (...) {
        return -1;
    }
}

// ============================================================================
// Performance counters
// ============================================================================

void NodeContext::PerfCounters::reset() {
    blocks_validated.store(0);
    txs_validated.store(0);
    blocks_downloaded.store(0);
    bytes_sent.store(0);
    bytes_recv.store(0);
    rpc_requests.store(0);
    rpc_errors.store(0);
    start_time = static_cast<int64_t>(std::time(nullptr));
}

double NodeContext::PerfCounters::blocks_per_second() const {
    int64_t elapsed = static_cast<int64_t>(std::time(nullptr)) - start_time;
    if (elapsed <= 0) return 0.0;
    return static_cast<double>(blocks_validated.load()) / static_cast<double>(elapsed);
}

double NodeContext::PerfCounters::txs_per_second() const {
    int64_t elapsed = static_cast<int64_t>(std::time(nullptr)) - start_time;
    if (elapsed <= 0) return 0.0;
    return static_cast<double>(txs_validated.load()) / static_cast<double>(elapsed);
}

double NodeContext::PerfCounters::rpc_per_second() const {
    int64_t elapsed = static_cast<int64_t>(std::time(nullptr)) - start_time;
    if (elapsed <= 0) return 0.0;
    return static_cast<double>(rpc_requests.load()) / static_cast<double>(elapsed);
}

std::string NodeContext::perf_report() const {
    std::ostringstream ss;
    ss << "=== Performance Report ===\n"
       << "  Uptime:            " << uptime() << "s\n"
       << "  Blocks validated:  " << perf.blocks_validated.load()
       << " (" << std::fixed << std::setprecision(2)
       << perf.blocks_per_second() << "/s)\n"
       << "  Txs validated:     " << perf.txs_validated.load()
       << " (" << perf.txs_per_second() << "/s)\n"
       << "  Blocks downloaded: " << perf.blocks_downloaded.load() << "\n"
       << "  Bytes sent:        " << perf.bytes_sent.load() / 1024 << " KB\n"
       << "  Bytes received:    " << perf.bytes_recv.load() / 1024 << " KB\n"
       << "  RPC requests:      " << perf.rpc_requests.load()
       << " (" << perf.rpc_per_second() << "/s)\n"
       << "  RPC errors:        " << perf.rpc_errors.load() << "\n"
       << "  RSS:               " << get_rss_mb() << " MB\n"
       << "  Disk free:         " << get_disk_free_mb() << " MB\n";
    return ss.str();
}

// ============================================================================
// Periodic maintenance (called by a timer in the main loop)
// ============================================================================

void NodeContext::periodic_maintenance() {
    // This method is called every ~60 seconds from the event loop.
    // It performs housekeeping tasks:

    // 1. Check disk space
    int64_t free_mb = get_disk_free_mb();
    if (free_mb >= 0 && free_mb < 100) {
        LogWarn("node", "Low disk space: %lld MB remaining in %s",
                static_cast<long long>(free_mb), datadir.c_str());
    }
    if (free_mb >= 0 && free_mb < 10) {
        LogError("node", "Critically low disk space (%lld MB) — "
                 "consider pruning or freeing space", static_cast<long long>(free_mb));
    }

    // 2. Log periodic status
    LogInfo("node", "Status: height=%lu peers=%lu mempool=%lu txs uptime=%s rss=%lld MB",
            static_cast<unsigned long>(chain_height()),
            static_cast<unsigned long>(peer_count()),
            static_cast<unsigned long>(mempool_size()),
            format_duration(uptime()).c_str(),
            static_cast<long long>(get_rss_mb()));

    // 3. Log rotate if needed
    log_rotate();
}

// ============================================================================
// Debug info dump (for RPC getdebuginfo)
// ============================================================================

std::string NodeContext::dump_debug_info() const {
    std::ostringstream ss;

    ss << "=== FlowCoin Debug Info ===\n\n";
    ss << "Version: " << CLIENT_NAME << " v" << CLIENT_VERSION_STRING << "\n";
    ss << "PID: " << ::getpid() << "\n";
    ss << "Network: " << get_network_name() << "\n";
    ss << "Data dir: " << datadir << "\n";
    ss << "Uptime: " << format_duration(uptime()) << "\n";
    ss << "Start time: " << start_time << "\n";
    ss << "Shutdown requested: " << (shutdown_requested.load() ? "yes" : "no") << "\n\n";

    // Subsystem states
    {
        std::lock_guard<std::mutex> lock(subsystems_mutex);
        ss << "Subsystems (" << subsystems.size() << "):\n";
        for (const auto& entry : subsystems) {
            ss << "  " << entry.name << ": "
               << subsystem_state_name(entry.state)
               << " (init: " << entry.init_duration_ms() << " ms)\n";
        }
    }
    ss << "\n";

    // Chain info
    ss << "Chain:\n";
    ss << "  Height: " << chain_height() << "\n";
    ss << "  IBD: " << (is_ibd.load() ? "yes" : "no") << "\n";
    ss << "\n";

    // Network info
    ss << "Network:\n";
    ss << "  Peers: " << peer_count() << "\n";
    ss << "  Magic: 0x" << std::hex << get_magic() << std::dec << "\n";
    ss << "  P2P port: " << get_port() << "\n";
    ss << "  RPC port: " << get_rpc_port() << "\n";
    ss << "\n";

    // Mempool info
    ss << "Mempool:\n";
    ss << "  Transactions: " << mempool_size() << "\n";
    ss << "  Size: " << format_bytes(mempool_bytes()) << "\n";
    ss << "\n";

    // Performance
    ss << perf_report() << "\n";

    // Health
    auto health = check_health();
    ss << "Health:\n";
    ss << "  Chain: " << (health.chain_ok ? "OK" : "FAIL") << "\n";
    ss << "  Wallet: " << (health.wallet_ok ? "OK" : "disabled") << "\n";
    ss << "  Network: " << (health.net_ok ? "OK" : "FAIL") << "\n";
    ss << "  RPC: " << (health.rpc_ok ? "OK" : "disabled") << "\n";
    ss << "  Mempool: " << (health.mempool_ok ? "OK" : "FAIL") << "\n";

    ss << "  Disk: " << health.disk_free_mb << " MB free"
       << (health.disk_space_ok ? "" : " (LOW)") << "\n";
    ss << "  RSS: " << health.rss_mb << " MB\n";
    ss << "\n";

    // Log stats
    auto lstats = log_get_stats();
    ss << "Log stats:\n";
    ss << "  Total entries: " << log_get_total_entries() << "\n";
    ss << "  TRACE: " << lstats.trace_count << "\n";
    ss << "  DEBUG: " << lstats.debug_count << "\n";
    ss << "  INFO:  " << lstats.info_count << "\n";
    ss << "  WARN:  " << lstats.warn_count << "\n";
    ss << "  ERROR: " << lstats.error_count << "\n";
    ss << "  FATAL: " << lstats.fatal_count << "\n";

    return ss.str();
}

// ============================================================================
// Ban score tracking
// ============================================================================

void NodeContext::add_ban_score(uint64_t peer_id, int score,
                                 const std::string& reason) {
    LogDebug("node", "Ban score +%d for peer %lu: %s",
             score, static_cast<unsigned long>(peer_id), reason.c_str());
    // The actual ban logic is delegated to the net module's BanManager.
    // This method provides a unified entry point for all subsystems
    // that might need to penalize peers (validation, sync, etc.)
}

// ============================================================================
// ShutdownState singleton
// ============================================================================

void ShutdownState::request_shutdown() {
    requested_.store(true, std::memory_order_release);
}

bool ShutdownState::is_shutdown_requested() const {
    return requested_.load(std::memory_order_acquire);
}

void ShutdownState::wait_for_shutdown() {
    // Busy-wait with sleep to avoid spinning
    while (!requested_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void ShutdownState::reset() {
    requested_.store(false, std::memory_order_release);
}

ShutdownState& get_shutdown_state() {
    static ShutdownState instance;
    return instance;
}

// ============================================================================
// NodeHealth — comprehensive health status
// ============================================================================

// NodeHealth is NodeContext::NodeHealthInfo (defined in context.h)
using NodeHealth = NodeContext::NodeHealthInfo;

NodeContext::NodeHealthInfo NodeContext::get_node_health() const {
    NodeHealthInfo health;

    // Memory stats
    health.rss_bytes = static_cast<size_t>(get_rss_mb()) * 1024 * 1024;
    health.peak_rss_bytes = 0;
    health.utxo_cache_bytes = 0;
    health.mempool_bytes = 0;
    // Read peak RSS from /proc/self/status
    {
        std::ifstream status_file("/proc/self/status");
        if (status_file.is_open()) {
            std::string line;
            while (std::getline(status_file, line)) {
                if (line.compare(0, 11, "VmHWM:") == 0) {
                    // VmHWM is peak RSS
                    std::string trimmed = line.substr(6);
                    // Skip whitespace
                    size_t start = trimmed.find_first_not_of(" \t");
                    if (start != std::string::npos) {
                        std::istringstream iss(trimmed.substr(start));
                        int64_t kb;
                        iss >> kb;
                        health.peak_rss_bytes = static_cast<size_t>(kb) * 1024;
                    }
                }
            }
        }
    }

    // UTXO cache and mempool memory
    if (chain) {
        health.utxo_cache_bytes = chain->utxo_set().cache_size() * 100; // approximate
    }
    if (mempool) {
        health.mempool_bytes = mempool->bytes();
    }

    // Disk stats
    health.blocks_disk_bytes = 0;
    health.chainstate_disk_bytes = 0;
    health.available_disk_bytes = 0;

    // Compute block store disk usage
    if (chain) {
        health.blocks_disk_bytes = chain->block_store().get_disk_usage();
    }

    // Available disk space
    try {
        auto info = std::filesystem::space(datadir);
        health.available_disk_bytes = info.available;
    } catch (...) {}

    // Network stats
    health.outbound_peers = 0;
    health.inbound_peers = 0;
    health.bytes_sent = static_cast<int64_t>(perf.bytes_sent.load());
    health.bytes_received = static_cast<int64_t>(perf.bytes_recv.load());
    health.avg_ping_ms = 0.0;

    if (net) {
        health.outbound_peers = static_cast<int>(net->outbound_count());
        health.inbound_peers = static_cast<int>(net->inbound_count());
        // avg_ping_ms could be computed from peer stats
        health.avg_ping_ms = 0.0;
    }

    // Chain stats
    health.height = chain_height();
    health.headers_height = health.height;  // TODO: track headers-only tip separately
    health.sync_progress = 1.0;
    health.time_since_last_block = 0;

    if (chain && chain->tip()) {
        int64_t tip_time = chain->tip()->timestamp;
        int64_t now = static_cast<int64_t>(std::time(nullptr));
        health.time_since_last_block = now - tip_time;

        // Estimate sync progress based on tip timestamp vs current time
        // If tip is within 2 hours of now, we consider ourselves synced
        if (health.time_since_last_block > 7200) {
            // Estimate progress: tip_time / now
            health.sync_progress = static_cast<double>(tip_time) /
                                   static_cast<double>(now);
            if (health.sync_progress < 0.0) health.sync_progress = 0.0;
            if (health.sync_progress > 1.0) health.sync_progress = 1.0;
        }
    }

    // Warnings
    health.is_healthy = true;

    if (health.available_disk_bytes < 100ULL * 1024 * 1024) {
        health.warnings.push_back("Low disk space: " +
            std::to_string(health.available_disk_bytes / (1024 * 1024)) + " MB remaining");
        health.is_healthy = false;
    }

    if (health.rss_bytes > 4ULL * 1024 * 1024 * 1024) {
        health.warnings.push_back("High memory usage: " +
            std::to_string(health.rss_bytes / (1024 * 1024)) + " MB RSS");
    }

    if (health.outbound_peers == 0 && health.inbound_peers == 0) {
        health.warnings.push_back("No connected peers");
        health.is_healthy = false;
    }

    if (health.time_since_last_block > 7200) {
        health.warnings.push_back("No new blocks in " +
            std::to_string(health.time_since_last_block / 60) + " minutes");
    }

    if (is_ibd.load()) {
        health.warnings.push_back("Initial Block Download in progress");
    }

    return health;
}

// ============================================================================
// run_maintenance — comprehensive periodic maintenance
// ============================================================================

void NodeContext::run_maintenance() {
    int64_t t0 = now_us();
    LogDebug("node", "Running maintenance cycle...");

    // 1. Flush UTXO cache if dirty
    if (chain) {
        chain->periodic_flush();
    }

    // 2. Compact databases if fragmented (less frequently)
    static int compact_counter = 0;
    compact_counter++;
    if (compact_counter % 60 == 0) {  // Every ~10 hours at 10-min intervals
        if (chain) {
            chain->periodic_compact();
        }
    }

    // 3. Prune old block files if pruning enabled
    if (chain && chain->is_pruning_enabled()) {
        chain->prune();
    }

    // 5. Rotate log file if large
    log_rotate();

    // 6. Clean expired bans from the network module
    if (net) {
        net->clean_expired_bans();
    }

    // 7. Save address database to peers.dat
    if (net) {
        std::string peers_path = datadir_path("peers.dat");
        net->save_peers(peers_path);
    }

    // 8. Check disk space and warn
    int64_t free_mb = get_disk_free_mb();
    if (free_mb >= 0 && free_mb < 50) {
        LogError("node", "Maintenance: critically low disk space: %lld MB",
                 static_cast<long long>(free_mb));
    } else if (free_mb >= 0 && free_mb < 200) {
        LogWarn("node", "Maintenance: low disk space: %lld MB",
                static_cast<long long>(free_mb));
    }

    // 9. Report health status
    NodeHealth health = get_node_health();
    for (const auto& warning : health.warnings) {
        LogWarn("node", "Health: %s", warning.c_str());
    }

    // 10. Update IBD status
    if (chain && is_ibd.load()) {
        uint64_t h = chain->height();
        int64_t tip_time = 0;
        if (chain->tip()) {
            tip_time = chain->tip()->timestamp;
        }
        int64_t now = static_cast<int64_t>(std::time(nullptr));

        // Exit IBD if tip is within 2 hours of current time
        if (tip_time > 0 && (now - tip_time) < 7200) {
            is_ibd.store(false);
            LogInfo("node", "Exiting Initial Block Download mode at height %lu",
                    static_cast<unsigned long>(h));
        }
    }

    int64_t t1 = now_us();
    LogDebug("node", "Maintenance cycle completed in %.1f ms",
             static_cast<double>(t1 - t0) / 1000.0);
}

// ============================================================================
// Block notification system
// ============================================================================

using BlockNotifyCallback = std::function<void(const CBlock& block, uint64_t height)>;
using TxNotifyCallback = std::function<void(const CTransaction& tx)>;

// Storage for notification callbacks
static std::vector<BlockNotifyCallback> g_block_connected_cbs;
static std::vector<BlockNotifyCallback> g_block_disconnected_cbs;
static std::vector<TxNotifyCallback> g_tx_mempool_cbs;
static std::mutex g_notify_mutex;

void NodeContext::on_block_connected(BlockNotifyCallback cb) {
    std::lock_guard<std::mutex> lock(g_notify_mutex);
    g_block_connected_cbs.push_back(std::move(cb));
}

void NodeContext::on_block_disconnected(BlockNotifyCallback cb) {
    std::lock_guard<std::mutex> lock(g_notify_mutex);
    g_block_disconnected_cbs.push_back(std::move(cb));
}

void NodeContext::on_transaction_added_mempool(TxNotifyCallback cb) {
    std::lock_guard<std::mutex> lock(g_notify_mutex);
    g_tx_mempool_cbs.push_back(std::move(cb));
}

void NodeContext::notify_block_connected(const CBlock& block, uint64_t height) {
    std::lock_guard<std::mutex> lock(g_notify_mutex);

    for (const auto& cb : g_block_connected_cbs) {
        try {
            cb(block, height);
        } catch (const std::exception& e) {
            LogWarn("node", "Block connected callback threw: %s", e.what());
        }
    }

    // Also fire the tip-changed callbacks
    uint256 block_hash = block.get_hash();
    notify_tip_changed(height, block_hash.data());

    // Update performance counters
    perf.blocks_validated.fetch_add(1);
    perf.txs_validated.fetch_add(block.vtx.size());
}

void NodeContext::notify_block_disconnected(const CBlock& block, uint64_t height) {
    std::lock_guard<std::mutex> lock(g_notify_mutex);

    for (const auto& cb : g_block_disconnected_cbs) {
        try {
            cb(block, height);
        } catch (const std::exception& e) {
            LogWarn("node", "Block disconnected callback threw: %s", e.what());
        }
    }
}

void NodeContext::notify_tx_mempool(const CTransaction& tx) {
    std::lock_guard<std::mutex> lock(g_notify_mutex);

    for (const auto& cb : g_tx_mempool_cbs) {
        try {
            cb(tx);
        } catch (const std::exception& e) {
            LogWarn("node", "Tx mempool callback threw: %s", e.what());
        }
    }
}

// ============================================================================
// Log rotation
// ============================================================================

static void log_rotate_impl(const std::string& log_file, size_t max_size) {
    try {
        if (!std::filesystem::exists(log_file)) return;

        auto file_size = std::filesystem::file_size(log_file);
        if (file_size < max_size) return;

        // Rotate: rename current -> .1, .1 -> .2, etc.
        // Keep up to 3 old log files.
        for (int i = 2; i >= 0; --i) {
            std::string old_name = log_file + "." + std::to_string(i + 1);
            std::string new_name = log_file + "." + std::to_string(i + 2);
            if (std::filesystem::exists(old_name)) {
                if (i == 2) {
                    std::filesystem::remove(old_name);
                } else {
                    std::filesystem::rename(old_name, new_name);
                }
            }
        }

        std::string rotated = log_file + ".1";
        std::filesystem::rename(log_file, rotated);

    } catch (const std::exception& e) {
        LogWarn("node", "Log rotation failed: %s", e.what());
    }
}

void NodeContext::log_rotate_check() {
    std::string lpath = log_path();
    // Rotate at 50 MB
    log_rotate_impl(lpath, 50ULL * 1024 * 1024);
}

// ============================================================================
// Comprehensive node info for RPC getinfo
// ============================================================================

// NodeInfo is NodeContext::NodeInfo (defined in context.h)

NodeContext::NodeInfo NodeContext::get_info() const {
    NodeInfo info;
    info.version = std::string(CLIENT_NAME) + " v" + CLIENT_VERSION_STRING;
    info.network = get_network_name();
    info.height = chain_height();
    info.headers = info.height;
    info.connections = static_cast<int>(peer_count());
    info.outbound = 0;
    info.inbound = 0;
    info.mempool_txs = mempool_size();
    info.mempool_bytes = mempool_bytes();
    info.uptime_seconds = uptime();
    info.ibd = is_ibd.load();
    info.sync_progress = 1.0;

    info.rss_mb = get_rss_mb();
    info.disk_free_mb = get_disk_free_mb();
    info.datadir = datadir;
    info.p2p_port = get_port();
    info.rpc_port = get_rpc_port();

    if (net) {
        info.outbound = static_cast<int>(net->outbound_count());
        info.inbound = static_cast<int>(net->inbound_count());
    }

    if (chain && chain->tip()) {

        int64_t tip_time = chain->tip()->timestamp;
        int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (now - tip_time > 7200) {
            info.sync_progress = static_cast<double>(tip_time) /
                                 static_cast<double>(now);
        }
    }

    return info;
}

// ============================================================================
// process_new_block — high-level block processing entry point
// ============================================================================

bool NodeContext::process_new_block(const CBlock& block) {
    if (!chain) {
        LogError("node", "process_new_block: chain not initialized");
        return false;
    }

    consensus::ValidationState state;

    int64_t t0 = now_us();

    bool accepted = chain->accept_block(block, state);

    int64_t t1 = now_us();
    double elapsed_ms = static_cast<double>(t1 - t0) / 1000.0;

    if (!accepted) {
        LogWarn("node", "Block rejected at height %lu: %s (%.1f ms)",
                static_cast<unsigned long>(block.height),
                state.to_string().c_str(),
                elapsed_ms);

        // Increment ban score for the peer that sent this block
        // (caller is responsible for providing peer_id)
        return false;
    }

    // Notify listeners
    notify_block_connected(block, block.height);

    // Update mempool: remove transactions that were included in this block
    if (mempool) {
        int removed = 0;
        for (size_t i = 1; i < block.vtx.size(); ++i) {
            uint256 txid = block.vtx[i].get_txid();
            if (mempool->exists(txid)) {
                mempool->remove(txid);
                removed++;
            }
        }
        if (removed > 0) {
            LogDebug("node", "Removed %d txs from mempool (included in block %lu)",
                     removed, static_cast<unsigned long>(block.height));
        }
    }

    // Check if we should exit IBD
    if (is_ibd.load()) {
        int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (block.timestamp > 0 && (now - block.timestamp) < 7200) {
            is_ibd.store(false);
            LogInfo("node", "Exiting IBD at height %lu",
                    static_cast<unsigned long>(block.height));
        }
    }

    LogInfo("node", "Block %lu connected: %zu txs, loss=%.4f (%.1f ms)",
            static_cast<unsigned long>(block.height),
            block.vtx.size(),

            elapsed_ms);

    return true;
}

// ============================================================================
// process_transaction — accept a new transaction into the mempool
// ============================================================================

bool NodeContext::process_transaction(const CTransaction& tx,
                                       consensus::ValidationState& state) {
    if (!chain || !mempool) {
        state.error("subsystems-not-ready");
        return false;
    }

    // Basic structural validation
    if (!consensus::check_transaction(tx, state)) {
        return false;
    }

    // Check if the transaction's inputs exist in the UTXO set
    for (const auto& input : tx.vin) {
        UTXOEntry entry;
        if (!chain->utxo_set().get(input.prevout.txid, input.prevout.index, entry)) {
            state.invalid(consensus::ValidationResult::TX_INVALID,
                          "missing-inputs",
                          "input UTXO not found in the set");
            return false;
        }

        // Verify pubkey hash matches
        uint256 pkh = keccak256(input.pubkey.data(), input.pubkey.size());
        if (std::memcmp(pkh.data(), entry.pubkey_hash.data(), 32) != 0) {
            state.invalid(consensus::ValidationResult::TX_INVALID,
                          "bad-txns-pubkey-hash",
                          "input pubkey hash does not match UTXO");
            return false;
        }

        // Check coinbase maturity
        if (entry.is_coinbase) {
            uint64_t current_height = chain->height();
            if (current_height < entry.height + consensus::COINBASE_MATURITY) {
                state.invalid(consensus::ValidationResult::TX_INVALID,
                              "bad-txns-premature-spend-of-coinbase",
                              "coinbase output not yet mature");
                return false;
            }
        }
    }

    // Compute fee (sum inputs - sum outputs)
    Amount input_sum = 0;
    for (const auto& input : tx.vin) {
        UTXOEntry entry;
        chain->utxo_set().get(input.prevout.txid, input.prevout.index, entry);
        input_sum += entry.value;
    }
    Amount output_sum = tx.get_value_out();
    Amount fee = input_sum - output_sum;

    if (fee < 0) {
        state.invalid(consensus::ValidationResult::TX_INVALID,
                      "bad-txns-fee-negative",
                      "transaction fee is negative (inputs < outputs)");
        return false;
    }

    // Check minimum fee
    size_t tx_size = 12 + tx.vin.size() * 132 + tx.vout.size() * 40;
    Amount min_fee = static_cast<Amount>(tx_size);  // 1 atomic unit per byte
    if (fee < min_fee) {
        state.invalid(consensus::ValidationResult::TX_INVALID,
                      "insufficient-fee",
                      "fee below minimum relay fee");
        return false;
    }

    // Add to mempool
    auto add_res = mempool->add_transaction(tx);
    (void)fee;
    if (!add_res.accepted) {
        state.invalid(consensus::ValidationResult::TX_INVALID,
                      "mempool-reject",
                      "transaction rejected by mempool");
        return false;
    }

    // Notify listeners
    notify_tx_mempool(tx);

    LogDebug("node", "Transaction accepted into mempool (fee=%ld, size=%zu)",
             static_cast<long>(fee), tx_size);

    return true;
}

// ============================================================================
// get_connection_info — detailed peer connection info
// ============================================================================

// PeerInfo is NodeContext::PeerInfo (defined in context.h)

std::vector<NodeContext::PeerInfo> NodeContext::get_peer_info() const {
    std::vector<PeerInfo> peers;

    if (!net) return peers;

    size_t count = net->peer_count();
    peers.reserve(count);

    // The actual peer enumeration would come from the NetManager.
    // For now, we return an empty list. The RPC layer calls
    // net->get_peer_info() directly.

    return peers;
}

} // namespace flow

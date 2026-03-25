// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// NodeContext: top-level container that owns all subsystems of a running
// FlowCoin node. Wires together the chain state, wallet, network manager,
// RPC server, mempool, eval engine, block assembler, block submitter, and
// sync manager into a single lifetime scope with deterministic init/destroy.

#ifndef FLOWCOIN_NODE_CONTEXT_H
#define FLOWCOIN_NODE_CONTEXT_H

#include "config.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "chain/utxo.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

struct uv_loop_s;
typedef struct uv_loop_s uv_loop_t;

namespace flow {

class ChainState;
class Wallet;
class NetManager;
class RpcServer;
class Mempool;
class SyncManager;

namespace consensus {
class EvalEngine;
}

struct BlockAssembler;
struct BlockSubmitter;

// ============================================================================
// Subsystem initialization state tracking
// ============================================================================

enum class SubsystemState : uint8_t {
    UNINITIALIZED = 0,
    INITIALIZING  = 1,
    RUNNING       = 2,
    STOPPING      = 3,
    STOPPED       = 4,
    FAILED        = 5,
};

const char* subsystem_state_name(SubsystemState s);

// ============================================================================
// SubsystemEntry: tracks a single subsystem with name, state, and timing
// ============================================================================

struct SubsystemEntry {
    std::string name;
    SubsystemState state = SubsystemState::UNINITIALIZED;
    int64_t init_start_us = 0;    // microseconds since epoch
    int64_t init_end_us   = 0;
    int64_t stop_start_us = 0;
    int64_t stop_end_us   = 0;

    double init_duration_ms() const {
        if (init_end_us > init_start_us)
            return static_cast<double>(init_end_us - init_start_us) / 1000.0;
        return 0.0;
    }
    double stop_duration_ms() const {
        if (stop_end_us > stop_start_us)
            return static_cast<double>(stop_end_us - stop_start_us) / 1000.0;
        return 0.0;
    }
};

// ============================================================================
// NodeContext: the root object for a running FlowCoin node
// ============================================================================

struct NodeContext {
    // -- Owned subsystems (initialized in order, destroyed in reverse) --------
    std::unique_ptr<ChainState>            chain;
    std::unique_ptr<Wallet>                wallet;
    std::unique_ptr<NetManager>            net;
    std::unique_ptr<RpcServer>             rpc;
    std::unique_ptr<Mempool>               mempool;
    std::unique_ptr<consensus::EvalEngine> eval_engine;
    std::unique_ptr<SyncManager>           sync;

    // -- Configuration --------------------------------------------------------
    Config config;
    std::string datadir;
    bool testnet = false;
    bool regtest = false;

    // -- State ----------------------------------------------------------------
    int64_t start_time = 0;       // unix timestamp of node start
    std::atomic<bool> is_ibd{true};           // initial block download
    std::atomic<bool> shutdown_requested{false};

    // -- Subsystem tracking ---------------------------------------------------
    std::vector<SubsystemEntry> subsystems;
    mutable std::mutex subsystems_mutex;

    // -- libuv event loop (shared between RPC and timers) ---------------------
    uv_loop_t* loop = nullptr;

    // -- PID and lock file management -----------------------------------------
    int lockfile_fd = -1;
    std::string pid_file_path;
    std::string lock_file_path;

    // -- Network parameters ---------------------------------------------------

    /// Get the 4-byte network magic for the active network.
    uint32_t get_magic() const;

    /// Get the default P2P listen port for the active network.
    uint16_t get_port() const;

    /// Get the default RPC listen port for the active network.
    uint16_t get_rpc_port() const;

    /// Get the Bech32m human-readable prefix for the active network.
    const char* get_hrp() const;

    /// Get the network name as a human-readable string.
    const char* get_network_name() const;

    /// Get the default data directory suffix for the active network.
    /// Mainnet returns "", testnet returns "/testnet", regtest returns "/regtest".
    std::string get_network_subdir() const;

    // -- Lifecycle ------------------------------------------------------------

    /// Initialize all subsystems in order. Returns false on failure.
    /// Each subsystem is tracked in the subsystems vector.
    bool init();

    /// Start networking, RPC, and sync after init() succeeds.
    bool start();

    /// Request a graceful shutdown. Safe to call from signal handlers.
    void interrupt();

    /// Perform the actual shutdown: stop all subsystems in reverse order,
    /// release resources, remove PID file.
    void stop();

    // -- Status ---------------------------------------------------------------

    /// Seconds since node started.
    int64_t uptime() const;

    /// True once we believe we are caught up with the network.
    bool is_synced() const;

    /// Get a human-readable status summary string.
    std::string status_summary() const;

    /// Get an extended status report with subsystem health info.
    std::string extended_status() const;

    /// Get the current chain height (thread-safe wrapper).
    uint64_t chain_height() const;

    /// Get the current peer count (thread-safe wrapper).
    size_t peer_count() const;

    /// Get the current mempool size in transactions.
    size_t mempool_size() const;

    /// Get the current mempool size in bytes.
    size_t mempool_bytes() const;

    // -- Subsystem tracking helpers -------------------------------------------

    /// Register a subsystem name for tracking (called during init setup).
    size_t register_subsystem(const std::string& name);

    /// Mark a subsystem as entering a new state.
    void set_subsystem_state(size_t index, SubsystemState state);

    /// Record init start time for a subsystem.
    void mark_init_start(size_t index);

    /// Record init end time for a subsystem.
    void mark_init_end(size_t index);

    /// Record stop start time for a subsystem.
    void mark_stop_start(size_t index);

    /// Record stop end time for a subsystem.
    void mark_stop_end(size_t index);

    /// Log all subsystem initialization timings.
    void log_init_timings() const;

    /// Log all subsystem shutdown timings.
    void log_stop_timings() const;

    // -- Lock and PID file management -----------------------------------------

    /// Attempt to lock the data directory to prevent concurrent instances.
    /// Returns false if the directory is already locked.
    bool lock_datadir();

    /// Release the data directory lock.
    void unlock_datadir();

    /// Write the PID file. Returns false on failure.
    bool write_pid_file();

    /// Remove the PID file.
    void remove_pid_file();

    // -- Data directory helpers -----------------------------------------------

    /// Ensure the data directory and all required subdirectories exist.
    bool ensure_datadir();

    /// Get the full path to a file within the data directory.
    std::string datadir_path(const std::string& filename) const;

    /// Get the blocks subdirectory path.
    std::string blocks_dir() const;

    /// Get the model subdirectory path.
    std::string model_dir() const;

    /// Get the wallet file path.
    std::string wallet_path() const;

    /// Get the log file path.
    std::string log_path() const;

    /// Get the config file path.
    std::string config_path() const;

    /// Get the cookie file path (for RPC auth).
    std::string cookie_path() const;

    // -- Chain tip notification -----------------------------------------------

    /// Callback type for chain tip updates
    using TipChangedCallback = std::function<void(uint64_t new_height, const uint8_t* block_hash)>;

    /// Register a callback for chain tip changes (e.g., wallet rescanning).
    size_t on_tip_changed(TipChangedCallback callback);

    /// Unregister a previously registered tip callback.
    void remove_tip_callback(size_t id);

    /// Fire all tip-changed callbacks (called by the chain validation code).
    void notify_tip_changed(uint64_t height, const uint8_t* block_hash);

    // -- Health monitoring ----------------------------------------------------

    struct HealthStatus {
        bool chain_ok       = false;
        bool wallet_ok      = false;
        bool net_ok          = false;
        bool rpc_ok          = false;
        bool mempool_ok      = false;
        bool eval_engine_ok  = false;
        bool disk_space_ok   = true;
        int64_t disk_free_mb = 0;
        int64_t chain_height = 0;
        int64_t peer_count   = 0;
        int64_t mempool_txs  = 0;
        double cpu_usage     = 0.0;
        int64_t rss_mb       = 0;
    };

    /// Run a health check on all subsystems.
    HealthStatus check_health() const;

    /// Get the current resident set size (RSS) in megabytes.
    static int64_t get_rss_mb();

    /// Get available disk space in the data directory (MB).
    int64_t get_disk_free_mb() const;

    // -- Reindex support ------------------------------------------------------

    /// Check if the chain tip matches the model state.
    /// If not, a reindex may be needed.
    bool verify_chain_model_consistency() const;

    /// Replay model state from the given height to the current tip.
    /// Returns false if the replay fails (corrupt data).
    bool replay_model_from(uint64_t from_height);

    // -- Performance counters -------------------------------------------------

    struct PerfCounters {
        std::atomic<uint64_t> blocks_validated{0};
        std::atomic<uint64_t> txs_validated{0};
        std::atomic<uint64_t> blocks_downloaded{0};
        std::atomic<uint64_t> bytes_sent{0};
        std::atomic<uint64_t> bytes_recv{0};
        std::atomic<uint64_t> rpc_requests{0};
        std::atomic<uint64_t> rpc_errors{0};
        std::atomic<uint64_t> model_evals{0};
        int64_t start_time = 0;

        void reset();
        double blocks_per_second() const;
        double txs_per_second() const;
        double rpc_per_second() const;
    };

    PerfCounters perf;

    /// Get a formatted performance report string.
    std::string perf_report() const;

    // -- Ban score tracking (aggregated from net module) -----------------------

    /// Increment the ban score for a peer.
    /// If the score exceeds the threshold, the peer is banned.
    void add_ban_score(uint64_t peer_id, int score, const std::string& reason);

    // -- Periodic maintenance -------------------------------------------------

    /// Run periodic housekeeping tasks (disk check, log rotate, checkpoint).
    /// Called by the main event loop timer every ~60 seconds.
    void periodic_maintenance();

    // -- Debug ----------------------------------------------------------------

    /// Dump comprehensive debug information for diagnostics.
    std::string dump_debug_info() const;

    // -- Extended health monitoring -------------------------------------------

    /// Comprehensive health status including memory, disk, network, chain.
    struct NodeHealthInfo {
        size_t rss_bytes = 0;
        size_t peak_rss_bytes = 0;
        size_t utxo_cache_bytes = 0;
        size_t mempool_bytes = 0;
        size_t model_bytes = 0;
        size_t blocks_disk_bytes = 0;
        size_t chainstate_disk_bytes = 0;
        size_t model_disk_bytes = 0;
        size_t available_disk_bytes = 0;
        int outbound_peers = 0;
        int inbound_peers = 0;
        int64_t bytes_sent = 0;
        int64_t bytes_received = 0;
        double avg_ping_ms = 0.0;
        uint64_t height = 0;
        uint64_t headers_height = 0;
        double sync_progress = 0.0;
        int64_t time_since_last_block = 0;
        size_t model_params = 0;
        float last_val_loss = 0.0f;
        uint256 model_hash;
        std::vector<std::string> warnings;
        bool is_healthy = false;
    };

    /// Get comprehensive health information.
    NodeHealthInfo get_node_health() const;

    // -- Maintenance tasks ----------------------------------------------------

    /// Run comprehensive periodic maintenance (10-minute interval).
    void run_maintenance();

    // -- Block notification system --------------------------------------------

    using BlockNotifyCallback = std::function<void(const CBlock& block, uint64_t height)>;
    using TxNotifyCallback = std::function<void(const CTransaction& tx)>;

    void on_block_connected(BlockNotifyCallback cb);
    void on_block_disconnected(BlockNotifyCallback cb);
    void on_transaction_added_mempool(TxNotifyCallback cb);
    void notify_block_connected(const CBlock& block, uint64_t height);
    void notify_block_disconnected(const CBlock& block, uint64_t height);
    void notify_tx_mempool(const CTransaction& tx);

    // -- High-level block/tx processing ---------------------------------------

    /// Process a newly received block through the full validation pipeline.
    bool process_new_block(const CBlock& block);

    /// Accept a transaction into the mempool after validation.
    bool process_transaction(const CTransaction& tx,
                              consensus::ValidationState& state);

    // -- Node info for RPC ----------------------------------------------------

    struct NodeInfo {
        std::string version;
        std::string network;
        uint64_t height;
        uint64_t headers;
        int connections;
        int outbound;
        int inbound;
        size_t mempool_txs;
        size_t mempool_bytes;
        int64_t uptime_seconds;
        bool ibd;
        double sync_progress;
        size_t model_params;
        float model_loss;
        int64_t rss_mb;
        int64_t disk_free_mb;
        std::string datadir;
        uint16_t p2p_port;
        uint16_t rpc_port;
    };

    NodeInfo get_info() const;

    // -- Peer info for RPC ----------------------------------------------------

    struct PeerInfo {
        uint64_t peer_id;
        std::string addr;
        bool inbound;
        int64_t conn_time;
        int64_t bytes_sent;
        int64_t bytes_recv;
        double ping_ms;
    };

    std::vector<PeerInfo> get_peer_info() const;

    // -- Log rotation ---------------------------------------------------------

    void log_rotate_check();

    // -- Construction / destruction -------------------------------------------

    NodeContext();
    ~NodeContext();

    // Non-copyable, non-movable
    NodeContext(const NodeContext&) = delete;
    NodeContext& operator=(const NodeContext&) = delete;
    NodeContext(NodeContext&&) = delete;
    NodeContext& operator=(NodeContext&&) = delete;

private:
    // Tip change callbacks
    std::vector<std::pair<size_t, TipChangedCallback>> tip_callbacks_;
    size_t next_tip_cb_id_ = 1;
    mutable std::mutex tip_cb_mutex_;
};

// ============================================================================
// ShutdownState: global shutdown signaling (for signal handlers)
// ============================================================================

class ShutdownState {
public:
    /// Request shutdown (safe to call from signal handlers).
    void request_shutdown();

    /// Check if shutdown has been requested.
    bool is_shutdown_requested() const;

    /// Block until shutdown is requested.
    void wait_for_shutdown();

    /// Reset the shutdown flag (for testing only).
    void reset();

private:
    std::atomic<bool> requested_{false};
};

/// Get the global shutdown state singleton.
ShutdownState& get_shutdown_state();

} // namespace flow

#endif // FLOWCOIN_NODE_CONTEXT_H

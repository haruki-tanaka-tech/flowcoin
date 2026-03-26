// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Core miner engine for FlowCoin.
//
// Runs a continuous hash-check-submit loop:
//   1. Get block template from node via RPC
//   2. Iterate nonce, computing keccak256d(header[0..91])
//   3. If hash <= target, sign and submit block
//   4. Real-time hashrate output
//
// Designed for 24/7 unattended operation.

#pragma once

#include "rpc_client.h"
#include "hash_check.h"

#include "../util/types.h"
#include "../consensus/params.h"
#include "../crypto/keys.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace flow::miner {

// =========================================================================
// Miner configuration
// =========================================================================

struct MinerConfig {
    // Data directory (contains wallet keys)
    std::string datadir;

    // RPC connection to the FlowCoin node
    std::string rpc_host = "127.0.0.1";
    int         rpc_port = 9334;
    std::string rpc_user;
    std::string rpc_password;

    // GPU device (-1 = auto)
    int gpu_device = -1;

    // Mining behavior
    int  status_interval_ms = 1000;
    bool verbose            = false;
};

// =========================================================================
// Miner statistics
// =========================================================================

struct MinerStats {
    uint64_t total_hashes   = 0;
    uint64_t blocks_found   = 0;
    uint64_t blocks_rejected = 0;
    double   hashrate       = 0.0;
};

struct LiveStats {
    std::atomic<uint64_t> total_hashes{0};
    std::atomic<uint64_t> blocks_found{0};
    std::atomic<uint64_t> blocks_rejected{0};
    double hashrate = 0.0;
};

// =========================================================================
// MinerEngine
// =========================================================================

class MinerEngine {
public:
    explicit MinerEngine(const MinerConfig& config);
    ~MinerEngine();

    MinerEngine(const MinerEngine&) = delete;
    MinerEngine& operator=(const MinerEngine&) = delete;

    /// Initialize: load keys, connect to node.
    bool init();

    /// Run the mining loop (blocks until stop() is called).
    void run();

    /// Signal the miner to stop gracefully.
    void stop();

    /// Get current statistics snapshot.
    MinerStats stats() const;

    /// Check if the miner is currently running.
    bool is_running() const { return running_.load(); }

private:
    MinerConfig config_;
    std::atomic<bool> running_{false};
    LiveStats stats_;

    // Miner identity (Ed25519 keypair)
    KeyPair miner_key_;

    // RPC client
    RPCClient rpc_;

    // Current block template
    RPCClient::BlockTemplate current_template_;
    uint256 current_target_;

    // Timing
    using Clock = std::chrono::steady_clock;
    Clock::time_point mining_start_;
    Clock::time_point last_status_print_;
    Clock::time_point last_template_refresh_;

    // Initialization helpers
    bool load_or_create_miner_key();
    bool connect_to_node();

    // Mining loop internals
    bool refresh_block_template();
    bool submit_block(const RPCClient::BlockTemplate& tmpl, uint32_t nonce);
    void print_status(uint64_t hashes);
    void print_block_found(uint64_t height, const std::string& hash_hex);

    // Utility
    static std::string format_hashrate(double h);
    static std::string format_elapsed(double seconds);
};

} // namespace flow::miner

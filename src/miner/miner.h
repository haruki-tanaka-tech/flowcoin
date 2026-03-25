// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Core miner engine for FlowCoin.
//
// Runs a continuous train-check-submit loop:
//   1. Get block template from node via RPC
//   2. Train ResonanceNet V5 model on dataset
//   3. After each training step, check if training hash meets target
//   4. If target met, compute sparse delta and submit block
//   5. Real-time progress output every step (no silences)
//
// Designed for 24/7 unattended operation. No Python, no PyTorch.

#pragma once

#include "model.h"
#include "rpc_client.h"
#include "hash_check.h"

#include "../util/types.h"
#include "../consensus/params.h"
#include "../consensus/growth.h"
#include "../crypto/keys.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace flow::miner {

// ═══════════════════════════════════════════════════════════════════════════
// Miner configuration
// ═══════════════════════════════════════════════════════════════════════════

struct MinerConfig {
    // Data directory (contains training/ subdirectory and wallet keys)
    std::string datadir;

    // RPC connection to the FlowCoin node
    std::string rpc_host = "127.0.0.1";
    int         rpc_port = 9334;
    std::string rpc_user;
    std::string rpc_password;

    // Training hyperparameters
    float learning_rate     = 0.001f;
    int   batch_size        = 1;
    int   seq_len           = 256;
    float sparse_threshold  = 0.01f;

    // Compute backend (ggml handles this automatically)
    std::string backend = "auto";  // auto (ggml selects best available)

    // Mining behavior
    int  status_interval_ms = 1000;   // Print status every N ms
    bool verbose            = false;  // Extra debug output
};

// ═══════════════════════════════════════════════════════════════════════════
// Miner statistics (real-time, lock-free)
// ═══════════════════════════════════════════════════════════════════════════

// Snapshot returned by stats() -- plain values, no atomics.
struct MinerStats {
    uint64_t total_steps    = 0;
    uint64_t total_checks   = 0;
    uint64_t blocks_found   = 0;
    uint64_t blocks_rejected = 0;
    float current_loss      = 0.0f;
    float best_loss         = 1e9f;
    float current_grad_norm = 0.0f;
    float steps_per_second  = 0.0f;
    float hashes_per_second = 0.0f;  // same as steps/sec for PoT
};

// Internal live stats with atomics for thread safety.
struct LiveStats {
    std::atomic<uint64_t> total_steps{0};
    std::atomic<uint64_t> total_checks{0};
    std::atomic<uint64_t> blocks_found{0};
    std::atomic<uint64_t> blocks_rejected{0};
    float current_loss      = 0.0f;
    float best_loss         = 1e9f;
    float current_grad_norm = 0.0f;
    float steps_per_second  = 0.0f;
    float hashes_per_second = 0.0f;
};

// ═══════════════════════════════════════════════════════════════════════════
// MinerEngine
// ═══════════════════════════════════════════════════════════════════════════

class MinerEngine {
public:
    explicit MinerEngine(const MinerConfig& config);
    ~MinerEngine();

    // Non-copyable, non-movable
    MinerEngine(const MinerEngine&) = delete;
    MinerEngine& operator=(const MinerEngine&) = delete;

    /// Initialize: load keys, training data, model, connect to node.
    /// Returns false on fatal error.
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

    // ── Training data ──
    std::vector<uint8_t> dataset_;
    uint256              dataset_hash_;
    size_t               data_pos_ = 0;

    // ── Miner identity (Ed25519 keypair) ──
    KeyPair miner_key_;

    // ── Model (ggml-based) ──
    GGMLModel model_;
    GGMLModel consensus_;  // Snapshot of consensus model for delta computation

    // ── RPC client ──
    RPCClient rpc_;

    // ── Current block template ──
    RPCClient::BlockTemplate current_template_;
    uint256 current_target_;

    // ── Timing ──
    using Clock = std::chrono::steady_clock;
    Clock::time_point mining_start_;
    Clock::time_point last_status_print_;
    Clock::time_point last_template_refresh_;

    // ── Initialization helpers ──
    bool load_training_data();
    bool load_or_create_miner_key();
    bool init_model();
    bool connect_to_node();

    // ── Mining loop internals ──
    bool refresh_block_template();
    void get_batch(uint8_t* input, uint8_t* target);
    float training_step();
    bool check_hash(float loss, uint64_t step, float grad_norm, uint256& out_hash);
    bool submit_block(const RPCClient::BlockTemplate& tmpl, float val_loss,
                      const uint256& training_hash);
    void print_status(uint64_t step, float loss, float grad_norm);
    void print_block_found(uint64_t height, float val_loss, const std::string& hash_hex);

    // ── Utility ──
    static std::string format_hashrate(double h);
    static std::string format_loss(float loss);
    static std::string format_elapsed(double seconds);
    static std::string format_params(size_t count);
};

} // namespace flow::miner

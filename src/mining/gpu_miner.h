// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Standalone GPU-accelerated miner for FlowCoin using ggml for training.
// Reads training data from <datadir>/training/, connects to flowcoind
// via JSON-RPC, and submits blocks when the training hash meets target.

#ifndef FLOWCOIN_MINING_GPU_MINER_H
#define FLOWCOIN_MINING_GPU_MINER_H

#include "consensus/consensus_model.h"
#include "consensus/params.h"
#include "util/types.h"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace flow {

// ============================================================================
// Mining configuration
// ============================================================================

struct MinerConfig {
    std::string datadir;           // ~/.flowcoin
    std::string rpc_user;
    std::string rpc_password;
    int rpc_port = 9334;
    bool force_cpu = false;
    int n_threads = 0;             // 0 = auto
    int steps_per_check = 100;     // hash check interval
    float learning_rate = 0.001f;
    int batch_size = 1;
    int seq_len = 256;
    float sparse_threshold = 1e-6f;
};

// ============================================================================
// Mining statistics
// ============================================================================

struct MiningStats {
    uint64_t total_steps = 0;
    uint64_t hash_checks = 0;
    uint64_t blocks_found = 0;
    float current_loss = 0;
    float best_loss = 1e9f;
    float steps_per_second = 0;
};

// ============================================================================
// Block template from RPC
// ============================================================================

struct BlockTemplate {
    uint64_t height = 0;
    uint256 prev_hash;
    uint32_t nbits = 0;
    float prev_val_loss = 0.0f;
    consensus::ModelDimensions dims{};
    Amount reward = 0;
    uint256 target;
};

// ============================================================================
// GPUMiner: trains ResonanceNet V5 using ggml, submits blocks via RPC
// ============================================================================

class GPUMiner {
public:
    explicit GPUMiner(const MinerConfig& config);
    ~GPUMiner();

    // Non-copyable
    GPUMiner(const GPUMiner&) = delete;
    GPUMiner& operator=(const GPUMiner&) = delete;

    bool init();       // Load dataset, check RPC connection
    void run();        // Main mining loop (blocking)
    void stop();       // Signal stop
    MiningStats get_stats() const;

private:
    MinerConfig config_;
    std::atomic<bool> running_{false};
    mutable std::mutex stats_mutex_;
    MiningStats stats_;

    // Training data (loaded from datadir/training/)
    std::vector<uint8_t> dataset_;
    uint256 dataset_hash_;
    size_t data_pos_ = 0;
    int file_count_ = 0;

    // RPC communication
    std::string rpc_call(const std::string& method,
                         const std::string& params = "[]");

    // Dataset
    bool load_training_data();
    void get_batch(std::vector<uint8_t>& input,
                   std::vector<uint8_t>& target);

    // Training step using ggml autodiff (simplified forward graph)
    // Builds: embedding -> [RMSNorm -> SwiGLU FFN + residual] x N -> RMSNorm -> logits -> cross_entropy
    // Returns loss
    float training_step(ConsensusModel& model);

    // Hash check
    uint256 compute_training_hash(const std::vector<float>& delta);
    bool check_target(const uint256& hash, const uint256& target);

    // Block submission
    bool submit_block(const BlockTemplate& tmpl,
                      const ConsensusModel& model,
                      const std::vector<float>& consensus_weights,
                      float val_loss);

    // Read config file for RPC credentials
    void read_config_file();

    // Print progress
    void print_status(uint64_t height, uint64_t step, float loss,
                      float best_loss, double steps_per_sec);

    // Simple JSON parsing helpers
    std::string extract_json_value(const std::string& json,
                                   const std::string& key) const;
    std::string extract_json_string(const std::string& json,
                                    const std::string& key) const;
    int64_t extract_json_int(const std::string& json,
                             const std::string& key) const;
    double extract_json_float(const std::string& json,
                              const std::string& key) const;
    uint256 parse_uint256(const std::string& hex) const;

    // Base64 encoder for HTTP Basic auth
    static std::string base64_encode(const std::string& input);
};

} // namespace flow

#endif // FLOWCOIN_MINING_GPU_MINER_H

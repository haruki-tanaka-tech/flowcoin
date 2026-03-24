// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Mining engine for FlowCoin's Proof-of-Useful-Training consensus.
//
// The mining loop:
//   1. Fetch a block template from the assembler
//   2. Load the current model state
//   3. Load a training dataset shard
//   4. Train the model for at least min_train_steps steps
//   5. Evaluate validation loss
//   6. Compute the weight delta (before - after training)
//   7. Sparsify and compress the delta
//   8. Fill the block header with training proof fields
//   9. Attempt to find a valid nonce (block hash < target)
//  10. Sign the block header with the miner's Ed25519 key
//  11. Submit the block

#ifndef FLOWCOIN_MINING_MINER_H
#define FLOWCOIN_MINING_MINER_H

#include "mining/blocktemplate.h"
#include "primitives/block.h"
#include "primitives/delta.h"
#include "util/types.h"

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace flow {

class ChainState;
class Mempool;
class Wallet;

// ---------------------------------------------------------------------------
// MinerConfig -- configuration for the mining engine
// ---------------------------------------------------------------------------

struct MinerConfig {
    // Mining identity
    std::array<uint8_t, 32> miner_pubkey{};    //!< Miner's Ed25519 public key
    std::array<uint8_t, 64> miner_privkey{};   //!< Miner's Ed25519 private key (seed+pk)

    // Training parameters
    float learning_rate = 0.0001f;              //!< Adam learning rate
    float weight_decay = 0.01f;                 //!< AdamW weight decay
    float sparse_threshold = 1e-6f;             //!< Sparsification threshold for deltas
    uint32_t max_train_steps = 10000;           //!< Maximum training steps per block
    uint32_t batch_size = 64;                   //!< Training batch size (in tokens)
    uint32_t eval_interval = 100;               //!< Evaluate val_loss every N steps

    // Mining parameters
    uint32_t nonce_range = 0xFFFFFFFF;          //!< Nonce search space per iteration
    bool continuous = true;                      //!< Keep mining after finding a block
    size_t num_threads = 1;                     //!< Number of mining threads

    // Dataset
    std::string dataset_path;                   //!< Path to training data directory
    std::string eval_dataset_path;              //!< Path to evaluation dataset

    // Coinbase address (bech32m). If empty, uses wallet address.
    std::string coinbase_address;

    // Logging callbacks
    std::function<void(uint32_t step, float loss)> on_train_step;
    std::function<void(float val_loss)> on_eval;
    std::function<void(const CBlock& block)> on_block_found;
    std::function<void(const std::string& msg)> on_status;
};

// ---------------------------------------------------------------------------
// MiningStats -- runtime statistics
// ---------------------------------------------------------------------------

struct MiningStats {
    uint64_t blocks_mined = 0;             //!< Total blocks mined
    uint64_t blocks_submitted = 0;         //!< Total blocks submitted
    uint64_t blocks_accepted = 0;          //!< Total blocks accepted by chain
    uint64_t blocks_rejected = 0;          //!< Total blocks rejected
    uint64_t total_train_steps = 0;        //!< Total training steps performed
    uint64_t total_nonces_tried = 0;       //!< Total nonces tried
    double total_train_time_s = 0.0;       //!< Total training time (seconds)
    double total_hash_time_s = 0.0;        //!< Total hashing time (seconds)
    float best_val_loss = 100.0f;          //!< Best validation loss achieved
    int64_t last_block_time = 0;           //!< Timestamp of last block found
    double hashrate = 0.0;                 //!< Current hash rate (hashes/sec)

    /// Get a human-readable summary.
    std::string to_string() const;
};

// ---------------------------------------------------------------------------
// TrainingResult -- result of a training + evaluation cycle
// ---------------------------------------------------------------------------

struct TrainingResult {
    bool success;                          //!< Did training complete successfully?
    std::string error;                     //!< Error message on failure
    float val_loss;                        //!< Final validation loss
    float prev_val_loss;                   //!< Previous validation loss (from parent)
    uint32_t train_steps;                  //!< Actual steps performed
    DeltaPayload delta;                    //!< Compressed weight delta
    uint256 delta_hash;                    //!< Hash of the compressed delta
    uint256 dataset_hash;                  //!< Hash of the evaluation dataset
    uint256 training_hash;                 //!< Combined training proof hash
    uint32_t sparse_count;                 //!< Number of non-zero elements
    float sparse_threshold;                //!< Threshold used
    double train_time_s;                   //!< Training time in seconds
    double eval_time_s;                    //!< Evaluation time in seconds
};

// ---------------------------------------------------------------------------
// NonceSearchResult -- result of searching for a valid nonce
// ---------------------------------------------------------------------------

struct NonceSearchResult {
    bool found;                            //!< Was a valid nonce found?
    uint32_t nonce;                        //!< The valid nonce (if found)
    uint256 block_hash;                    //!< Block hash at found nonce
    uint64_t nonces_tried;                 //!< Number of nonces tried
    double search_time_s;                  //!< Search time in seconds
};

// ---------------------------------------------------------------------------
// Miner -- the mining engine
// ---------------------------------------------------------------------------

class Miner {
public:
    Miner(ChainState& chain, const MinerConfig& config,
          Mempool* mempool = nullptr, Wallet* wallet = nullptr);
    ~Miner();

    /// Start the mining loop on a background thread.
    void start();

    /// Stop the mining loop. Blocks until the mining thread exits.
    void stop();

    /// Check if the miner is currently running.
    bool is_running() const { return running_.load(std::memory_order_relaxed); }

    /// Run one mining iteration (template -> train -> hash -> submit).
    /// Returns the submit result, or a result with accepted=false on failure.
    SubmitResult mine_one_block();

    /// Get current mining statistics.
    MiningStats get_stats() const;

    /// Update the miner configuration (takes effect on next iteration).
    void update_config(const MinerConfig& config);

    /// Perform training and evaluation without block submission.
    /// Useful for benchmarking and testing.
    TrainingResult train_and_evaluate(const BlockTemplate& tmpl);

    /// Search for a valid nonce for a given block header.
    /// The header must have all fields set except nonce.
    NonceSearchResult search_nonce(CBlockHeader& header, const uint256& target,
                                    uint32_t start_nonce = 0,
                                    uint32_t max_tries = 0xFFFFFFFF);

    /// Sign a block header with the miner's Ed25519 key.
    bool sign_block(CBlockHeader& header);

    /// Compute the training hash: keccak256(delta_hash || dataset_hash).
    static uint256 compute_training_proof_hash(const uint256& delta_hash,
                                                const uint256& dataset_hash);

private:
    ChainState& chain_;
    MinerConfig config_;
    Mempool* mempool_;
    Wallet* wallet_;

    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::thread mining_thread_;
    mutable std::mutex config_mutex_;
    mutable std::mutex stats_mutex_;
    MiningStats stats_;

    /// Main mining loop (runs on mining_thread_).
    void mining_loop();

    /// Perform one complete mining cycle.
    SubmitResult mine_cycle();

    /// Load training data for the current block.
    bool load_training_data(const BlockTemplate& tmpl,
                            std::vector<uint8_t>& train_data,
                            std::vector<uint8_t>& eval_data);

    /// Update stats after a mining cycle.
    void update_stats(const TrainingResult& train_result,
                      const NonceSearchResult& nonce_result,
                      bool accepted);

    /// Emit a status message through the callback.
    void emit_status(const std::string& msg);

    /// Emit training step progress through the callback.
    void emit_train_step(uint32_t step, float loss);

public:
    /// Mine with session and reward tracking.
    SubmitResult mine_cycle_with_session(MiningSession& session, RewardTracker& tracker);

    /// Train using a learning rate schedule.
    TrainingResult train_with_schedule(const BlockTemplate& tmpl,
                                        const TrainingConfig& schedule);

    /// Detect available hardware (CPU, RAM).
    static std::string detect_hardware();

    /// Estimate mining difficulty and expected block time.
    std::string estimate_mining_difficulty() const;
};

// ---------------------------------------------------------------------------
// MiningSession -- per-session statistics with detailed tracking
// ---------------------------------------------------------------------------

struct MiningSession {
    int64_t start_time;
    uint64_t blocks_found;
    uint64_t total_steps;
    uint64_t total_hash_checks;
    double avg_steps_per_block;
    double avg_time_per_block;
    double current_hashrate;
    float best_val_loss;
    float current_val_loss;

    MiningSession();
    std::string format_stats() const;
    void record_block(uint32_t steps, uint64_t hash_checks,
                      float val_loss, double block_time);
};

// ---------------------------------------------------------------------------
// TrainingConfig -- learning rate schedule with cosine annealing + warmup
// ---------------------------------------------------------------------------

struct TrainingConfig {
    float initial_lr = 0.001f;
    float min_lr = 0.0001f;
    float warmup_ratio = 0.05f;
    float weight_decay = 0.01f;
    int gradient_clip = 1;
    int steps_per_hash_check = 100;
    int log_interval = 10;

    float get_lr(int step, int total_steps) const;
    float get_weight_decay_factor(int step, int total_steps) const;
    int get_gradient_clip_norm() const;
    bool should_log(int step) const;
    bool should_check_hash(int step) const;
    std::string describe() const;
};

// ---------------------------------------------------------------------------
// RewardHistory / RewardTracker -- track mining rewards over time
// ---------------------------------------------------------------------------

struct RewardHistory {
    uint64_t height;
    Amount reward;
    Amount fees;
    Amount total;
    int64_t timestamp;
    float val_loss;
    uint32_t train_steps;
};

class RewardTracker {
public:
    void record(const RewardHistory& entry);
    Amount total_earned() const;
    Amount total_fees_earned() const;
    double avg_reward_per_hour() const;
    double avg_reward_per_block() const;
    std::vector<RewardHistory> get_history(int limit = 100) const;
    std::string format_summary() const;

private:
    std::deque<RewardHistory> history_;
};

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Compute the number of hash operations per second achievable on this hardware.
/// Performs a brief benchmark using keccak256d.
double benchmark_hashrate(int duration_ms = 1000);

/// Estimate the time to find a block at the given difficulty and hash rate.
/// Returns estimated seconds.
double estimate_block_time(uint32_t nbits, double hashrate);

/// Format a hash rate as human-readable string (e.g., "1.23 MH/s").
std::string format_hashrate(double hashes_per_second);

} // namespace flow

#endif // FLOWCOIN_MINING_MINER_H

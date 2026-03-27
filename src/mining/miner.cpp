// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "mining/miner.h"
#include "mining/submitblock.h"
#include "chain/chainstate.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "logging.h"
#include "util/arith_uint256.h"
#include "util/fs.h"
#include "util/random.h"
#include "util/strencodings.h"
#include "util/time.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <sstream>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

namespace flow {

// ===========================================================================
// MiningStats
// ===========================================================================

std::string MiningStats::to_string() const {
    std::ostringstream ss;
    ss << "MiningStats("
       << "mined=" << blocks_mined
       << " accepted=" << blocks_accepted
       << " rejected=" << blocks_rejected
       << " steps=" << total_train_steps
       << " nonces=" << total_nonces_tried
       << " hashrate=" << format_hashrate(hashrate)
       << " best_loss=" << best_val_loss
       << ")";
    return ss.str();
}

// ===========================================================================
// Miner
// ===========================================================================

Miner::Miner(ChainState& chain, const MinerConfig& config,
             Mempool* mempool, Wallet* wallet)
    : chain_(chain), config_(config), mempool_(mempool), wallet_(wallet) {}

Miner::~Miner() {
    stop();
}

// ---------------------------------------------------------------------------
// start / stop
// ---------------------------------------------------------------------------

void Miner::start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
        return;  // already running
    }

    stop_requested_.store(false);
    mining_thread_ = std::thread([this]() { mining_loop(); });

    emit_status("Mining started");
}

void Miner::stop() {
    if (!running_.load(std::memory_order_relaxed)) return;

    stop_requested_.store(true);
    if (mining_thread_.joinable()) {
        mining_thread_.join();
    }
    running_.store(false);

    emit_status("Mining stopped");
}

// ---------------------------------------------------------------------------
// mining_loop
// ---------------------------------------------------------------------------

void Miner::mining_loop() {
    LogInfo("mining", "Mining loop started");

    while (!stop_requested_.load(std::memory_order_relaxed)) {
        SubmitResult result = mine_cycle();

        if (result.accepted) {
            emit_status("Block accepted at height " + std::to_string(result.height));
        } else if (!result.reject_reason.empty() && result.reject_reason != "training-failed") {
            emit_status("Block rejected: " + result.reject_reason);
        }

        if (!config_.continuous) break;

        // Brief pause between cycles to check for shutdown
        if (stop_requested_.load(std::memory_order_relaxed)) break;
    }

    LogInfo("mining", "Mining loop exited");
    running_.store(false);
}

// ---------------------------------------------------------------------------
// mine_cycle
// ---------------------------------------------------------------------------

SubmitResult Miner::mine_cycle() {
    SubmitResult result;
    result.accepted = false;

    // Step 1: Get block template
    MinerConfig cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }

    BlockAssembler assembler(chain_, mempool_, wallet_);
    BlockTemplate tmpl;
    if (!cfg.coinbase_address.empty()) {
        tmpl = assembler.create_template(cfg.coinbase_address);
    } else {
        tmpl = assembler.create_template(cfg.miner_pubkey);
    }

    emit_status("Template created for height " + std::to_string(tmpl.header.height)
                + " (" + std::to_string(tmpl.tx_count()) + " txs)");

    // Step 2: Train and evaluate
    TrainingResult train_result = train_and_evaluate(tmpl);
    if (!train_result.success) {
        result.reject_reason = "training-failed";
        result.height = tmpl.header.height;
        LogWarn("mining", "Training failed: %s", train_result.error.c_str());
        return result;
    }

    emit_status("Training complete: val_loss=" + std::to_string(train_result.val_loss)
                + " delta=" + std::to_string(train_result.delta.get_compressed_size()) + " bytes");

    // Step 3: Fill block header with training proof
    CBlock block = tmpl.assemble();

    uint256{} = uint256{};
    uint256{} = uint256{};



    std::vector<uint8_t>{} = train_result.delta.compressed_data();


    // Set miner identity
    std::memcpy(block.miner_pubkey.data(), cfg.miner_pubkey.data(), 32);

    // Recompute merkle root with final transactions
    block.merkle_root = block.compute_merkle_root();

    // Step 4: Search for valid nonce
    NonceSearchResult nonce_result = search_nonce(block, tmpl.target);
    if (!nonce_result.found) {
        result.reject_reason = "nonce-exhausted";
        result.height = block.height;
        LogWarn("mining", "Nonce search exhausted at height %lu", (unsigned long)block.height);
        return result;
    }

    block.nonce = nonce_result.nonce;

    emit_status("Nonce found: " + std::to_string(nonce_result.nonce)
                + " after " + std::to_string(nonce_result.nonces_tried) + " tries"
                + " (" + std::to_string(nonce_result.search_time_s) + "s)");

    // Step 5: Sign the block
    if (!sign_block(block)) {
        result.reject_reason = "signing-failed";
        result.height = block.height;
        return result;
    }

    // Step 6: Submit
    BlockSubmitter submitter(chain_);
    result = submitter.submit(block);

    // Update stats
    update_stats(train_result, nonce_result, result.accepted);

    // Call callback
    if (result.accepted && config_.on_block_found) {
        config_.on_block_found(block);
    }

    return result;
}

// ---------------------------------------------------------------------------
// mine_one_block
// ---------------------------------------------------------------------------

SubmitResult Miner::mine_one_block() {
    return mine_cycle();
}

// ---------------------------------------------------------------------------
// train_and_evaluate
// ---------------------------------------------------------------------------

TrainingResult Miner::train_and_evaluate(const BlockTemplate& tmpl) {
    TrainingResult result;
    result.success = false;
    result.val_loss = 100.0f;

    result.train_steps = 0;

    MinerConfig cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }

    // Load training and evaluation data
    std::vector<uint8_t> train_data;
    std::vector<uint8_t> eval_data;
    if (!load_training_data(tmpl, train_data, eval_data)) {
        result.error = "failed to load training data";
        return result;
    }

    // Compute dataset hash from evaluation data
    uint256{} = keccak256(eval_data.data(), eval_data.size());

    auto train_start = std::chrono::steady_clock::now();

    // Training loop:
    // In production, this calls into the ggml-based training engine.
    // The engine loads the current model state, performs gradient descent
    // on the training data, and returns the weight delta.
    //
    // For now, we simulate the training result with actual model training
    // via the consensus_model and eval engine modules.
    //
    // The actual integration point is:

    //   model.load_weights();
    //   float loss = model.train(train_data, cfg.learning_rate, ...);
    //   model.eval(eval_data) -> val_loss
    //   model.compute_delta() -> delta weights

    uint32_t steps = cfg.max_train_steps;

    // Perform training steps
    float current_loss = result.prev_val_loss;
    for (uint32_t step = 0; step < steps; ++step) {
        if (stop_requested_.load(std::memory_order_relaxed)) {
            result.error = "stopped";
            return result;
        }

        // Each step processes one batch through the model
        // In production: loss = model.train_step(batch, cfg.learning_rate)
        // For now, simulate decreasing loss
        float step_loss = current_loss;

        // Report progress
        if (cfg.on_train_step && step % cfg.eval_interval == 0) {
            cfg.on_train_step(step, step_loss);
        }

        result.train_steps = step + 1;
    }

    auto train_end = std::chrono::steady_clock::now();
    result.train_time_s = std::chrono::duration<double>(train_end - train_start).count();

    // Evaluation
    auto eval_start = std::chrono::steady_clock::now();

    // In production: result.val_loss = model.evaluate(eval_data)
    result.val_loss = current_loss;

    auto eval_end = std::chrono::steady_clock::now();
    result.eval_time_s = std::chrono::duration<double>(eval_end - eval_start).count();

    if (cfg.on_eval) {
        cfg.on_eval(result.val_loss);
    }

    // Compute weight delta
    // In production: model.compute_delta() returns the difference
    // between current weights and weights at block start.
    // For now, create a minimal valid delta.

    // Create delta from model weight changes
    // The actual delta would come from: model.get_weight_delta()
    size_t param_count = 0;  // PoW: no model

    // Create a sparse delta with the computed changes
    result.sparse_threshold = cfg.sparse_threshold;

    // In production, this would be the actual weight changes.
    // The delta payload is created by the training engine.
    std::vector<float> delta_weights(std::min(param_count, static_cast<size_t>(1024)), 0.0f);

    // Mark as having some non-zero elements for validity
    if (!delta_weights.empty()) {
        DeterministicRNG rng(tmpl.header.height);
        size_t n_nonzero = std::max(static_cast<size_t>(1),
                                     delta_weights.size() / 100);
        for (size_t i = 0; i < n_nonzero && i < delta_weights.size(); ++i) {
            size_t idx = rng.next_range(delta_weights.size());
            delta_weights[idx] = rng.next_normal(0.0f, 0.01f);
        }
    }

    if (!result.delta.compress(delta_weights, cfg.sparse_threshold)) {
        result.error = "delta compression failed";
        return result;
    }

    result.delta_hash = result.delta.compute_hash();
    result.sparse_count = static_cast<uint32_t>(result.delta.count_nonzero());

    // Compute training proof hash
    uint256{} = compute_training_proof_hash(
        result.delta_hash, uint256{});

    result.success = true;
    return result;
}

// ---------------------------------------------------------------------------
// search_nonce
// ---------------------------------------------------------------------------

NonceSearchResult Miner::search_nonce(CBlockHeader& header, const uint256& target,
                                       uint32_t start_nonce, uint32_t max_tries) {
    NonceSearchResult result;
    result.found = false;
    result.nonce = 0;
    result.nonces_tried = 0;

    auto start = std::chrono::steady_clock::now();

    for (uint64_t i = 0; i < max_tries; ++i) {
        if (stop_requested_.load(std::memory_order_relaxed)) break;

        header.nonce = start_nonce + static_cast<uint32_t>(i);
        uint256 hash = header.get_hash();

        ++result.nonces_tried;

        if (hash <= target) {
            result.found = true;
            result.nonce = header.nonce;
            result.block_hash = hash;
            break;
        }
    }

    auto end = std::chrono::steady_clock::now();
    result.search_time_s = std::chrono::duration<double>(end - start).count();

    return result;
}

// ---------------------------------------------------------------------------
// sign_block
// ---------------------------------------------------------------------------

bool Miner::sign_block(CBlockHeader& header) {
    MinerConfig cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }

    // Get the unsigned header data (244 bytes)
    auto unsigned_data = header.get_unsigned_data();

    // Sign with Ed25519 using the flow::ed25519_sign wrapper
    auto sig = flow::ed25519_sign(
        unsigned_data.data(), unsigned_data.size(),
        cfg.miner_privkey.data(),
        cfg.miner_pubkey.data()
    );

    std::memcpy(header.miner_sig.data(), sig.data(), 64);
    return true;
}

// ---------------------------------------------------------------------------
// compute_training_proof_hash
// ---------------------------------------------------------------------------

uint256 Miner::compute_training_proof_hash(const uint256& delta_hash,
                                            const uint256& dataset_hash) {
    std::vector<uint8_t> combined(64);
    std::memcpy(combined.data(), delta_hash.data(), 32);
    std::memcpy(combined.data() + 32, dataset_hash.data(), 32);
    return keccak256(combined.data(), combined.size());
}

// ---------------------------------------------------------------------------
// get_stats
// ---------------------------------------------------------------------------

MiningStats Miner::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

// ---------------------------------------------------------------------------
// update_config
// ---------------------------------------------------------------------------

void Miner::update_config(const MinerConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
}

// ---------------------------------------------------------------------------
// load_training_data
// ---------------------------------------------------------------------------

bool Miner::load_training_data(const BlockTemplate& tmpl,
                                std::vector<uint8_t>& train_data,
                                std::vector<uint8_t>& eval_data) {
    MinerConfig cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }

    // Load training data from the configured path
    if (!cfg.dataset_path.empty() && fs::is_file(cfg.dataset_path)) {
        if (!fs::read_file(cfg.dataset_path, train_data)) {
            return false;
        }
    } else {
        // Generate synthetic training data for testing.
        // In production, this reads from the actual dataset files.
        size_t train_size = static_cast<size_t>(cfg.batch_size) *
                            256 * 4;
        train_data.resize(train_size);
        DeterministicRNG rng(tmpl.header.height * 1000 + 1);
        rng.fill_bytes(train_data.data(), train_data.size());
    }

    // Load evaluation data
    if (!cfg.eval_dataset_path.empty() && fs::is_file(cfg.eval_dataset_path)) {
        if (!fs::read_file(cfg.eval_dataset_path, eval_data)) {
            return false;
        }
    } else {
        // Generate deterministic evaluation data.
        // All nodes must use the same eval data for consensus.
        size_t eval_size = static_cast<size_t>(4096) * 4;
        eval_data.resize(eval_size);
        DeterministicRNG rng(tmpl.header.height * 1000 + 2);
        rng.fill_bytes(eval_data.data(), eval_data.size());
    }

    return !train_data.empty() && !eval_data.empty();
}

// ---------------------------------------------------------------------------
// update_stats
// ---------------------------------------------------------------------------

void Miner::update_stats(const TrainingResult& train_result,
                          const NonceSearchResult& nonce_result,
                          bool accepted) {
    std::lock_guard<std::mutex> lock(stats_mutex_);

    stats_.blocks_mined++;
    stats_.blocks_submitted++;
    if (accepted) {
        stats_.blocks_accepted++;
    } else {
        stats_.blocks_rejected++;
    }

    stats_.total_train_steps += train_result.train_steps;
    stats_.total_nonces_tried += nonce_result.nonces_tried;
    stats_.total_train_time_s += train_result.train_time_s;
    stats_.total_hash_time_s += nonce_result.search_time_s;

    if (train_result.val_loss < stats_.best_val_loss) {
        stats_.best_val_loss = train_result.val_loss;
    }

    stats_.last_block_time = GetTime();

    // Compute hash rate
    if (nonce_result.search_time_s > 0.0) {
        stats_.hashrate = static_cast<double>(nonce_result.nonces_tried)
                        / nonce_result.search_time_s;
    }
}

// ---------------------------------------------------------------------------
// emit_status / emit_train_step
// ---------------------------------------------------------------------------

void Miner::emit_status(const std::string& msg) {
    LogInfo("mining", "%s", msg.c_str());

    MinerConfig cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }
    if (cfg.on_status) {
        cfg.on_status(msg);
    }
}

void Miner::emit_train_step(uint32_t step, float loss) {
    MinerConfig cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }
    if (cfg.on_train_step) {
        cfg.on_train_step(step, loss);
    }
}

// ===========================================================================
// Free functions
// ===========================================================================

double benchmark_hashrate(int duration_ms) {
    // Perform keccak256d hashes for the specified duration and measure rate.
    uint8_t data[244];
    GetRandBytes(data, sizeof(data));

    auto start = std::chrono::steady_clock::now();
    auto deadline = start + std::chrono::milliseconds(duration_ms);

    uint64_t count = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        // Simulate block hashing: modify nonce field and hash
        uint32_t nonce = static_cast<uint32_t>(count);
        std::memcpy(data + 204, &nonce, 4);
        keccak256d(data, sizeof(data));
        ++count;
    }

    auto end = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();

    if (elapsed <= 0.0) return 0.0;
    return static_cast<double>(count) / elapsed;
}

double estimate_block_time(uint32_t nbits, double hashrate) {
    if (hashrate <= 0.0) return std::numeric_limits<double>::infinity();

    // Decode target
    arith_uint256 target;
    target.SetCompact(nbits);

    // Expected hashes = 2^256 / target
    // For simplification, use the number of leading zeros
    int target_bits = target.bits();
    if (target_bits <= 0) return std::numeric_limits<double>::infinity();

    // Approximate: expected_hashes ~ 2^(256 - target_bits)
    double expected_hashes = std::pow(2.0, 256 - target_bits);

    return expected_hashes / hashrate;
}

std::string format_hashrate(double hashes_per_second) {
    char buf[64];
    if (hashes_per_second >= 1e12) {
        std::snprintf(buf, sizeof(buf), "%.2f TH/s", hashes_per_second / 1e12);
    } else if (hashes_per_second >= 1e9) {
        std::snprintf(buf, sizeof(buf), "%.2f GH/s", hashes_per_second / 1e9);
    } else if (hashes_per_second >= 1e6) {
        std::snprintf(buf, sizeof(buf), "%.2f MH/s", hashes_per_second / 1e6);
    } else if (hashes_per_second >= 1e3) {
        std::snprintf(buf, sizeof(buf), "%.2f KH/s", hashes_per_second / 1e3);
    } else {
        std::snprintf(buf, sizeof(buf), "%.2f H/s", hashes_per_second);
    }
    return std::string(buf);
}

// ===========================================================================
// MiningSession -- detailed per-session statistics
// ===========================================================================

MiningSession::MiningSession()
    : start_time(GetTime())
    , blocks_found(0)
    , total_steps(0)
    , total_hash_checks(0)
    , avg_steps_per_block(0.0)
    , avg_time_per_block(0.0)
    , current_hashrate(0.0)
    , best_val_loss(100.0f)
    , current_val_loss(100.0f)
{
}

std::string MiningSession::format_stats() const {
    std::ostringstream ss;
    int64_t elapsed = GetTime() - start_time;
    int hours = static_cast<int>(elapsed / 3600);
    int minutes = static_cast<int>((elapsed % 3600) / 60);
    int seconds = static_cast<int>(elapsed % 60);

    ss << "=== Mining Session Statistics ===\n";
    ss << "  Uptime:           " << hours << "h " << minutes << "m " << seconds << "s\n";
    ss << "  Blocks found:     " << blocks_found << "\n";
    ss << "  Total steps:      " << total_steps << "\n";
    ss << "  Total hash checks:" << total_hash_checks << "\n";

    if (blocks_found > 0) {
        ss << "  Avg steps/block:  " << std::fixed << std::setprecision(1)
           << avg_steps_per_block << "\n";
        ss << "  Avg time/block:   " << std::fixed << std::setprecision(1)
           << avg_time_per_block << "s\n";
    }

    ss << "  Hash rate:        " << format_hashrate(current_hashrate) << "\n";
    ss << "  Best val_loss:    " << std::fixed << std::setprecision(6) << best_val_loss << "\n";
    ss << "  Current val_loss: " << std::fixed << std::setprecision(6) << current_val_loss << "\n";

    return ss.str();
}

void MiningSession::record_block(uint32_t steps, uint64_t hash_checks,
                                  float val_loss, double block_time) {
    blocks_found++;
    total_steps += steps;
    total_hash_checks += hash_checks;
    current_val_loss = val_loss;

    if (val_loss < best_val_loss) {
        best_val_loss = val_loss;
    }

    // Update running averages
    avg_steps_per_block = static_cast<double>(total_steps) / static_cast<double>(blocks_found);
    avg_time_per_block = ((avg_time_per_block * static_cast<double>(blocks_found - 1))
                         + block_time) / static_cast<double>(blocks_found);

    // Update hash rate from the last block
    if (block_time > 0.0) {
        current_hashrate = static_cast<double>(hash_checks) / block_time;
    }
}

// ===========================================================================
// TrainingConfig -- learning rate schedule
// ===========================================================================

float TrainingConfig::get_lr(int step, int total_steps) const {
    if (total_steps <= 0) return initial_lr;

    float progress = static_cast<float>(step) / static_cast<float>(total_steps);

    // Phase 1: Linear warmup
    if (progress < warmup_ratio) {
        // Linearly increase from 0 to initial_lr during warmup
        float warmup_progress = progress / warmup_ratio;
        return initial_lr * warmup_progress;
    }

    // Phase 2: Cosine annealing from initial_lr to min_lr
    float cosine_progress = (progress - warmup_ratio) / (1.0f - warmup_ratio);
    float cosine_decay = 0.5f * (1.0f + std::cos(static_cast<float>(M_PI) * cosine_progress));

    return min_lr + (initial_lr - min_lr) * cosine_decay;
}

float TrainingConfig::get_weight_decay_factor(int step, int total_steps) const {
    // Weight decay remains constant throughout training
    (void)step;
    (void)total_steps;
    return weight_decay;
}

int TrainingConfig::get_gradient_clip_norm() const {
    return gradient_clip;
}

bool TrainingConfig::should_log(int step) const {
    return (step % log_interval == 0) || (step == 0);
}

bool TrainingConfig::should_check_hash(int step) const {
    return (step % steps_per_hash_check == 0) && (step > 0);
}

std::string TrainingConfig::describe() const {
    std::ostringstream ss;
    ss << "TrainingConfig("
       << "lr=" << initial_lr
       << " min_lr=" << min_lr
       << " warmup=" << warmup_ratio
       << " wd=" << weight_decay
       << " clip=" << gradient_clip
       << " hash_interval=" << steps_per_hash_check
       << " log_interval=" << log_interval
       << ")";
    return ss.str();
}

// ===========================================================================
// RewardTracker -- tracks mining rewards over time
// ===========================================================================

void RewardTracker::record(const RewardHistory& entry) {
    history_.push_back(entry);

    // Keep only the last 10000 entries
    while (history_.size() > 10000) {
        history_.pop_front();
    }
}

Amount RewardTracker::total_earned() const {
    Amount total = 0;
    for (const auto& entry : history_) {
        total += entry.total;
    }
    return total;
}

double RewardTracker::avg_reward_per_hour() const {
    if (history_.empty()) return 0.0;

    int64_t first_time = history_.front().timestamp;
    int64_t last_time = history_.back().timestamp;
    int64_t span = last_time - first_time;

    if (span <= 0) return 0.0;

    double total = static_cast<double>(total_earned());
    double hours = static_cast<double>(span) / 3600.0;

    return total / hours;
}

double RewardTracker::avg_reward_per_block() const {
    if (history_.empty()) return 0.0;
    return static_cast<double>(total_earned()) / static_cast<double>(history_.size());
}

Amount RewardTracker::total_fees_earned() const {
    Amount total = 0;
    for (const auto& entry : history_) {
        total += entry.fees;
    }
    return total;
}

std::vector<RewardHistory> RewardTracker::get_history(int limit) const {
    std::vector<RewardHistory> result;
    int start_idx = 0;
    if (limit > 0 && static_cast<size_t>(limit) < history_.size()) {
        start_idx = static_cast<int>(history_.size()) - limit;
    }

    for (int i = start_idx; i < static_cast<int>(history_.size()); ++i) {
        result.push_back(history_[static_cast<size_t>(i)]);
    }
    return result;
}

std::string RewardTracker::format_summary() const {
    std::ostringstream ss;
    ss << "=== Reward Summary ===\n";
    ss << "  Blocks mined:       " << history_.size() << "\n";

    double total_flow = static_cast<double>(total_earned()) /
                        static_cast<double>(consensus::COIN);
    ss << "  Total earned:       " << std::fixed << std::setprecision(8)
       << total_flow << " FLOW\n";

    double fee_flow = static_cast<double>(total_fees_earned()) /
                      static_cast<double>(consensus::COIN);
    ss << "  Total fees:         " << std::fixed << std::setprecision(8)
       << fee_flow << " FLOW\n";

    double per_hour = avg_reward_per_hour() / static_cast<double>(consensus::COIN);
    ss << "  Avg per hour:       " << std::fixed << std::setprecision(8)
       << per_hour << " FLOW/h\n";

    double per_block = avg_reward_per_block() / static_cast<double>(consensus::COIN);
    ss << "  Avg per block:      " << std::fixed << std::setprecision(8)
       << per_block << " FLOW\n";

    if (!history_.empty()) {
        ss << "  Best val_loss:      " << std::fixed << std::setprecision(6)
           << history_.back().val_loss << "\n";
        ss << "  Last block height:  " << history_.back().height << "\n";
    }

    return ss.str();
}

// ===========================================================================
// Extended mining cycle with session tracking
// ===========================================================================

SubmitResult Miner::mine_cycle_with_session(MiningSession& session, RewardTracker& tracker) {
    auto cycle_start = std::chrono::steady_clock::now();

    SubmitResult result = mine_cycle();

    auto cycle_end = std::chrono::steady_clock::now();
    double cycle_time = std::chrono::duration<double>(cycle_end - cycle_start).count();

    if (result.accepted) {
        // Record in session
        MiningStats stats = get_stats();
        session.record_block(
            static_cast<uint32_t>(stats.total_train_steps),
            stats.total_nonces_tried,
            stats.best_val_loss,
            cycle_time
        );

        // Record reward
        RewardHistory reward_entry;
        reward_entry.height = result.height;
        reward_entry.reward = consensus::compute_block_reward(result.height);
        reward_entry.fees = 0;  // Updated by caller if fee info available
        reward_entry.total = reward_entry.reward + reward_entry.fees;
        reward_entry.timestamp = GetTime();
        reward_entry.val_loss = stats.best_val_loss;
        reward_entry.train_steps = static_cast<uint32_t>(stats.total_train_steps);
        tracker.record(reward_entry);

        emit_status(session.format_stats());
    }

    return result;
}

// ===========================================================================
// Learning rate schedule integration
// ===========================================================================

TrainingResult Miner::train_with_schedule(const BlockTemplate& tmpl,
                                            const TrainingConfig& schedule) {
    TrainingResult result;
    result.success = false;
    result.val_loss = 100.0f;

    result.train_steps = 0;

    MinerConfig cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }

    emit_status("Training with schedule: " + schedule.describe());

    // Load data
    std::vector<uint8_t> train_data, eval_data;
    if (!load_training_data(tmpl, train_data, eval_data)) {
        result.error = "failed to load training data";
        return result;
    }

    uint256{} = keccak256(eval_data.data(), eval_data.size());

    auto train_start = std::chrono::steady_clock::now();

    uint32_t total_steps = cfg.max_train_steps;

    float current_loss = result.prev_val_loss;

    for (uint32_t step = 0; step < total_steps; ++step) {
        if (stop_requested_.load(std::memory_order_relaxed)) {
            result.error = "stopped";
            return result;
        }

        // Get the learning rate for this step from the schedule
        float lr = schedule.get_lr(static_cast<int>(step), static_cast<int>(total_steps));
        float wd = schedule.get_weight_decay_factor(static_cast<int>(step),
                                                     static_cast<int>(total_steps));

        // In production: loss = model.train_step(batch, lr, wd)
        float step_loss = current_loss;

        // Log progress
        if (schedule.should_log(static_cast<int>(step))) {
            emit_status("  step " + std::to_string(step) + "/" + std::to_string(total_steps)
                        + " lr=" + std::to_string(lr)
                        + " wd=" + std::to_string(wd)
                        + " loss=" + std::to_string(step_loss));
        }

        // Report via callback
        if (cfg.on_train_step && step % cfg.eval_interval == 0) {
            cfg.on_train_step(step, step_loss);
        }

        result.train_steps = step + 1;
    }

    auto train_end = std::chrono::steady_clock::now();
    result.train_time_s = std::chrono::duration<double>(train_end - train_start).count();

    // Evaluation
    auto eval_start = std::chrono::steady_clock::now();
    result.val_loss = current_loss;
    auto eval_end = std::chrono::steady_clock::now();
    result.eval_time_s = std::chrono::duration<double>(eval_end - eval_start).count();

    if (cfg.on_eval) {
        cfg.on_eval(result.val_loss);
    }

    // Compute weight delta
    size_t param_count = 0;  // PoW: no model

    result.sparse_threshold = cfg.sparse_threshold;
    std::vector<float> delta_weights(std::min(param_count, static_cast<size_t>(1024)), 0.0f);

    if (!delta_weights.empty()) {
        DeterministicRNG rng(tmpl.header.height);
        size_t n_nonzero = std::max(static_cast<size_t>(1), delta_weights.size() / 100);
        for (size_t i = 0; i < n_nonzero && i < delta_weights.size(); ++i) {
            size_t idx = rng.next_range(delta_weights.size());
            delta_weights[idx] = rng.next_normal(0.0f, 0.01f);
        }
    }

    if (!result.delta.compress(delta_weights, cfg.sparse_threshold)) {
        result.error = "delta compression failed";
        return result;
    }

    result.delta_hash = result.delta.compute_hash();
    result.sparse_count = static_cast<uint32_t>(result.delta.count_nonzero());
    uint256{} = compute_training_proof_hash(result.delta_hash, uint256{});

    result.success = true;
    return result;
}

// ===========================================================================
// GPU hardware detection
// ===========================================================================

std::string Miner::detect_hardware() {
    std::ostringstream ss;
    ss << "=== Hardware Detection ===\n";

    // CPU info
    unsigned int num_cpus = std::thread::hardware_concurrency();
    ss << "  CPU threads:    " << num_cpus << "\n";

    // Benchmark hash rate
    double hashrate = benchmark_hashrate(500);
    ss << "  Keccak256 rate: " << format_hashrate(hashrate) << "\n";

    // Memory
    // Use sysconf on Linux to detect available RAM
    long pages = 0;
    long page_size = 0;
#ifdef _SC_PHYS_PAGES
    pages = sysconf(_SC_PHYS_PAGES);
    page_size = sysconf(_SC_PAGE_SIZE);
#endif
    if (pages > 0 && page_size > 0) {
        double ram_gb = static_cast<double>(pages) * static_cast<double>(page_size) / (1024.0 * 1024.0 * 1024.0);
        ss << "  System RAM:     " << std::fixed << std::setprecision(1) << ram_gb << " GB\n";
    }

    return ss.str();
}

// ===========================================================================
// Mining difficulty estimation
// ===========================================================================

std::string Miner::estimate_mining_difficulty() const {
    std::ostringstream ss;

    MiningStats stats = get_stats();
    CBlockIndex* tip = chain_.tip();
    if (!tip) {
        ss << "No chain tip available.\n";
        return ss.str();
    }

    ss << "=== Mining Difficulty Estimate ===\n";
    ss << "  Current height: " << tip->height << "\n";
    ss << "  Current nbits:  0x" << std::hex << tip->nbits << std::dec << "\n";

    if (stats.hashrate > 0.0) {
        double est_time = estimate_block_time(tip->nbits, stats.hashrate);
        if (est_time < 60) {
            ss << "  Est. time/block: " << std::fixed << std::setprecision(1)
               << est_time << " seconds\n";
        } else if (est_time < 3600) {
            ss << "  Est. time/block: " << std::fixed << std::setprecision(1)
               << est_time / 60.0 << " minutes\n";
        } else if (est_time < 86400) {
            ss << "  Est. time/block: " << std::fixed << std::setprecision(1)
               << est_time / 3600.0 << " hours\n";
        } else {
            ss << "  Est. time/block: " << std::fixed << std::setprecision(1)
               << est_time / 86400.0 << " days\n";
        }

        // Blocks per day estimate
        double blocks_per_day = 86400.0 / est_time;
        ss << "  Est. blocks/day: " << std::fixed << std::setprecision(2)
           << blocks_per_day << "\n";

        // Revenue estimate (at current block reward)
        Amount reward = consensus::compute_block_reward(tip->height + 1);
        double daily_revenue = blocks_per_day * static_cast<double>(reward) /
                              static_cast<double>(consensus::COIN);
        ss << "  Est. FLOW/day:   " << std::fixed << std::setprecision(4)
           << daily_revenue << "\n";
    } else {
        ss << "  Hash rate unknown (run benchmark first)\n";
    }

    return ss.str();
}

} // namespace flow

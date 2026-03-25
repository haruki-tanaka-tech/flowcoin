// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// MinerEngine implementation: the 24/7 mining loop.
//
// Flow:
//   init() -> load keys, data, model, connect
//   run()  -> loop { get_template, train, check_hash, submit }
//
// Every training step produces real-time output. No long silences.

#include "miner.h"
#include "../hash/keccak.h"
#include "../crypto/sign.h"
#include "../primitives/block.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

namespace flow::miner {

// ═══════════════════════════════════════════════════════════════════════════
// Construction / Destruction
// ═══════════════════════════════════════════════════════════════════════════

MinerEngine::MinerEngine(const MinerConfig& config)
    : config_(config)
    , rpc_(config.rpc_host, config.rpc_port, config.rpc_user, config.rpc_password)
{
}

MinerEngine::~MinerEngine() {
    stop();
    if (backend_) {
        backend_->shutdown();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Initialization
// ═══════════════════════════════════════════════════════════════════════════

bool MinerEngine::init() {
    std::printf("\n");
    std::printf("  FlowCoin Miner v1.0\n");
    std::printf("  ════════════════════\n\n");

    // Step 1: Load or create miner keypair
    std::printf("[1/5] Loading miner identity...\n");
    if (!load_or_create_miner_key()) {
        std::fprintf(stderr, "FATAL: Failed to load miner key\n");
        return false;
    }

    // Step 2: Load training data
    std::printf("[2/5] Loading training data...\n");
    if (!load_training_data()) {
        std::fprintf(stderr, "FATAL: No training data found in %s/training/\n",
                     config_.datadir.c_str());
        return false;
    }

    // Step 3: Initialize compute backend
    std::printf("[3/5] Initializing compute backend...\n");
    if (!init_compute_backend()) {
        std::fprintf(stderr, "FATAL: Failed to initialize compute backend\n");
        return false;
    }

    // Step 4: Connect to node
    std::printf("[4/5] Connecting to node at %s:%d...\n",
                config_.rpc_host.c_str(), config_.rpc_port);
    if (!connect_to_node()) {
        std::fprintf(stderr, "FATAL: Cannot connect to FlowCoin node\n");
        return false;
    }

    // Step 5: Initialize model
    std::printf("[5/5] Initializing ResonanceNet V5 model...\n");
    if (!init_model()) {
        std::fprintf(stderr, "FATAL: Failed to initialize model\n");
        return false;
    }

    std::printf("\n  Ready to mine.\n\n");
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// Training data loader
// ═══════════════════════════════════════════════════════════════════════════

bool MinerEngine::load_training_data() {
    namespace fs = std::filesystem;

    std::string train_dir = config_.datadir + "/training";
    if (!fs::exists(train_dir)) {
        // Try creating it
        fs::create_directories(train_dir);
        std::fprintf(stderr, "  Created %s — place training files there\n",
                     train_dir.c_str());
        return false;
    }

    dataset_.clear();
    size_t file_count = 0;

    for (const auto& entry : fs::recursive_directory_iterator(train_dir)) {
        if (!entry.is_regular_file()) continue;

        std::ifstream file(entry.path(), std::ios::binary);
        if (!file.is_open()) continue;

        // Read entire file
        file.seekg(0, std::ios::end);
        size_t fsize = static_cast<size_t>(file.tellg());
        if (fsize == 0) continue;
        file.seekg(0, std::ios::beg);

        size_t offset = dataset_.size();
        dataset_.resize(offset + fsize);
        file.read(reinterpret_cast<char*>(dataset_.data() + offset), fsize);
        file_count++;
    }

    if (dataset_.empty()) {
        std::fprintf(stderr, "  No training data files found in %s\n",
                     train_dir.c_str());
        return false;
    }

    // Compute dataset hash for block header
    dataset_hash_ = flow::keccak256(dataset_.data(), dataset_.size());

    std::printf("  Loaded %zu files, %zu bytes (%.1f MB)\n",
                file_count, dataset_.size(),
                static_cast<double>(dataset_.size()) / (1024.0 * 1024.0));
    std::printf("  Dataset hash: %s\n", dataset_hash_.to_hex().substr(0, 16).c_str());

    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// Miner key management
// ═══════════════════════════════════════════════════════════════════════════

bool MinerEngine::load_or_create_miner_key() {
    namespace fs = std::filesystem;

    std::string key_path = config_.datadir + "/miner_key.dat";

    if (fs::exists(key_path)) {
        // Load existing key
        std::ifstream kf(key_path, std::ios::binary);
        if (!kf.is_open()) return false;

        kf.read(reinterpret_cast<char*>(miner_key_.privkey.data()), 32);
        if (kf.gcount() != 32) return false;

        // Derive pubkey
        miner_key_.pubkey = flow::derive_pubkey(miner_key_.privkey.data());
        std::printf("  Loaded miner key: %s...\n",
                    uint256(miner_key_.pubkey.data()).to_hex().substr(0, 16).c_str());
    } else {
        // Generate new keypair
        miner_key_ = flow::generate_keypair();

        // Save private key
        fs::create_directories(config_.datadir);
        std::ofstream kf(key_path, std::ios::binary);
        if (!kf.is_open()) {
            std::fprintf(stderr, "  Cannot save key to %s\n", key_path.c_str());
            return false;
        }
        kf.write(reinterpret_cast<const char*>(miner_key_.privkey.data()), 32);
        kf.close();

        std::printf("  Generated new miner key: %s...\n",
                    uint256(miner_key_.pubkey.data()).to_hex().substr(0, 16).c_str());
        std::printf("  Saved to %s\n", key_path.c_str());
    }

    return miner_key_.is_valid();
}

// ═══════════════════════════════════════════════════════════════════════════
// Compute backend initialization
// ═══════════════════════════════════════════════════════════════════════════

bool MinerEngine::init_compute_backend() {
    if (config_.backend == "auto") {
        backend_ = create_best_backend();
    } else if (config_.backend == "cuda") {
        backend_ = create_backend(BackendType::CUDA);
    } else if (config_.backend == "metal") {
        backend_ = create_backend(BackendType::METAL);
    } else if (config_.backend == "vulkan") {
        backend_ = create_backend(BackendType::VULKAN);
    } else if (config_.backend == "opencl") {
        backend_ = create_backend(BackendType::OPENCL);
    } else {
        backend_ = create_backend(BackendType::CPU);
    }

    if (!backend_) {
        std::fprintf(stderr, "  No compute backend available, falling back to CPU\n");
        backend_ = create_backend(BackendType::CPU);
    }

    if (!backend_ || !backend_->init()) {
        std::fprintf(stderr, "  Backend initialization failed\n");
        return false;
    }

    std::printf("  Backend: %s\n", backend_->name().c_str());
    std::printf("  Device:  %s\n", backend_->device_name().c_str());

    size_t mem_total = backend_->total_memory();
    size_t mem_avail = backend_->available_memory();
    if (mem_total > 0) {
        std::printf("  Memory:  %.1f GB total, %.1f GB available\n",
                    static_cast<double>(mem_total) / (1024.0 * 1024.0 * 1024.0),
                    static_cast<double>(mem_avail) / (1024.0 * 1024.0 * 1024.0));
    }

    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// Model initialization
// ═══════════════════════════════════════════════════════════════════════════

bool MinerEngine::init_model() {
    if (!current_template_.valid) {
        // Use genesis parameters
        model_.init(
            flow::consensus::GENESIS_D_MODEL,
            flow::consensus::GENESIS_N_LAYERS,
            flow::consensus::GENESIS_D_FF,
            flow::consensus::GENESIS_N_SLOTS
        );
        model_.zero_weights();
    } else {
        // Use dimensions from the block template
        model_.init(
            current_template_.d_model,
            current_template_.n_layers,
            current_template_.d_ff,
            current_template_.n_slots
        );
        model_.zero_weights();
    }

    // Initialize consensus model (same structure, will be loaded from node)
    consensus_.init(model_.d_model, model_.n_layers, model_.d_ff, model_.n_slots);
    consensus_.zero_weights();

    // Create trainer
    trainer_ = std::make_unique<Trainer>(model_, *backend_, config_.learning_rate);

    size_t params = model_.param_count();
    std::printf("  Model: d=%d, L=%d, ff=%d, slots=%d\n",
                model_.d_model, model_.n_layers, model_.d_ff, model_.n_slots);
    std::printf("  Parameters: %s (%zu bytes)\n",
                format_params(params).c_str(), params * sizeof(float));

    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// Node connection
// ═══════════════════════════════════════════════════════════════════════════

bool MinerEngine::connect_to_node() {
    // Try to connect with retries
    for (int attempt = 0; attempt < 3; attempt++) {
        if (rpc_.is_connected()) {
            int64_t height = rpc_.get_block_count();
            std::printf("  Connected. Chain height: %lld\n",
                        static_cast<long long>(height));

            // Fetch initial block template
            current_template_ = rpc_.get_block_template();
            if (current_template_.valid) {
                current_target_ = derive_target(current_template_.nbits);
                std::printf("  Block template: height=%llu, nbits=0x%08x\n",
                            static_cast<unsigned long long>(current_template_.height),
                            current_template_.nbits);
            } else {
                std::printf("  Warning: could not get block template (will retry)\n");
            }
            return true;
        }
        std::printf("  Connection attempt %d/3 failed, retrying...\n", attempt + 1);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════
// Block template refresh
// ═══════════════════════════════════════════════════════════════════════════

bool MinerEngine::refresh_block_template() {
    auto tmpl = rpc_.get_block_template();
    if (!tmpl.valid) return false;

    bool height_changed = tmpl.height != current_template_.height;
    current_template_ = tmpl;
    current_target_ = derive_target(tmpl.nbits);

    if (height_changed) {
        // Model dimensions may have changed
        flow::consensus::ModelDimensions dims = flow::consensus::compute_growth(tmpl.height);

        if (static_cast<int>(dims.d_model)  != model_.d_model  ||
            static_cast<int>(dims.n_layers) != model_.n_layers ||
            static_cast<int>(dims.d_ff)     != model_.d_ff     ||
            static_cast<int>(dims.n_slots)  != model_.n_slots) {

            std::printf("\n  Model growth: d=%u L=%u ff=%u slots=%u\n",
                        dims.d_model, dims.n_layers, dims.d_ff, dims.n_slots);

            // Re-init model with new dimensions
            // Weights from previous model are discarded; consensus weights
            // would be loaded from the node in production
            model_.init(dims.d_model, dims.n_layers, dims.d_ff, dims.n_slots);
            model_.zero_weights();
            consensus_.init(dims.d_model, dims.n_layers, dims.d_ff, dims.n_slots);
            consensus_.zero_weights();

            trainer_ = std::make_unique<Trainer>(model_, *backend_, config_.learning_rate);
        }

        // Reset GRU states for new block
        model_.reset_gru_states();
    }

    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// Training data batch extraction
// ═══════════════════════════════════════════════════════════════════════════

void MinerEngine::get_batch(uint8_t* input, uint8_t* target) {
    int seq = config_.seq_len;

    // Ensure enough data for input + 1 byte target shift
    if (dataset_.size() < static_cast<size_t>(seq + 1)) {
        // Dataset too small, pad with zeros
        std::memset(input, 0, seq);
        std::memset(target, 0, seq);
        return;
    }

    // Wrap around if needed
    if (data_pos_ + seq + 1 > dataset_.size()) {
        data_pos_ = 0;
    }

    // Input: bytes [pos .. pos+seq)
    std::memcpy(input, dataset_.data() + data_pos_, seq);

    // Target: bytes [pos+1 .. pos+seq+1) — next-token prediction
    std::memcpy(target, dataset_.data() + data_pos_ + 1, seq);

    data_pos_ += seq;
}

// ═══════════════════════════════════════════════════════════════════════════
// Training step
// ═══════════════════════════════════════════════════════════════════════════

float MinerEngine::training_step() {
    std::vector<uint8_t> input(config_.seq_len);
    std::vector<uint8_t> target(config_.seq_len);

    get_batch(input.data(), target.data());

    float loss = trainer_->step(input.data(), target.data(), config_.seq_len);
    stats_.current_grad_norm = trainer_->grad_norm();

    return loss;
}

// ═══════════════════════════════════════════════════════════════════════════
// Hash checking
// ═══════════════════════════════════════════════════════════════════════════

bool MinerEngine::check_hash(float loss, uint64_t step, float grad_norm,
                              uint256& out_hash) {
    out_hash = compute_mining_hash(loss, step, grad_norm, dataset_hash_);
    stats_.total_checks.fetch_add(1, std::memory_order_relaxed);
    return meets_target(out_hash, current_target_);
}

// ═══════════════════════════════════════════════════════════════════════════
// Block submission
// ═══════════════════════════════════════════════════════════════════════════

bool MinerEngine::submit_block(const RPCClient::BlockTemplate& tmpl,
                                float val_loss, const uint256& training_hash) {
    // Build the block header
    CBlockHeader header;

    // Parse prev_hash from template
    std::string ph = tmpl.prev_hash;
    for (size_t i = 0; i < 32 && i * 2 + 1 < ph.size(); i++) {
        std::string byte_hex = ph.substr(i * 2, 2);
        header.prev_hash[i] = static_cast<uint8_t>(std::strtoul(byte_hex.c_str(), nullptr, 16));
    }

    header.training_hash = training_hash;
    header.dataset_hash  = dataset_hash_;
    header.height        = tmpl.height;
    header.timestamp     = std::time(nullptr);
    header.nbits         = tmpl.nbits;
    header.val_loss      = val_loss;
    header.prev_val_loss = tmpl.prev_val_loss;
    header.d_model       = static_cast<uint32_t>(model_.d_model);
    header.n_layers      = static_cast<uint32_t>(model_.n_layers);
    header.d_ff          = static_cast<uint32_t>(model_.d_ff);
    header.n_heads       = static_cast<uint32_t>(model_.n_heads);
    header.gru_dim       = static_cast<uint32_t>(model_.d_model);
    header.n_slots       = static_cast<uint32_t>(model_.n_slots);
    header.version       = 1;
    header.nonce         = 0;  // PoT doesn't use a nonce in the traditional sense
    header.sparse_threshold = config_.sparse_threshold;

    // Compute sparse delta
    auto delta = model_.compute_delta(consensus_, config_.sparse_threshold);
    header.sparse_count = static_cast<uint32_t>(delta.indices.size());

    // Serialize delta payload
    auto delta_bytes = delta.serialize();
    header.delta_length = static_cast<uint32_t>(delta_bytes.size());

    // Set miner pubkey
    std::memcpy(header.miner_pubkey.data(), miner_key_.pubkey.data(), 32);

    // Sign the unsigned header data
    auto unsigned_data = header.get_unsigned_data();
    header.miner_sig = flow::ed25519_sign(
        unsigned_data.data(), unsigned_data.size(),
        miner_key_.privkey.data(), miner_key_.pubkey.data());

    // Serialize full block
    CBlock block(header);
    block.delta_payload = delta_bytes;

    // Create coinbase transaction
    // Compute block reward
    int halving_count = static_cast<int>(tmpl.height / flow::consensus::HALVING_INTERVAL);
    int64_t reward = flow::consensus::INITIAL_REWARD;
    for (int i = 0; i < halving_count && i < 64; i++) {
        reward >>= 1;
    }
    if (reward < flow::consensus::MIN_REWARD) reward = 0;

    auto coinbase = CBlock::make_coinbase(tmpl.height, reward,
                                           miner_key_.pubkey, "");
    block.vtx.push_back(coinbase);
    header.merkle_root = block.compute_merkle_root();

    // Re-serialize with merkle root
    auto block_data = block.serialize();

    // Convert to hex for RPC submission
    std::string hex;
    hex.reserve(block_data.size() * 2);
    static const char hx[] = "0123456789abcdef";
    for (uint8_t b : block_data) {
        hex.push_back(hx[b >> 4]);
        hex.push_back(hx[b & 0x0F]);
    }

    // Submit
    std::string result = rpc_.submit_block(hex);

    if (result.empty() || result == "null") {
        // Accepted
        stats_.blocks_found.fetch_add(1, std::memory_order_relaxed);
        print_block_found(tmpl.height, val_loss, header.get_hash_hex());
        return true;
    } else {
        // Rejected
        stats_.blocks_rejected.fetch_add(1, std::memory_order_relaxed);
        std::printf("\n  Block REJECTED: %s\n", result.c_str());
        return false;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Status printing
// ═══════════════════════════════════════════════════════════════════════════

void MinerEngine::print_status(uint64_t step, float loss, float grad_norm) {
    auto now = Clock::now();
    double elapsed = std::chrono::duration<double>(now - mining_start_).count();
    double sps = (elapsed > 0.0) ? static_cast<double>(step) / elapsed : 0.0;
    stats_.steps_per_second = static_cast<float>(sps);
    stats_.hashes_per_second = static_cast<float>(sps);

    // Leading zeros in recent hash
    uint256 recent_hash = compute_mining_hash(loss, step, grad_norm, dataset_hash_);
    int lz = flow::count_leading_zeros(recent_hash);

    // Overwrite the current line
    std::printf("\r  [%s] step=%llu  loss=%.4f  best=%.4f  "
                "grad=%.2e  speed=%.1f st/s  lz=%d  blocks=%llu   ",
                format_elapsed(elapsed).c_str(),
                static_cast<unsigned long long>(step),
                loss,
                stats_.best_loss,
                grad_norm,
                sps,
                lz,
                static_cast<unsigned long long>(
                    stats_.blocks_found.load(std::memory_order_relaxed)));
    std::fflush(stdout);
}

void MinerEngine::print_block_found(uint64_t height, float val_loss,
                                     const std::string& hash_hex) {
    std::printf("\n\n");
    std::printf("  ╔══════════════════════════════════════════════╗\n");
    std::printf("  ║              BLOCK FOUND!                   ║\n");
    std::printf("  ╠══════════════════════════════════════════════╣\n");
    std::printf("  ║  Height:   %-33llu ║\n",
                static_cast<unsigned long long>(height));
    std::printf("  ║  Loss:     %-33.6f ║\n", val_loss);
    std::printf("  ║  Hash:     %.38s...  ║\n", hash_hex.c_str());
    std::printf("  ╚══════════════════════════════════════════════╝\n");
    std::printf("\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// Formatting helpers
// ═══════════════════════════════════════════════════════════════════════════

std::string MinerEngine::format_hashrate(double h) {
    if (h >= 1e6) return std::to_string(static_cast<int>(h / 1e6)) + " MH/s";
    if (h >= 1e3) return std::to_string(static_cast<int>(h / 1e3)) + " kH/s";
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.1f H/s", h);
    return buf;
}

std::string MinerEngine::format_loss(float loss) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.6f", loss);
    return buf;
}

std::string MinerEngine::format_elapsed(double seconds) {
    int h = static_cast<int>(seconds / 3600);
    int m = static_cast<int>(std::fmod(seconds, 3600) / 60);
    int s = static_cast<int>(std::fmod(seconds, 60));
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d", h, m, s);
    return buf;
}

std::string MinerEngine::format_params(size_t count) {
    if (count >= 1'000'000'000) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.1fB", static_cast<double>(count) / 1e9);
        return buf;
    }
    if (count >= 1'000'000) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.1fM", static_cast<double>(count) / 1e6);
        return buf;
    }
    if (count >= 1'000) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.1fK", static_cast<double>(count) / 1e3);
        return buf;
    }
    return std::to_string(count);
}

// ═══════════════════════════════════════════════════════════════════════════
// Main mining loop
// ═══════════════════════════════════════════════════════════════════════════

void MinerEngine::run() {
    running_.store(true);
    mining_start_ = Clock::now();
    last_status_print_ = mining_start_;
    last_template_refresh_ = mining_start_;

    uint64_t step = 0;
    uint64_t template_refresh_interval_ms = 5000;  // Check for new block every 5s

    std::printf("  Mining started. Press Ctrl+C to stop.\n\n");

    while (running_.load()) {
        auto now = Clock::now();

        // ── Periodically refresh block template ──
        auto since_refresh = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_template_refresh_).count();
        if (since_refresh >= static_cast<int64_t>(template_refresh_interval_ms)) {
            bool had_valid = current_template_.valid;
            uint64_t old_height = current_template_.height;

            refresh_block_template();
            last_template_refresh_ = now;

            if (current_template_.valid && current_template_.height != old_height) {
                std::printf("\n  New block at height %llu, resetting...\n",
                            static_cast<unsigned long long>(current_template_.height));
                step = 0;
                mining_start_ = now;
                model_.reset_gru_states();
                data_pos_ = 0;
            }

            if (!had_valid && !current_template_.valid) {
                // Still no template -- wait and retry
                std::printf("\r  Waiting for block template from node...");
                std::fflush(stdout);
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }
        }

        // ── Training step ──
        float loss = training_step();
        step++;
        stats_.total_steps.fetch_add(1, std::memory_order_relaxed);
        stats_.current_loss = loss;
        if (loss < stats_.best_loss) {
            stats_.best_loss = loss;
        }

        // ── Hash check ──
        uint256 training_hash;
        if (check_hash(loss, step, stats_.current_grad_norm, training_hash)) {
            // Found a block!
            if (current_template_.valid) {
                submit_block(current_template_, loss, training_hash);

                // After submission, get new template
                refresh_block_template();
                last_template_refresh_ = Clock::now();
                step = 0;
                mining_start_ = Clock::now();
                model_.reset_gru_states();
            }
        }

        // ── Status output ──
        now = Clock::now();
        auto since_status = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_status_print_).count();
        if (since_status >= config_.status_interval_ms) {
            print_status(step, loss, stats_.current_grad_norm);
            last_status_print_ = now;
        }
    }

    std::printf("\n\n  Miner stopped.\n");
    std::printf("  Total steps: %llu\n",
                static_cast<unsigned long long>(
                    stats_.total_steps.load(std::memory_order_relaxed)));
    std::printf("  Blocks found: %llu\n",
                static_cast<unsigned long long>(
                    stats_.blocks_found.load(std::memory_order_relaxed)));
    std::printf("\n");
}

void MinerEngine::stop() {
    running_.store(false);
}

MinerStats MinerEngine::stats() const {
    MinerStats s;
    s.total_steps    = stats_.total_steps.load(std::memory_order_relaxed);
    s.total_checks   = stats_.total_checks.load(std::memory_order_relaxed);
    s.blocks_found   = stats_.blocks_found.load(std::memory_order_relaxed);
    s.blocks_rejected = stats_.blocks_rejected.load(std::memory_order_relaxed);
    s.current_loss    = stats_.current_loss;
    s.best_loss       = stats_.best_loss;
    s.current_grad_norm = stats_.current_grad_norm;
    s.steps_per_second  = stats_.steps_per_second;
    s.hashes_per_second = stats_.hashes_per_second;
    return s;
}

} // namespace flow::miner

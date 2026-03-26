// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// MinerEngine implementation: the 24/7 PoW mining loop.
//
// Flow:
//   init() -> load keys, connect
//   run()  -> loop { get_template, iterate nonce, submit }

#include "miner.h"
#include "../hash/keccak.h"
#include "../crypto/sign.h"
#include "../primitives/block.h"
#include "../consensus/difficulty.h"
#include "../consensus/pow.h"
#include "../util/strencodings.h"
#include "../util/arith_uint256.h"

#ifdef FLOWCOIN_USE_CUDA
#include "cuda_miner.h"
#endif

#include <chrono>
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

// =========================================================================
// Construction / Destruction
// =========================================================================

MinerEngine::MinerEngine(const MinerConfig& config)
    : config_(config)
    , rpc_(config.rpc_host, config.rpc_port, config.rpc_user, config.rpc_password)
{
}

MinerEngine::~MinerEngine() {
    stop();
}

// =========================================================================
// Initialization
// =========================================================================

bool MinerEngine::init() {
    std::printf("\n");
    std::printf("  FlowCoin Miner v1.0\n");
    std::printf("  Keccak-256d Proof-of-Work\n");
    std::printf("  ════════════════════════════\n\n");

    // Step 1: Load or create miner keypair
    std::printf("[1/2] Loading miner identity...\n");
    if (!load_or_create_miner_key()) {
        std::fprintf(stderr, "FATAL: Failed to load miner key\n");
        return false;
    }

    // Step 2: Connect to node
    std::printf("[2/2] Connecting to node at %s:%d...\n",
                config_.rpc_host.c_str(), config_.rpc_port);
    if (!connect_to_node()) {
        std::fprintf(stderr, "FATAL: Cannot connect to FlowCoin node\n");
        return false;
    }

    // Step 3 (optional): Initialize CUDA
#ifdef FLOWCOIN_USE_CUDA
    std::printf("[3/3] Initializing CUDA...\n");
    if (cuda::cuda_init()) {
        std::printf("  GPU mining enabled\n");
    } else {
        std::printf("  No GPU found, falling back to CPU\n");
    }
#endif

    std::printf("\n  Ready to mine.\n\n");
    return true;
}

// =========================================================================
// Key management
// =========================================================================

bool MinerEngine::load_or_create_miner_key() {
    namespace fs = std::filesystem;

    std::string key_path = config_.datadir + "/miner_key.dat";

    if (fs::exists(key_path)) {
        // Load existing key
        std::ifstream f(key_path, std::ios::binary);
        if (!f) {
            std::fprintf(stderr, "  Cannot read %s\n", key_path.c_str());
            return false;
        }

        f.read(reinterpret_cast<char*>(miner_key_.privkey.data()), 64);
        f.read(reinterpret_cast<char*>(miner_key_.pubkey.data()), 32);

        if (!f) {
            std::fprintf(stderr, "  Corrupt key file %s\n", key_path.c_str());
            return false;
        }

        std::printf("  Loaded miner key from %s\n", key_path.c_str());
    } else {
        // Generate new key
        miner_key_ = generate_keypair();

        // Save to disk
        fs::create_directories(config_.datadir);
        std::ofstream f(key_path, std::ios::binary);
        if (!f) {
            std::fprintf(stderr, "  Cannot write %s\n", key_path.c_str());
            return false;
        }

        f.write(reinterpret_cast<const char*>(miner_key_.privkey.data()), 64);
        f.write(reinterpret_cast<const char*>(miner_key_.pubkey.data()), 32);

        std::printf("  Generated new miner key, saved to %s\n", key_path.c_str());
    }

    // Print public key
    std::printf("  Miner pubkey: ");
    for (int i = 0; i < 8; ++i) {
        std::printf("%02x", miner_key_.pubkey[i]);
    }
    std::printf("...\n");

    return true;
}

bool MinerEngine::connect_to_node() {
    if (!rpc_.is_connected()) {
        std::fprintf(stderr, "  Connection failed\n");
        return false;
    }

    int64_t height = rpc_.get_block_count();
    std::printf("  Connected. Chain height: %lld\n",
                static_cast<long long>(height));
    return true;
}

// =========================================================================
// Block template management
// =========================================================================

bool MinerEngine::refresh_block_template() {
    auto tmpl = rpc_.get_block_template();
    if (!tmpl.valid) {
        return false;
    }

    current_template_ = tmpl;

    // Derive target from nbits
    arith_uint256 target;
    std::fprintf(stderr, "  DEBUG: nbits = %u (0x%08x)\n", tmpl.nbits, tmpl.nbits);
    if (!consensus::derive_target(tmpl.nbits, target)) {
        std::fprintf(stderr, "  ERROR: derive_target failed for nbits=0x%08x\n", tmpl.nbits);
        return false;
    }
    current_target_ = ArithToUint256(target);

    return true;
}

// =========================================================================
// Mining loop
// =========================================================================

void MinerEngine::run() {
    running_.store(true);
    mining_start_ = Clock::now();
    last_status_print_ = mining_start_;
    last_template_refresh_ = mining_start_;

    std::printf("  Mining started. Target: %s\n\n",
                consensus::FormatTarget(current_template_.nbits).c_str());

    while (running_.load()) {
        // Refresh template periodically or on first iteration
        auto now = Clock::now();
        double since_refresh = std::chrono::duration<double>(
            now - last_template_refresh_).count();

        if (since_refresh > 30.0 || current_template_.height == 0) {
            if (!refresh_block_template()) {
                std::fprintf(stderr, "  Failed to get block template, retrying...\n");
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }
            last_template_refresh_ = now;
        }

        // Build header
        CBlockHeader header;
        header.height = current_template_.height;
        header.timestamp = std::time(nullptr);
        header.nbits = current_template_.nbits;
        header.version = 1;
        std::memcpy(header.miner_pubkey.data(), miner_key_.pubkey.data(), 32);

        // Set prev_hash from template
        auto prev_bytes = hex_decode(current_template_.prev_hash);
        if (prev_bytes.size() == 32) {
            std::memcpy(header.prev_hash.data(), prev_bytes.data(), 32);
        }

        // Build coinbase and compute merkle root
        // For now, use a simple coinbase. The node provides the template.
        // We set merkle_root from the assembled transactions.
        header.merkle_root.set_null();  // Will be set by submit_block

        // PoW: iterate nonce
        auto unsigned_base = header.get_unsigned_data();  // 92 bytes

        uint32_t nonce = 0;
        bool found = false;

#ifdef FLOWCOIN_USE_CUDA
        // ── GPU mining path ──
        // Mine in batches of 16M nonces per kernel launch.
        // The GPU handles all nonce iteration internally.
        const uint32_t cuda_batch = 1U << 24;  // 16M nonces per launch

        while (running_.load()) {
            auto batch_start = Clock::now();

            uint32_t result = cuda::cuda_mine_batch(
                unsigned_base.data(),
                static_cast<int>(unsigned_base.size()),
                current_target_.data(),
                nonce,
                cuda_batch
            );

            auto batch_end = Clock::now();
            double batch_secs = std::chrono::duration<double>(
                batch_end - batch_start).count();

            stats_.total_hashes.fetch_add(cuda_batch, std::memory_order_relaxed);

            if (result != 0) {
                header.nonce = result;
                found = true;
                break;
            }

            nonce += cuda_batch;

            // Print status with GPU hashrate
            now = Clock::now();
            double since_print = std::chrono::duration<double>(
                now - last_status_print_).count();

            if (since_print >= static_cast<double>(config_.status_interval_ms) / 1000.0) {
                double gpu_rate = static_cast<double>(cuda_batch) / batch_secs;
                std::printf("\r  [%s] %s (GPU) | height=%llu | blocks=%llu",
                            format_elapsed(std::chrono::duration<double>(
                                now - mining_start_).count()).c_str(),
                            format_hashrate(gpu_rate).c_str(),
                            static_cast<unsigned long long>(current_template_.height),
                            static_cast<unsigned long long>(stats_.blocks_found.load()));
                std::fflush(stdout);
                last_status_print_ = now;
            }

            // Refresh template if too much time passed
            double since_ref = std::chrono::duration<double>(
                now - last_template_refresh_).count();
            if (since_ref > 30.0) {
                break;  // Get new template
            }

            if (nonce == 0) break;  // overflow
        }
#else
        // ── CPU mining path ──
        while (running_.load()) {
            // Set nonce in the unsigned data at offset 84
            std::memcpy(&unsigned_base[84], &nonce, 4);

            // Double Keccak-256
            uint256 hash = keccak256d(unsigned_base.data(), unsigned_base.size());

            if (hash <= current_target_) {
                header.nonce = nonce;
                found = true;
                break;
            }

            nonce++;
            stats_.total_hashes.fetch_add(1, std::memory_order_relaxed);

            // Print status periodically
            now = Clock::now();
            double since_print = std::chrono::duration<double>(
                now - last_status_print_).count();

            if (since_print >= static_cast<double>(config_.status_interval_ms) / 1000.0) {
                print_status(stats_.total_hashes.load());
                last_status_print_ = now;
            }

            // Refresh template if too much time passed
            double since_ref = std::chrono::duration<double>(
                now - last_template_refresh_).count();
            if (since_ref > 30.0) {
                break;  // Get new template
            }

            if (nonce == 0) break;  // overflow
        }
#endif

        if (found) {
            // Submit block
            if (submit_block(current_template_, nonce)) {
                stats_.blocks_found.fetch_add(1, std::memory_order_relaxed);
                print_block_found(current_template_.height,
                                  header.get_hash_hex());
            } else {
                stats_.blocks_rejected.fetch_add(1, std::memory_order_relaxed);
            }

            // Force template refresh after finding a block
            last_template_refresh_ = Clock::time_point{};
        }
    }
}

void MinerEngine::stop() {
    running_.store(false);
#ifdef FLOWCOIN_USE_CUDA
    cuda::cuda_shutdown();
#endif
}

// =========================================================================
// Block submission
// =========================================================================

bool MinerEngine::submit_block(const RPCClient::BlockTemplate& tmpl,
                                uint32_t nonce) {
    (void)tmpl;
    (void)nonce;

    // Build the full block, sign it, and submit via RPC.
    // The actual implementation depends on the RPC protocol.
    // For now, we signal success to the caller.

    CBlockHeader header;
    header.height = tmpl.height;
    header.timestamp = std::time(nullptr);
    header.nbits = tmpl.nbits;
    header.nonce = nonce;
    header.version = 1;
    std::memcpy(header.miner_pubkey.data(), miner_key_.pubkey.data(), 32);

    auto prev_bytes = hex_decode(tmpl.prev_hash);
    if (prev_bytes.size() == 32) {
        std::memcpy(header.prev_hash.data(), prev_bytes.data(), 32);
    }

    // Sign the unsigned header
    auto unsigned_data = header.get_unsigned_data();
    ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                 miner_key_.privkey.data(),
                 header.miner_sig.data());

    // Serialize and submit
    auto header_bytes = header.serialize();
    std::string hex_block = hex_encode(header_bytes.data(), header_bytes.size());

    std::string result = rpc_.submit_block(hex_block);
    return result.find("error") == std::string::npos;
}

// =========================================================================
// Statistics
// =========================================================================

MinerStats MinerEngine::stats() const {
    MinerStats s;
    s.total_hashes = stats_.total_hashes.load();
    s.blocks_found = stats_.blocks_found.load();
    s.blocks_rejected = stats_.blocks_rejected.load();

    auto elapsed = std::chrono::duration<double>(
        Clock::now() - mining_start_).count();
    s.hashrate = (elapsed > 0) ? static_cast<double>(s.total_hashes) / elapsed : 0.0;

    return s;
}

// =========================================================================
// Output
// =========================================================================

void MinerEngine::print_status(uint64_t hashes) {
    auto elapsed = std::chrono::duration<double>(
        Clock::now() - mining_start_).count();
    double hashrate = (elapsed > 0) ? static_cast<double>(hashes) / elapsed : 0.0;

    std::printf("\r  [%s] %s | height=%llu | blocks=%llu",
                format_elapsed(elapsed).c_str(),
                format_hashrate(hashrate).c_str(),
                static_cast<unsigned long long>(current_template_.height),
                static_cast<unsigned long long>(stats_.blocks_found.load()));
    std::fflush(stdout);
}

void MinerEngine::print_block_found(uint64_t height, const std::string& hash_hex) {
    std::printf("\n\n  *** BLOCK FOUND ***\n");
    std::printf("  Height: %llu\n", static_cast<unsigned long long>(height));
    std::printf("  Hash:   %s\n\n", hash_hex.c_str());
}

std::string MinerEngine::format_hashrate(double h) {
    char buf[64];
    if (h >= 1e9) {
        std::snprintf(buf, sizeof(buf), "%.2f GH/s", h / 1e9);
    } else if (h >= 1e6) {
        std::snprintf(buf, sizeof(buf), "%.2f MH/s", h / 1e6);
    } else if (h >= 1e3) {
        std::snprintf(buf, sizeof(buf), "%.2f KH/s", h / 1e3);
    } else {
        std::snprintf(buf, sizeof(buf), "%.0f H/s", h);
    }
    return buf;
}

std::string MinerEngine::format_elapsed(double seconds) {
    int h = static_cast<int>(seconds) / 3600;
    int m = (static_cast<int>(seconds) % 3600) / 60;
    int s = static_cast<int>(seconds) % 60;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d", h, m, s);
    return buf;
}

} // namespace flow::miner

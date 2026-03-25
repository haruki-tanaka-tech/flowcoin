// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "interfaces/node.h"
#include "chain/chainstate.h"
#include "init.h"
#include "mempool/mempool.h"
#include "node/context.h"
#include "version.h"
#include "wallet/wallet.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace flow::interfaces {

// ============================================================================
// NodeImpl: concrete implementation wrapping NodeContext
// ============================================================================

class NodeImpl : public Node {
public:
    NodeImpl() = default;
    explicit NodeImpl(NodeContext* ctx) : ctx_(ctx) {}
    ~NodeImpl() override = default;

    // ---- Lifecycle ---------------------------------------------------------

    bool init(int argc, char* argv[]) override {
        args_ = parse_args(argc, argv);
        return true;
    }

    bool start() override {
        running_ = true;
        return true;
    }

    void stop() override {
        running_ = false;
        shutdown_cv_.notify_all();
    }

    void wait_for_shutdown() override {
        std::unique_lock<std::mutex> lock(shutdown_mutex_);
        shutdown_cv_.wait(lock, [this]() { return !running_.load(); });
    }

    bool is_running() override {
        return running_;
    }

    // ---- Chain information -------------------------------------------------

    uint64_t get_height() override {
        if (ctx_ && ctx_->chain) {
            return ctx_->chain->height();
        }
        return 0;
    }

    uint256 get_best_block_hash() override {
        if (ctx_ && ctx_->chain) {
            auto* tip = ctx_->chain->tip();
            if (tip) return tip->hash;
        }
        return uint256();
    }

    double get_difficulty() override {
        if (ctx_ && ctx_->chain) {
            auto* tip = ctx_->chain->tip();
            if (tip && tip->nbits > 0) {
                // Compute difficulty from nbits using compact target expansion
                uint32_t nbits = tip->nbits;
                int exp = (nbits >> 24) & 0xFF;
                uint32_t mantissa = nbits & 0x007FFFFF;
                if (mantissa == 0) return 0.0;

                // Genesis difficulty target
                double target = static_cast<double>(mantissa) *
                                std::pow(256.0, exp - 3);
                double max_target = static_cast<double>(0x00FFFFFF) *
                                    std::pow(256.0, 0x20 - 3);
                if (target == 0.0) return 0.0;
                return max_target / target;
            }
        }
        return 1.0;
    }

    bool is_initial_block_download() override {
        if (ctx_ && ctx_->chain) {
            auto* tip = ctx_->chain->tip();
            if (!tip) return true;

            // IBD heuristic: tip timestamp more than 24 hours behind
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();

            return (now - tip->timestamp) > 86400;
        }
        return true;
    }

    double get_verification_progress() override {
        if (ctx_ && ctx_->chain) {
            auto* tip = ctx_->chain->tip();
            if (!tip) return 0.0;

            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();

            if (now <= 0) return 1.0;
            double progress = static_cast<double>(tip->timestamp) /
                              static_cast<double>(now);
            return std::min(1.0, std::max(0.0, progress));
        }
        return 0.0;
    }

    int64_t get_last_block_time() override {
        if (ctx_ && ctx_->chain) {
            auto* tip = ctx_->chain->tip();
            if (tip) return tip->timestamp;
        }
        return 0;
    }

    uint64_t get_block_count() override {
        return get_height();
    }

    uint256 get_block_hash(uint64_t height) override {
        if (ctx_ && ctx_->chain) {
            auto* idx = ctx_->chain->get_block_index_at_height(height);
            if (idx) return idx->hash;
        }
        return uint256();
    }

    std::string get_chain_work() override {
        if (ctx_ && ctx_->chain) {
            auto* tip = ctx_->chain->tip();
            if (tip) {
                auto work = ctx_->chain->compute_chain_work(tip);
                return work.ToString();
            }
        }
        return "0";
    }

    // ---- Network information -----------------------------------------------

    int get_num_connections() override {
        // Network manager integration
        return 0;
    }

    int64_t get_total_bytes_sent() override {
        return 0;
    }

    int64_t get_total_bytes_recv() override {
        return 0;
    }

    std::string get_network_name() override {
        return "mainnet";
    }

    bool is_listening() override {
        return running_;
    }

    std::vector<std::string> get_local_addresses() override {
        return {};
    }

    // ---- Mempool -----------------------------------------------------------

    size_t get_mempool_size() override {
        if (ctx_ && ctx_->mempool) {
            return ctx_->mempool->size();
        }
        return 0;
    }

    Amount get_mempool_min_fee() override {
        return 1000;  // 1 sat/byte default
    }

    size_t get_mempool_bytes() override {
        if (ctx_ && ctx_->mempool) {
            return ctx_->mempool->total_bytes();
        }
        return 0;
    }

    // ---- Wallet (simplified) -----------------------------------------------

    Amount get_balance() override {
        if (ctx_ && ctx_->wallet) {
            return ctx_->wallet->get_balance();
        }
        return 0;
    }

    std::string get_new_address() override {
        if (ctx_ && ctx_->wallet) {
            return ctx_->wallet->get_new_address();
        }
        return "";
    }

    std::string send_to_address(const std::string& addr,
                                 Amount amount) override {
        if (ctx_ && ctx_->wallet) {
            auto result = ctx_->wallet->send_to_address(addr, amount);
            if (result.success) {
                // Convert txid to hex
                uint256 txid = result.tx.get_txid();
                std::string hex;
                hex.reserve(64);
                static const char* digits = "0123456789abcdef";
                for (int i = 31; i >= 0; --i) {
                    hex.push_back(digits[txid[i] >> 4]);
                    hex.push_back(digits[txid[i] & 0xf]);
                }
                return hex;
            }
        }
        return "";
    }

    Amount get_unconfirmed_balance() override {
        return 0;  // Requires mempool scanning
    }

    // ---- Mining ------------------------------------------------------------

    bool is_mining() override {
        return false;
    }

    double get_network_hashrate() override {
        return 0.0;
    }

    uint32_t get_nbits() override {
        if (ctx_ && ctx_->chain) {
            auto* tip = ctx_->chain->tip();
            if (tip) return tip->nbits;
        }
        return 0;
    }

    // ---- Model (Proof-of-Training) -----------------------------------------

    size_t get_model_param_count() override {
        if (ctx_ && ctx_->chain) {
            auto* tip = ctx_->chain->tip();
            if (tip) {
                // Approximate parameter count from architecture dimensions
                size_t d = tip->d_model;
                size_t n = tip->n_layers;
                size_t ff = tip->d_ff;
                return d * d * n * 4 + d * ff * n * 2;
            }
        }
        return 0;
    }

    float get_model_val_loss() override {
        if (ctx_ && ctx_->chain) {
            auto* tip = ctx_->chain->tip();
            if (tip) return tip->val_loss;
        }
        return 0.0f;
    }

    uint256 get_model_hash() override {
        if (ctx_ && ctx_->chain) {
            auto* tip = ctx_->chain->tip();
            if (tip) return tip->hash;  // Use block hash as proxy
        }
        return uint256();
    }

    // get_train_steps removed: not a consensus field

    // ---- Fee estimation ----------------------------------------------------

    Amount estimate_smart_fee(int /*target_blocks*/) override {
        return 1000;  // Default: 1 sat/byte
    }

    // ---- Notifications -----------------------------------------------------

    void register_block_tip_callback(BlockTipCallback cb) override {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        block_tip_callbacks_.push_back(std::move(cb));
    }

    void register_header_tip_callback(HeaderTipCallback cb) override {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        header_tip_callbacks_.push_back(std::move(cb));
    }

    void register_alert_callback(AlertCallback cb) override {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        alert_callbacks_.push_back(std::move(cb));
    }

    void register_shutdown_callback(ShutdownCallback cb) override {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        shutdown_callbacks_.push_back(std::move(cb));
    }

    // ---- Version info ------------------------------------------------------

    std::string get_version_string() override {
        return std::string(CLIENT_VERSION_STRING);
    }

    int get_protocol_version() override {
        return flow::version::CLIENT_VERSION;
    }

private:
    NodeContext* ctx_ = nullptr;
    AppArgs args_;
    std::atomic<bool> running_{false};

    std::mutex shutdown_mutex_;
    std::condition_variable shutdown_cv_;

    std::mutex cb_mutex_;
    std::vector<BlockTipCallback> block_tip_callbacks_;
    std::vector<HeaderTipCallback> header_tip_callbacks_;
    std::vector<AlertCallback> alert_callbacks_;
    std::vector<ShutdownCallback> shutdown_callbacks_;
};

// ============================================================================
// Factory functions
// ============================================================================

std::unique_ptr<Node> make_node() {
    return std::make_unique<NodeImpl>();
}

std::unique_ptr<Node> make_node(NodeContext& context) {
    return std::make_unique<NodeImpl>(&context);
}

} // namespace flow::interfaces

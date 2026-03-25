// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "kernel/context.h"
#include "kernel/validation.h"
#include "kernel/chainparams.h"
#include "chain/chainstate.h"
#include "chain/utxo.h"
#include "consensus/difficulty.h"
#include "consensus/eval.h"
#include "consensus/genesis.h"
#include "consensus/growth.h"
#include "consensus/reward.h"
#include "consensus/validation.h"

#include <cstdio>
#include <filesystem>

namespace flow::kernel {

// ============================================================================
// Construction / Destruction
// ============================================================================

Kernel::Kernel(const KernelConfig& config)
    : config_(config) {
}

Kernel::~Kernel() {
    if (initialized_) {
        shutdown();
    }
}

// ============================================================================
// Initialization
// ============================================================================

bool Kernel::init() {
    if (initialized_) return true;

    // Select network parameters
    select_params(config_.network_name());

    // Ensure data directory exists
    std::error_code ec;
    if (!config_.datadir.empty()) {
        std::filesystem::create_directories(config_.datadir, ec);
        if (ec) {
            std::fprintf(stderr, "Kernel: failed to create data directory %s: %s\n",
                         config_.datadir.c_str(), ec.message().c_str());
            return false;
        }
    }

    // Open chain state database
    std::string chain_dir = config_.datadir;
    if (chain_dir.empty()) chain_dir = ".";

    try {
        chain_ = std::make_unique<ChainState>(chain_dir);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Kernel: failed to open chain state: %s\n", e.what());
        return false;
    }

    // Initialize evaluation engine
    if (!config_.skip_model_eval) {
        eval_ = std::make_unique<consensus::EvalEngine>();

        // Try to load from checkpoint first
        std::string checkpoint_path = chain_dir + "/model_checkpoint.bin";
        if (std::filesystem::exists(checkpoint_path, ec)) {
            if (!eval_->load_checkpoint(checkpoint_path)) {
                std::fprintf(stderr, "Kernel: failed to load model checkpoint, "
                             "will replay from genesis\n");
                if (!eval_->init_genesis()) {
                    std::fprintf(stderr, "Kernel: failed to init genesis model\n");
                    return false;
                }
            }
        } else {
            if (!eval_->init_genesis()) {
                std::fprintf(stderr, "Kernel: failed to init genesis model\n");
                return false;
            }
        }
    }

    // Load chain or create genesis
    if (!load_chain()) {
        if (!init_genesis()) {
            std::fprintf(stderr, "Kernel: failed to initialize genesis block\n");
            return false;
        }
    }

    // Cache current model dimensions
    uint64_t height = get_height();
    current_dims_ = consensus::compute_growth(height);

    initialized_ = true;
    return true;
}

void Kernel::shutdown() {
    if (!initialized_) return;

    // Save model checkpoint if eval engine is active
    if (eval_ && !config_.datadir.empty()) {
        std::string checkpoint_path = config_.datadir + "/model_checkpoint.bin";
        eval_->save_checkpoint(checkpoint_path);
    }

    // Chain state flushes on destruction
    eval_.reset();
    chain_.reset();

    initialized_ = false;
}

bool Kernel::init_genesis() {
    CBlock genesis = consensus::create_genesis_block();

    // Verify genesis hash matches hardcoded value
    uint256 genesis_hash = genesis.get_hash();
    const auto& chain_params = params();
    if (genesis_hash != chain_params.genesis_hash) {
        std::fprintf(stderr, "Kernel: genesis hash mismatch\n");
        return false;
    }

    // Accept the genesis block into the chain
    if (!chain_) return false;

    (void)genesis;
    return chain_->accept_genesis();
}

bool Kernel::load_chain() {
    if (!chain_) return false;
    return chain_->load();
}

// ============================================================================
// Header validation
// ============================================================================

consensus::ValidationState Kernel::validate_header(const CBlockHeader& header) {
    consensus::ValidationState state;

    if (!initialized_) {
        state.invalid(consensus::ValidationResult::INTERNAL_ERROR,
                      "kernel-not-initialized",
                      "Kernel::validate_header called before init()");
        return state;
    }

    // Get parent header from chain state
    if (!chain_) {
        state.invalid(consensus::ValidationResult::INTERNAL_ERROR,
                      "no-chain-state");
        return state;
    }

    // Delegate to consensus validation with default context
    consensus::BlockContext ctx;
    consensus::check_header(header, ctx, state);
    return state;
}

consensus::ValidationState Kernel::validate_header(
    const CBlockHeader& header,
    const CBlockHeader& parent,
    uint64_t parent_height) {

    consensus::ValidationState state;

    if (!initialized_) {
        state.invalid(consensus::ValidationResult::INTERNAL_ERROR,
                      "kernel-not-initialized");
        return state;
    }

    // Validate using the standard header check
    (void)parent;
    (void)parent_height;
    consensus::BlockContext ctx2;
    consensus::check_header(header, ctx2, state);
    return state;
}

// ============================================================================
// Full block validation
// ============================================================================

consensus::ValidationState Kernel::validate_block(const CBlock& block) {
    consensus::ValidationState state;

    if (!initialized_) {
        state.invalid(consensus::ValidationResult::INTERNAL_ERROR,
                      "kernel-not-initialized");
        return state;
    }

    // Validate using default context
    consensus::BlockContext ctx;
    consensus::check_block(block, ctx, state);
    return state;
}

// ============================================================================
// Block acceptance
// ============================================================================

consensus::ValidationState Kernel::accept_block(const CBlock& block) {
    consensus::ValidationState state;

    if (!initialized_) {
        state.invalid(consensus::ValidationResult::INTERNAL_ERROR,
                      "kernel-not-initialized");
        return state;
    }

    // Validate first
    state = validate_block(block);
    if (state.is_invalid()) return state;

    // Connect block to chain
    // Accept block through ChainState (which handles connect_block internally)
    if (!chain_->accept_block(block, state)) {
        if (!state.is_invalid()) {
            state.invalid(consensus::ValidationResult::INTERNAL_ERROR,
                          "accept-block-failed",
                          "Failed to accept block to chain state");
        }
        return state;
    }

    // Update cached dimensions
    current_dims_ = consensus::compute_growth(chain_->height());

    return state;
}

// ============================================================================
// Chain state queries
// ============================================================================

uint64_t Kernel::get_height() const {
    if (!chain_) return 0;
    return chain_->get_height();
}

uint256 Kernel::get_tip_hash() const {
    if (!chain_) return uint256();
    return chain_->get_tip_hash();
}

bool Kernel::get_header_at_height(uint64_t height, CBlockHeader& header) const {
    if (!chain_) return false;
    return chain_->get_header(height, header);
}

// ============================================================================
// Consensus parameter queries
// ============================================================================

const consensus::ModelDimensions& Kernel::get_model_dims() const {
    return current_dims_;
}

consensus::ModelDimensions Kernel::get_model_dims_at(uint64_t height) const {
    return consensus::compute_growth(height);
}

uint32_t Kernel::get_next_nbits() const {
    if (!chain_) return consensus::INITIAL_NBITS;
    return chain_->get_next_nbits();
}

Amount Kernel::get_block_reward() const {
    return consensus::compute_block_reward(get_height());
}

Amount Kernel::get_block_reward_at(uint64_t height) const {
    return consensus::compute_block_reward(height);
}

// ============================================================================
// UTXO queries
// ============================================================================

bool Kernel::get_utxo(const uint256& txid, uint32_t vout,
                       UTXOEntry& entry) const {
    if (!chain_) return false;
    return chain_->get_utxo(txid, vout, entry);
}

bool Kernel::has_utxo(const uint256& txid, uint32_t vout) const {
    if (!chain_) return false;
    UTXOEntry entry;
    return chain_->get_utxo(txid, vout, entry);
}

// ============================================================================
// Model state queries
// ============================================================================

uint256 Kernel::get_model_hash() const {
    if (!eval_) return uint256();
    return eval_->get_model_hash();
}

size_t Kernel::get_model_params() const {
    if (!eval_) return 0;
    return eval_->param_count();
}

// ============================================================================
// Network parameter queries
// ============================================================================

uint32_t Kernel::get_network_magic() const {
    return params().magic;
}

uint16_t Kernel::get_default_port() const {
    return params().default_port;
}

const char* Kernel::get_hrp() const {
    return params().hrp;
}

} // namespace flow::kernel

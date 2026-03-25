// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// libflowcoinkernel: consensus engine as a library.
// This is the minimal interface needed to validate blocks WITHOUT
// networking, wallet, RPC, or UI. External projects (block explorers,
// lightweight verifiers, fuzz harnesses) can link against the kernel
// to validate chain data independently.
//
// The kernel owns:
//   - Chain parameters (mainnet, testnet, regtest)
//   - Block header validation (fast, no UTXO needed)
//   - Full block validation (requires UTXO + model state)
//   - Block acceptance (update chain tip)
//   - Consensus queries (height, tip hash, model dimensions, reward)

#ifndef FLOWCOIN_KERNEL_CONTEXT_H
#define FLOWCOIN_KERNEL_CONTEXT_H

#include "consensus/params.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "util/types.h"

#include <cstdint>
#include <memory>
#include <string>

namespace flow {
class ChainState;
class UTXOSet;
struct UTXOEntry;
}

namespace flow::consensus {
class EvalEngine;
}

namespace flow::kernel {

// ============================================================================
// Kernel configuration
// ============================================================================

struct KernelConfig {
    /// Data directory path (for chain database, UTXO, checkpoints).
    std::string datadir;

    /// Network selection.
    bool testnet = false;
    bool regtest = false;

    /// Assume-valid block hash: skip signature verification for all
    /// ancestors of this block. Empty string disables.
    std::string assume_valid;

    /// Skip model evaluation during validation (for light/header-only sync).
    /// When true, check 15 (forward eval) is bypassed.
    bool skip_model_eval = false;

    /// Maximum UTXO cache size in MB.
    int utxo_cache_mb = 450;

    /// Enable transaction index.
    bool txindex = false;

    /// Prune mode: keep only the last N blocks of data.
    /// 0 = disabled (keep everything).
    uint64_t prune_target_mb = 0;

    /// Return the network name based on flags.
    std::string network_name() const {
        if (regtest) return "regtest";
        if (testnet) return "testnet";
        return "mainnet";
    }
};

// ============================================================================
// Kernel — the consensus engine
// ============================================================================

class Kernel {
public:
    explicit Kernel(const KernelConfig& config);
    ~Kernel();

    // Non-copyable, non-movable (owns unique resources)
    Kernel(const Kernel&) = delete;
    Kernel& operator=(const Kernel&) = delete;
    Kernel(Kernel&&) = delete;
    Kernel& operator=(Kernel&&) = delete;

    // ---- Initialization ----------------------------------------------------

    /// Initialize the kernel: open databases, load chain state, verify
    /// genesis block. Returns false on unrecoverable errors.
    bool init();

    /// Shutdown gracefully: flush state, close databases.
    void shutdown();

    /// Check if the kernel is initialized and ready.
    bool is_initialized() const { return initialized_; }

    // ---- Header validation (fast, no UTXO needed) --------------------------

    /// Validate a block header against the current chain state.
    /// Checks: prev_hash linkage, height, timestamps, difficulty,
    /// growth fields, and miner signature. Does NOT check transactions.
    consensus::ValidationState validate_header(const CBlockHeader& header);

    /// Validate a block header against a specific parent.
    /// Used during IBD when the parent may not be the current tip.
    consensus::ValidationState validate_header(const CBlockHeader& header,
                                                const CBlockHeader& parent,
                                                uint64_t parent_height);

    // ---- Full block validation (requires UTXO) -----------------------------

    /// Validate a complete block: all header checks plus merkle root,
    /// transaction signatures, UTXO spending, coinbase reward, and
    /// (optionally) forward evaluation.
    consensus::ValidationState validate_block(const CBlock& block);

    // ---- Block acceptance --------------------------------------------------

    /// Accept a validated block: update UTXO set, chain index, and model
    /// state. The block must have been previously validated.
    consensus::ValidationState accept_block(const CBlock& block);

    // ---- Chain state queries -----------------------------------------------

    /// Get the current chain height (0 = genesis only).
    uint64_t get_height() const;

    /// Get the hash of the current chain tip.
    uint256 get_tip_hash() const;

    /// Get the block header at a specific height.
    /// Returns false if the height is beyond the current chain.
    bool get_header_at_height(uint64_t height, CBlockHeader& header) const;

    // ---- Consensus parameter queries ---------------------------------------

    /// Get the model dimensions for the current chain height.
    const consensus::ModelDimensions& get_model_dims() const;

    /// Get the model dimensions for a specific height.
    consensus::ModelDimensions get_model_dims_at(uint64_t height) const;

    /// Get the next required nbits value (difficulty target).
    uint32_t get_next_nbits() const;

    /// Get the block reward at the current height.
    Amount get_block_reward() const;

    /// Get the block reward at a specific height.
    Amount get_block_reward_at(uint64_t height) const;

    // ---- UTXO queries ------------------------------------------------------

    /// Look up a UTXO by outpoint (txid + vout index).
    bool get_utxo(const uint256& txid, uint32_t vout,
                  UTXOEntry& entry) const;

    /// Check if a UTXO exists.
    bool has_utxo(const uint256& txid, uint32_t vout) const;

    // ---- Model state queries -----------------------------------------------

    /// Get the hash of the current consensus model weights.
    uint256 get_model_hash() const;

    /// Get the total parameter count of the current model.
    size_t get_model_params() const;

    // ---- Configuration access ----------------------------------------------

    /// Get the kernel configuration.
    const KernelConfig& config() const { return config_; }

    /// Get the network magic bytes.
    uint32_t get_network_magic() const;

    /// Get the network default port.
    uint16_t get_default_port() const;

    /// Get the bech32m human-readable prefix.
    const char* get_hrp() const;

private:
    KernelConfig config_;
    bool initialized_ = false;

    // Chain state (contains block index, UTXO set, block store)
    std::unique_ptr<ChainState> chain_;

    // Consensus model evaluation engine
    std::unique_ptr<consensus::EvalEngine> eval_;

    // Cached model dimensions for current height
    consensus::ModelDimensions current_dims_;

    // Initialize genesis block if this is a fresh chain
    bool init_genesis();

    // Load chain state from disk
    bool load_chain();
};

} // namespace flow::kernel

#endif // FLOWCOIN_KERNEL_CONTEXT_H

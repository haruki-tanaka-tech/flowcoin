// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Model state persistence and checkpointing.
// ModelState owns the EvalEngine and coordinates model updates with
// block processing. Checkpoints are saved to disk every CHECKPOINT_INTERVAL
// blocks, allowing new nodes to fast-sync from a recent checkpoint
// instead of replaying all deltas from genesis.

#ifndef FLOWCOIN_CHAIN_MODELSTATE_H
#define FLOWCOIN_CHAIN_MODELSTATE_H

#include "consensus/eval.h"
#include "consensus/params.h"
#include "primitives/block.h"
#include "util/types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace flow {

class ModelState {
public:
    explicit ModelState(const std::string& datadir);

    // Initialize: load current model or create from genesis
    bool init();

    // Get the eval engine
    consensus::EvalEngine& engine() { return engine_; }
    const consensus::EvalEngine& engine() const { return engine_; }

    // Process a new accepted block
    // Applies delta, saves checkpoint if at interval
    bool process_block(const CBlock& block, uint64_t height);

    // Undo last block (reorg support)
    bool undo_block();

    // Save current state to disk
    bool save() const;

    // Model checkpoints
    // Saved every CHECKPOINT_INTERVAL blocks
    bool save_checkpoint(uint64_t height) const;
    bool load_nearest_checkpoint(uint64_t target_height);

    // List available checkpoints
    std::vector<uint64_t> list_checkpoints() const;

    // Get model info for RPC
    struct ModelInfo {
        consensus::ModelDimensions dims;
        size_t param_count;
        uint256 weights_hash;
        uint64_t last_applied_height;
    };
    ModelInfo get_info() const;

    // Current height the model is synced to
    uint64_t last_applied_height() const { return last_applied_height_; }

private:
    std::string datadir_;
    consensus::EvalEngine engine_;
    uint64_t last_applied_height_ = 0;

    std::string model_dir() const;
    std::string current_model_path() const;
    std::string checkpoint_path(uint64_t height) const;
};

} // namespace flow

#endif // FLOWCOIN_CHAIN_MODELSTATE_H

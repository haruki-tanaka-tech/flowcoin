// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Model state persistence and checkpointing implementation.
// Manages the consensus model lifecycle: genesis initialization,
// delta application, checkpoint saving/loading, and reorg support.

#include "chain/modelstate.h"
#include "consensus/growth.h"
#include "consensus/params.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace flow {

// ════════════════════════════════════════════════════════════════════════════
// Constructor
// ════════════════════════════════════════════════════════════════════════════

ModelState::ModelState(const std::string& datadir)
    : datadir_(datadir)
{
}

// ════════════════════════════════════════════════════════════════════════════
// Path helpers
// ════════════════════════════════════════════════════════════════════════════

std::string ModelState::model_dir() const {
    return datadir_ + "/model";
}

std::string ModelState::current_model_path() const {
    return model_dir() + "/current.flwm";
}

std::string ModelState::checkpoint_path(uint64_t height) const {
    char buf[128];
    snprintf(buf, sizeof(buf), "/checkpoint_%010lu.flwm",
             static_cast<unsigned long>(height));
    return model_dir() + buf;
}

// ════════════════════════════════════════════════════════════════════════════
// Helper: ensure directory exists
// ════════════════════════════════════════════════════════════════════════════

static bool ensure_dir(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    return mkdir(path.c_str(), 0755) == 0;
}

// ════════════════════════════════════════════════════════════════════════════
// init — load model or create from genesis
// ════════════════════════════════════════════════════════════════════════════

bool ModelState::init() {
    if (!ensure_dir(model_dir())) {
        fprintf(stderr, "ModelState: failed to create model directory: %s\n",
                model_dir().c_str());
        return false;
    }

    // Try to load the current model state
    std::string current_path = current_model_path();
    struct stat st;
    if (stat(current_path.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
        if (engine_.load_checkpoint(current_path)) {
            // Read the height marker file
            std::string height_path = model_dir() + "/current_height.dat";
            FILE* hf = fopen(height_path.c_str(), "rb");
            if (hf) {
                uint64_t h = 0;
                if (fread(&h, sizeof(h), 1, hf) == 1) {
                    last_applied_height_ = h;
                }
                fclose(hf);
            }

            fprintf(stderr, "ModelState: loaded model at height %lu (%zu params)\n",
                    static_cast<unsigned long>(last_applied_height_),
                    engine_.param_count());

            // Register as global eval engine instance
            consensus::EvalEngine::set_instance(&engine_);
            return true;
        }

        fprintf(stderr, "ModelState: failed to load current model, "
                "falling back to genesis\n");
    }

    // No saved state — initialize from genesis
    if (!engine_.init_genesis()) {
        fprintf(stderr, "ModelState: genesis initialization failed\n");
        return false;
    }

    last_applied_height_ = 0;

    // Save initial state
    if (!save()) {
        fprintf(stderr, "ModelState: warning: failed to save initial state\n");
    }

    // Register as global eval engine instance
    consensus::EvalEngine::set_instance(&engine_);

    fprintf(stderr, "ModelState: initialized from genesis (%zu params)\n",
            engine_.param_count());
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// process_block — apply a block's training delta to the model
// ════════════════════════════════════════════════════════════════════════════

bool ModelState::process_block(const CBlock& block, uint64_t height) {
    // Check if model dimensions need to change at this height.
    // At plateau transitions (every GROWTH_PLATEAU_LEN blocks during Phase 1),
    // the model architecture expands.
    consensus::ModelDimensions expected_dims =
        consensus::compute_growth(height, 0);  // improving_blocks handled by caller

    const consensus::ModelDimensions& current_dims = engine_.dims();

    bool needs_expansion =
        expected_dims.d_model  != current_dims.d_model  ||
        expected_dims.n_layers != current_dims.n_layers  ||
        expected_dims.d_ff     != current_dims.d_ff      ||
        expected_dims.n_slots  != current_dims.n_slots;

    if (needs_expansion) {
        fprintf(stderr, "ModelState: expanding model at height %lu "
                "(d=%u->%u, L=%u->%u)\n",
                static_cast<unsigned long>(height),
                current_dims.d_model, expected_dims.d_model,
                current_dims.n_layers, expected_dims.n_layers);

        if (!engine_.expand_model(expected_dims)) {
            fprintf(stderr, "ModelState: model expansion failed at height %lu\n",
                    static_cast<unsigned long>(height));
            return false;
        }
    }

    // Apply the block's delta payload
    if (!block.delta_payload.empty()) {
        if (!engine_.apply_block_delta(block.delta_payload)) {
            fprintf(stderr, "ModelState: failed to apply delta at height %lu\n",
                    static_cast<unsigned long>(height));
            return false;
        }
    }

    last_applied_height_ = height;

    // Save checkpoint at regular intervals
    if (height > 0 && (height % consensus::CHECKPOINT_INTERVAL) == 0) {
        if (!save_checkpoint(height)) {
            fprintf(stderr, "ModelState: warning: checkpoint save failed "
                    "at height %lu\n", static_cast<unsigned long>(height));
            // Non-fatal — we can continue without the checkpoint
        }
    }

    // Save current state periodically (every 100 blocks)
    if (height > 0 && (height % 100) == 0) {
        if (!save()) {
            fprintf(stderr, "ModelState: warning: periodic save failed "
                    "at height %lu\n", static_cast<unsigned long>(height));
        }
    }

    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// undo_block — reverse the last applied delta (for reorg)
// ════════════════════════════════════════════════════════════════════════════

bool ModelState::undo_block() {
    if (last_applied_height_ == 0) {
        fprintf(stderr, "ModelState: cannot undo past genesis\n");
        return false;
    }

    if (!engine_.undo_last_delta()) {
        fprintf(stderr, "ModelState: undo_last_delta failed at height %lu\n",
                static_cast<unsigned long>(last_applied_height_));
        return false;
    }

    last_applied_height_--;
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// save — persist current model state to disk
// ════════════════════════════════════════════════════════════════════════════

bool ModelState::save() const {
    if (!ensure_dir(model_dir())) {
        return false;
    }

    // Save model weights
    if (!engine_.save_checkpoint(current_model_path())) {
        return false;
    }

    // Save height marker
    std::string height_path = model_dir() + "/current_height.dat";
    FILE* hf = fopen(height_path.c_str(), "wb");
    if (!hf) {
        return false;
    }
    uint64_t h = last_applied_height_;
    bool ok = (fwrite(&h, sizeof(h), 1, hf) == 1);
    fclose(hf);

    return ok;
}

// ════════════════════════════════════════════════════════════════════════════
// Checkpoint management
// ════════════════════════════════════════════════════════════════════════════

bool ModelState::save_checkpoint(uint64_t height) const {
    if (!ensure_dir(model_dir())) {
        return false;
    }

    std::string path = checkpoint_path(height);
    if (!engine_.save_checkpoint(path)) {
        return false;
    }

    fprintf(stderr, "ModelState: checkpoint saved at height %lu -> %s\n",
            static_cast<unsigned long>(height), path.c_str());
    return true;
}

bool ModelState::load_nearest_checkpoint(uint64_t target_height) {
    std::vector<uint64_t> checkpoints = list_checkpoints();
    if (checkpoints.empty()) {
        fprintf(stderr, "ModelState: no checkpoints available\n");
        return false;
    }

    // Find the highest checkpoint at or below target_height
    uint64_t best_height = 0;
    bool found = false;

    for (uint64_t cp : checkpoints) {
        if (cp <= target_height && cp >= best_height) {
            best_height = cp;
            found = true;
        }
    }

    if (!found) {
        fprintf(stderr, "ModelState: no checkpoint found at or below height %lu\n",
                static_cast<unsigned long>(target_height));
        return false;
    }

    std::string path = checkpoint_path(best_height);
    if (!engine_.load_checkpoint(path)) {
        fprintf(stderr, "ModelState: failed to load checkpoint at height %lu\n",
                static_cast<unsigned long>(best_height));
        return false;
    }

    last_applied_height_ = best_height;
    fprintf(stderr, "ModelState: loaded checkpoint at height %lu\n",
            static_cast<unsigned long>(best_height));
    return true;
}

std::vector<uint64_t> ModelState::list_checkpoints() const {
    std::vector<uint64_t> result;

    DIR* dir = opendir(model_dir().c_str());
    if (!dir) {
        return result;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        // Match "checkpoint_NNNNNNNNNN.flwm"
        std::string name(entry->d_name);
        const std::string prefix = "checkpoint_";
        const std::string suffix = ".flwm";

        if (name.size() > prefix.size() + suffix.size() &&
            name.substr(0, prefix.size()) == prefix &&
            name.substr(name.size() - suffix.size()) == suffix) {

            std::string num_str = name.substr(
                prefix.size(),
                name.size() - prefix.size() - suffix.size());

            // Parse the height
            char* end = nullptr;
            unsigned long long h = strtoull(num_str.c_str(), &end, 10);
            if (end && *end == '\0') {
                result.push_back(static_cast<uint64_t>(h));
            }
        }
    }

    closedir(dir);

    std::sort(result.begin(), result.end());
    return result;
}

// ════════════════════════════════════════════════════════════════════════════
// get_info — model information for RPC
// ════════════════════════════════════════════════════════════════════════════

ModelState::ModelInfo ModelState::get_info() const {
    ModelInfo info;
    info.dims = engine_.dims();
    info.param_count = engine_.param_count();
    info.weights_hash = engine_.get_model_hash();
    info.last_applied_height = last_applied_height_;
    return info;
}

} // namespace flow

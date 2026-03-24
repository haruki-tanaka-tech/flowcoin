// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Deterministic forward evaluation engine for consensus validation.
// This file implements Check 15 — the forward evaluation that verifies
// a miner's reported val_loss matches what the model actually produces
// when the submitted delta is applied.
//
// The evaluate_with_delta() method is the heart of consensus:
//   1. Decompress the zstd-compressed delta payload
//   2. Clone current model weights
//   3. Add delta to cloned weights
//   4. Create a temporary ConsensusModel with the cloned weights
//   5. Generate deterministic validation data from VALIDATION_SEED
//   6. Run forward_eval() to compute cross-entropy loss
//   7. Return the loss (must be bit-identical across all nodes)

#include "eval.h"
#include "growth.h"
#include "params.h"
#include "../hash/keccak.h"

#include <zstd.h>

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace flow::consensus {

// ════════════════════════════════════════════════════════════════════════════
// Static instance (singleton)
// ════════════════════════════════════════════════════════════════════════════

EvalEngine* EvalEngine::instance_ = nullptr;

void EvalEngine::set_instance(EvalEngine* engine) {
    instance_ = engine;
}

EvalEngine* EvalEngine::instance() {
    return instance_;
}

// ════════════════════════════════════════════════════════════════════════════
// Construction / Destruction
// ════════════════════════════════════════════════════════════════════════════

EvalEngine::EvalEngine() = default;

EvalEngine::~EvalEngine() {
    if (instance_ == this) {
        instance_ = nullptr;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Initialization
// ════════════════════════════════════════════════════════════════════════════

bool EvalEngine::init_genesis() {
    ModelDimensions genesis_dims = compute_growth(0, 0);

    if (!model_.init(genesis_dims, GENESIS_SEED)) {
        fprintf(stderr, "EvalEngine: failed to initialize genesis model\n");
        return false;
    }

    delta_history_.clear();
    fprintf(stderr, "EvalEngine: initialized genesis model (%zu params, seed=%u)\n",
            model_.param_count(), GENESIS_SEED);
    return true;
}

bool EvalEngine::load_checkpoint(const std::string& path) {
    if (!model_.load_from_file(path)) {
        fprintf(stderr, "EvalEngine: failed to load checkpoint from %s\n",
                path.c_str());
        return false;
    }

    delta_history_.clear();
    fprintf(stderr, "EvalEngine: loaded checkpoint from %s (%zu params)\n",
            path.c_str(), model_.param_count());
    return true;
}

bool EvalEngine::save_checkpoint(const std::string& path) const {
    if (!model_.save_to_file(path)) {
        fprintf(stderr, "EvalEngine: failed to save checkpoint to %s\n",
                path.c_str());
        return false;
    }

    fprintf(stderr, "EvalEngine: saved checkpoint to %s (%zu params)\n",
            path.c_str(), model_.param_count());
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// Accessors
// ════════════════════════════════════════════════════════════════════════════

const ModelDimensions& EvalEngine::dims() const {
    return model_.dims();
}

uint256 EvalEngine::get_model_hash() const {
    return model_.get_weights_hash();
}

size_t EvalEngine::param_count() const {
    return model_.param_count();
}

// ════════════════════════════════════════════════════════════════════════════
// Delta decompression
// ════════════════════════════════════════════════════════════════════════════

std::vector<float> EvalEngine::decompress_delta(
        const std::vector<uint8_t>& compressed,
        size_t expected_floats) {

    if (compressed.empty()) {
        return {};
    }

    // Get the decompressed size from the zstd frame header
    const size_t expected_size = expected_floats * sizeof(float);
    unsigned long long const frame_size =
        ZSTD_getFrameContentSize(compressed.data(), compressed.size());

    if (frame_size == ZSTD_CONTENTSIZE_ERROR ||
        frame_size == ZSTD_CONTENTSIZE_UNKNOWN) {
        // Try decompressing with the expected size as a hint
        // (frame might not have content size in header)
        std::vector<uint8_t> decompressed(expected_size);
        size_t const result = ZSTD_decompress(
            decompressed.data(), decompressed.size(),
            compressed.data(), compressed.size());

        if (ZSTD_isError(result)) {
            fprintf(stderr, "EvalEngine: zstd decompress error: %s\n",
                    ZSTD_getErrorName(result));
            return {};
        }

        if (result != expected_size) {
            fprintf(stderr, "EvalEngine: decompressed size mismatch: "
                    "got %zu, expected %zu\n", result, expected_size);
            return {};
        }

        std::vector<float> delta(expected_floats);
        std::memcpy(delta.data(), decompressed.data(), expected_size);
        return delta;
    }

    // Frame size is known
    if (static_cast<size_t>(frame_size) != expected_size) {
        // The delta may be a sparse delta: only non-zero entries stored.
        // In sparse format, the payload is:
        //   [uint32_t count][count * (uint32_t index, float value)]
        // We try both: full-size first, then sparse.

        // Try sparse interpretation
        std::vector<uint8_t> decompressed(static_cast<size_t>(frame_size));
        size_t const result = ZSTD_decompress(
            decompressed.data(), decompressed.size(),
            compressed.data(), compressed.size());

        if (ZSTD_isError(result)) {
            fprintf(stderr, "EvalEngine: zstd decompress error (sparse): %s\n",
                    ZSTD_getErrorName(result));
            return {};
        }

        // Check if this is a sparse delta
        // Sparse format: [uint32_t count] [count * {uint32_t idx, float val}]
        // Total size: 4 + count * 8
        if (result >= 4) {
            uint32_t sparse_count = 0;
            std::memcpy(&sparse_count, decompressed.data(), 4);
            size_t expected_sparse_size = 4 + static_cast<size_t>(sparse_count) * 8;

            if (result == expected_sparse_size && sparse_count > 0) {
                // Reconstruct full delta from sparse representation
                std::vector<float> delta(expected_floats, 0.0f);
                const uint8_t* ptr = decompressed.data() + 4;

                for (uint32_t i = 0; i < sparse_count; i++) {
                    uint32_t idx = 0;
                    float val = 0.0f;
                    std::memcpy(&idx, ptr, 4);
                    ptr += 4;
                    std::memcpy(&val, ptr, 4);
                    ptr += 4;

                    if (idx < expected_floats) {
                        delta[idx] = val;
                    } else {
                        fprintf(stderr, "EvalEngine: sparse delta index %u "
                                "out of range (max %zu)\n", idx, expected_floats);
                        return {};
                    }
                }
                return delta;
            }
        }

        // Not a recognized format
        fprintf(stderr, "EvalEngine: unrecognized delta format "
                "(frame_size=%llu, expected=%zu)\n", frame_size, expected_size);
        return {};
    }

    // Standard full-size delta
    std::vector<uint8_t> decompressed(expected_size);
    size_t const result = ZSTD_decompress(
        decompressed.data(), decompressed.size(),
        compressed.data(), compressed.size());

    if (ZSTD_isError(result)) {
        fprintf(stderr, "EvalEngine: zstd decompress error: %s\n",
                ZSTD_getErrorName(result));
        return {};
    }

    if (result != expected_size) {
        fprintf(stderr, "EvalEngine: decompressed size mismatch: "
                "got %zu, expected %zu\n", result, expected_size);
        return {};
    }

    std::vector<float> delta(expected_floats);
    std::memcpy(delta.data(), decompressed.data(), expected_size);
    return delta;
}

// ════════════════════════════════════════════════════════════════════════════
// Block processing: apply delta
// ════════════════════════════════════════════════════════════════════════════

bool EvalEngine::apply_block_delta(const std::vector<uint8_t>& compressed_delta) {
    if (compressed_delta.empty()) {
        // Genesis or empty delta block — nothing to apply
        return true;
    }

    const size_t n_params = model_.param_count();
    std::vector<float> delta = decompress_delta(compressed_delta, n_params);

    if (delta.empty()) {
        fprintf(stderr, "EvalEngine: failed to decompress delta "
                "(%zu compressed bytes, %zu expected params)\n",
                compressed_delta.size(), n_params);
        return false;
    }

    // Store in history before applying (for undo support)
    DeltaRecord record;
    record.delta_weights = delta;  // Store the delta itself
    record.height = 0;  // Caller should set this, but we don't have height here

    // Apply the delta to the model
    if (!model_.apply_delta(delta)) {
        fprintf(stderr, "EvalEngine: failed to apply delta to model\n");
        return false;
    }

    // Push to history, evict oldest if needed
    delta_history_.push_back(std::move(record));
    if (delta_history_.size() > MAX_DELTA_HISTORY) {
        delta_history_.pop_front();
    }

    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// Block processing: undo delta (for reorg)
// ════════════════════════════════════════════════════════════════════════════

bool EvalEngine::undo_last_delta() {
    if (delta_history_.empty()) {
        fprintf(stderr, "EvalEngine: no delta history available for undo\n");
        return false;
    }

    const DeltaRecord& record = delta_history_.back();

    // Negate the delta to reverse it: weight -= delta (i.e., apply -delta)
    std::vector<float> neg_delta(record.delta_weights.size());
    for (size_t i = 0; i < neg_delta.size(); i++) {
        neg_delta[i] = -record.delta_weights[i];
    }

    if (!model_.apply_delta(neg_delta)) {
        fprintf(stderr, "EvalEngine: failed to apply negative delta for undo\n");
        return false;
    }

    delta_history_.pop_back();
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// Model expansion
// ════════════════════════════════════════════════════════════════════════════

bool EvalEngine::expand_model(const ModelDimensions& new_dims) {
    // Clear delta history — after expansion, old deltas are incompatible
    // (different parameter count / layout)
    delta_history_.clear();

    if (!model_.expand_to(new_dims)) {
        fprintf(stderr, "EvalEngine: model expansion failed\n");
        return false;
    }

    fprintf(stderr, "EvalEngine: model expanded to d=%u, L=%u, d_ff=%u, "
            "slots=%u (%zu params)\n",
            new_dims.d_model, new_dims.n_layers, new_dims.d_ff,
            new_dims.n_slots, model_.param_count());
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// Evaluation: Check 15 — the consensus-critical forward pass
// ════════════════════════════════════════════════════════════════════════════

float EvalEngine::evaluate_with_delta(
        const std::vector<uint8_t>& compressed_delta,
        const uint256& dataset_hash) const {

    // Step 1: Verify dataset hash matches consensus
    uint256 expected_hash = compute_dataset_hash();
    if (dataset_hash != expected_hash) {
        fprintf(stderr, "EvalEngine: dataset hash mismatch in evaluation\n");
        return MAX_VAL_LOSS;
    }

    const size_t n_params = model_.param_count();

    // Step 2: Clone the current model weights
    std::vector<float> cloned_weights = model_.get_weights();
    if (cloned_weights.size() != n_params) {
        fprintf(stderr, "EvalEngine: weight clone size mismatch\n");
        return MAX_VAL_LOSS;
    }

    // Step 3: Decompress the delta
    std::vector<float> delta = decompress_delta(compressed_delta, n_params);
    if (delta.empty() && !compressed_delta.empty()) {
        fprintf(stderr, "EvalEngine: delta decompression failed during eval\n");
        return MAX_VAL_LOSS;
    }

    // Step 4: Apply delta to cloned weights
    if (!delta.empty()) {
        if (delta.size() != n_params) {
            fprintf(stderr, "EvalEngine: delta size mismatch "
                    "(%zu vs %zu params)\n", delta.size(), n_params);
            return MAX_VAL_LOSS;
        }
        for (size_t i = 0; i < n_params; i++) {
            cloned_weights[i] += delta[i];
        }
    }

    // Step 5: Create a temporary ConsensusModel with cloned weights
    // We construct a new model with the same dimensions and load the
    // modified weights into it.
    ConsensusModel eval_model;
    if (!eval_model.init(model_.dims(), GENESIS_SEED)) {
        fprintf(stderr, "EvalEngine: failed to create eval model\n");
        return MAX_VAL_LOSS;
    }

    if (!eval_model.set_weights(cloned_weights)) {
        fprintf(stderr, "EvalEngine: failed to set weights on eval model\n");
        return MAX_VAL_LOSS;
    }

    // Step 6: Generate validation data
    std::vector<uint8_t> val_data = generate_validation_data();
    if (val_data.empty()) {
        fprintf(stderr, "EvalEngine: failed to generate validation data\n");
        return MAX_VAL_LOSS;
    }

    // Step 7: Run forward evaluation
    float loss = eval_model.forward_eval(val_data);

    // Sanity check the result
    if (!std::isfinite(loss) || loss <= 0.0f) {
        fprintf(stderr, "EvalEngine: forward_eval returned invalid loss: %f\n",
                static_cast<double>(loss));
        return MAX_VAL_LOSS;
    }

    return loss;
}

// ════════════════════════════════════════════════════════════════════════════
// Validation data generation
// ════════════════════════════════════════════════════════════════════════════

std::vector<uint8_t> EvalEngine::generate_validation_data() {
    // Use the shared deterministic generation function from consensus_model.h
    return flow::generate_validation_data(
        flow::VALIDATION_SEED,
        static_cast<size_t>(EVAL_TOKENS));
}

uint256 EvalEngine::compute_dataset_hash() {
    std::vector<uint8_t> data = generate_validation_data();
    return keccak256(data.data(), data.size());
}

// ════════════════════════════════════════════════════════════════════════════
// Static adapter for validation.cpp's EvalFunction
// ════════════════════════════════════════════════════════════════════════════

float EvalEngine::eval_function_adapter(
        const std::vector<uint8_t>& delta,
        const uint256& dataset_hash) {

    if (!instance_) {
        fprintf(stderr, "EvalEngine: eval_function_adapter called but "
                "no instance set\n");
        return MAX_VAL_LOSS;
    }

    return instance_->evaluate_with_delta(delta, dataset_hash);
}

} // namespace flow::consensus

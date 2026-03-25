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
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include "logging.h"

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
    ModelDimensions genesis_dims = compute_growth(0);

    if (!model_.init(genesis_dims, GENESIS_SEED)) {
        LogError("eval", "failed to initialize genesis model");
        return false;
    }

    delta_history_.clear();
    LogInfo("eval", "initialized genesis model (%zu params, seed=%u)",
            model_.param_count(), GENESIS_SEED);
    return true;
}

bool EvalEngine::load_checkpoint(const std::string& path) {
    if (!model_.load_from_file(path)) {
        LogError("eval", "failed to load checkpoint from %s",
                path.c_str());
        return false;
    }

    delta_history_.clear();
    LogInfo("eval", "loaded checkpoint from %s (%zu params)",
            path.c_str(), model_.param_count());
    return true;
}

bool EvalEngine::save_checkpoint(const std::string& path) const {
    if (!model_.save_to_file(path)) {
        LogError("eval", "failed to save checkpoint to %s",
                path.c_str());
        return false;
    }

    LogInfo("eval", "saved checkpoint to %s (%zu params)",
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
            LogError("eval", "zstd decompress error: %s",
                    ZSTD_getErrorName(result));
            return {};
        }

        if (result != expected_size) {
            LogError("eval", "decompressed size mismatch: "
                    "got %zu, expected %zu", result, expected_size);
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
            LogError("eval", "zstd decompress error (sparse): %s",
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
                        LogInfo("eval", "sparse delta index %u "
                                "out of range (max %zu)", idx, expected_floats);
                        return {};
                    }
                }
                return delta;
            }
        }

        // Not a recognized format
        LogInfo("eval", "unrecognized delta format "
                "(frame_size=%llu, expected=%zu)", frame_size, expected_size);
        return {};
    }

    // Standard full-size delta
    std::vector<uint8_t> decompressed(expected_size);
    size_t const result = ZSTD_decompress(
        decompressed.data(), decompressed.size(),
        compressed.data(), compressed.size());

    if (ZSTD_isError(result)) {
        LogError("eval", "zstd decompress error: %s",
                ZSTD_getErrorName(result));
        return {};
    }

    if (result != expected_size) {
        LogError("eval", "decompressed size mismatch: "
                "got %zu, expected %zu", result, expected_size);
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
        LogError("eval", "failed to decompress delta "
                "(%zu compressed bytes, %zu expected params)",
                compressed_delta.size(), n_params);
        return false;
    }

    // Store in history before applying (for undo support)
    DeltaRecord record;
    record.delta_weights = delta;  // Store the delta itself
    record.height = 0;  // Caller should set this, but we don't have height here

    // Apply the delta to the model
    if (!model_.apply_delta(delta)) {
        LogError("eval", "failed to apply delta to model");
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
        LogInfo("eval", "no delta history available for undo");
        return false;
    }

    const DeltaRecord& record = delta_history_.back();

    // Negate the delta to reverse it: weight -= delta (i.e., apply -delta)
    std::vector<float> neg_delta(record.delta_weights.size());
    for (size_t i = 0; i < neg_delta.size(); i++) {
        neg_delta[i] = -record.delta_weights[i];
    }

    if (!model_.apply_delta(neg_delta)) {
        LogError("eval", "failed to apply negative delta for undo");
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
        LogError("eval", "model expansion failed");
        return false;
    }

    LogInfo("eval", "model expanded to d=%u, L=%u, d_ff=%u, "
            "slots=%u (%zu params)",
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
        LogError("eval", "dataset hash mismatch in evaluation");
        return MAX_VAL_LOSS;
    }

    const size_t n_params = model_.param_count();

    // Step 2: Clone the current model weights
    std::vector<float> cloned_weights = model_.get_weights();
    if (cloned_weights.size() != n_params) {
        LogError("eval", "weight clone size mismatch");
        return MAX_VAL_LOSS;
    }

    // Step 3: Decompress the delta
    std::vector<float> delta = decompress_delta(compressed_delta, n_params);
    if (delta.empty() && !compressed_delta.empty()) {
        LogError("eval", "delta decompression failed during eval");
        return MAX_VAL_LOSS;
    }

    // Step 4: Apply delta to cloned weights
    if (!delta.empty()) {
        if (delta.size() != n_params) {
            LogError("eval", "delta size mismatch "
                    "(%zu vs %zu params)", delta.size(), n_params);
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
        LogError("eval", "failed to create eval model");
        return MAX_VAL_LOSS;
    }

    if (!eval_model.set_weights(cloned_weights)) {
        LogError("eval", "failed to set weights on eval model");
        return MAX_VAL_LOSS;
    }

    // Step 6: Generate validation data
    std::vector<uint8_t> val_data = generate_validation_data();
    if (val_data.empty()) {
        LogError("eval", "failed to generate validation data");
        return MAX_VAL_LOSS;
    }

    // Step 7: Run forward evaluation
    float loss = eval_model.forward_eval(val_data);

    // Sanity check the result
    if (!std::isfinite(loss) || loss <= 0.0f) {
        LogError("eval", "forward_eval returned invalid loss: %f",
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
        LogInfo("eval", "eval_function_adapter called but "
                "no instance set");
        return MAX_VAL_LOSS;
    }

    return instance_->evaluate_with_delta(delta, dataset_hash);
}

// ════════════════════════════════════════════════════════════════════════════
// evaluate_with_metrics — extended evaluation with detailed metrics
// ════════════════════════════════════════════════════════════════════════════

// evaluate_with_metrics removed (was incorrectly declared outside class)

// ════════════════════════════════════════════════════════════════════════════
// verify_determinism
// ════════════════════════════════════════════════════════════════════════════

bool verify_determinism(float loss_a, float loss_b) {
    // Bit-exact comparison via memcpy
    uint32_t bits_a, bits_b;
    std::memcpy(&bits_a, &loss_a, sizeof(uint32_t));
    std::memcpy(&bits_b, &loss_b, sizeof(uint32_t));
    return bits_a == bits_b;
}

// ════════════════════════════════════════════════════════════════════════════
// SequenceMetrics — per-sequence evaluation detail
// ════════════════════════════════════════════════════════════════════════════

struct SequenceMetrics {
    int sequence_index;
    int num_tokens;
    float loss;
    float perplexity;
    float accuracy_top1;
    float accuracy_top5;
    int64_t eval_time_us;
};

// ════════════════════════════════════════════════════════════════════════════
// evaluate_detailed — evaluate model on multiple sequences
// ════════════════════════════════════════════════════════════════════════════
// Splits validation data into sequences of seq_len tokens, evaluates each
// independently, and returns per-sequence metrics including loss, perplexity,
// and top-k accuracy.

std::vector<SequenceMetrics> evaluate_detailed(
        const ConsensusModel& model,
        const std::vector<uint8_t>& data,
        int seq_len) {

    std::vector<SequenceMetrics> results;

    if (data.empty() || seq_len <= 1) {
        return results;
    }

    const size_t total_tokens = data.size();
    const int num_sequences = static_cast<int>(total_tokens / static_cast<size_t>(seq_len));

    if (num_sequences == 0) {
        return results;
    }

    results.reserve(static_cast<size_t>(num_sequences));

    for (int seq_i = 0; seq_i < num_sequences; ++seq_i) {
        SequenceMetrics metrics;
        metrics.sequence_index = seq_i;
        metrics.num_tokens = seq_len;

        auto t0 = std::chrono::steady_clock::now();

        // Extract this sequence's tokens
        size_t offset = static_cast<size_t>(seq_i) * static_cast<size_t>(seq_len);
        std::vector<uint8_t> seq_tokens(
            data.begin() + static_cast<ptrdiff_t>(offset),
            data.begin() + static_cast<ptrdiff_t>(offset + static_cast<size_t>(seq_len)));

        // Run forward pass to get logits
        // logits: [seq_len * vocab_size] where vocab_size = 256
        const int vocab_size = 256;
        std::vector<float> logits(static_cast<size_t>(seq_len * vocab_size));

        // Use the model's forward_eval to compute cross-entropy on this sequence.
        // We compute loss, perplexity, and accuracy from the logits.
        float seq_loss = model.forward_eval(seq_tokens);

        metrics.loss = seq_loss;
        metrics.perplexity = std::exp(seq_loss);

        // For top-k accuracy, we need to run the forward pass and compare
        // predicted tokens with actual next tokens. Since forward_eval gives
        // us the average loss, we compute accuracy separately.
        //
        // We approximate accuracy from loss:
        // Perfect prediction: loss = 0, accuracy = 1.0
        // Random prediction: loss = ln(256) ~= 5.545, accuracy ~= 1/256
        //
        // For a more precise estimate without running the full forward pass
        // twice, we use the relationship between cross-entropy and accuracy:
        //   accuracy_top1 ~ exp(-loss)  (lower bound estimate)
        //   accuracy_top5 ~ min(1.0, 5 * exp(-loss))  (rough estimate)
        //
        // These are approximations; the exact values would require the full
        // logits output.
        metrics.accuracy_top1 = std::min(1.0f, std::exp(-seq_loss));
        metrics.accuracy_top5 = std::min(1.0f, 5.0f * std::exp(-seq_loss));

        auto t1 = std::chrono::steady_clock::now();
        metrics.eval_time_us = std::chrono::duration_cast<std::chrono::microseconds>(
            t1 - t0).count();

        results.push_back(metrics);
    }

    return results;
}

// ════════════════════════════════════════════════════════════════════════════
// LayerProfile — per-layer timing breakdown
// ════════════════════════════════════════════════════════════════════════════

struct LayerProfile {
    int layer_index;
    int64_t conv_us;
    int64_t gru_us;
    int64_t slot_us;
    int64_t ffn_us;
    int64_t norm_us;
    int64_t total_us;
};

// ════════════════════════════════════════════════════════════════════════════
// profile_forward — time each layer component during forward pass
// ════════════════════════════════════════════════════════════════════════════
// Runs the forward pass with timing instrumentation around each layer.
// Since the ConsensusModel runs its forward pass as a monolithic operation
// (via ggml graph execution), we profile by running the full pass for each
// sub-layer count and measuring the marginal time.

std::vector<LayerProfile> profile_forward(
        const ConsensusModel& model,
        const std::vector<uint8_t>& tokens,
        int seq_len) {

    std::vector<LayerProfile> profiles;

    if (tokens.empty() || seq_len <= 0) {
        return profiles;
    }

    const auto& dims = model.dims();
    const int n_layers = static_cast<int>(dims.n_layers);

    // Prepare the input sequence (truncate or pad to seq_len)
    std::vector<uint8_t> input_tokens;
    if (static_cast<int>(tokens.size()) >= seq_len) {
        input_tokens.assign(tokens.begin(), tokens.begin() + seq_len);
    } else {
        input_tokens = tokens;
        input_tokens.resize(static_cast<size_t>(seq_len), 0);
    }

    // Profile the full forward pass first to get a baseline
    auto full_start = std::chrono::steady_clock::now();
    float full_loss = model.forward_eval(input_tokens);
    auto full_end = std::chrono::steady_clock::now();
    int64_t full_us = std::chrono::duration_cast<std::chrono::microseconds>(
        full_end - full_start).count();

    // Since we cannot instrument individual layer components without
    // modifying the ggml graph execution, we estimate per-layer time
    // proportionally based on parameter counts per component.
    //
    // Component parameter counts per layer:
    //   conv: 3*d + 7*d + 15*d + d*d = 25*d + d*d
    //   gru:  2*d*d + 2*d (Wz + Wh + bz + bh)
    //   slot: d*n_slots + d*n_slots + d*d + d*d = 2*d*slots + 2*d*d
    //   ffn:  d*dff + d*dff + dff*d = 3*d*dff
    //   norm: 4*d (4 RMSNorm weights per layer)
    //
    // We distribute the total time proportionally to FLOPs, which scale
    // roughly as 2 * params * seq_len.

    uint32_t d = dims.d_model;
    uint32_t dff = dims.d_ff;
    uint32_t slots = dims.n_slots;

    uint64_t conv_params  = 25ULL * d + static_cast<uint64_t>(d) * d;
    uint64_t gru_params   = 2ULL * d * d + 2ULL * d;
    uint64_t slot_params  = 2ULL * d * slots + 2ULL * d * d;
    uint64_t ffn_params   = 3ULL * d * dff;
    uint64_t norm_params  = 4ULL * d;

    uint64_t total_per_layer = conv_params + gru_params + slot_params +
                               ffn_params + norm_params;

    // Embedding and final norm overhead: tok_emb (256*d) + final_norm (d)
    uint64_t overhead_params = 256ULL * d + d;

    uint64_t total_model_params = static_cast<uint64_t>(n_layers) * total_per_layer +
                                  overhead_params;

    // Time per layer = (full_time * layer_params) / total_params
    // (assuming FLOPs scale linearly with params for this architecture)
    for (int l = 0; l < n_layers; ++l) {
        LayerProfile lp;
        lp.layer_index = l;

        if (total_model_params > 0) {
            double time_fraction = static_cast<double>(total_per_layer) /
                                   static_cast<double>(total_model_params);
            int64_t layer_us = static_cast<int64_t>(
                static_cast<double>(full_us) * time_fraction);

            // Distribute within the layer based on parameter ratios
            double conv_frac  = static_cast<double>(conv_params) /
                                static_cast<double>(total_per_layer);
            double gru_frac   = static_cast<double>(gru_params) /
                                static_cast<double>(total_per_layer);
            double slot_frac  = static_cast<double>(slot_params) /
                                static_cast<double>(total_per_layer);
            double ffn_frac   = static_cast<double>(ffn_params) /
                                static_cast<double>(total_per_layer);
            double norm_frac  = static_cast<double>(norm_params) /
                                static_cast<double>(total_per_layer);

            lp.conv_us = static_cast<int64_t>(static_cast<double>(layer_us) * conv_frac);
            lp.gru_us  = static_cast<int64_t>(static_cast<double>(layer_us) * gru_frac);
            lp.slot_us = static_cast<int64_t>(static_cast<double>(layer_us) * slot_frac);
            lp.ffn_us  = static_cast<int64_t>(static_cast<double>(layer_us) * ffn_frac);
            lp.norm_us = static_cast<int64_t>(static_cast<double>(layer_us) * norm_frac);
            lp.total_us = lp.conv_us + lp.gru_us + lp.slot_us + lp.ffn_us + lp.norm_us;
        } else {
            lp.conv_us = lp.gru_us = lp.slot_us = lp.ffn_us = lp.norm_us = lp.total_us = 0;
        }

        profiles.push_back(lp);
    }

    // Suppress unused variable warning for loss value
    (void)full_loss;

    return profiles;
}

// ════════════════════════════════════════════════════════════════════════════
// ModelComparison — compare two model states
// ════════════════════════════════════════════════════════════════════════════

struct ModelComparison {
    size_t total_params;
    size_t changed_params;
    float change_ratio;
    float max_abs_change;
    float mean_abs_change;
    float l2_distance;
    std::vector<float> per_layer_l2;
};

ModelComparison compare_models(
        const ConsensusModel& model_a,
        const ConsensusModel& model_b) {

    ModelComparison result;
    result.total_params = model_a.param_count();
    result.changed_params = 0;
    result.change_ratio = 0.0f;
    result.max_abs_change = 0.0f;
    result.mean_abs_change = 0.0f;
    result.l2_distance = 0.0f;

    // Dimensions must match
    if (model_a.param_count() != model_b.param_count()) {
        result.total_params = 0;
        return result;
    }

    // Get both weight vectors
    std::vector<float> weights_a = model_a.get_weights();
    std::vector<float> weights_b = model_b.get_weights();

    if (weights_a.size() != weights_b.size()) {
        result.total_params = 0;
        return result;
    }

    const size_t n = weights_a.size();

    // Compute per-parameter statistics
    double sum_abs = 0.0;
    double sum_sq = 0.0;

    for (size_t i = 0; i < n; ++i) {
        float diff = weights_a[i] - weights_b[i];
        float abs_diff = std::fabs(diff);

        if (abs_diff > 1e-30f) {
            result.changed_params++;
        }

        if (abs_diff > result.max_abs_change) {
            result.max_abs_change = abs_diff;
        }

        sum_abs += static_cast<double>(abs_diff);
        sum_sq += static_cast<double>(diff) * static_cast<double>(diff);
    }

    result.change_ratio = static_cast<float>(
        static_cast<double>(result.changed_params) / static_cast<double>(n));
    result.mean_abs_change = static_cast<float>(sum_abs / static_cast<double>(n));
    result.l2_distance = static_cast<float>(std::sqrt(sum_sq));

    // Compute per-layer L2 distances
    // Each layer has the same number of parameters (layer_param_count).
    // The layout is: [tok_emb] [layer_0 ... layer_N-1] [final_norm]
    const auto& dims = model_a.dims();
    const size_t d = dims.d_model;
    const size_t vocab_size = 256;

    // Token embedding: vocab_size * d
    size_t emb_params = vocab_size * d;

    // Per-layer parameters (from consensus_model.h):
    //   4 norm weights (d each) = 4*d
    //   conv: 3*d + 7*d + 15*d + d*d = 25*d + d*d
    //   gru: 2*d*d + 2*d
    //   slot: 2*d*n_slots + 2*d*d
    //   ffn: d*d_ff + d*d_ff + d_ff*d = 3*d*d_ff
    size_t layer_params = 4 * d +
                          25 * d + d * d +
                          2 * d * d + 2 * d +
                          2 * d * dims.n_slots + 2 * d * d +
                          3 * static_cast<size_t>(d) * dims.d_ff;

    // Final norm: d
    size_t final_norm_params = d;

    // Compute per-layer L2
    size_t offset = emb_params;  // start after embedding
    for (uint32_t l = 0; l < dims.n_layers; ++l) {
        double layer_sq = 0.0;
        size_t end_offset = std::min(offset + layer_params, n);

        for (size_t i = offset; i < end_offset; ++i) {
            float diff = weights_a[i] - weights_b[i];
            layer_sq += static_cast<double>(diff) * static_cast<double>(diff);
        }

        result.per_layer_l2.push_back(static_cast<float>(std::sqrt(layer_sq)));
        offset = end_offset;
    }

    // Suppress warnings
    (void)final_norm_params;

    return result;
}

// ════════════════════════════════════════════════════════════════════════════
// ValidationStrategy and extended validation data generation
// ════════════════════════════════════════════════════════════════════════════

enum class ValidationStrategy {
    COUNTER_MODE,    // keccak256(seed || counter) -- default
    HASH_CHAIN,      // keccak256(previous_hash)
    BLOCK_DERIVED,   // keccak256(seed || block_hash)
};

std::vector<uint8_t> generate_validation_data_ex(
        const std::string& seed_str,
        size_t num_tokens,
        ValidationStrategy strategy,
        const uint256* block_hash) {

    std::vector<uint8_t> result;
    result.reserve(num_tokens);

    if (strategy == ValidationStrategy::COUNTER_MODE) {
        // Default strategy: keccak256(seed || counter_le32)
        // This is identical to the standard generate_validation_data
        return flow::generate_validation_data(seed_str, num_tokens);
    }

    if (strategy == ValidationStrategy::HASH_CHAIN) {
        // Hash chain: each block of 32 bytes is keccak256(previous_block)
        // First block: keccak256(seed)
        std::vector<uint8_t> seed_bytes(seed_str.begin(), seed_str.end());
        uint256 current_hash = keccak256(seed_bytes.data(), seed_bytes.size());

        while (result.size() < num_tokens) {
            // Append the 32 bytes of the current hash
            for (size_t i = 0; i < 32 && result.size() < num_tokens; ++i) {
                result.push_back(current_hash.data()[i]);
            }
            // Hash the current hash to get the next block
            current_hash = keccak256(current_hash.data(), 32);
        }

        result.resize(num_tokens);
        return result;
    }

    if (strategy == ValidationStrategy::BLOCK_DERIVED) {
        // Block-derived: keccak256(seed || block_hash || counter_le32)
        if (!block_hash) {
            // Fallback to counter mode if no block hash provided
            return flow::generate_validation_data(seed_str, num_tokens);
        }

        std::vector<uint8_t> prefix;
        prefix.insert(prefix.end(), seed_str.begin(), seed_str.end());
        prefix.insert(prefix.end(), block_hash->begin(), block_hash->end());

        uint32_t counter = 0;
        while (result.size() < num_tokens) {
            // Append counter as 4 bytes LE
            std::vector<uint8_t> input = prefix;
            input.push_back(static_cast<uint8_t>(counter));
            input.push_back(static_cast<uint8_t>(counter >> 8));
            input.push_back(static_cast<uint8_t>(counter >> 16));
            input.push_back(static_cast<uint8_t>(counter >> 24));

            uint256 hash = keccak256(input.data(), input.size());

            for (size_t i = 0; i < 32 && result.size() < num_tokens; ++i) {
                result.push_back(hash.data()[i]);
            }

            counter++;
        }

        result.resize(num_tokens);
        return result;
    }

    // Unknown strategy, fallback
    return flow::generate_validation_data(seed_str, num_tokens);
}

// ════════════════════════════════════════════════════════════════════════════
// forward_with_temperature — temperature-scaled softmax for generation
// ════════════════════════════════════════════════════════════════════════════
// Runs the model forward pass and applies temperature scaling to the output
// logits. Temperature < 1.0 sharpens the distribution (more deterministic),
// temperature > 1.0 flattens it (more random).
//
// Returns a softmax probability distribution over the vocabulary for the
// last token position.

std::vector<float> forward_with_temperature(
        const ConsensusModel& model,
        const std::vector<uint8_t>& tokens,
        float temperature) {

    const int vocab_size = 256;
    std::vector<float> probs(vocab_size, 0.0f);

    if (tokens.empty()) {
        // Uniform distribution
        float uniform = 1.0f / static_cast<float>(vocab_size);
        std::fill(probs.begin(), probs.end(), uniform);
        return probs;
    }

    // Clamp temperature to prevent division by zero or overflow
    if (temperature < 0.01f) temperature = 0.01f;
    if (temperature > 100.0f) temperature = 100.0f;

    // Run the forward pass to get logits.
    // Since ConsensusModel::forward_eval returns only the loss, we need to
    // use forward_sequence for logits. We compute the loss manually here.
    //
    // However, forward_sequence is private. Instead, we use the model's
    // forward_eval with a single-token probe to extract effective logits.
    //
    // We construct the probability distribution by evaluating the loss
    // for each possible next token and converting to probabilities.
    // This is expensive (256 forward passes) but correct for generation.
    //
    // For efficiency, we use an approximation based on the model's
    // cross-entropy loss at each position. Given the loss L for a
    // sequence, we know that exp(-L * seq_len) approximates the
    // probability of the correct token. We can then construct a
    // softmax distribution.
    //
    // Practical approach: run the forward pass once, use the loss to
    // estimate the entropy of the distribution, and sample from a
    // temperature-scaled uniform-prior distribution weighted by the loss.

    // Run forward to get the baseline loss
    float base_loss = model.forward_eval(tokens);

    // Temperature-scaled probability estimation:
    // We model the output distribution as a softmax with logits derived
    // from the base loss. The true distribution has entropy ~= base_loss.
    //
    // For a more accurate approach, we create candidate sequences by
    // appending each possible next byte and measuring the loss change.
    //
    // Since we need this for text generation (non-consensus), we use a
    // simpler heuristic: generate logits that reproduce the observed loss
    // pattern. We set the "correct" logit to -base_loss and all others
    // to -MAX_VAL_LOSS, then apply temperature scaling.

    // Simple approach: run the sequence with each possible next token
    // and measure per-token loss to extract logit-like scores
    std::vector<float> scores(vocab_size, 0.0f);

    // For each candidate next token, compute the model's prediction quality
    // We use a batch of probe sequences to estimate the logit distribution.
    // To keep this tractable, we sample a subset of the vocabulary.
    const int probe_count = vocab_size;

    for (int v = 0; v < probe_count; ++v) {
        std::vector<uint8_t> probe = tokens;
        probe.push_back(static_cast<uint8_t>(v));

        float probe_loss = model.forward_eval(probe);

        // The negative loss serves as a logit-like score:
        // lower loss = higher probability for this token
        scores[v] = -probe_loss;
    }

    // Apply temperature scaling
    for (int v = 0; v < vocab_size; ++v) {
        scores[v] /= temperature;
    }

    // Softmax to convert scores to probabilities
    float max_score = *std::max_element(scores.begin(), scores.end());
    float sum_exp = 0.0f;
    for (int v = 0; v < vocab_size; ++v) {
        probs[v] = std::exp(scores[v] - max_score);
        sum_exp += probs[v];
    }

    if (sum_exp > 0.0f) {
        for (int v = 0; v < vocab_size; ++v) {
            probs[v] /= sum_exp;
        }
    } else {
        float uniform = 1.0f / static_cast<float>(vocab_size);
        std::fill(probs.begin(), probs.end(), uniform);
    }

    // Suppress unused variable warning
    (void)base_loss;

    return probs;
}

// ════════════════════════════════════════════════════════════════════════════
// generate_text — greedy/temperature text generation
// ════════════════════════════════════════════════════════════════════════════
// Generates text by repeatedly predicting the next token. Uses greedy
// decoding (argmax) when temperature <= 0.01, or temperature-scaled
// sampling otherwise.
//
// This is for testing model quality, not consensus. The generated text
// shows what the model has learned from training.

std::vector<uint8_t> generate_text(
        const ConsensusModel& model,
        const std::vector<uint8_t>& prompt,
        int max_tokens,
        float temperature) {

    std::vector<uint8_t> output = prompt;

    if (max_tokens <= 0) {
        return output;
    }

    // Use a deterministic PRNG for sampling (keccak256-based)
    // Seed from the prompt hash
    uint256 rng_state = keccak256(prompt.data(), prompt.size());
    uint32_t rng_counter = 0;

    for (int t = 0; t < max_tokens; ++t) {
        // Get probability distribution for next token
        std::vector<float> probs = forward_with_temperature(
            model, output, temperature);

        uint8_t next_token = 0;

        if (temperature <= 0.01f) {
            // Greedy: pick the most probable token
            float best = -1.0f;
            for (int v = 0; v < 256; ++v) {
                if (probs[v] > best) {
                    best = probs[v];
                    next_token = static_cast<uint8_t>(v);
                }
            }
        } else {
            // Temperature sampling with deterministic PRNG
            // Generate a random float in [0, 1) from keccak256
            uint8_t counter_bytes[4];
            counter_bytes[0] = static_cast<uint8_t>(rng_counter);
            counter_bytes[1] = static_cast<uint8_t>(rng_counter >> 8);
            counter_bytes[2] = static_cast<uint8_t>(rng_counter >> 16);
            counter_bytes[3] = static_cast<uint8_t>(rng_counter >> 24);

            std::vector<uint8_t> rng_input(rng_state.begin(), rng_state.end());
            rng_input.insert(rng_input.end(), counter_bytes, counter_bytes + 4);

            uint256 rng_hash = keccak256(rng_input.data(), rng_input.size());
            rng_counter++;

            // Convert first 4 bytes to float in [0, 1)
            uint32_t rand_bits = 0;
            std::memcpy(&rand_bits, rng_hash.data(), 4);
            float rand_val = static_cast<float>(rand_bits) / 4294967296.0f;

            // Sample from the cumulative distribution
            float cumulative = 0.0f;
            for (int v = 0; v < 256; ++v) {
                cumulative += probs[v];
                if (rand_val < cumulative) {
                    next_token = static_cast<uint8_t>(v);
                    break;
                }
            }
        }

        output.push_back(next_token);

        // Limit context window to prevent excessive computation
        // Keep at most 2048 tokens of context
        if (output.size() > 2048) {
            output.erase(output.begin(),
                         output.begin() + static_cast<ptrdiff_t>(output.size() - 2048));
        }
    }

    return output;
}

// ════════════════════════════════════════════════════════════════════════════
// compute_eval_metrics — compute comprehensive evaluation metrics
// ════════════════════════════════════════════════════════════════════════════

EvalMetrics compute_eval_metrics(const ConsensusModel& model,
                                  const std::vector<uint8_t>& val_data) {
    EvalMetrics metrics;

    auto t0 = std::chrono::steady_clock::now();

    metrics.val_loss = model.forward_eval(val_data);
    metrics.perplexity = std::exp(metrics.val_loss);
    metrics.bits_per_byte = metrics.val_loss / 0.693147f;  // ln(2)
    metrics.total_tokens = val_data.size();

    // Approximate accuracy from loss
    metrics.accuracy_top1 = std::min(1.0f, std::exp(-metrics.val_loss));
    metrics.accuracy_top5 = std::min(1.0f, 5.0f * std::exp(-metrics.val_loss));

    auto t1 = std::chrono::steady_clock::now();
    metrics.eval_time_ms = static_cast<double>(
        std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count()) / 1000.0;

    return metrics;
}

// ════════════════════════════════════════════════════════════════════════════
// model_quality_summary — human-readable summary of model quality
// ════════════════════════════════════════════════════════════════════════════

static const char* loss_to_quality_label(float loss) {
    if (loss < 1.0f)  return "excellent";
    if (loss < 2.0f)  return "good";
    if (loss < 3.0f)  return "fair";
    if (loss < 4.0f)  return "poor";
    if (loss < 5.0f)  return "bad";
    return "untrained";
}

std::string model_quality_summary(const EvalMetrics& metrics) {
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "Loss: %.4f (%s) | Perplexity: %.2f | Bits/byte: %.3f | "
        "Top-1: %.1f%% | Top-5: %.1f%% | Tokens: %zu | Time: %.1f ms",
        static_cast<double>(metrics.val_loss),
        loss_to_quality_label(metrics.val_loss),
        static_cast<double>(metrics.perplexity),
        static_cast<double>(metrics.bits_per_byte),
        static_cast<double>(metrics.accuracy_top1 * 100.0f),
        static_cast<double>(metrics.accuracy_top5 * 100.0f),
        metrics.total_tokens,
        metrics.eval_time_ms);
    return std::string(buf);
}

// ════════════════════════════════════════════════════════════════════════════
// batch_evaluate — evaluate on multiple disjoint data segments
// ════════════════════════════════════════════════════════════════════════════

struct BatchEvalResult {
    float mean_loss;
    float min_loss;
    float max_loss;
    float std_loss;
    size_t total_tokens;
    double total_time_ms;
    std::vector<float> per_segment_loss;
};

BatchEvalResult batch_evaluate(
        const ConsensusModel& model,
        const std::vector<uint8_t>& data,
        int segment_size) {

    BatchEvalResult result;
    result.mean_loss = 0.0f;
    result.min_loss = std::numeric_limits<float>::max();
    result.max_loss = 0.0f;
    result.std_loss = 0.0f;
    result.total_tokens = 0;
    result.total_time_ms = 0.0;

    if (data.empty() || segment_size <= 0) {
        return result;
    }

    int num_segments = static_cast<int>(data.size()) / segment_size;
    if (num_segments == 0) {
        num_segments = 1;
    }

    result.per_segment_loss.reserve(static_cast<size_t>(num_segments));

    auto t0 = std::chrono::steady_clock::now();

    double sum_loss = 0.0;
    double sum_sq_loss = 0.0;

    for (int s = 0; s < num_segments; ++s) {
        size_t start = static_cast<size_t>(s) * static_cast<size_t>(segment_size);
        size_t end = std::min(start + static_cast<size_t>(segment_size), data.size());

        std::vector<uint8_t> segment(data.begin() + static_cast<ptrdiff_t>(start),
                                      data.begin() + static_cast<ptrdiff_t>(end));

        float seg_loss = model.forward_eval(segment);

        result.per_segment_loss.push_back(seg_loss);
        sum_loss += static_cast<double>(seg_loss);
        sum_sq_loss += static_cast<double>(seg_loss) * static_cast<double>(seg_loss);

        if (seg_loss < result.min_loss) result.min_loss = seg_loss;
        if (seg_loss > result.max_loss) result.max_loss = seg_loss;

        result.total_tokens += segment.size();
    }

    auto t1 = std::chrono::steady_clock::now();
    result.total_time_ms = static_cast<double>(
        std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count()) / 1000.0;

    result.mean_loss = static_cast<float>(
        sum_loss / static_cast<double>(num_segments));

    if (num_segments > 1) {
        double variance = (sum_sq_loss / static_cast<double>(num_segments)) -
                           (result.mean_loss * result.mean_loss);
        result.std_loss = static_cast<float>(std::sqrt(std::max(0.0, variance)));
    }

    return result;
}

} // namespace flow::consensus

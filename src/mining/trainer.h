// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Trainer: SGD training loop using ggml.
// Produces weight deltas that constitute Proof-of-Training.
//
// For v0.1: simple 2-layer MLP for demonstration.
// Production will use the full Transformer + MoE architecture.

#pragma once

#include "core/types.h"
#include <cstdint>
#include <string>
#include <vector>

struct ggml_context;
struct ggml_tensor;

namespace flow::mining {

// Training result from one mining attempt
struct TrainingResult {
    float loss_before;
    float loss_after;
    uint32_t steps;
    std::vector<uint8_t> weight_deltas; // compressed delta
    Hash256 model_hash_before;
    Hash256 model_hash_after;
};

class Trainer {
public:
    // Initialize with model dimensions
    Trainer(uint32_t d_model, uint32_t d_ff, uint32_t vocab_size);
    ~Trainer();

    Trainer(const Trainer&) = delete;
    Trainer& operator=(const Trainer&) = delete;

    // Run one training step (SGD) on the given data.
    // Returns loss before and after the step.
    TrainingResult train_step(const std::vector<int32_t>& input_tokens,
                               const std::vector<int32_t>& target_tokens,
                               float learning_rate = 0.001f);

    // Compute forward pass loss on validation data (deterministic).
    // Single-threaded, IEEE 754, fixed accumulation order.
    float eval_loss(const std::vector<int32_t>& tokens);

    // Get hash of current model weights
    Hash256 model_hash() const;

    // Get serialized weight deltas (difference from initial weights)
    std::vector<uint8_t> get_deltas() const;

private:
    uint32_t d_model_;
    uint32_t d_ff_;
    uint32_t vocab_size_;

    ggml_context* ctx_{nullptr};

    // Model parameters (owned by ctx_)
    ggml_tensor* embed_;    // [vocab_size, d_model]
    ggml_tensor* w1_;       // [d_model, d_ff]
    ggml_tensor* b1_;       // [d_ff]
    ggml_tensor* w2_;       // [d_ff, vocab_size]
    ggml_tensor* b2_;       // [vocab_size]

    // Snapshot of initial weights for computing deltas
    std::vector<float> initial_weights_;

    void init_weights();
    std::vector<float> flatten_weights() const;
};

} // namespace flow::mining

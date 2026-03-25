// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// ResonanceNet V5 miner model using ggml for all tensor operations.
// Simplified architecture for mining (matches consensus model layout):
//   Embedding -> [RMSNorm -> MinGRU -> +res -> RMSNorm -> SwiGLU FFN -> +res] x N
//     -> final_norm -> logits -> cross_entropy
//
// ggml provides:
//   - CPU backend automatically
//   - CUDA via ggml-cuda (when available)
//   - Metal via ggml-metal (when available)
//   - No custom backends needed

#pragma once

#include "../ggml/ggml.h"
#include "../ggml/ggml-cpu.h"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>

namespace flow::miner {

// ResonanceNet V5 model using ggml for all tensor operations
class GGMLModel {
public:
    GGMLModel();
    ~GGMLModel();

    // Non-copyable
    GGMLModel(const GGMLModel&) = delete;
    GGMLModel& operator=(const GGMLModel&) = delete;

    // Initialize model with given dimensions (weights = zero for genesis)
    void init(int d_model, int n_layers, int d_ff, int n_slots);

    // Zero all weights (genesis model)
    void zero_weights();

    // Reset GRU hidden states (called on new block)
    void reset_gru_states();

    // Total parameter count
    size_t param_count() const;

    // Total memory used
    size_t memory_bytes() const;

    // Training step: forward + backward + SGD update.
    // Returns cross-entropy loss.
    float train_step(const uint8_t* input_tokens, const uint8_t* target_tokens,
                     int seq_len, float lr);

    // Forward only (for eval): returns cross-entropy loss.
    float eval_loss(const uint8_t* input_tokens, const uint8_t* target_tokens,
                    int seq_len);

    // Gradient L2 norm from last train_step
    float grad_norm() const { return last_grad_norm_; }

    // Get all weights as flat float array
    std::vector<float> get_weights() const;

    // Sparse delta vs zero (genesis) model
    struct SparseDelta {
        std::vector<uint32_t> indices;
        std::vector<float> values;
        size_t total_params;

        std::vector<uint8_t> serialize() const;
        size_t byte_size() const {
            return 4 + indices.size() * (sizeof(uint32_t) + sizeof(float));
        }
    };
    SparseDelta compute_sparse_delta(float threshold = 0.01f) const;

    // Compute delta vs another model (consensus)
    SparseDelta compute_delta(const GGMLModel& consensus, float threshold = 0.01f) const;

    // Model dimensions
    int d_model() const { return d_model_; }
    int n_layers() const { return n_layers_; }
    int d_ff() const { return d_ff_; }
    int n_slots() const { return n_slots_; }

private:
    int d_model_ = 0, n_layers_ = 0, d_ff_ = 0, n_slots_ = 0;
    int vocab_ = 256;
    float last_grad_norm_ = 0.0f;

    // ggml context for weight storage
    struct ggml_context* ctx_ = nullptr;

    // Weight tensors (stored in ctx_)
    struct ggml_tensor* tok_emb_ = nullptr;      // [d_model, vocab]

    struct LayerWeights {
        ggml_tensor* norm1_w;   // RMSNorm weight [d_model]
        ggml_tensor* norm2_w;   // RMSNorm weight [d_model]

        // MinGRU
        ggml_tensor* gru_wz;    // [d_model, d_model]
        ggml_tensor* gru_wh;    // [d_model, d_model]
        ggml_tensor* gru_bz;    // [d_model]
        ggml_tensor* gru_bh;    // [d_model]

        // SwiGLU FFN
        ggml_tensor* ffn_gate_w; // [d_model, d_ff]
        ggml_tensor* ffn_up_w;   // [d_model, d_ff]
        ggml_tensor* ffn_down_w; // [d_ff, d_model]
    };
    std::vector<LayerWeights> layers_;
    struct ggml_tensor* final_norm_w_ = nullptr;  // [d_model]

    // Helper: collect all weight tensor pointers in serialization order
    std::vector<ggml_tensor*> weight_tensors() const;

    // Build forward compute graph, returns loss tensor.
    // All intermediate tensors are allocated in compute_ctx.
    ggml_tensor* build_forward(struct ggml_context* compute_ctx,
                               const uint8_t* input, const uint8_t* target,
                               int seq_len);
};

} // namespace flow::miner

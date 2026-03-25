// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "miner/training.h"

#include <cmath>
#include <cstring>
#include <algorithm>
#include <numeric>
#include <vector>

namespace flow::miner {

// =========================================================================
// Constructor / Destructor
// =========================================================================

Trainer::Trainer(Model& model, ComputeBackend& backend, float lr)
    : model_(model), backend_(backend), lr_(lr)
{
}

Trainer::~Trainer() {
    free_buffers();
}

// =========================================================================
// Buffer management
// =========================================================================

void Trainer::allocate_buffers(int seq_len) {
    if (bufs_.allocated && bufs_.alloc_seq_len >= seq_len) return;

    free_buffers();

    int D    = model_.d_model;
    int V    = model_.vocab;
    int d_ff = model_.d_ff;

    bufs_.x           = backend_.alloc(static_cast<size_t>(seq_len) * D * sizeof(float));
    bufs_.residual    = backend_.alloc(static_cast<size_t>(seq_len) * D * sizeof(float));
    bufs_.normed      = backend_.alloc(static_cast<size_t>(seq_len) * D * sizeof(float));
    bufs_.tmp         = backend_.alloc(static_cast<size_t>(seq_len) * D * sizeof(float));
    bufs_.logits      = backend_.alloc(static_cast<size_t>(seq_len) * V * sizeof(float));
    bufs_.grad_output = backend_.alloc(static_cast<size_t>(seq_len) * D * sizeof(float));
    bufs_.z_all       = backend_.alloc(static_cast<size_t>(seq_len) * D * sizeof(float));
    bufs_.h_all       = backend_.alloc(static_cast<size_t>(seq_len) * D * sizeof(float));
    bufs_.gate        = backend_.alloc(static_cast<size_t>(seq_len) * d_ff * sizeof(float));
    bufs_.up          = backend_.alloc(static_cast<size_t>(seq_len) * d_ff * sizeof(float));

    bufs_.allocated = true;
    bufs_.alloc_seq_len = seq_len;
}

void Trainer::free_buffers() {
    if (!bufs_.allocated) return;

    backend_.free(bufs_.x);
    backend_.free(bufs_.residual);
    backend_.free(bufs_.normed);
    backend_.free(bufs_.tmp);
    backend_.free(bufs_.logits);
    backend_.free(bufs_.grad_output);
    backend_.free(bufs_.z_all);
    backend_.free(bufs_.h_all);
    backend_.free(bufs_.gate);
    backend_.free(bufs_.up);

    bufs_ = GPUBuffers{};
}

// =========================================================================
// Forward pass (CPU path using model.h functions)
// =========================================================================

float Trainer::forward(const uint8_t* input, const uint8_t* target, int seq_len) {
    // Use the CPU reference forward pass from model.h
    // This handles: embedding -> layers (conv, gru, slot, ffn) -> final norm -> logits -> loss
    return flow::miner::forward(model_, input, seq_len, target);
}

// =========================================================================
// Backward pass (CPU path using model.h functions)
// =========================================================================

void Trainer::backward(const uint8_t* target, int seq_len) {
    // The model.h backward() uses the same tokens as the last forward call
    // We need the input tokens too — they were passed to forward().
    // Re-derive from the training data. backward() in model.h recomputes
    // forward internally if needed.
    (void)target;
    (void)seq_len;
    // backward() was called with the same tokens in step()
}

// =========================================================================
// Weight update: SGD w -= lr * grad
// =========================================================================

void Trainer::update_weights() {
    sgd_step(model_, lr_);
}

// =========================================================================
// Training step
// =========================================================================

float Trainer::step(const uint8_t* input_tokens, const uint8_t* target_tokens, int seq_len) {
    allocate_buffers(seq_len);

    // Zero gradients
    model_.zero_grad();

    // Forward pass — compute loss
    float loss = forward(input_tokens, target_tokens, seq_len);

    // Backward pass — accumulate gradients
    flow::miner::backward(model_, input_tokens, seq_len, target_tokens);

    // Weight update
    update_weights();

    // Reset GRU hidden states for next sequence
    model_.reset_gru_states();

    return loss;
}

// =========================================================================
// Gradient norm (L2)
// =========================================================================

float Trainer::grad_norm() const {
    double sum_sq = 0.0;
    size_t count = 0;

    // Embedding gradient
    for (size_t i = 0; i < model_.tok_emb_grad.size(); ++i) {
        float g = model_.tok_emb_grad.data[i];
        sum_sq += static_cast<double>(g) * g;
    }
    count += model_.tok_emb_grad.size();

    // Per-layer gradients
    for (size_t l = 0; l < model_.layer_grads.size(); ++l) {
        auto accumulate_tensor = [&](const Tensor& t) {
            for (size_t i = 0; i < t.size(); ++i) {
                float g = t.data[i];
                sum_sq += static_cast<double>(g) * g;
            }
            count += t.size();
        };

        const auto& lg = model_.layer_grads[l];
        accumulate_tensor(lg.norm1_w);
        accumulate_tensor(lg.norm2_w);
        accumulate_tensor(lg.norm3_w);
        accumulate_tensor(lg.norm4_w);
        accumulate_tensor(lg.conv3_w);
        accumulate_tensor(lg.conv7_w);
        accumulate_tensor(lg.conv15_w);
        accumulate_tensor(lg.conv_mix_w);
        accumulate_tensor(lg.gru_wz);
        accumulate_tensor(lg.gru_wh);
        accumulate_tensor(lg.gru_bz);
        accumulate_tensor(lg.gru_bh);
        accumulate_tensor(lg.slot_keys);
        accumulate_tensor(lg.slot_values);
        accumulate_tensor(lg.slot_proj_q);
        accumulate_tensor(lg.slot_proj_out);
        accumulate_tensor(lg.ffn_gate_w);
        accumulate_tensor(lg.ffn_up_w);
        accumulate_tensor(lg.ffn_down_w);
    }

    // Final norm gradient
    for (size_t i = 0; i < model_.final_norm_w_grad.size(); ++i) {
        float g = model_.final_norm_w_grad.data[i];
        sum_sq += static_cast<double>(g) * g;
    }
    count += model_.final_norm_w_grad.size();

    if (count == 0) return 0.0f;
    return static_cast<float>(std::sqrt(sum_sq));
}

} // namespace flow::miner

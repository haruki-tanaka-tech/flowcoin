// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Training loop for the standalone miner.
// Operates on Model (model.h) using ComputeBackend (backend.h).

#pragma once

#include "miner/model.h"
#include "miner/backend.h"
#include <vector>
#include <cstdint>

namespace flow::miner {

class Trainer {
public:
    Trainer(Model& model, ComputeBackend& backend, float lr = 0.001f);
    ~Trainer();

    // Train one step on a batch of data.
    // Returns cross-entropy loss.
    float step(const uint8_t* input_tokens, const uint8_t* target_tokens, int seq_len);

    // Get/set learning rate
    float lr() const { return lr_; }
    void set_lr(float lr) { lr_ = lr; }

    // Compute gradient L2 norm after a step
    float grad_norm() const;

private:
    Model& model_;
    ComputeBackend& backend_;
    float lr_;

    // GPU memory handles for intermediate activations
    // (allocated once, reused each step)
    struct GPUBuffers {
        void* x           = nullptr;  // [seq_len, d_model]
        void* residual    = nullptr;  // [seq_len, d_model]
        void* normed      = nullptr;  // [seq_len, d_model]
        void* tmp         = nullptr;  // [seq_len, d_model]
        void* logits      = nullptr;  // [seq_len, vocab]
        void* grad_output = nullptr;
        // Per-layer intermediates
        void* z_all       = nullptr;  // [seq_len, d_model] MinGRU gates
        void* h_all       = nullptr;  // [seq_len, d_model] MinGRU candidates
        void* gate        = nullptr;  // [seq_len, d_ff] FFN
        void* up          = nullptr;  // [seq_len, d_ff]
        bool allocated = false;
        int alloc_seq_len = 0;
    };
    GPUBuffers bufs_;

    void allocate_buffers(int seq_len);
    void free_buffers();

    // Forward pass (fills bufs_, returns loss)
    float forward(const uint8_t* input, const uint8_t* target, int seq_len);

    // Backward pass (fills model gradients)
    void backward(const uint8_t* target, int seq_len);

    // Weight update (SGD)
    void update_weights();
};

} // namespace flow::miner

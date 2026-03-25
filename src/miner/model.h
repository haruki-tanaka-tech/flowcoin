// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// ResonanceNet V5 model -- pure C++ tensors, no external ML frameworks.
//
// Architecture per layer:
//   1. RMSNorm -> Multi-scale causal convolution (k=3,7,15) -> +residual
//   2. RMSNorm -> MinGRU (sequential scan) -> +residual
//   3. RMSNorm -> Slot memory attention (top-k=2) -> +residual
//   4. RMSNorm -> SwiGLU FFN -> +residual
//
// All tensors are contiguous float32 arrays with (rows, cols) shape.
// Byte-level tokenization: vocab=256, no BPE.

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <cmath>
#include <cstring>
#include <algorithm>

namespace flow::miner {

// ═══════════════════════════════════════════════════════════════════════════
// Tensor: contiguous float32 array with 2D shape
// ═══════════════════════════════════════════════════════════════════════════

struct Tensor {
    std::vector<float> data;
    int rows = 0;
    int cols = 0;

    Tensor() = default;
    Tensor(int r, int c) : data(r * c, 0.0f), rows(r), cols(c) {}

    float& at(int r, int c) { return data[r * cols + c]; }
    float  at(int r, int c) const { return data[r * cols + c]; }
    float* ptr() { return data.data(); }
    const float* ptr() const { return data.data(); }
    size_t size() const { return data.size(); }
    size_t bytes() const { return data.size() * sizeof(float); }

    void zero() { std::fill(data.begin(), data.end(), 0.0f); }

    void resize(int r, int c) {
        rows = r;
        cols = c;
        data.assign(static_cast<size_t>(r) * c, 0.0f);
    }

    void fill_val(float v) { std::fill(data.begin(), data.end(), v); }
};

// ═══════════════════════════════════════════════════════════════════════════
// LayerWeights: all trainable parameters for one ResonanceNet V5 layer
// ═══════════════════════════════════════════════════════════════════════════

struct LayerWeights {
    // RMSNorm scales (4 per layer, one before each sub-block)
    Tensor norm1_w, norm2_w, norm3_w, norm4_w;  // [1, d_model]

    // Multi-scale causal depthwise convolution
    Tensor conv3_w, conv7_w, conv15_w;  // [d_model, kernel_size]
    Tensor conv_mix_w;                   // [d_model, d_model]

    // MinGRU
    Tensor gru_wz, gru_wh;  // [d_model, d_model]
    Tensor gru_bz, gru_bh;  // [1, d_model]

    // Slot memory attention
    Tensor slot_keys, slot_values;      // [n_slots, d_model]
    Tensor slot_proj_q, slot_proj_out;  // [d_model, d_model]

    // SwiGLU feed-forward network
    Tensor ffn_gate_w, ffn_up_w;  // [d_model, d_ff]
    Tensor ffn_down_w;             // [d_ff, d_model]
};

// ═══════════════════════════════════════════════════════════════════════════
// Model: complete ResonanceNet V5
// ═══════════════════════════════════════════════════════════════════════════

struct Model {
    int d_model  = 0;
    int n_layers = 0;
    int d_ff     = 0;
    int n_slots  = 0;
    int n_heads  = 0;
    int vocab    = 256;
    int seq_len  = 256;

    // ── Weights ──
    Tensor tok_emb;                       // [vocab, d_model]
    std::vector<LayerWeights> layers;
    Tensor final_norm_w;                  // [1, d_model]

    // ── Gradients (same structure as weights) ──
    Tensor tok_emb_grad;
    std::vector<LayerWeights> layer_grads;
    Tensor final_norm_w_grad;

    // ── MinGRU hidden states (per layer) ──
    std::vector<Tensor> gru_states;       // each [1, d_model]

    // ── Lifecycle ──
    void init(int d_model, int n_layers, int d_ff, int n_slots);
    void zero_weights();
    void zero_grad();
    void reset_gru_states();

    // ── Inspection ──
    size_t param_count() const;

    // ── Serialization ──
    std::vector<float> get_weights() const;

    // ── Optimizer support ──
    struct ParamGrad {
        float* weight;
        float* grad;
        size_t count;
    };
    std::vector<ParamGrad> get_param_grad_pairs();

    // ── Sparse delta for block submission ──
    struct SparseDelta {
        std::vector<uint32_t> indices;
        std::vector<float>    values;
        size_t total_params;

        std::vector<uint8_t> serialize() const;
        size_t byte_size() const {
            return 4 + indices.size() * (sizeof(uint32_t) + sizeof(float));
        }
    };
    SparseDelta compute_delta(const Model& consensus, float threshold = 0.01f) const;
};

// ═══════════════════════════════════════════════════════════════════════════
// Forward / backward / optimizer (operate on Model)
// ═══════════════════════════════════════════════════════════════════════════

/// Full forward pass. Returns cross-entropy loss.
/// Writes logits into `logits_out` if non-null (caller must allocate seq_len * vocab).
float forward(Model& model, const uint8_t* tokens, int seq_len,
              const uint8_t* targets, float* logits_out = nullptr);

/// Full backward pass. Assumes forward() was just called with same data.
/// Accumulates gradients into model grad tensors.
void backward(Model& model, const uint8_t* tokens, int seq_len,
              const uint8_t* targets);

/// SGD weight update: w -= lr * grad.
void sgd_step(Model& model, float lr);

// ═══════════════════════════════════════════════════════════════════════════
// CPU reference compute kernels
// ═══════════════════════════════════════════════════════════════════════════

namespace cpu {

/// Matrix multiply: C = A @ B^T   (A:[M,K], B:[N,K], C:[M,N])
void matmul(const float* A, const float* B, float* C, int M, int N, int K);

/// Matrix multiply: C = A @ B     (A:[M,K], B:[K,N], C:[M,N])
void matmul_nn(const float* A, const float* B, float* C, int M, int N, int K);

/// RMSNorm: out = x * w / sqrt(mean(x^2) + eps)
void rms_norm(const float* x, const float* w, float* out, int n, float eps = 1e-6f);

/// SiLU activation: out = x * sigmoid(x)
void silu(const float* x, float* out, int n);

/// Element-wise multiply: out = a * b
void mul(const float* a, const float* b, float* out, int n);

/// Element-wise add: out = a + b
void add(const float* a, const float* b, float* out, int n);

/// Sigmoid: out = 1 / (1 + exp(-x))
void sigmoid(const float* x, float* out, int n);

/// Softmax over a vector of length n (in-place safe)
void softmax(const float* x, float* out, int n);

/// Cross-entropy loss over (seq_len) positions with (vocab)-sized logits
float cross_entropy(const float* logits, const uint8_t* targets, int seq_len, int vocab);

/// Top-k: find the k largest values in scores[0..n-1]
void topk(const float* scores, int* indices, float* values, int n, int k);

/// Causal depthwise convolution with 3 kernel sizes, mixed through a projection
void causal_conv(const float* x, const Tensor& k3, const Tensor& k7,
                 const Tensor& k15, const Tensor& mix_w,
                 float* out, int seq_len, int D);

/// MinGRU forward scan
void mingru_forward(const float* x, const LayerWeights& L, Tensor& h_state,
                    float* out, int seq_len, int D);

/// Slot memory attention forward
void slot_attention(const float* x, const LayerWeights& L,
                    float* out, int seq_len, int D, int n_slots, int top_k);

/// SwiGLU FFN forward
void swiglu_ffn(const float* x, const LayerWeights& L,
                float* out, int seq_len, int D, int d_ff);

} // namespace cpu

} // namespace flow::miner

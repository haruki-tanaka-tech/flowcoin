// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// GGMLModel: ResonanceNet V5 miner model using ggml for all ops.
// Forward and backward passes run through ggml compute graphs,
// giving us automatic CPU/CUDA/Metal support via ggml backends.

#include "model.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <numeric>
#include <thread>

namespace flow::miner {

// ═══════════════════════════════════════════════════════════════════════════
// Construction / Destruction
// ═══════════════════════════════════════════════════════════════════════════

GGMLModel::GGMLModel() = default;

GGMLModel::~GGMLModel() {
    if (ctx_) {
        ggml_free(ctx_);
        ctx_ = nullptr;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Initialization
// ═══════════════════════════════════════════════════════════════════════════

void GGMLModel::init(int d_model, int n_layers, int d_ff, int n_slots) {
    // Free previous context if any
    if (ctx_) {
        ggml_free(ctx_);
        ctx_ = nullptr;
    }

    d_model_  = d_model;
    n_layers_ = n_layers;
    d_ff_     = d_ff;
    n_slots_  = n_slots;

    // Calculate memory needed for weight tensors
    const size_t params = param_count();
    const size_t data_size = params * sizeof(float);

    // Tensors per layer: 9 (norm1, norm2, gru_wz, gru_wh, gru_bz, gru_bh, ffn_gate, ffn_up, ffn_down)
    // Plus: tok_emb, final_norm = 2
    const size_t n_tensors = 2 + static_cast<size_t>(n_layers) * 9;
    const size_t overhead = n_tensors * 512 + 1024 * 1024;  // tensor structs + alignment

    struct ggml_init_params params_init = {
        /*.mem_size   =*/ data_size + overhead,
        /*.mem_buffer =*/ nullptr,
        /*.no_alloc   =*/ false,
    };

    ctx_ = ggml_init(params_init);
    assert(ctx_ != nullptr);

    // Create weight tensors
    const int64_t d = d_model;
    const int64_t ff = d_ff;
    const int64_t V = vocab_;

    // Token embedding: ne[0]=d, ne[1]=vocab (each row is one token's embedding)
    tok_emb_ = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, V);
    ggml_set_name(tok_emb_, "tok_emb");

    layers_.resize(n_layers);
    for (int i = 0; i < n_layers; i++) {
        auto& L = layers_[i];
        char name[64];

        L.norm1_w = ggml_new_tensor_1d(ctx_, GGML_TYPE_F32, d);
        std::snprintf(name, sizeof(name), "l%d.norm1_w", i);
        ggml_set_name(L.norm1_w, name);

        L.norm2_w = ggml_new_tensor_1d(ctx_, GGML_TYPE_F32, d);
        std::snprintf(name, sizeof(name), "l%d.norm2_w", i);
        ggml_set_name(L.norm2_w, name);

        L.gru_wz = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, d);
        std::snprintf(name, sizeof(name), "l%d.gru_wz", i);
        ggml_set_name(L.gru_wz, name);

        L.gru_wh = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, d);
        std::snprintf(name, sizeof(name), "l%d.gru_wh", i);
        ggml_set_name(L.gru_wh, name);

        L.gru_bz = ggml_new_tensor_1d(ctx_, GGML_TYPE_F32, d);
        std::snprintf(name, sizeof(name), "l%d.gru_bz", i);
        ggml_set_name(L.gru_bz, name);

        L.gru_bh = ggml_new_tensor_1d(ctx_, GGML_TYPE_F32, d);
        std::snprintf(name, sizeof(name), "l%d.gru_bh", i);
        ggml_set_name(L.gru_bh, name);

        L.ffn_gate_w = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, ff);
        std::snprintf(name, sizeof(name), "l%d.ffn_gate_w", i);
        ggml_set_name(L.ffn_gate_w, name);

        L.ffn_up_w = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, ff);
        std::snprintf(name, sizeof(name), "l%d.ffn_up_w", i);
        ggml_set_name(L.ffn_up_w, name);

        L.ffn_down_w = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, ff, d);
        std::snprintf(name, sizeof(name), "l%d.ffn_down_w", i);
        ggml_set_name(L.ffn_down_w, name);
    }

    final_norm_w_ = ggml_new_tensor_1d(ctx_, GGML_TYPE_F32, d);
    ggml_set_name(final_norm_w_, "final_norm_w");

    // Zero-initialize all weights (genesis model)
    zero_weights();
}

void GGMLModel::zero_weights() {
    auto tensors = weight_tensors();
    for (auto* t : tensors) {
        std::memset(t->data, 0, ggml_nbytes(t));
    }

    // Norm weights should be 1.0 (RMSNorm scale)
    auto set_ones = [](ggml_tensor* t) {
        float* data = reinterpret_cast<float*>(t->data);
        int64_t n = ggml_nelements(t);
        for (int64_t i = 0; i < n; i++) {
            data[i] = 1.0f;
        }
    };

    for (int i = 0; i < n_layers_; i++) {
        set_ones(layers_[i].norm1_w);
        set_ones(layers_[i].norm2_w);
    }
    set_ones(final_norm_w_);
}

void GGMLModel::reset_gru_states() {
    // GRU states are not persistent in this ggml implementation
    // (we use a simplified parallel GRU formulation in the graph)
    // Nothing to reset.
}

// ═══════════════════════════════════════════════════════════════════════════
// Parameter counting
// ═══════════════════════════════════════════════════════════════════════════

size_t GGMLModel::param_count() const {
    size_t count = 0;

    // Token embedding: vocab * d_model
    count += static_cast<size_t>(vocab_) * d_model_;

    // Per layer:
    //   norm1_w: d_model
    //   norm2_w: d_model
    //   gru_wz: d_model * d_model
    //   gru_wh: d_model * d_model
    //   gru_bz: d_model
    //   gru_bh: d_model
    //   ffn_gate_w: d_model * d_ff
    //   ffn_up_w: d_model * d_ff
    //   ffn_down_w: d_ff * d_model
    size_t per_layer = 4 * static_cast<size_t>(d_model_)
                     + 2 * static_cast<size_t>(d_model_) * d_model_
                     + 3 * static_cast<size_t>(d_model_) * d_ff_;
    count += static_cast<size_t>(n_layers_) * per_layer;

    // Final norm: d_model
    count += d_model_;

    return count;
}

size_t GGMLModel::memory_bytes() const {
    return param_count() * sizeof(float);
}

// ═══════════════════════════════════════════════════════════════════════════
// Weight tensor enumeration
// ═══════════════════════════════════════════════════════════════════════════

std::vector<ggml_tensor*> GGMLModel::weight_tensors() const {
    std::vector<ggml_tensor*> tensors;
    tensors.reserve(2 + static_cast<size_t>(n_layers_) * 9);

    tensors.push_back(tok_emb_);

    for (int i = 0; i < n_layers_; i++) {
        const auto& L = layers_[i];
        tensors.push_back(L.norm1_w);
        tensors.push_back(L.norm2_w);
        tensors.push_back(L.gru_wz);
        tensors.push_back(L.gru_wh);
        tensors.push_back(L.gru_bz);
        tensors.push_back(L.gru_bh);
        tensors.push_back(L.ffn_gate_w);
        tensors.push_back(L.ffn_up_w);
        tensors.push_back(L.ffn_down_w);
    }

    tensors.push_back(final_norm_w_);

    return tensors;
}

// ═══════════════════════════════════════════════════════════════════════════
// Weight serialization
// ═══════════════════════════════════════════════════════════════════════════

std::vector<float> GGMLModel::get_weights() const {
    std::vector<float> weights;
    weights.reserve(param_count());

    auto tensors = weight_tensors();
    for (const auto* t : tensors) {
        const int64_t n = ggml_nelements(t);
        const float* data = reinterpret_cast<const float*>(t->data);
        weights.insert(weights.end(), data, data + n);
    }

    return weights;
}

// ═══════════════════════════════════════════════════════════════════════════
// Sparse delta computation
// ═══════════════════════════════════════════════════════════════════════════

GGMLModel::SparseDelta GGMLModel::compute_sparse_delta(float threshold) const {
    SparseDelta delta;
    delta.total_params = param_count();

    auto weights = get_weights();
    for (size_t i = 0; i < weights.size(); i++) {
        if (std::fabs(weights[i]) > threshold) {
            delta.indices.push_back(static_cast<uint32_t>(i));
            delta.values.push_back(weights[i]);
        }
    }

    return delta;
}

GGMLModel::SparseDelta GGMLModel::compute_delta(const GGMLModel& consensus,
                                                 float threshold) const {
    SparseDelta delta;
    delta.total_params = param_count();

    auto my_weights = get_weights();
    auto con_weights = consensus.get_weights();

    size_t n = std::min(my_weights.size(), con_weights.size());
    for (size_t i = 0; i < n; i++) {
        float diff = my_weights[i] - con_weights[i];
        if (std::fabs(diff) > threshold) {
            delta.indices.push_back(static_cast<uint32_t>(i));
            delta.values.push_back(diff);
        }
    }

    return delta;
}

std::vector<uint8_t> GGMLModel::SparseDelta::serialize() const {
    // Format: [count:u32] [idx0:u32 val0:f32] [idx1:u32 val1:f32] ...
    size_t n = indices.size();
    std::vector<uint8_t> buf(4 + n * (sizeof(uint32_t) + sizeof(float)));

    uint32_t count = static_cast<uint32_t>(n);
    std::memcpy(buf.data(), &count, 4);

    size_t offset = 4;
    for (size_t i = 0; i < n; i++) {
        std::memcpy(buf.data() + offset, &indices[i], sizeof(uint32_t));
        offset += sizeof(uint32_t);
        std::memcpy(buf.data() + offset, &values[i], sizeof(float));
        offset += sizeof(float);
    }

    return buf;
}

// ═══════════════════════════════════════════════════════════════════════════
// Build forward compute graph
// ═══════════════════════════════════════════════════════════════════════════

ggml_tensor* GGMLModel::build_forward(ggml_context* ctx,
                                       const uint8_t* input, const uint8_t* target,
                                       int seq_len) {
    const int64_t V = vocab_;
    const int64_t S = seq_len;

    // Input token indices as I32 tensor
    ggml_tensor* inp = ggml_new_tensor_1d(ctx, GGML_TYPE_I32, S);
    {
        int32_t* inp_data = reinterpret_cast<int32_t*>(inp->data);
        for (int i = 0; i < seq_len; i++) {
            inp_data[i] = static_cast<int32_t>(input[i]);
        }
    }
    ggml_set_name(inp, "input_tokens");
    ggml_set_input(inp);

    // Embedding lookup: x = tok_emb[inp]
    // tok_emb: [D, V], ggml_get_rows selects rows by index
    // Result: [D, S]
    ggml_tensor* x = ggml_get_rows(ctx, tok_emb_, inp);
    ggml_set_name(x, "emb");

    // Layer loop
    for (int l = 0; l < n_layers_; l++) {
        auto& L = layers_[l];

        // ── Sub-layer 1: RMSNorm -> MinGRU -> +residual ──

        // RMSNorm
        ggml_tensor* normed = ggml_rms_norm(ctx, x, 1e-6f);
        normed = ggml_mul(ctx, normed, L.norm1_w);

        // MinGRU (parallel approximation):
        //   z = sigmoid(normed @ Wz^T + bz)
        //   h_tilde = normed @ Wh^T + bh
        //   out = z * h_tilde
        //
        // ggml_mul_mat(A, B) computes B @ A^T when A is [ne0, ne1] and B is [ne0, ne2]
        // Result shape: [ne1, ne2]
        // Our normed is [D, S], gru_wz is [D, D]
        // ggml_mul_mat(gru_wz, normed) = normed @ gru_wz^T -> [D, S]
        ggml_tensor* z = ggml_mul_mat(ctx, L.gru_wz, normed);
        z = ggml_add(ctx, z, L.gru_bz);  // broadcast bias [D] over [D, S]
        z = ggml_sigmoid(ctx, z);

        ggml_tensor* h_tilde = ggml_mul_mat(ctx, L.gru_wh, normed);
        h_tilde = ggml_add(ctx, h_tilde, L.gru_bh);

        // Simplified GRU output: z * h_tilde
        // This loses the recurrent property but the matmuls are the expensive part
        // and gradients flow correctly
        ggml_tensor* gru_out = ggml_mul(ctx, z, h_tilde);

        // Residual
        x = ggml_add(ctx, x, gru_out);

        // ── Sub-layer 2: RMSNorm -> SwiGLU FFN -> +residual ──

        normed = ggml_rms_norm(ctx, x, 1e-6f);
        normed = ggml_mul(ctx, normed, L.norm2_w);

        // SwiGLU: gate = silu(normed @ gate_w^T), up = normed @ up_w^T
        // ffn_gate_w: [D, d_ff], normed: [D, S]
        // ggml_mul_mat(ffn_gate_w, normed) -> [d_ff, S]
        ggml_tensor* gate = ggml_mul_mat(ctx, L.ffn_gate_w, normed);
        gate = ggml_silu(ctx, gate);

        ggml_tensor* up = ggml_mul_mat(ctx, L.ffn_up_w, normed);

        // Element-wise multiply: gate * up -> [d_ff, S]
        ggml_tensor* ffn_hidden = ggml_mul(ctx, gate, up);

        // Down projection: ffn_hidden @ ffn_down_w^T -> [D, S]
        // ffn_down_w: [d_ff, D]
        ggml_tensor* ffn_out = ggml_mul_mat(ctx, L.ffn_down_w, ffn_hidden);

        // Residual
        x = ggml_add(ctx, x, ffn_out);
    }

    // Final RMSNorm
    x = ggml_rms_norm(ctx, x, 1e-6f);
    x = ggml_mul(ctx, x, final_norm_w_);

    // Logits via tied embedding weights: x @ tok_emb^T
    // tok_emb: [D, V], x: [D, S]
    // ggml_mul_mat(tok_emb, x) -> [V, S]
    ggml_tensor* logits = ggml_mul_mat(ctx, tok_emb_, x);
    ggml_set_name(logits, "logits");

    // Target as one-hot for cross_entropy_loss
    // ggml_cross_entropy_loss expects logits: [V, S] and labels: [V, S]
    ggml_tensor* tgt = ggml_new_tensor_2d(ctx, GGML_TYPE_F32, V, S);
    ggml_set_name(tgt, "targets");
    ggml_set_input(tgt);
    {
        float* tgt_data = reinterpret_cast<float*>(tgt->data);
        std::memset(tgt_data, 0, static_cast<size_t>(V * S) * sizeof(float));
        for (int i = 0; i < seq_len; i++) {
            tgt_data[i * V + target[i]] = 1.0f;
        }
    }

    // Cross-entropy loss (scalar output)
    ggml_tensor* loss = ggml_cross_entropy_loss(ctx, logits, tgt);
    ggml_set_name(loss, "loss");

    return loss;
}

// ═══════════════════════════════════════════════════════════════════════════
// Training step
// ═══════════════════════════════════════════════════════════════════════════

float GGMLModel::train_step(const uint8_t* input, const uint8_t* target,
                             int seq_len, float lr) {
    // Allocate compute context (separate from weight context)
    // Estimate: each ggml op creates a tensor, we have ~20 ops per layer + overhead
    // Backward pass roughly doubles memory needs (grad tensors + intermediate)
    const size_t est_tensors = 512 + static_cast<size_t>(n_layers_) * 128;
    const size_t compute_mem = est_tensors * ggml_tensor_overhead()
                             + ggml_graph_overhead_custom(16384, true)
                             + static_cast<size_t>(seq_len) * vocab_ * sizeof(float) * 4  // logits + targets + grads
                             + static_cast<size_t>(seq_len) * d_model_ * sizeof(float) * n_layers_ * 40
                             + param_count() * sizeof(float) * 2  // grad accumulators
                             + 256 * 1024 * 1024;  // extra headroom

    struct ggml_init_params cparams = {
        /*.mem_size   =*/ compute_mem,
        /*.mem_buffer =*/ nullptr,
        /*.no_alloc   =*/ false,
    };
    struct ggml_context* compute_ctx = ggml_init(cparams);
    if (!compute_ctx) {
        std::fprintf(stderr, "GGMLModel::train_step: failed to allocate compute context (%zu bytes)\n",
                     compute_mem);
        return 999.0f;
    }

    // Mark weight tensors as parameters (for gradient computation)
    auto wt = weight_tensors();
    for (auto* t : wt) {
        ggml_set_param(t);
    }

    // Build forward graph
    ggml_tensor* loss = build_forward(compute_ctx, input, target, seq_len);

    // Mark loss tensor
    ggml_set_loss(loss);

    // Build compute graph with backward pass
    struct ggml_cgraph* graph = ggml_new_graph_custom(compute_ctx, 16384, true);
    ggml_build_forward_expand(graph, loss);

    // Allocate gradient accumulator tensors for backward pass
    // One grad_acc per weight tensor, in the compute context
    const size_t n_params = wt.size();
    std::vector<ggml_tensor*> grad_accs(n_params, nullptr);
    for (size_t i = 0; i < n_params; i++) {
        grad_accs[i] = ggml_dup_tensor(compute_ctx, wt[i]);
        ggml_set_zero(grad_accs[i]);
        ggml_set_name(grad_accs[i], (std::string("grad_") + ggml_get_name(wt[i])).c_str());
    }

    ggml_build_backward_expand(compute_ctx, graph, grad_accs.data());

    // Compute (forward + backward)
    int n_threads = std::max(1, static_cast<int>(std::thread::hardware_concurrency()));
    if (n_threads > 8) n_threads = 8;  // Diminishing returns beyond 8 threads

    struct ggml_cplan plan = ggml_graph_plan(graph, n_threads, nullptr);
    std::vector<uint8_t> work;
    if (plan.work_size > 0) {
        work.resize(plan.work_size);
        plan.work_data = work.data();
    }
    ggml_graph_compute(graph, &plan);

    // Extract loss value
    float loss_val = ggml_get_f32_1d(loss, 0);

    // SGD update: weight -= lr * grad
    // Also compute gradient norm
    double grad_norm_sq = 0.0;
    for (size_t i = 0; i < n_params; i++) {
        ggml_tensor* grad = grad_accs[i];
        if (!grad) continue;

        float* w = reinterpret_cast<float*>(wt[i]->data);
        const float* g = reinterpret_cast<const float*>(grad->data);
        const int64_t n = ggml_nelements(wt[i]);

        for (int64_t j = 0; j < n; j++) {
            grad_norm_sq += static_cast<double>(g[j]) * g[j];
            w[j] -= lr * g[j];
        }
    }
    last_grad_norm_ = static_cast<float>(std::sqrt(grad_norm_sq));

    // Clear param/loss flags (important for next step)
    for (auto* t : wt) {
        t->flags &= ~GGML_TENSOR_FLAG_PARAM;
    }
    loss->flags &= ~GGML_TENSOR_FLAG_LOSS;

    // Free compute context (weight tensors remain in ctx_)
    ggml_free(compute_ctx);

    return loss_val;
}

// ═══════════════════════════════════════════════════════════════════════════
// Eval loss (forward only)
// ═══════════════════════════════════════════════════════════════════════════

float GGMLModel::eval_loss(const uint8_t* input, const uint8_t* target,
                            int seq_len) {
    // Same as train_step but no backward pass
    const size_t est_tensors = 128 + static_cast<size_t>(n_layers_) * 32;
    const size_t compute_mem = est_tensors * ggml_tensor_overhead()
                             + ggml_graph_overhead()
                             + static_cast<size_t>(seq_len) * vocab_ * sizeof(float) * 2
                             + static_cast<size_t>(seq_len) * d_model_ * sizeof(float) * n_layers_ * 10
                             + 32 * 1024 * 1024;

    struct ggml_init_params cparams = {
        /*.mem_size   =*/ compute_mem,
        /*.mem_buffer =*/ nullptr,
        /*.no_alloc   =*/ false,
    };
    struct ggml_context* compute_ctx = ggml_init(cparams);
    if (!compute_ctx) return 999.0f;

    ggml_tensor* loss = build_forward(compute_ctx, input, target, seq_len);

    struct ggml_cgraph* graph = ggml_new_graph(compute_ctx);
    ggml_build_forward_expand(graph, loss);

    int n_threads = std::max(1, static_cast<int>(std::thread::hardware_concurrency()));
    if (n_threads > 8) n_threads = 8;

    struct ggml_cplan plan = ggml_graph_plan(graph, n_threads, nullptr);
    std::vector<uint8_t> work;
    if (plan.work_size > 0) {
        work.resize(plan.work_size);
        plan.work_data = work.data();
    }
    ggml_graph_compute(graph, &plan);

    float loss_val = ggml_get_f32_1d(loss, 0);

    ggml_free(compute_ctx);
    return loss_val;
}

} // namespace flow::miner

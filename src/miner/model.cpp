// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// ResonanceNet V5 model implementation -- pure C++, no frameworks.
//
// Contains:
//   - Model initialization and lifecycle
//   - CPU reference kernels (matmul, rms_norm, silu, sigmoid, softmax, ...)
//   - Full forward pass through all 4 sub-blocks per layer
//   - Full backward pass with manual gradient computation
//   - SGD optimizer step
//   - Sparse delta computation for block submission

#include "model.h"

#include <cassert>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <limits>
#include <numeric>

namespace flow::miner {

// ═══════════════════════════════════════════════════════════════════════════
// Model lifecycle
// ═══════════════════════════════════════════════════════════════════════════

static void init_layer_weights(LayerWeights& L, int d_model, int d_ff, int n_slots) {
    L.norm1_w.resize(1, d_model); L.norm1_w.fill_val(1.0f);
    L.norm2_w.resize(1, d_model); L.norm2_w.fill_val(1.0f);
    L.norm3_w.resize(1, d_model); L.norm3_w.fill_val(1.0f);
    L.norm4_w.resize(1, d_model); L.norm4_w.fill_val(1.0f);

    L.conv3_w.resize(d_model, 3);
    L.conv7_w.resize(d_model, 7);
    L.conv15_w.resize(d_model, 15);
    L.conv_mix_w.resize(d_model, d_model);

    L.gru_wz.resize(d_model, d_model);
    L.gru_wh.resize(d_model, d_model);
    L.gru_bz.resize(1, d_model);
    L.gru_bh.resize(1, d_model);

    L.slot_keys.resize(n_slots, d_model);
    L.slot_values.resize(n_slots, d_model);
    L.slot_proj_q.resize(d_model, d_model);
    L.slot_proj_out.resize(d_model, d_model);

    L.ffn_gate_w.resize(d_model, d_ff);
    L.ffn_up_w.resize(d_model, d_ff);
    L.ffn_down_w.resize(d_ff, d_model);
}

static void init_layer_grads(LayerWeights& G, int d_model, int d_ff, int n_slots) {
    // Same structure as weights, all zeros
    init_layer_weights(G, d_model, d_ff, n_slots);
    // Norm grads start at 0, not 1
    G.norm1_w.zero();
    G.norm2_w.zero();
    G.norm3_w.zero();
    G.norm4_w.zero();
}

void Model::init(int dm, int nl, int df, int ns) {
    d_model  = dm;
    n_layers = nl;
    d_ff     = df;
    n_slots  = ns;
    n_heads  = dm / 64;
    if (n_heads < 1) n_heads = 1;

    tok_emb.resize(vocab, d_model);
    final_norm_w.resize(1, d_model);
    final_norm_w.fill_val(1.0f);

    layers.resize(n_layers);
    layer_grads.resize(n_layers);
    gru_states.resize(n_layers);

    for (int i = 0; i < n_layers; i++) {
        init_layer_weights(layers[i], d_model, d_ff, n_slots);
        init_layer_grads(layer_grads[i], d_model, d_ff, n_slots);
        gru_states[i].resize(1, d_model);
    }

    tok_emb_grad.resize(vocab, d_model);
    final_norm_w_grad.resize(1, d_model);
}

void Model::zero_weights() {
    tok_emb.zero();
    // Keep norm weights at 1.0 (identity normalization)
    final_norm_w.fill_val(1.0f);
    for (int i = 0; i < n_layers; i++) {
        auto& L = layers[i];
        L.conv3_w.zero(); L.conv7_w.zero(); L.conv15_w.zero();
        L.conv_mix_w.zero();
        L.gru_wz.zero(); L.gru_wh.zero();
        L.gru_bz.zero(); L.gru_bh.zero();
        L.slot_keys.zero(); L.slot_values.zero();
        L.slot_proj_q.zero(); L.slot_proj_out.zero();
        L.ffn_gate_w.zero(); L.ffn_up_w.zero(); L.ffn_down_w.zero();
        L.norm1_w.fill_val(1.0f);
        L.norm2_w.fill_val(1.0f);
        L.norm3_w.fill_val(1.0f);
        L.norm4_w.fill_val(1.0f);
    }
}

void Model::zero_grad() {
    tok_emb_grad.zero();
    final_norm_w_grad.zero();
    for (int i = 0; i < n_layers; i++) {
        auto& G = layer_grads[i];
        G.norm1_w.zero(); G.norm2_w.zero(); G.norm3_w.zero(); G.norm4_w.zero();
        G.conv3_w.zero(); G.conv7_w.zero(); G.conv15_w.zero();
        G.conv_mix_w.zero();
        G.gru_wz.zero(); G.gru_wh.zero();
        G.gru_bz.zero(); G.gru_bh.zero();
        G.slot_keys.zero(); G.slot_values.zero();
        G.slot_proj_q.zero(); G.slot_proj_out.zero();
        G.ffn_gate_w.zero(); G.ffn_up_w.zero(); G.ffn_down_w.zero();
    }
}

void Model::reset_gru_states() {
    for (auto& s : gru_states) {
        s.zero();
    }
}

size_t Model::param_count() const {
    size_t count = tok_emb.size() + final_norm_w.size();
    for (int i = 0; i < n_layers; i++) {
        auto& L = layers[i];
        count += L.norm1_w.size() + L.norm2_w.size() + L.norm3_w.size() + L.norm4_w.size();
        count += L.conv3_w.size() + L.conv7_w.size() + L.conv15_w.size();
        count += L.conv_mix_w.size();
        count += L.gru_wz.size() + L.gru_wh.size() + L.gru_bz.size() + L.gru_bh.size();
        count += L.slot_keys.size() + L.slot_values.size();
        count += L.slot_proj_q.size() + L.slot_proj_out.size();
        count += L.ffn_gate_w.size() + L.ffn_up_w.size() + L.ffn_down_w.size();
    }
    return count;
}

std::vector<float> Model::get_weights() const {
    std::vector<float> out;
    out.reserve(param_count());

    auto append = [&](const Tensor& t) {
        out.insert(out.end(), t.data.begin(), t.data.end());
    };

    append(tok_emb);
    for (int i = 0; i < n_layers; i++) {
        auto& L = layers[i];
        append(L.norm1_w); append(L.norm2_w); append(L.norm3_w); append(L.norm4_w);
        append(L.conv3_w); append(L.conv7_w); append(L.conv15_w); append(L.conv_mix_w);
        append(L.gru_wz); append(L.gru_wh); append(L.gru_bz); append(L.gru_bh);
        append(L.slot_keys); append(L.slot_values);
        append(L.slot_proj_q); append(L.slot_proj_out);
        append(L.ffn_gate_w); append(L.ffn_up_w); append(L.ffn_down_w);
    }
    append(final_norm_w);
    return out;
}

std::vector<Model::ParamGrad> Model::get_param_grad_pairs() {
    std::vector<ParamGrad> pairs;

    auto add = [&](Tensor& w, Tensor& g) {
        if (!w.data.empty()) {
            pairs.push_back({w.ptr(), g.ptr(), w.size()});
        }
    };

    add(tok_emb, tok_emb_grad);
    for (int i = 0; i < n_layers; i++) {
        auto& L = layers[i];
        auto& G = layer_grads[i];
        add(L.norm1_w, G.norm1_w); add(L.norm2_w, G.norm2_w);
        add(L.norm3_w, G.norm3_w); add(L.norm4_w, G.norm4_w);
        add(L.conv3_w, G.conv3_w); add(L.conv7_w, G.conv7_w);
        add(L.conv15_w, G.conv15_w); add(L.conv_mix_w, G.conv_mix_w);
        add(L.gru_wz, G.gru_wz); add(L.gru_wh, G.gru_wh);
        add(L.gru_bz, G.gru_bz); add(L.gru_bh, G.gru_bh);
        add(L.slot_keys, G.slot_keys); add(L.slot_values, G.slot_values);
        add(L.slot_proj_q, G.slot_proj_q); add(L.slot_proj_out, G.slot_proj_out);
        add(L.ffn_gate_w, G.ffn_gate_w); add(L.ffn_up_w, G.ffn_up_w);
        add(L.ffn_down_w, G.ffn_down_w);
    }
    add(final_norm_w, final_norm_w_grad);
    return pairs;
}

// ═══════════════════════════════════════════════════════════════════════════
// Sparse delta
// ═══════════════════════════════════════════════════════════════════════════

Model::SparseDelta Model::compute_delta(const Model& consensus, float threshold) const {
    SparseDelta delta;
    auto w_mine = get_weights();
    auto w_cons = consensus.get_weights();

    delta.total_params = w_mine.size();

    for (size_t i = 0; i < w_mine.size(); i++) {
        float diff = w_mine[i] - w_cons[i];
        if (std::fabs(diff) >= threshold) {
            delta.indices.push_back(static_cast<uint32_t>(i));
            delta.values.push_back(diff);
        }
    }
    return delta;
}

std::vector<uint8_t> Model::SparseDelta::serialize() const {
    // Format: [total_params:4][count:4][indices:4*count][values:4*count]
    size_t count = indices.size();
    std::vector<uint8_t> buf(8 + count * 8);
    uint32_t tp = static_cast<uint32_t>(total_params);
    uint32_t ct = static_cast<uint32_t>(count);
    std::memcpy(buf.data(), &tp, 4);
    std::memcpy(buf.data() + 4, &ct, 4);
    std::memcpy(buf.data() + 8, indices.data(), count * 4);
    std::memcpy(buf.data() + 8 + count * 4, values.data(), count * 4);
    return buf;
}

// ═══════════════════════════════════════════════════════════════════════════
// CPU compute kernels
// ═══════════════════════════════════════════════════════════════════════════

void cpu::matmul(const float* A, const float* B, float* C, int M, int N, int K) {
    // C[i][j] = sum_k A[i][k] * B[j][k]   (B is transposed: B shape [N, K])
    for (int i = 0; i < M; i++) {
        for (int j = 0; j < N; j++) {
            float sum = 0.0f;
            const float* a_row = A + i * K;
            const float* b_row = B + j * K;
            for (int k = 0; k < K; k++) {
                sum += a_row[k] * b_row[k];
            }
            C[i * N + j] = sum;
        }
    }
}

void cpu::matmul_nn(const float* A, const float* B, float* C, int M, int N, int K) {
    // C[i][j] = sum_k A[i][k] * B[k][j]   (neither transposed)
    for (int i = 0; i < M; i++) {
        for (int j = 0; j < N; j++) {
            float sum = 0.0f;
            for (int k = 0; k < K; k++) {
                sum += A[i * K + k] * B[k * N + j];
            }
            C[i * N + j] = sum;
        }
    }
}

void cpu::rms_norm(const float* x, const float* w, float* out, int n, float eps) {
    float sum_sq = 0.0f;
    for (int i = 0; i < n; i++) {
        sum_sq += x[i] * x[i];
    }
    float rms = std::sqrt(sum_sq / n + eps);
    float inv_rms = 1.0f / rms;
    for (int i = 0; i < n; i++) {
        out[i] = x[i] * w[i] * inv_rms;
    }
}

void cpu::silu(const float* x, float* out, int n) {
    for (int i = 0; i < n; i++) {
        float s = 1.0f / (1.0f + std::exp(-x[i]));
        out[i] = x[i] * s;
    }
}

void cpu::mul(const float* a, const float* b, float* out, int n) {
    for (int i = 0; i < n; i++) {
        out[i] = a[i] * b[i];
    }
}

void cpu::add(const float* a, const float* b, float* out, int n) {
    for (int i = 0; i < n; i++) {
        out[i] = a[i] + b[i];
    }
}

void cpu::sigmoid(const float* x, float* out, int n) {
    for (int i = 0; i < n; i++) {
        out[i] = 1.0f / (1.0f + std::exp(-x[i]));
    }
}

void cpu::softmax(const float* x, float* out, int n) {
    float max_val = x[0];
    for (int i = 1; i < n; i++) {
        if (x[i] > max_val) max_val = x[i];
    }
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        out[i] = std::exp(x[i] - max_val);
        sum += out[i];
    }
    float inv_sum = 1.0f / sum;
    for (int i = 0; i < n; i++) {
        out[i] *= inv_sum;
    }
}

float cpu::cross_entropy(const float* logits, const uint8_t* targets,
                          int seq_len, int vocab) {
    float total_loss = 0.0f;
    std::vector<float> probs(vocab);

    for (int t = 0; t < seq_len; t++) {
        const float* row = logits + t * vocab;
        softmax(row, probs.data(), vocab);

        float p = probs[targets[t]];
        if (p < 1e-10f) p = 1e-10f;
        total_loss -= std::log(p);
    }
    return total_loss / seq_len;
}

void cpu::topk(const float* scores, int* indices, float* values, int n, int k) {
    // Simple partial sort for small k
    std::vector<int> idx(n);
    std::iota(idx.begin(), idx.end(), 0);

    // Partial sort to get top-k
    int actual_k = std::min(k, n);
    std::partial_sort(idx.begin(), idx.begin() + actual_k, idx.end(),
                      [&](int a, int b) { return scores[a] > scores[b]; });

    for (int i = 0; i < actual_k; i++) {
        indices[i] = idx[i];
        values[i] = scores[idx[i]];
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Causal depthwise convolution with multi-scale kernels
// ═══════════════════════════════════════════════════════════════════════════

void cpu::causal_conv(const float* x, const Tensor& k3, const Tensor& k7,
                      const Tensor& k15, const Tensor& mix_w,
                      float* out, int seq_len, int D) {
    // Each kernel operates as a depthwise causal convolution per channel.
    // Results from all three kernel sizes are summed, then mixed through
    // a dense projection (mix_w).

    std::vector<float> conv_sum(seq_len * D, 0.0f);
    std::vector<float> conv_tmp(seq_len * D);

    // Helper: depthwise causal conv for one kernel size
    auto depthwise_causal = [&](const Tensor& kernel, int ksize) {
        for (int t = 0; t < seq_len; t++) {
            for (int d = 0; d < D; d++) {
                float val = 0.0f;
                for (int ki = 0; ki < ksize; ki++) {
                    int src_t = t - ki;  // causal: look back
                    if (src_t >= 0) {
                        val += x[src_t * D + d] * kernel.data[d * ksize + ki];
                    }
                }
                conv_tmp[t * D + d] = val;
            }
        }
        // Accumulate
        for (int i = 0; i < seq_len * D; i++) {
            conv_sum[i] += conv_tmp[i];
        }
    };

    depthwise_causal(k3, 3);
    depthwise_causal(k7, 7);
    depthwise_causal(k15, 15);

    // Mix through dense projection: out = conv_sum @ mix_w^T
    matmul(conv_sum.data(), mix_w.ptr(), out, seq_len, D, D);
}

// ═══════════════════════════════════════════════════════════════════════════
// MinGRU forward scan
// ═══════════════════════════════════════════════════════════════════════════

void cpu::mingru_forward(const float* x, const LayerWeights& L, Tensor& h_state,
                          float* out, int seq_len, int D) {
    // Pre-compute all gate and candidate projections
    std::vector<float> z_all(seq_len * D);
    std::vector<float> h_all(seq_len * D);

    // z = x @ Wz^T,  h_tilde = x @ Wh^T
    matmul(x, L.gru_wz.ptr(), z_all.data(), seq_len, D, D);
    matmul(x, L.gru_wh.ptr(), h_all.data(), seq_len, D, D);

    // Add biases
    for (int t = 0; t < seq_len; t++) {
        for (int d = 0; d < D; d++) {
            z_all[t * D + d] += L.gru_bz.data[d];
            h_all[t * D + d] += L.gru_bh.data[d];
        }
    }

    // Sigmoid on z (update gate)
    sigmoid(z_all.data(), z_all.data(), seq_len * D);

    // Sequential scan: h_t = (1 - z_t) * h_{t-1} + z_t * h_tilde_t
    float* h = h_state.ptr();
    for (int t = 0; t < seq_len; t++) {
        for (int d = 0; d < D; d++) {
            float z = z_all[t * D + d];
            float h_tilde = h_all[t * D + d];
            h[d] = (1.0f - z) * h[d] + z * h_tilde;
            out[t * D + d] = h[d];
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Slot memory attention (top-k sparse retrieval)
// ═══════════════════════════════════════════════════════════════════════════

void cpu::slot_attention(const float* x, const LayerWeights& L,
                          float* out, int seq_len, int D, int n_slots, int top_k) {
    std::vector<float> query(seq_len * D);
    std::vector<float> scores(n_slots);
    std::vector<int>   top_idx(top_k);
    std::vector<float> top_val(top_k);
    std::vector<float> attn_out(D);

    // Project input to query space: query = x @ slot_proj_q^T
    matmul(x, L.slot_proj_q.ptr(), query.data(), seq_len, D, D);

    float scale = 1.0f / std::sqrt(static_cast<float>(D));

    for (int t = 0; t < seq_len; t++) {
        const float* q = query.data() + t * D;

        // Compute scores against all slot keys: scores[s] = q . slot_keys[s]
        for (int s = 0; s < n_slots; s++) {
            float dot = 0.0f;
            const float* key = L.slot_keys.ptr() + s * D;
            for (int d = 0; d < D; d++) {
                dot += q[d] * key[d];
            }
            scores[s] = dot * scale;
        }

        // Top-k selection
        topk(scores.data(), top_idx.data(), top_val.data(), n_slots, top_k);

        // Softmax over top-k scores
        softmax(top_val.data(), top_val.data(), top_k);

        // Weighted sum of slot values
        std::fill(attn_out.begin(), attn_out.end(), 0.0f);
        for (int ki = 0; ki < top_k; ki++) {
            float w = top_val[ki];
            const float* val = L.slot_values.ptr() + top_idx[ki] * D;
            for (int d = 0; d < D; d++) {
                attn_out[d] += w * val[d];
            }
        }

        // Output projection: out_t = attn_out @ slot_proj_out^T
        for (int d = 0; d < D; d++) {
            float sum = 0.0f;
            for (int k = 0; k < D; k++) {
                sum += attn_out[k] * L.slot_proj_out.data[d * D + k];
            }
            out[t * D + d] = sum;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SwiGLU feed-forward network
// ═══════════════════════════════════════════════════════════════════════════

void cpu::swiglu_ffn(const float* x, const LayerWeights& L,
                      float* out, int seq_len, int D, int d_ff) {
    // gate = x @ ffn_gate_w^T   [seq_len, d_ff]
    // up   = x @ ffn_up_w^T     [seq_len, d_ff]
    // hidden = SiLU(gate) * up
    // out = hidden @ ffn_down_w^T  [seq_len, D]

    std::vector<float> gate(seq_len * d_ff);
    std::vector<float> up(seq_len * d_ff);
    std::vector<float> hidden(seq_len * d_ff);

    matmul(x, L.ffn_gate_w.ptr(), gate.data(), seq_len, d_ff, D);
    matmul(x, L.ffn_up_w.ptr(), up.data(), seq_len, d_ff, D);

    // SiLU(gate) * up
    silu(gate.data(), gate.data(), seq_len * d_ff);
    mul(gate.data(), up.data(), hidden.data(), seq_len * d_ff);

    // down projection
    matmul(hidden.data(), L.ffn_down_w.ptr(), out, seq_len, D, d_ff);
}

// ═══════════════════════════════════════════════════════════════════════════
// Forward pass
// ═══════════════════════════════════════════════════════════════════════════

// Thread-local activation cache for backward pass
struct ActivationCache {
    // Per-layer caches
    struct LayerCache {
        std::vector<float> pre_conv_normed;   // after norm1, before conv
        std::vector<float> conv_out;          // conv output before residual
        std::vector<float> pre_gru_normed;    // after norm2, before gru
        std::vector<float> gru_out;           // gru output before residual
        std::vector<float> pre_slot_normed;   // after norm3, before slot
        std::vector<float> slot_out;          // slot output before residual
        std::vector<float> pre_ffn_normed;    // after norm4, before ffn
        std::vector<float> ffn_out;           // ffn output before residual
        std::vector<float> x_input;           // layer input (for grad computation)
    };

    std::vector<float> embedding;     // [seq_len * D] after embedding lookup
    std::vector<LayerCache> layers;
    std::vector<float> final_normed;  // after final RMSNorm
    std::vector<float> logits;        // [seq_len * vocab]
};

static thread_local ActivationCache g_cache;

float forward(Model& model, const uint8_t* tokens, int seq_len,
              const uint8_t* targets, float* logits_out) {
    int D = model.d_model;
    int V = model.vocab;
    int total = seq_len * D;

    // Resize cache
    g_cache.embedding.resize(total);
    g_cache.layers.resize(model.n_layers);
    g_cache.final_normed.resize(total);
    g_cache.logits.resize(seq_len * V);

    // ── Embedding lookup ──
    for (int t = 0; t < seq_len; t++) {
        std::memcpy(&g_cache.embedding[t * D],
                     &model.tok_emb.data[tokens[t] * D],
                     D * sizeof(float));
    }

    // Working buffer (current activations)
    std::vector<float> x(g_cache.embedding.begin(), g_cache.embedding.end());
    std::vector<float> normed(total);
    std::vector<float> tmp(total);

    for (int l = 0; l < model.n_layers; l++) {
        auto& L = model.layers[l];
        auto& C = g_cache.layers[l];

        // Save layer input
        C.x_input.assign(x.begin(), x.end());

        // ── Sub-block 1: RMSNorm -> Multi-scale Conv -> +residual ──
        C.pre_conv_normed.resize(total);
        for (int t = 0; t < seq_len; t++) {
            cpu::rms_norm(&x[t * D], L.norm1_w.ptr(), &C.pre_conv_normed[t * D], D);
        }
        C.conv_out.resize(total);
        cpu::causal_conv(C.pre_conv_normed.data(), L.conv3_w, L.conv7_w,
                         L.conv15_w, L.conv_mix_w, C.conv_out.data(), seq_len, D);
        cpu::add(x.data(), C.conv_out.data(), x.data(), total);

        // ── Sub-block 2: RMSNorm -> MinGRU -> +residual ──
        C.pre_gru_normed.resize(total);
        for (int t = 0; t < seq_len; t++) {
            cpu::rms_norm(&x[t * D], L.norm2_w.ptr(), &C.pre_gru_normed[t * D], D);
        }
        C.gru_out.resize(total);
        cpu::mingru_forward(C.pre_gru_normed.data(), L, model.gru_states[l],
                            C.gru_out.data(), seq_len, D);
        cpu::add(x.data(), C.gru_out.data(), x.data(), total);

        // ── Sub-block 3: RMSNorm -> Slot Memory -> +residual ──
        C.pre_slot_normed.resize(total);
        for (int t = 0; t < seq_len; t++) {
            cpu::rms_norm(&x[t * D], L.norm3_w.ptr(), &C.pre_slot_normed[t * D], D);
        }
        C.slot_out.resize(total);
        cpu::slot_attention(C.pre_slot_normed.data(), L, C.slot_out.data(),
                            seq_len, D, model.n_slots, 2);
        cpu::add(x.data(), C.slot_out.data(), x.data(), total);

        // ── Sub-block 4: RMSNorm -> SwiGLU FFN -> +residual ──
        C.pre_ffn_normed.resize(total);
        for (int t = 0; t < seq_len; t++) {
            cpu::rms_norm(&x[t * D], L.norm4_w.ptr(), &C.pre_ffn_normed[t * D], D);
        }
        C.ffn_out.resize(total);
        cpu::swiglu_ffn(C.pre_ffn_normed.data(), L, C.ffn_out.data(),
                        seq_len, D, model.d_ff);
        cpu::add(x.data(), C.ffn_out.data(), x.data(), total);
    }

    // ── Final RMSNorm ──
    for (int t = 0; t < seq_len; t++) {
        cpu::rms_norm(&x[t * D], model.final_norm_w.ptr(),
                      &g_cache.final_normed[t * D], D);
    }

    // ── Logits (tied embedding): logits = final_normed @ tok_emb^T ──
    cpu::matmul(g_cache.final_normed.data(), model.tok_emb.ptr(),
                g_cache.logits.data(), seq_len, V, D);

    if (logits_out) {
        std::memcpy(logits_out, g_cache.logits.data(), seq_len * V * sizeof(float));
    }

    // ── Cross-entropy loss ──
    return cpu::cross_entropy(g_cache.logits.data(), targets, seq_len, V);
}

// ═══════════════════════════════════════════════════════════════════════════
// Backward pass helpers
// ═══════════════════════════════════════════════════════════════════════════

// RMSNorm backward:
// Given d_out (grad w.r.t. output of rms_norm), compute d_x and d_w.
static void rms_norm_backward(const float* x, const float* w, const float* d_out,
                               float* d_x, float* d_w, int n, float eps = 1e-6f) {
    // Forward: rms = sqrt(mean(x^2) + eps), out = x * w / rms
    float sum_sq = 0.0f;
    for (int i = 0; i < n; i++) sum_sq += x[i] * x[i];
    float var = sum_sq / n + eps;
    float rms = std::sqrt(var);
    float inv_rms = 1.0f / rms;

    // d_w[i] += d_out[i] * x[i] / rms
    for (int i = 0; i < n; i++) {
        d_w[i] += d_out[i] * x[i] * inv_rms;
    }

    // d_x: need to account for the normalization
    // out_i = x_i * w_i * inv_rms
    // d_x_i = d_out_i * w_i * inv_rms
    //       - x_i * inv_rms^3 * (1/n) * sum_j(d_out_j * w_j * x_j)
    float dot = 0.0f;
    for (int i = 0; i < n; i++) {
        dot += d_out[i] * w[i] * x[i];
    }
    float coeff = dot * inv_rms * inv_rms * inv_rms / n;
    for (int i = 0; i < n; i++) {
        d_x[i] = d_out[i] * w[i] * inv_rms - x[i] * coeff;
    }
}

// matmul backward: C = A @ B^T
// Given d_C, compute d_A and d_B
static void matmul_backward_bt(const float* A, const float* B, const float* d_C,
                                 float* d_A, float* d_B,
                                 int M, int N, int K) {
    // d_A[i][k] += sum_j d_C[i][j] * B[j][k]
    // d_B[j][k] += sum_i d_C[i][j] * A[i][k]
    if (d_A) {
        for (int i = 0; i < M; i++) {
            for (int k = 0; k < K; k++) {
                float sum = 0.0f;
                for (int j = 0; j < N; j++) {
                    sum += d_C[i * N + j] * B[j * K + k];
                }
                d_A[i * K + k] += sum;
            }
        }
    }
    if (d_B) {
        for (int j = 0; j < N; j++) {
            for (int k = 0; k < K; k++) {
                float sum = 0.0f;
                for (int i = 0; i < M; i++) {
                    sum += d_C[i * N + j] * A[i * K + k];
                }
                d_B[j * K + k] += sum;
            }
        }
    }
}

// SwiGLU FFN backward
static void swiglu_ffn_backward(const float* x, const LayerWeights& L,
                                  LayerWeights& G, const float* d_out,
                                  float* d_x, int seq_len, int D, int d_ff) {
    int total_ff = seq_len * d_ff;
    int total_d  = seq_len * D;

    // Recompute forward intermediates
    std::vector<float> gate(total_ff), up(total_ff);
    std::vector<float> gate_silu(total_ff), hidden(total_ff);

    cpu::matmul(x, L.ffn_gate_w.ptr(), gate.data(), seq_len, d_ff, D);
    cpu::matmul(x, L.ffn_up_w.ptr(), up.data(), seq_len, d_ff, D);

    // gate_silu = SiLU(gate)
    for (int i = 0; i < total_ff; i++) {
        float s = 1.0f / (1.0f + std::exp(-gate[i]));
        gate_silu[i] = gate[i] * s;
    }
    // hidden = gate_silu * up
    cpu::mul(gate_silu.data(), up.data(), hidden.data(), total_ff);

    // d_hidden = d_out @ ffn_down_w  (d_out:[S,D], down:[d_ff,D] -> d_hidden:[S,d_ff])
    // But our matmul does C = A @ B^T, so we need down^T which is [D, d_ff]
    // Actually down_w is [d_ff, D], and forward was: out = hidden @ down_w^T
    // So backward: d_hidden[s][f] += sum_d d_out[s][d] * down_w[f][d]
    // which is: d_hidden = d_out @ down_w (not transposed, since down_w^T was used in forward)
    std::vector<float> d_hidden(total_ff, 0.0f);
    // d_out @ down_w: d_out is [S,D], down_w is [d_ff, D] -> d_out @ down_w^T would give [S, d_ff]
    // But we already have down_w^T in forward via matmul(hidden, down_w, out, S, D, d_ff)
    // So d_hidden = d_out @ (down_w^T)^T = d_out @ down_w... Wait:
    // forward: out = hidden @ down_w^T  using matmul(hidden, down_w, out, S, D, d_ff)
    //   meaning C[s][d] = sum_f hidden[s][f] * down_w[d][f]
    // So d_hidden[s][f] = sum_d d_out[s][d] * down_w[d][f]
    //   = d_out[s,:] @ down_w[:,f]  => need d_out @ down_w (non-transposed)
    cpu::matmul_nn(d_out, L.ffn_down_w.ptr(), d_hidden.data(), seq_len, d_ff, D);

    // d_down_w: d_down[d][f] += sum_s d_out[s][d] * hidden[s][f]
    //  = d_out^T @ hidden
    // Using matmul_backward_bt: forward was matmul(hidden, down_w, out, S, D, d_ff)
    matmul_backward_bt(hidden.data(), L.ffn_down_w.ptr(), d_out,
                       nullptr, G.ffn_down_w.ptr(), seq_len, D, d_ff);

    // d_gate_silu = d_hidden * up,  d_up = d_hidden * gate_silu
    std::vector<float> d_gate_silu(total_ff);
    std::vector<float> d_up(total_ff);
    cpu::mul(d_hidden.data(), up.data(), d_gate_silu.data(), total_ff);
    cpu::mul(d_hidden.data(), gate_silu.data(), d_up.data(), total_ff);

    // d_gate: SiLU backward
    // silu(x) = x * sigmoid(x)
    // d_silu/dx = sigmoid(x) + x * sigmoid(x) * (1 - sigmoid(x))
    //           = sigmoid(x) * (1 + x * (1 - sigmoid(x)))
    std::vector<float> d_gate(total_ff);
    for (int i = 0; i < total_ff; i++) {
        float s = 1.0f / (1.0f + std::exp(-gate[i]));
        d_gate[i] = d_gate_silu[i] * s * (1.0f + gate[i] * (1.0f - s));
    }

    // d_gate_w, d_up_w, d_x from the two matmuls
    // gate = x @ gate_w^T: d_x += d_gate @ gate_w, d_gate_w += d_gate^T @ x
    // up   = x @ up_w^T:   d_x += d_up @ up_w,     d_up_w += d_up^T @ x
    std::fill(d_x, d_x + total_d, 0.0f);
    matmul_backward_bt(x, L.ffn_gate_w.ptr(), d_gate.data(),
                       d_x, G.ffn_gate_w.ptr(), seq_len, d_ff, D);
    // Add d_up contribution to d_x
    std::vector<float> d_x_up(total_d, 0.0f);
    matmul_backward_bt(x, L.ffn_up_w.ptr(), d_up.data(),
                       d_x_up.data(), G.ffn_up_w.ptr(), seq_len, d_ff, D);
    cpu::add(d_x, d_x_up.data(), d_x, total_d);
}

// MinGRU backward (simplified: accumulates grads for Wz, Wh, bz, bh)
static void mingru_backward(const float* x, const LayerWeights& L,
                              LayerWeights& G, const float* d_out,
                              float* d_x, int seq_len, int D) {
    int total = seq_len * D;

    // Recompute forward intermediates
    std::vector<float> z_pre(total), h_pre(total);
    std::vector<float> z_sig(total);

    cpu::matmul(x, L.gru_wz.ptr(), z_pre.data(), seq_len, D, D);
    cpu::matmul(x, L.gru_wh.ptr(), h_pre.data(), seq_len, D, D);

    for (int t = 0; t < seq_len; t++) {
        for (int d = 0; d < D; d++) {
            z_pre[t * D + d] += L.gru_bz.data[d];
            h_pre[t * D + d] += L.gru_bh.data[d];
        }
    }
    cpu::sigmoid(z_pre.data(), z_sig.data(), total);

    // Recompute hidden states for backward
    std::vector<float> h_states((seq_len + 1) * D, 0.0f);
    // h_states[0] = initial state (zeros for simplicity in backward)
    for (int t = 0; t < seq_len; t++) {
        for (int d = 0; d < D; d++) {
            float z = z_sig[t * D + d];
            h_states[(t + 1) * D + d] = (1.0f - z) * h_states[t * D + d] + z * h_pre[t * D + d];
        }
    }

    // Backward through sequential scan
    std::vector<float> d_h(D, 0.0f);  // grad flowing from future timesteps
    std::vector<float> d_z_pre(total, 0.0f);
    std::vector<float> d_h_pre(total, 0.0f);

    for (int t = seq_len - 1; t >= 0; t--) {
        // d_h_t = d_out[t] + d_h (from t+1)
        for (int d = 0; d < D; d++) {
            float d_ht = d_out[t * D + d] + d_h[d];

            float z = z_sig[t * D + d];
            float h_prev = h_states[t * D + d];
            float h_tilde = h_pre[t * D + d];

            // d_z = d_ht * (h_tilde - h_prev)
            float d_z = d_ht * (h_tilde - h_prev);
            // sigmoid backward: d_z_pre = d_z * z * (1 - z)
            d_z_pre[t * D + d] = d_z * z * (1.0f - z);

            // d_h_tilde = d_ht * z
            d_h_pre[t * D + d] = d_ht * z;

            // d_h_prev = d_ht * (1 - z) -> flows to previous timestep
            d_h[d] = d_ht * (1.0f - z);
        }
    }

    // Gradients for Wz, Wh, bz, bh
    // z_pre = x @ Wz^T + bz => d_Wz += d_z_pre^T @ x, d_bz += sum(d_z_pre)
    // h_pre = x @ Wh^T + bh => d_Wh += d_h_pre^T @ x, d_bh += sum(d_h_pre)
    std::fill(d_x, d_x + total, 0.0f);
    matmul_backward_bt(x, L.gru_wz.ptr(), d_z_pre.data(),
                       d_x, G.gru_wz.ptr(), seq_len, D, D);
    std::vector<float> d_x_h(total, 0.0f);
    matmul_backward_bt(x, L.gru_wh.ptr(), d_h_pre.data(),
                       d_x_h.data(), G.gru_wh.ptr(), seq_len, D, D);
    cpu::add(d_x, d_x_h.data(), d_x, total);

    // Bias gradients
    for (int t = 0; t < seq_len; t++) {
        for (int d = 0; d < D; d++) {
            G.gru_bz.data[d] += d_z_pre[t * D + d];
            G.gru_bh.data[d] += d_h_pre[t * D + d];
        }
    }
}

// Causal conv backward (simplified: accumulates kernel and mix_w grads)
static void causal_conv_backward(const float* x, const LayerWeights& L,
                                   LayerWeights& G, const float* d_out,
                                   float* d_x, int seq_len, int D) {
    int total = seq_len * D;

    // Recompute conv_sum from forward
    std::vector<float> conv_sum(total, 0.0f);

    auto depthwise_causal_and_grad = [&](const Tensor& kernel, Tensor& d_kernel, int ksize) {
        for (int t = 0; t < seq_len; t++) {
            for (int d = 0; d < D; d++) {
                float val = 0.0f;
                for (int ki = 0; ki < ksize; ki++) {
                    int src_t = t - ki;
                    if (src_t >= 0) {
                        val += x[src_t * D + d] * kernel.data[d * ksize + ki];
                    }
                }
                conv_sum[t * D + d] += val;
            }
        }
    };

    depthwise_causal_and_grad(L.conv3_w, G.conv3_w, 3);
    depthwise_causal_and_grad(L.conv7_w, G.conv7_w, 7);
    depthwise_causal_and_grad(L.conv15_w, G.conv15_w, 15);

    // Forward: out = conv_sum @ mix_w^T
    // d_conv_sum and d_mix_w
    std::vector<float> d_conv_sum(total, 0.0f);
    matmul_backward_bt(conv_sum.data(), L.conv_mix_w.ptr(), d_out,
                       d_conv_sum.data(), G.conv_mix_w.ptr(), seq_len, D, D);

    // Backward through each depthwise conv
    std::fill(d_x, d_x + total, 0.0f);

    auto conv_kernel_backward = [&](const Tensor& kernel, Tensor& d_kernel, int ksize) {
        for (int t = 0; t < seq_len; t++) {
            for (int d = 0; d < D; d++) {
                float d_val = d_conv_sum[t * D + d];
                for (int ki = 0; ki < ksize; ki++) {
                    int src_t = t - ki;
                    if (src_t >= 0) {
                        // d_kernel
                        d_kernel.data[d * ksize + ki] += d_val * x[src_t * D + d];
                        // d_x
                        d_x[src_t * D + d] += d_val * kernel.data[d * ksize + ki];
                    }
                }
            }
        }
    };

    conv_kernel_backward(L.conv3_w, G.conv3_w, 3);
    conv_kernel_backward(L.conv7_w, G.conv7_w, 7);
    conv_kernel_backward(L.conv15_w, G.conv15_w, 15);
}

// Slot attention backward (simplified: accumulates grads for slot params)
static void slot_attention_backward(const float* x, const LayerWeights& L,
                                      LayerWeights& G, const float* d_out,
                                      float* d_x, int seq_len, int D,
                                      int n_slots, int top_k) {
    int total = seq_len * D;
    std::fill(d_x, d_x + total, 0.0f);

    std::vector<float> query(total);
    cpu::matmul(x, L.slot_proj_q.ptr(), query.data(), seq_len, D, D);

    float scale = 1.0f / std::sqrt(static_cast<float>(D));
    std::vector<float> scores(n_slots);
    std::vector<int>   top_idx(top_k);
    std::vector<float> top_val(top_k);
    std::vector<float> attn_w(top_k);
    std::vector<float> attn_out(D);

    std::vector<float> d_query(total, 0.0f);

    for (int t = 0; t < seq_len; t++) {
        const float* q = query.data() + t * D;

        // Recompute forward for this timestep
        for (int s = 0; s < n_slots; s++) {
            float dot = 0.0f;
            const float* key = L.slot_keys.ptr() + s * D;
            for (int d = 0; d < D; d++) dot += q[d] * key[d];
            scores[s] = dot * scale;
        }
        cpu::topk(scores.data(), top_idx.data(), top_val.data(), n_slots, top_k);
        cpu::softmax(top_val.data(), attn_w.data(), top_k);

        // Backward through output projection
        // out_t[d] = sum_k attn_out[k] * proj_out[d][k]
        const float* d_out_t = d_out + t * D;
        std::vector<float> d_attn_out(D, 0.0f);
        for (int d = 0; d < D; d++) {
            for (int k = 0; k < D; k++) {
                d_attn_out[k] += d_out_t[d] * L.slot_proj_out.data[d * D + k];
                G.slot_proj_out.data[d * D + k] += d_out_t[d] *
                    [&]() -> float {
                        // Recompute attn_out[k]
                        float v = 0.0f;
                        for (int ki = 0; ki < top_k; ki++) {
                            v += attn_w[ki] * L.slot_values.data[top_idx[ki] * D + k];
                        }
                        return v;
                    }();
            }
        }

        // Backward through weighted sum of slot values
        std::vector<float> d_attn_w(top_k, 0.0f);
        for (int ki = 0; ki < top_k; ki++) {
            const float* val = L.slot_values.ptr() + top_idx[ki] * D;
            for (int d = 0; d < D; d++) {
                d_attn_w[ki] += d_attn_out[d] * val[d];
                G.slot_values.data[top_idx[ki] * D + d] += d_attn_out[d] * attn_w[ki];
            }
        }

        // Backward through softmax (simplified: approximate gradient)
        // d_score[i] = attn_w[i] * (d_attn_w[i] - sum_j attn_w[j] * d_attn_w[j])
        float dot_da = 0.0f;
        for (int ki = 0; ki < top_k; ki++) dot_da += attn_w[ki] * d_attn_w[ki];
        std::vector<float> d_top_scores(top_k);
        for (int ki = 0; ki < top_k; ki++) {
            d_top_scores[ki] = attn_w[ki] * (d_attn_w[ki] - dot_da) * scale;
        }

        // Backward through dot product with keys
        for (int ki = 0; ki < top_k; ki++) {
            int s = top_idx[ki];
            for (int d = 0; d < D; d++) {
                d_query[t * D + d] += d_top_scores[ki] * L.slot_keys.data[s * D + d];
                G.slot_keys.data[s * D + d] += d_top_scores[ki] * q[d];
            }
        }
    }

    // Backward through query projection: query = x @ proj_q^T
    matmul_backward_bt(x, L.slot_proj_q.ptr(), d_query.data(),
                       d_x, G.slot_proj_q.ptr(), seq_len, D, D);
}

// ═══════════════════════════════════════════════════════════════════════════
// Full backward pass
// ═══════════════════════════════════════════════════════════════════════════

void backward(Model& model, const uint8_t* tokens, int seq_len,
              const uint8_t* targets) {
    int D = model.d_model;
    int V = model.vocab;
    int total = seq_len * D;

    model.zero_grad();

    // ── 1. Cross-entropy backward -> d_logits ──
    // logits[t][v] -> softmax -> loss
    // d_logits[t][v] = softmax(logits[t])[v] - (v == target[t] ? 1 : 0)
    // Divided by seq_len for mean loss
    std::vector<float> d_logits(seq_len * V);
    std::vector<float> probs(V);
    float inv_seq = 1.0f / seq_len;

    for (int t = 0; t < seq_len; t++) {
        cpu::softmax(&g_cache.logits[t * V], probs.data(), V);
        for (int v = 0; v < V; v++) {
            d_logits[t * V + v] = (probs[v] - (v == targets[t] ? 1.0f : 0.0f)) * inv_seq;
        }
    }

    // ── 2. Logits backward: logits = final_normed @ tok_emb^T ──
    // d_final_normed, d_tok_emb
    std::vector<float> d_normed(total, 0.0f);
    matmul_backward_bt(g_cache.final_normed.data(), model.tok_emb.ptr(),
                       d_logits.data(),
                       d_normed.data(), model.tok_emb_grad.ptr(),
                       seq_len, V, D);

    // ── 3. Final RMSNorm backward ──
    // The input to final_norm was the output of the last layer (stored in layers' cache)
    // We need to reconstruct the last layer's output.
    // After all layers, x was the value before final_norm.
    // We can reconstruct it from layer caches.
    // Actually, we need d_x for the layer stack. Let's compute it.

    // Reconstruct final x from cache: start from embedding, add all residuals
    std::vector<float> x_final(total);
    std::memcpy(x_final.data(), g_cache.embedding.data(), total * sizeof(float));
    for (int l = 0; l < model.n_layers; l++) {
        auto& C = g_cache.layers[l];
        cpu::add(x_final.data(), C.conv_out.data(), x_final.data(), total);
        cpu::add(x_final.data(), C.gru_out.data(), x_final.data(), total);
        cpu::add(x_final.data(), C.slot_out.data(), x_final.data(), total);
        cpu::add(x_final.data(), C.ffn_out.data(), x_final.data(), total);
    }

    std::vector<float> d_x(total, 0.0f);
    for (int t = 0; t < seq_len; t++) {
        rms_norm_backward(&x_final[t * D], model.final_norm_w.ptr(),
                          &d_normed[t * D], &d_x[t * D],
                          model.final_norm_w_grad.ptr(), D);
    }

    // ── 4. Backward through layers (reverse order) ──
    std::vector<float> d_sub(total);
    std::vector<float> d_sub_input(total);

    for (int l = model.n_layers - 1; l >= 0; l--) {
        auto& L = model.layers[l];
        auto& G = model.layer_grads[l];
        auto& C = g_cache.layers[l];

        // Reconstruct x at each sub-block boundary
        // x_after_conv = x_input + conv_out
        // x_after_gru  = x_after_conv + gru_out
        // x_after_slot = x_after_gru + slot_out
        // x_after_ffn  = x_after_slot + ffn_out  (= input to next layer)

        std::vector<float> x_after_conv(total), x_after_gru(total), x_after_slot(total);
        cpu::add(C.x_input.data(), C.conv_out.data(), x_after_conv.data(), total);
        cpu::add(x_after_conv.data(), C.gru_out.data(), x_after_gru.data(), total);
        cpu::add(x_after_gru.data(), C.slot_out.data(), x_after_slot.data(), total);

        // ── Sub-block 4 backward: FFN ──
        // d_x passes through residual, d_ffn_out = d_x
        // d_pre_ffn_normed from ffn_backward
        swiglu_ffn_backward(C.pre_ffn_normed.data(), L, G,
                            d_x.data(), d_sub.data(), seq_len, D, model.d_ff);
        // d_x += d_sub (through residual); also norm4 backward
        std::vector<float> d_norm4_input(total, 0.0f);
        for (int t = 0; t < seq_len; t++) {
            rms_norm_backward(&x_after_slot[t * D], L.norm4_w.ptr(),
                              &d_sub[t * D], &d_norm4_input[t * D],
                              G.norm4_w.ptr(), D);
        }
        // d_x flows through residual: d_x = d_x + d_norm4_input
        cpu::add(d_x.data(), d_norm4_input.data(), d_x.data(), total);

        // ── Sub-block 3 backward: Slot Attention ──
        slot_attention_backward(C.pre_slot_normed.data(), L, G,
                                 d_x.data(), d_sub.data(), seq_len, D,
                                 model.n_slots, 2);
        std::vector<float> d_norm3_input(total, 0.0f);
        for (int t = 0; t < seq_len; t++) {
            rms_norm_backward(&x_after_gru[t * D], L.norm3_w.ptr(),
                              &d_sub[t * D], &d_norm3_input[t * D],
                              G.norm3_w.ptr(), D);
        }
        cpu::add(d_x.data(), d_norm3_input.data(), d_x.data(), total);

        // ── Sub-block 2 backward: MinGRU ──
        mingru_backward(C.pre_gru_normed.data(), L, G,
                        d_x.data(), d_sub.data(), seq_len, D);
        std::vector<float> d_norm2_input(total, 0.0f);
        for (int t = 0; t < seq_len; t++) {
            rms_norm_backward(&x_after_conv[t * D], L.norm2_w.ptr(),
                              &d_sub[t * D], &d_norm2_input[t * D],
                              G.norm2_w.ptr(), D);
        }
        cpu::add(d_x.data(), d_norm2_input.data(), d_x.data(), total);

        // ── Sub-block 1 backward: Causal Conv ──
        causal_conv_backward(C.pre_conv_normed.data(), L, G,
                              d_x.data(), d_sub.data(), seq_len, D);
        std::vector<float> d_norm1_input(total, 0.0f);
        for (int t = 0; t < seq_len; t++) {
            rms_norm_backward(&C.x_input[t * D], L.norm1_w.ptr(),
                              &d_sub[t * D], &d_norm1_input[t * D],
                              G.norm1_w.ptr(), D);
        }
        cpu::add(d_x.data(), d_norm1_input.data(), d_x.data(), total);
    }

    // ── 5. Embedding backward ──
    // d_tok_emb[token[t]] += d_x[t]  (add to existing grad from logits backward)
    for (int t = 0; t < seq_len; t++) {
        int tok = tokens[t];
        for (int d = 0; d < D; d++) {
            model.tok_emb_grad.data[tok * D + d] += d_x[t * D + d];
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SGD optimizer
// ═══════════════════════════════════════════════════════════════════════════

void sgd_step(Model& model, float lr) {
    auto pairs = model.get_param_grad_pairs();
    for (auto& pg : pairs) {
        for (size_t i = 0; i < pg.count; i++) {
            pg.weight[i] -= lr * pg.grad[i];
        }
    }
}

} // namespace flow::miner

// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// SGD training using ggml compute graphs.
// v0.1: simple 2-layer MLP (embed → linear+relu → linear → logits).
// Production: full Transformer + MoE via llama.cpp.

#include "trainer.h"
#include "core/hash.h"

#include <ggml.h>
#include <cmath>
#include <cstring>
#include <numeric>
#include <random>

namespace flow::mining {

Trainer::Trainer(uint32_t d_model, uint32_t d_ff, uint32_t vocab_size)
    : d_model_(d_model), d_ff_(d_ff), vocab_size_(vocab_size) {

    // Allocate ggml context for model weights
    size_t mem_size = 0;
    mem_size += vocab_size * d_model * sizeof(float);  // embed
    mem_size += d_model * d_ff * sizeof(float);         // w1
    mem_size += d_ff * sizeof(float);                   // b1
    mem_size += d_ff * vocab_size * sizeof(float);      // w2
    mem_size += vocab_size * sizeof(float);             // b2
    mem_size += 1024 * 1024; // overhead for ggml structs

    struct ggml_init_params params = {
        .mem_size   = mem_size,
        .mem_buffer = nullptr,
        .no_alloc   = false,
    };
    ctx_ = ggml_init(params);

    embed_ = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d_model, vocab_size);
    w1_    = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d_ff, d_model);
    b1_    = ggml_new_tensor_1d(ctx_, GGML_TYPE_F32, d_ff);
    w2_    = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, vocab_size, d_ff);
    b2_    = ggml_new_tensor_1d(ctx_, GGML_TYPE_F32, vocab_size);

    init_weights();
    initial_weights_ = flatten_weights();
}

Trainer::~Trainer() {
    if (ctx_) ggml_free(ctx_);
}

void Trainer::init_weights() {
    // Xavier initialization with deterministic seed
    std::mt19937 rng(42);

    auto xavier_init = [&](ggml_tensor* t, int fan_in, int fan_out) {
        float scale = std::sqrt(2.0f / static_cast<float>(fan_in + fan_out));
        std::normal_distribution<float> dist(0.0f, scale);
        float* data = reinterpret_cast<float*>(t->data);
        int64_t n = ggml_nelements(t);
        for (int64_t i = 0; i < n; ++i) {
            data[i] = dist(rng);
        }
    };

    auto zero_init = [](ggml_tensor* t) {
        std::memset(t->data, 0, ggml_nbytes(t));
    };

    xavier_init(embed_, static_cast<int>(d_model_), static_cast<int>(vocab_size_));
    xavier_init(w1_, static_cast<int>(d_model_), static_cast<int>(d_ff_));
    zero_init(b1_);
    xavier_init(w2_, static_cast<int>(d_ff_), static_cast<int>(vocab_size_));
    zero_init(b2_);
}

std::vector<float> Trainer::flatten_weights() const {
    std::vector<float> result;
    auto append = [&](const ggml_tensor* t) {
        const float* data = reinterpret_cast<const float*>(t->data);
        int64_t n = ggml_nelements(t);
        result.insert(result.end(), data, data + n);
    };
    append(embed_);
    append(w1_);
    append(b1_);
    append(w2_);
    append(b2_);
    return result;
}

Hash256 Trainer::model_hash() const {
    auto weights = flatten_weights();
    return keccak256(reinterpret_cast<const uint8_t*>(weights.data()),
                      weights.size() * sizeof(float));
}

std::vector<uint8_t> Trainer::get_deltas() const {
    auto current = flatten_weights();
    std::vector<float> deltas(current.size());
    for (size_t i = 0; i < current.size(); ++i) {
        deltas[i] = current[i] - initial_weights_[i];
    }
    // Serialize as raw float bytes (compression would go here in production)
    std::vector<uint8_t> result(deltas.size() * sizeof(float));
    std::memcpy(result.data(), deltas.data(), result.size());
    return result;
}

// Simple forward pass: embed → w1*x+b1 → relu → w2*x+b2 → softmax → loss
// Done manually (no ggml graph) for clarity and determinism.
static float forward_loss(const float* embed, uint32_t d_model, uint32_t vocab_size,
                           const float* w1, const float* b1, uint32_t d_ff,
                           const float* w2, const float* b2,
                           const int32_t* tokens, size_t seq_len) {
    if (seq_len < 2) return 0.0f;

    float total_loss = 0.0f;
    size_t count = 0;

    for (size_t t = 0; t + 1 < seq_len; ++t) {
        int32_t input_tok = tokens[t];
        int32_t target_tok = tokens[t + 1];

        if (input_tok < 0 || input_tok >= static_cast<int32_t>(vocab_size)) continue;
        if (target_tok < 0 || target_tok >= static_cast<int32_t>(vocab_size)) continue;

        // Embedding lookup
        const float* x = embed + input_tok * d_model;

        // Hidden layer: h = relu(w1 @ x + b1)
        std::vector<float> hidden(d_ff);
        for (uint32_t j = 0; j < d_ff; ++j) {
            float sum = b1[j];
            for (uint32_t k = 0; k < d_model; ++k) {
                sum += w1[j * d_model + k] * x[k];
            }
            hidden[j] = (sum > 0.0f) ? sum : 0.0f; // ReLU
        }

        // Output layer: logits = w2 @ h + b2
        std::vector<float> logits(vocab_size);
        float max_logit = -1e30f;
        for (uint32_t j = 0; j < vocab_size; ++j) {
            float sum = b2[j];
            for (uint32_t k = 0; k < d_ff; ++k) {
                sum += w2[j * d_ff + k] * hidden[k];
            }
            logits[j] = sum;
            if (sum > max_logit) max_logit = sum;
        }

        // Softmax + cross-entropy loss
        float log_sum_exp = 0.0f;
        for (uint32_t j = 0; j < vocab_size; ++j) {
            log_sum_exp += std::exp(logits[j] - max_logit);
        }
        log_sum_exp = max_logit + std::log(log_sum_exp);

        float loss = log_sum_exp - logits[target_tok];
        total_loss += loss;
        count++;
    }

    return (count > 0) ? total_loss / static_cast<float>(count) : 0.0f;
}

float Trainer::eval_loss(const std::vector<int32_t>& tokens) {
    return forward_loss(
        reinterpret_cast<const float*>(embed_->data), d_model_, vocab_size_,
        reinterpret_cast<const float*>(w1_->data),
        reinterpret_cast<const float*>(b1_->data), d_ff_,
        reinterpret_cast<const float*>(w2_->data),
        reinterpret_cast<const float*>(b2_->data),
        tokens.data(), tokens.size());
}

TrainingResult Trainer::train_step(const std::vector<int32_t>& input_tokens,
                                    const std::vector<int32_t>& target_tokens,
                                    float learning_rate) {
    TrainingResult result;
    result.model_hash_before = model_hash();

    // Compute loss before
    // Use input_tokens as sequence for loss computation
    result.loss_before = eval_loss(input_tokens);

    // Simple numerical gradient descent
    // For each weight: perturb → compute loss → compute gradient → update
    // This is slow but correct. Production uses backpropagation via ggml.
    float eps = 1e-4f;

    auto update_tensor = [&](ggml_tensor* t) {
        float* data = reinterpret_cast<float*>(t->data);
        int64_t n = ggml_nelements(t);
        // Update a random subset for speed (stochastic)
        std::mt19937 rng(static_cast<unsigned>(result.loss_before * 1e6f));
        int updates = std::min(static_cast<int64_t>(100), n);
        for (int i = 0; i < updates; ++i) {
            int64_t idx = rng() % n;
            float orig = data[idx];

            data[idx] = orig + eps;
            float loss_plus = eval_loss(input_tokens);

            data[idx] = orig - eps;
            float loss_minus = eval_loss(input_tokens);

            float grad = (loss_plus - loss_minus) / (2.0f * eps);
            data[idx] = orig - learning_rate * grad;
        }
    };

    update_tensor(embed_);
    update_tensor(w1_);
    update_tensor(b1_);
    update_tensor(w2_);
    update_tensor(b2_);

    result.loss_after = eval_loss(input_tokens);
    result.steps = 1;
    result.model_hash_after = model_hash();
    result.weight_deltas = get_deltas();

    return result;
}

} // namespace flow::mining

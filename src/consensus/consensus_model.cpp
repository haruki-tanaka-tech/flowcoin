// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// ResonanceNet V5 consensus model — full ggml implementation.
// This is the most critical consensus module: every node must produce
// bit-identical forward pass results for the same weights and inputs.
//
// Architecture per layer:
//   1. RMSNorm -> Multi-Scale Causal Conv (kernels 3,7,15) -> +residual
//   2. RMSNorm -> MinGRU (sequential scan) -> +residual
//   3. RMSNorm -> Slot Memory (cross-attention, top-k routing) -> +residual
//   4. RMSNorm -> SwiGLU FFN -> +residual
//
// Full model:
//   token_id -> Embedding[256, d_model] -> layers -> RMSNorm -> logits (tied)

#include "consensus_model.h"
#include "../hash/keccak.h"

#include "../ggml/ggml.h"
#include "../ggml/ggml-cpu.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <fstream>
#include <numeric>

namespace flow {

// ════════════════════════════════════════════════════════════════════════════
// File format magic
// ════════════════════════════════════════════════════════════════════════════

static constexpr uint32_t MODEL_FILE_MAGIC = 0x464C574D; // "FLWM"
static constexpr uint32_t MODEL_FILE_VERSION = 1;

// ════════════════════════════════════════════════════════════════════════════
// Deterministic PRNG based on Keccak-256
// Produces float32 values in [-scale, +scale] from a seed.
// ════════════════════════════════════════════════════════════════════════════

class KeccakPRNG {
public:
    explicit KeccakPRNG(uint32_t seed) {
        // Initialize state from seed
        uint8_t seed_bytes[4];
        seed_bytes[0] = static_cast<uint8_t>(seed & 0xFF);
        seed_bytes[1] = static_cast<uint8_t>((seed >> 8) & 0xFF);
        seed_bytes[2] = static_cast<uint8_t>((seed >> 16) & 0xFF);
        seed_bytes[3] = static_cast<uint8_t>((seed >> 24) & 0xFF);

        state_ = keccak256(seed_bytes, 4);
        buf_pos_ = 32; // force initial refill
    }

    // Generate a float in [-scale, +scale]
    float next_float(float scale) {
        if (buf_pos_ >= 32) {
            refill();
        }

        // Take 4 bytes, interpret as uint32_t (little-endian)
        uint32_t u = 0;
        u |= static_cast<uint32_t>(buf_[buf_pos_]);
        u |= static_cast<uint32_t>(buf_[buf_pos_ + 1]) << 8;
        u |= static_cast<uint32_t>(buf_[buf_pos_ + 2]) << 16;
        u |= static_cast<uint32_t>(buf_[buf_pos_ + 3]) << 24;
        buf_pos_ += 4;

        // Map to [-1, 1] then scale
        // u / 2^32 gives [0, 1), map to [-1, 1)
        float f = (static_cast<float>(u) / 4294967296.0f) * 2.0f - 1.0f;
        return f * scale;
    }

private:
    void refill() {
        // Hash the current state to produce new random bytes
        state_ = keccak256(state_.data(), 32);
        std::memcpy(buf_, state_.data(), 32);
        buf_pos_ = 0;
    }

    uint256 state_;
    uint8_t buf_[32];
    int buf_pos_ = 0;
};

// ════════════════════════════════════════════════════════════════════════════
// Constructor / Destructor
// ════════════════════════════════════════════════════════════════════════════

ConsensusModel::ConsensusModel() = default;

ConsensusModel::~ConsensusModel() {
    if (ctx_) {
        ggml_free(ctx_);
        ctx_ = nullptr;
    }
}

ConsensusModel::ConsensusModel(ConsensusModel&& other) noexcept
    : dims_(other.dims_),
      ctx_(other.ctx_),
      tok_emb_(other.tok_emb_),
      layers_(std::move(other.layers_)),
      final_norm_w_(other.final_norm_w_) {
    other.ctx_ = nullptr;
    other.tok_emb_ = nullptr;
    other.final_norm_w_ = nullptr;
}

ConsensusModel& ConsensusModel::operator=(ConsensusModel&& other) noexcept {
    if (this != &other) {
        if (ctx_) ggml_free(ctx_);
        dims_ = other.dims_;
        ctx_ = other.ctx_;
        tok_emb_ = other.tok_emb_;
        layers_ = std::move(other.layers_);
        final_norm_w_ = other.final_norm_w_;
        other.ctx_ = nullptr;
        other.tok_emb_ = nullptr;
        other.final_norm_w_ = nullptr;
    }
    return *this;
}

// ════════════════════════════════════════════════════════════════════════════
// Parameter counting
// ════════════════════════════════════════════════════════════════════════════

size_t ConsensusModel::layer_param_count() const {
    const uint32_t d = dims_.d_model;
    const uint32_t d_ff = dims_.d_ff;
    const uint32_t n_slots = dims_.n_slots;

    size_t count = 0;

    // 4 RMSNorm weights: [d_model] each
    count += 4 * d;

    // Multi-scale causal conv: 3 depthwise kernels + mix matrix
    count += 3 * d;   // conv3_w: [3, d]  -> 3*d
    count += 7 * d;   // conv7_w: [7, d]  -> 7*d
    count += 15 * d;  // conv15_w: [15, d] -> 15*d
    count += d * d;   // conv_mix_w: [d, d]

    // MinGRU: 2 weight matrices + 2 biases
    count += d * d;   // gru_wz
    count += d * d;   // gru_wh
    count += d;       // gru_bz
    count += d;       // gru_bh

    // Slot memory: keys, values, query proj, output proj
    count += d * n_slots; // slot_keys
    count += d * n_slots; // slot_values
    count += d * d;       // slot_proj_q
    count += d * d;       // slot_proj_out

    // SwiGLU FFN: gate, up, down
    count += d * d_ff;    // ffn_gate_w
    count += d * d_ff;    // ffn_up_w
    count += d_ff * d;    // ffn_down_w

    return count;
}

size_t ConsensusModel::param_count() const {
    size_t count = 0;

    // Token embedding: [vocab, d_model]
    count += dims_.vocab * dims_.d_model;

    // Per-layer
    count += dims_.n_layers * layer_param_count();

    // Final norm: [d_model]
    count += dims_.d_model;

    return count;
}

// ════════════════════════════════════════════════════════════════════════════
// Context allocation and tensor creation
// ════════════════════════════════════════════════════════════════════════════

bool ConsensusModel::allocate_context() {
    if (ctx_) {
        ggml_free(ctx_);
        ctx_ = nullptr;
    }

    // Calculate total memory needed for all weight tensors
    // Each tensor needs: sizeof(ggml_tensor) + data + padding
    // ggml overhead per tensor is ~384 bytes (GGML_TENSOR_SIZE + object header)
    // Data is float32 = 4 bytes per element

    const size_t n_tensors_per_layer = 17; // count of fields in LayerTensors
    const size_t total_tensors = 1 /*tok_emb*/ + dims_.n_layers * n_tensors_per_layer + 1 /*final_norm*/;

    // Data memory: param_count * sizeof(float)
    const size_t data_size = param_count() * sizeof(float);

    // Overhead: ggml object headers + tensor structs + alignment padding
    // Conservative estimate: 512 bytes per tensor + 1MB overhead
    const size_t overhead = total_tensors * 512 + 1024 * 1024;

    const size_t total_mem = data_size + overhead;

    struct ggml_init_params params = {
        /*.mem_size   =*/ total_mem,
        /*.mem_buffer =*/ nullptr,
        /*.no_alloc   =*/ false,
    };

    ctx_ = ggml_init(params);
    return ctx_ != nullptr;
}

void ConsensusModel::create_tensors() {
    const int64_t d = dims_.d_model;
    const int64_t d_ff = dims_.d_ff;
    const int64_t n_slots = dims_.n_slots;
    const int64_t vocab = dims_.vocab;

    // Token embedding: [vocab, d_model]
    // ggml convention: ne[0] = innermost dim (columns)
    // So a [vocab, d_model] matrix has ne[0]=d_model, ne[1]=vocab
    // This way each row is a d_model-dimensional embedding vector
    tok_emb_ = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, vocab);
    ggml_set_name(tok_emb_, "tok_emb");

    layers_.resize(dims_.n_layers);

    for (uint32_t i = 0; i < dims_.n_layers; i++) {
        auto& L = layers_[i];
        char name[64];

        // RMSNorm weights
        L.norm1_w = ggml_new_tensor_1d(ctx_, GGML_TYPE_F32, d);
        snprintf(name, sizeof(name), "l%u.norm1_w", i);
        ggml_set_name(L.norm1_w, name);

        L.norm2_w = ggml_new_tensor_1d(ctx_, GGML_TYPE_F32, d);
        snprintf(name, sizeof(name), "l%u.norm2_w", i);
        ggml_set_name(L.norm2_w, name);

        L.norm3_w = ggml_new_tensor_1d(ctx_, GGML_TYPE_F32, d);
        snprintf(name, sizeof(name), "l%u.norm3_w", i);
        ggml_set_name(L.norm3_w, name);

        L.norm4_w = ggml_new_tensor_1d(ctx_, GGML_TYPE_F32, d);
        snprintf(name, sizeof(name), "l%u.norm4_w", i);
        ggml_set_name(L.norm4_w, name);

        // Multi-scale causal convolution (depthwise)
        // ggml_conv_1d_dw expects kernel shape [kernel_size, channels, 1]
        // We store as 2D: [kernel_size, d_model]
        L.conv3_w = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, 3, d);
        snprintf(name, sizeof(name), "l%u.conv3_w", i);
        ggml_set_name(L.conv3_w, name);

        L.conv7_w = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, 7, d);
        snprintf(name, sizeof(name), "l%u.conv7_w", i);
        ggml_set_name(L.conv7_w, name);

        L.conv15_w = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, 15, d);
        snprintf(name, sizeof(name), "l%u.conv15_w", i);
        ggml_set_name(L.conv15_w, name);

        L.conv_mix_w = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, d);
        snprintf(name, sizeof(name), "l%u.conv_mix_w", i);
        ggml_set_name(L.conv_mix_w, name);

        // MinGRU weights
        L.gru_wz = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, d);
        snprintf(name, sizeof(name), "l%u.gru_wz", i);
        ggml_set_name(L.gru_wz, name);

        L.gru_wh = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, d);
        snprintf(name, sizeof(name), "l%u.gru_wh", i);
        ggml_set_name(L.gru_wh, name);

        L.gru_bz = ggml_new_tensor_1d(ctx_, GGML_TYPE_F32, d);
        snprintf(name, sizeof(name), "l%u.gru_bz", i);
        ggml_set_name(L.gru_bz, name);

        L.gru_bh = ggml_new_tensor_1d(ctx_, GGML_TYPE_F32, d);
        snprintf(name, sizeof(name), "l%u.gru_bh", i);
        ggml_set_name(L.gru_bh, name);

        // Slot memory
        L.slot_keys = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, n_slots);
        snprintf(name, sizeof(name), "l%u.slot_keys", i);
        ggml_set_name(L.slot_keys, name);

        L.slot_values = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, n_slots);
        snprintf(name, sizeof(name), "l%u.slot_values", i);
        ggml_set_name(L.slot_values, name);

        L.slot_proj_q = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, d);
        snprintf(name, sizeof(name), "l%u.slot_proj_q", i);
        ggml_set_name(L.slot_proj_q, name);

        L.slot_proj_out = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, d);
        snprintf(name, sizeof(name), "l%u.slot_proj_out", i);
        ggml_set_name(L.slot_proj_out, name);

        // SwiGLU FFN
        L.ffn_gate_w = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, d_ff);
        snprintf(name, sizeof(name), "l%u.ffn_gate_w", i);
        ggml_set_name(L.ffn_gate_w, name);

        L.ffn_up_w = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d, d_ff);
        snprintf(name, sizeof(name), "l%u.ffn_up_w", i);
        ggml_set_name(L.ffn_up_w, name);

        L.ffn_down_w = ggml_new_tensor_2d(ctx_, GGML_TYPE_F32, d_ff, d);
        snprintf(name, sizeof(name), "l%u.ffn_down_w", i);
        ggml_set_name(L.ffn_down_w, name);
    }

    // Final RMSNorm
    final_norm_w_ = ggml_new_tensor_1d(ctx_, GGML_TYPE_F32, d);
    ggml_set_name(final_norm_w_, "final_norm_w");
}

// ════════════════════════════════════════════════════════════════════════════
// Weight tensor enumeration (fixed order for serialization)
// ════════════════════════════════════════════════════════════════════════════

std::vector<ggml_tensor*> ConsensusModel::weight_tensors() const {
    std::vector<ggml_tensor*> tensors;
    tensors.reserve(2 + dims_.n_layers * 17);

    tensors.push_back(tok_emb_);

    for (uint32_t i = 0; i < dims_.n_layers; i++) {
        const auto& L = layers_[i];

        tensors.push_back(L.norm1_w);
        tensors.push_back(L.norm2_w);
        tensors.push_back(L.norm3_w);
        tensors.push_back(L.norm4_w);

        tensors.push_back(L.conv3_w);
        tensors.push_back(L.conv7_w);
        tensors.push_back(L.conv15_w);
        tensors.push_back(L.conv_mix_w);

        tensors.push_back(L.gru_wz);
        tensors.push_back(L.gru_wh);
        tensors.push_back(L.gru_bz);
        tensors.push_back(L.gru_bh);

        tensors.push_back(L.slot_keys);
        tensors.push_back(L.slot_values);
        tensors.push_back(L.slot_proj_q);
        tensors.push_back(L.slot_proj_out);

        tensors.push_back(L.ffn_gate_w);
        tensors.push_back(L.ffn_up_w);
        tensors.push_back(L.ffn_down_w);
    }

    tensors.push_back(final_norm_w_);

    return tensors;
}

// ════════════════════════════════════════════════════════════════════════════
// Weight initialization (deterministic from seed)
// ════════════════════════════════════════════════════════════════════════════

void ConsensusModel::init_weights(uint32_t seed) {
    KeccakPRNG rng(seed);

    auto tensors = weight_tensors();

    for (auto* t : tensors) {
        const int64_t n = ggml_nelements(t);
        float* data = ggml_get_data_f32(t);

        // Compute fan_in for Xavier-style initialization
        // For 1D tensors (biases, norms): fan_in = ne[0]
        // For 2D tensors: fan_in = ne[0] (input dimension)
        int64_t fan_in = t->ne[0];
        float scale = 1.0f / std::sqrt(static_cast<float>(fan_in));

        // Special cases for norm weights: initialize to 1.0
        // (RMSNorm scale parameters)
        const char* name = ggml_get_name(t);
        bool is_norm = (name && (strstr(name, "norm") != nullptr));

        if (is_norm) {
            // Norm weights initialized to 1.0
            for (int64_t j = 0; j < n; j++) {
                data[j] = 1.0f;
                // Still consume PRNG output to keep deterministic sequence
                (void)rng.next_float(scale);
            }
        } else {
            // Standard Xavier initialization
            for (int64_t j = 0; j < n; j++) {
                data[j] = rng.next_float(scale);
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// init()
// ════════════════════════════════════════════════════════════════════════════

bool ConsensusModel::init(const consensus::ModelDimensions& dims, uint32_t seed) {
    dims_ = dims;

    if (!allocate_context()) {
        return false;
    }

    create_tensors();
    init_weights(seed);

    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// Weight serialization
// ════════════════════════════════════════════════════════════════════════════

std::vector<float> ConsensusModel::get_weights() const {
    std::vector<float> weights;
    weights.reserve(param_count());

    auto tensors = weight_tensors();
    for (const auto* t : tensors) {
        const int64_t n = ggml_nelements(t);
        const float* data = ggml_get_data_f32(t);
        weights.insert(weights.end(), data, data + n);
    }

    return weights;
}

bool ConsensusModel::set_weights(const std::vector<float>& weights) {
    if (weights.size() != param_count()) {
        return false;
    }

    auto tensors = weight_tensors();
    size_t offset = 0;

    for (auto* t : tensors) {
        const int64_t n = ggml_nelements(t);
        float* data = ggml_get_data_f32(t);
        std::memcpy(data, weights.data() + offset, n * sizeof(float));
        offset += n;
    }

    return true;
}

bool ConsensusModel::apply_delta(const std::vector<float>& delta_weights) {
    if (delta_weights.size() != param_count()) {
        return false;
    }

    auto tensors = weight_tensors();
    size_t offset = 0;

    for (auto* t : tensors) {
        const int64_t n = ggml_nelements(t);
        float* data = ggml_get_data_f32(t);
        for (int64_t j = 0; j < n; j++) {
            data[j] += delta_weights[offset + j];
        }
        offset += n;
    }

    return true;
}

uint256 ConsensusModel::get_weights_hash() const {
    auto weights = get_weights();
    return keccak256(reinterpret_cast<const uint8_t*>(weights.data()),
                     weights.size() * sizeof(float));
}

// ════════════════════════════════════════════════════════════════════════════
// Forward pass: single sequence
//
// The forward pass is implemented as direct computation using ggml's
// CPU tensor operations. For consensus determinism, we run single-threaded
// with float32 and fixed accumulation order.
//
// Architecture per layer:
//   1. x = x + MultiScaleCausalConv(RMSNorm(x))
//   2. x = x + MinGRU(RMSNorm(x))
//   3. x = x + SlotMemory(RMSNorm(x))
//   4. x = x + SwiGLU_FFN(RMSNorm(x))
// ════════════════════════════════════════════════════════════════════════════

// Helper: RMSNorm on a raw buffer
// x: [seq_len, d_model] row-major
// w: [d_model] scale weights
// out: [seq_len, d_model] row-major
static void rmsnorm_cpu(const float* x, const float* w, float* out,
                        int seq_len, int d_model) {
    constexpr float eps = 1e-6f;

    for (int t = 0; t < seq_len; t++) {
        const float* row = x + t * d_model;
        float* orow = out + t * d_model;

        // Compute mean of squares
        float sum_sq = 0.0f;
        for (int j = 0; j < d_model; j++) {
            sum_sq += row[j] * row[j];
        }
        float rms = std::sqrt(sum_sq / static_cast<float>(d_model) + eps);
        float inv_rms = 1.0f / rms;

        // Scale
        for (int j = 0; j < d_model; j++) {
            orow[j] = row[j] * inv_rms * w[j];
        }
    }
}

// Helper: matrix multiply C = A @ B^T
// A: [M, K] row-major
// B: [N, K] row-major (transposed: each row of B is a column of the result)
// C: [M, N] row-major
// Result: C[i][j] = sum_k A[i][k] * B[j][k]
static void matmul_cpu(const float* A, const float* B, float* C,
                       int M, int K, int N) {
    for (int i = 0; i < M; i++) {
        for (int j = 0; j < N; j++) {
            float sum = 0.0f;
            for (int k = 0; k < K; k++) {
                sum += A[i * K + k] * B[j * K + k];
            }
            C[i * N + j] = sum;
        }
    }
}

// (matmul_nn_cpu and add_bias_cpu removed: forward_sequence uses
//  matmul_cpu (A @ B^T) directly, matching ggml's row-major layout
//  where weight matrices have ne[0]=input_dim stored as rows.)

// Helper: sigmoid
static inline float sigmoid_f(float x) {
    return 1.0f / (1.0f + std::exp(-x));
}

// Helper: SiLU (swish)
static inline float silu_f(float x) {
    return x * sigmoid_f(x);
}

// Helper: element-wise add
static void add_cpu(float* dst, const float* a, const float* b, int n) {
    for (int i = 0; i < n; i++) {
        dst[i] = a[i] + b[i];
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Sub-layer 1: Multi-Scale Causal Convolution
// ────────────────────────────────────────────────────────────────────────────

// Depthwise causal conv1d: for each channel independently
// input: [seq_len, d_model] row-major
// kernel: [kernel_size, d_model] stored as kernel[k][ch] (ggml 2D: ne[0]=kernel_size, ne[1]=d_model)
//         but ggml stores column-major: data layout is [kernel_size * d_model] with kernel_size contiguous
// output: [seq_len, d_model] row-major
static void causal_conv1d_depthwise_cpu(const float* input, const float* kernel,
                                        float* output, int seq_len, int d_model,
                                        int kernel_size) {
    // kernel layout in ggml (ne[0]=kernel_size, ne[1]=d_model):
    //   kernel[ch * kernel_size + k] for channel ch, tap k
    // Causal: output[t][ch] = sum_{k=0}^{kernel_size-1} input[t-k][ch] * kernel[ch * kernel_size + k]
    // When t-k < 0, treat as zero (causal padding)

    for (int t = 0; t < seq_len; t++) {
        for (int ch = 0; ch < d_model; ch++) {
            float sum = 0.0f;
            for (int k = 0; k < kernel_size; k++) {
                int src_t = t - k;
                if (src_t >= 0) {
                    sum += input[src_t * d_model + ch] * kernel[ch * kernel_size + k];
                }
            }
            output[t * d_model + ch] = sum;
        }
    }
}

// Sub-layer implementations are inlined in forward_sequence() below for
// clarity and to avoid passing many tensor pointers through helper functions.

// ════════════════════════════════════════════════════════════════════════════
// Forward pass for a single sequence
// ════════════════════════════════════════════════════════════════════════════

void ConsensusModel::forward_sequence(const uint8_t* tokens, int seq_len,
                                      float* logits_out) const {
    const int d = static_cast<int>(dims_.d_model);
    const int d_ff = static_cast<int>(dims_.d_ff);
    const int n_slots = static_cast<int>(dims_.n_slots);
    const int top_k = static_cast<int>(dims_.top_k);
    const int vocab = static_cast<int>(dims_.vocab);

    // Working buffers
    // x: current hidden state [seq_len, d]
    // tmp_norm: after RMSNorm [seq_len, d]
    // tmp_conv1/2/3: conv temporaries [seq_len, d]
    // tmp_conv_sum: conv sum [seq_len, d]
    // tmp_proj: projection temporary [seq_len, max(d, d_ff, n_slots)]
    // h_state: MinGRU hidden state [d]
    // tmp_gru_z: gate values [d]
    // tmp_gru_h: candidate values [d]

    const size_t buf_sd = static_cast<size_t>(seq_len) * d;
    const size_t buf_sd_ff = static_cast<size_t>(seq_len) * d_ff;
    const size_t buf_s_ns = static_cast<size_t>(seq_len) * n_slots;

    std::vector<float> x(buf_sd);
    std::vector<float> tmp_norm(buf_sd);
    std::vector<float> tmp_conv1(buf_sd);
    std::vector<float> tmp_conv2(buf_sd);
    std::vector<float> tmp_conv3(buf_sd);
    std::vector<float> tmp_conv_sum(buf_sd);
    std::vector<float> tmp_sub(buf_sd);  // general sub-layer output

    // GRU temporaries
    std::vector<float> tmp_gru_proj(buf_sd);     // [seq_len, d] projection
    std::vector<float> h_state(d, 0.0f);         // MinGRU hidden state [d]

    // Slot memory temporaries
    std::vector<float> tmp_slot_q(buf_sd);       // [seq_len, d]
    std::vector<float> tmp_slot_scores(buf_s_ns);// [seq_len, n_slots]
    std::vector<float> tmp_slot_retrieved(buf_sd);// [seq_len, d]

    // FFN temporaries
    std::vector<float> tmp_ffn_gate(buf_sd_ff);  // [seq_len, d_ff]
    std::vector<float> tmp_ffn_up(buf_sd_ff);    // [seq_len, d_ff]
    std::vector<float> tmp_ffn_act(buf_sd_ff);   // [seq_len, d_ff]

    // ── Step 1: Token embedding lookup ──────────────────────────
    // tok_emb_ is [d, vocab] in ggml (ne[0]=d, ne[1]=vocab)
    // Row i of tok_emb_ = embedding for token i
    const float* emb_data = ggml_get_data_f32(tok_emb_);
    for (int t = 0; t < seq_len; t++) {
        int tok = tokens[t];
        // Copy embedding row for token
        std::memcpy(x.data() + t * d, emb_data + tok * d, d * sizeof(float));
    }

    // ── Step 2: Layer loop ──────────────────────────────────────
    for (uint32_t layer_idx = 0; layer_idx < dims_.n_layers; layer_idx++) {
        const auto& L = layers_[layer_idx];

        // ── Sub-layer 1: Multi-Scale Causal Conv ────────────────
        {
            const float* norm_w = ggml_get_data_f32(L.norm1_w);
            rmsnorm_cpu(x.data(), norm_w, tmp_norm.data(), seq_len, d);

            // Depthwise causal conv with kernel sizes 3, 7, 15
            const float* k3 = ggml_get_data_f32(L.conv3_w);
            const float* k7 = ggml_get_data_f32(L.conv7_w);
            const float* k15 = ggml_get_data_f32(L.conv15_w);

            causal_conv1d_depthwise_cpu(tmp_norm.data(), k3, tmp_conv1.data(),
                                        seq_len, d, 3);
            causal_conv1d_depthwise_cpu(tmp_norm.data(), k7, tmp_conv2.data(),
                                        seq_len, d, 7);
            causal_conv1d_depthwise_cpu(tmp_norm.data(), k15, tmp_conv3.data(),
                                        seq_len, d, 15);

            // Sum the three conv outputs
            for (size_t i = 0; i < buf_sd; i++) {
                tmp_conv_sum[i] = tmp_conv1[i] + tmp_conv2[i] + tmp_conv3[i];
            }

            // Project through conv_mix_w: [d, d] in ggml (ne[0]=d, ne[1]=d)
            // tmp_conv_sum is [seq_len, d], conv_mix_w^T is [d, d]
            // out = tmp_conv_sum @ conv_mix_w^T
            const float* mix_w = ggml_get_data_f32(L.conv_mix_w);
            matmul_cpu(tmp_conv_sum.data(), mix_w, tmp_sub.data(),
                       seq_len, d, d);

            // Residual connection
            add_cpu(x.data(), x.data(), tmp_sub.data(), static_cast<int>(buf_sd));
        }

        // ── Sub-layer 2: MinGRU ─────────────────────────────────
        {
            const float* norm_w = ggml_get_data_f32(L.norm2_w);
            rmsnorm_cpu(x.data(), norm_w, tmp_norm.data(), seq_len, d);

            const float* wz = ggml_get_data_f32(L.gru_wz);
            const float* wh = ggml_get_data_f32(L.gru_wh);
            const float* bz = ggml_get_data_f32(L.gru_bz);
            const float* bh = ggml_get_data_f32(L.gru_bh);

            // Reset hidden state to zero for each sequence
            std::fill(h_state.begin(), h_state.end(), 0.0f);

            // Process sequentially, token by token
            for (int t = 0; t < seq_len; t++) {
                const float* xt = tmp_norm.data() + t * d;
                float* out_t = tmp_sub.data() + t * d;

                // z = sigmoid(xt @ Wz^T + bz)
                // xt: [d], Wz: [d, d] (ne[0]=d, ne[1]=d)
                // xt @ Wz^T: for each output dim j, sum_k xt[k] * Wz[j*d+k]
                for (int j = 0; j < d; j++) {
                    float sum = bz[j];
                    for (int k = 0; k < d; k++) {
                        sum += xt[k] * wz[j * d + k];
                    }
                    // tmp_gru_proj used as z storage
                    tmp_gru_proj[j] = sigmoid_f(sum);
                }

                // h_tilde = xt @ Wh^T + bh
                for (int j = 0; j < d; j++) {
                    float sum = bh[j];
                    for (int k = 0; k < d; k++) {
                        sum += xt[k] * wh[j * d + k];
                    }
                    // Store h_tilde in out_t temporarily
                    out_t[j] = sum;
                }

                // h = (1 - z) * h_prev + z * h_tilde
                for (int j = 0; j < d; j++) {
                    float z = tmp_gru_proj[j];
                    h_state[j] = (1.0f - z) * h_state[j] + z * out_t[j];
                    out_t[j] = h_state[j];
                }
            }

            // Residual connection
            add_cpu(x.data(), x.data(), tmp_sub.data(), static_cast<int>(buf_sd));
        }

        // ── Sub-layer 3: Slot Memory ────────────────────────────
        {
            const float* norm_w = ggml_get_data_f32(L.norm3_w);
            rmsnorm_cpu(x.data(), norm_w, tmp_norm.data(), seq_len, d);

            const float* proj_q_w = ggml_get_data_f32(L.slot_proj_q);
            const float* sk = ggml_get_data_f32(L.slot_keys);
            const float* sv = ggml_get_data_f32(L.slot_values);
            const float* proj_out_w = ggml_get_data_f32(L.slot_proj_out);

            // q = normed @ slot_proj_q^T  [seq_len, d]
            matmul_cpu(tmp_norm.data(), proj_q_w, tmp_slot_q.data(),
                       seq_len, d, d);

            // scores = q @ slot_keys^T  [seq_len, n_slots]
            // slot_keys: [d, n_slots] in ggml, stored as n_slots rows of d elements
            // Actually ggml stores ne[0]=d, ne[1]=n_slots
            // So slot_keys data is [n_slots * d], with row i = slot i
            // scores[t][s] = sum_k q[t][k] * slot_keys[s*d + k]
            matmul_cpu(tmp_slot_q.data(), sk, tmp_slot_scores.data(),
                       seq_len, d, n_slots);

            // For each token: top-k routing + softmax + retrieve
            const float scale = 1.0f / std::sqrt(static_cast<float>(d));

            for (int t = 0; t < seq_len; t++) {
                float* scores_t = tmp_slot_scores.data() + t * n_slots;

                // Scale scores
                for (int s = 0; s < n_slots; s++) {
                    scores_t[s] *= scale;
                }

                // Find top-k indices
                // Use partial sort: find the k largest values
                std::vector<int> top_idx(top_k);
                std::vector<float> top_val(top_k, -1e30f);

                for (int s = 0; s < n_slots; s++) {
                    // Check if this score belongs in top-k
                    int min_pos = 0;
                    for (int ki = 1; ki < top_k; ki++) {
                        if (top_val[ki] < top_val[min_pos]) {
                            min_pos = ki;
                        }
                    }
                    if (scores_t[s] > top_val[min_pos]) {
                        top_val[min_pos] = scores_t[s];
                        top_idx[min_pos] = s;
                    }
                }

                // Softmax over top-k scores
                float max_score = *std::max_element(top_val.begin(), top_val.end());
                float sum_exp = 0.0f;
                for (int ki = 0; ki < top_k; ki++) {
                    top_val[ki] = std::exp(top_val[ki] - max_score);
                    sum_exp += top_val[ki];
                }
                for (int ki = 0; ki < top_k; ki++) {
                    top_val[ki] /= sum_exp;
                }

                // Retrieve: weighted sum of slot_values
                float* retrieved_t = tmp_slot_retrieved.data() + t * d;
                std::fill(retrieved_t, retrieved_t + d, 0.0f);

                for (int ki = 0; ki < top_k; ki++) {
                    int si = top_idx[ki];
                    float w = top_val[ki];
                    const float* val_row = sv + si * d;
                    for (int j = 0; j < d; j++) {
                        retrieved_t[j] += w * val_row[j];
                    }
                }
            }

            // Project output: retrieved @ slot_proj_out^T  [seq_len, d]
            matmul_cpu(tmp_slot_retrieved.data(), proj_out_w, tmp_sub.data(),
                       seq_len, d, d);

            // Residual connection
            add_cpu(x.data(), x.data(), tmp_sub.data(), static_cast<int>(buf_sd));
        }

        // ── Sub-layer 4: SwiGLU FFN ────────────────────────────
        {
            const float* norm_w = ggml_get_data_f32(L.norm4_w);
            rmsnorm_cpu(x.data(), norm_w, tmp_norm.data(), seq_len, d);

            const float* gate_w = ggml_get_data_f32(L.ffn_gate_w);
            const float* up_w = ggml_get_data_f32(L.ffn_up_w);
            const float* down_w = ggml_get_data_f32(L.ffn_down_w);

            // gate = normed @ gate_w^T  [seq_len, d_ff]
            // gate_w: [d, d_ff] in ggml, ne[0]=d, ne[1]=d_ff
            // stored as d_ff rows of d elements
            matmul_cpu(tmp_norm.data(), gate_w, tmp_ffn_gate.data(),
                       seq_len, d, d_ff);

            // up = normed @ up_w^T  [seq_len, d_ff]
            matmul_cpu(tmp_norm.data(), up_w, tmp_ffn_up.data(),
                       seq_len, d, d_ff);

            // activated = silu(gate) * up
            for (size_t i = 0; i < buf_sd_ff; i++) {
                tmp_ffn_act[i] = silu_f(tmp_ffn_gate[i]) * tmp_ffn_up[i];
            }

            // out = activated @ down_w^T  [seq_len, d]
            // down_w: [d_ff, d] in ggml, ne[0]=d_ff, ne[1]=d
            // stored as d rows of d_ff elements
            matmul_cpu(tmp_ffn_act.data(), down_w, tmp_sub.data(),
                       seq_len, d_ff, d);

            // Residual connection
            add_cpu(x.data(), x.data(), tmp_sub.data(), static_cast<int>(buf_sd));
        }
    }

    // ── Step 3: Final RMSNorm ───────────────────────────────────
    {
        const float* norm_w = ggml_get_data_f32(final_norm_w_);
        rmsnorm_cpu(x.data(), norm_w, tmp_norm.data(), seq_len, d);
    }

    // ── Step 4: Compute logits (tied embedding) ─────────────────
    // logits = normed @ tok_emb^T  [seq_len, vocab]
    // tok_emb: [d, vocab] in ggml, ne[0]=d, ne[1]=vocab
    // stored as vocab rows of d elements
    // logits[t][v] = sum_k normed[t][k] * tok_emb[v*d + k]
    matmul_cpu(tmp_norm.data(), emb_data, logits_out,
               seq_len, d, vocab);
}

// ════════════════════════════════════════════════════════════════════════════
// Forward evaluation: loss computation
// ════════════════════════════════════════════════════════════════════════════

float ConsensusModel::forward_eval(const std::vector<uint8_t>& data) const {
    const int seq_len = static_cast<int>(dims_.seq_len);
    const int vocab = static_cast<int>(dims_.vocab);

    if (data.size() < static_cast<size_t>(seq_len + 1)) {
        return consensus::MAX_VAL_LOSS;
    }

    // Process data in chunks of seq_len
    // Input: tokens [i .. i+seq_len-1]
    // Target: tokens [i+1 .. i+seq_len]
    const int n_sequences = static_cast<int>((data.size() - 1) / seq_len);
    if (n_sequences <= 0) {
        return consensus::MAX_VAL_LOSS;
    }

    double total_loss = 0.0;
    int total_tokens = 0;

    // Logits buffer: [seq_len, vocab]
    std::vector<float> logits(static_cast<size_t>(seq_len) * vocab);

    for (int seq = 0; seq < n_sequences; seq++) {
        const int offset = seq * seq_len;

        // Check we have enough data for input + target
        if (offset + seq_len >= static_cast<int>(data.size())) {
            break;
        }

        const uint8_t* input_tokens = data.data() + offset;

        // Run forward pass
        forward_sequence(input_tokens, seq_len, logits.data());

        // Compute cross-entropy loss for each position
        // Target is the next token: data[offset+1 .. offset+seq_len]
        for (int t = 0; t < seq_len; t++) {
            int target = data[offset + t + 1];
            const float* log_row = logits.data() + t * vocab;

            // Numerically stable log-softmax:
            // log_softmax[j] = logits[j] - log(sum(exp(logits)))
            // = logits[j] - max - log(sum(exp(logits - max)))

            float max_logit = log_row[0];
            for (int v = 1; v < vocab; v++) {
                if (log_row[v] > max_logit) {
                    max_logit = log_row[v];
                }
            }

            float sum_exp = 0.0f;
            for (int v = 0; v < vocab; v++) {
                sum_exp += std::exp(log_row[v] - max_logit);
            }

            float log_sum_exp = max_logit + std::log(sum_exp);
            float log_prob = log_row[target] - log_sum_exp;

            total_loss -= static_cast<double>(log_prob);
            total_tokens++;
        }
    }

    if (total_tokens == 0) {
        return consensus::MAX_VAL_LOSS;
    }

    return static_cast<float>(total_loss / static_cast<double>(total_tokens));
}

// ════════════════════════════════════════════════════════════════════════════
// Persistence: save/load
// ════════════════════════════════════════════════════════════════════════════

bool ConsensusModel::save_to_file(const std::string& path) const {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    // Write header
    file.write(reinterpret_cast<const char*>(&MODEL_FILE_MAGIC), 4);
    file.write(reinterpret_cast<const char*>(&MODEL_FILE_VERSION), 4);

    // Write dimensions struct
    file.write(reinterpret_cast<const char*>(&dims_), sizeof(dims_));

    // Write weights
    auto weights = get_weights();
    const uint32_t n_weights = static_cast<uint32_t>(weights.size());
    file.write(reinterpret_cast<const char*>(&n_weights), 4);
    file.write(reinterpret_cast<const char*>(weights.data()),
               weights.size() * sizeof(float));

    return file.good();
}

bool ConsensusModel::load_from_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    // Read and verify magic
    uint32_t magic = 0;
    file.read(reinterpret_cast<char*>(&magic), 4);
    if (magic != MODEL_FILE_MAGIC) {
        return false;
    }

    // Read and verify version
    uint32_t version = 0;
    file.read(reinterpret_cast<char*>(&version), 4);
    if (version != MODEL_FILE_VERSION) {
        return false;
    }

    // Read dimensions
    consensus::ModelDimensions dims;
    file.read(reinterpret_cast<char*>(&dims), sizeof(dims));

    // Initialize model structure with these dimensions
    dims_ = dims;
    if (!allocate_context()) {
        return false;
    }
    create_tensors();

    // Read weight count
    uint32_t n_weights = 0;
    file.read(reinterpret_cast<char*>(&n_weights), 4);

    if (n_weights != param_count()) {
        return false;
    }

    // Read weights
    std::vector<float> weights(n_weights);
    file.read(reinterpret_cast<char*>(weights.data()),
              n_weights * sizeof(float));

    if (!file.good()) {
        return false;
    }

    return set_weights(weights);
}

// ════════════════════════════════════════════════════════════════════════════
// Growth: expand model to new dimensions
// ════════════════════════════════════════════════════════════════════════════

bool ConsensusModel::expand_to(const consensus::ModelDimensions& new_dims) {
    // Validate: new dimensions must be >= old dimensions
    if (new_dims.d_model < dims_.d_model ||
        new_dims.n_layers < dims_.n_layers ||
        new_dims.d_ff < dims_.d_ff ||
        new_dims.n_slots < dims_.n_slots) {
        return false;
    }

    // If dimensions haven't changed, nothing to do
    if (new_dims.d_model == dims_.d_model &&
        new_dims.n_layers == dims_.n_layers &&
        new_dims.d_ff == dims_.d_ff &&
        new_dims.n_slots == dims_.n_slots) {
        return true;
    }

    // Save current weights and dimensions
    auto old_weights = get_weights();
    auto old_dims = dims_;
    auto old_tensors = weight_tensors();

    // Collect old tensor sizes for indexing
    std::vector<int64_t> old_tensor_sizes;
    old_tensor_sizes.reserve(old_tensors.size());
    for (const auto* t : old_tensors) {
        old_tensor_sizes.push_back(ggml_nelements(t));
    }

    // Reinitialize with new dimensions
    // Use a deterministic seed for new weights based on old state
    dims_ = new_dims;
    if (!allocate_context()) {
        return false;
    }
    create_tensors();

    // Initialize all new weights to zero first
    auto new_tensors = weight_tensors();
    for (auto* t : new_tensors) {
        ggml_set_zero(t);
    }

    // Copy old weights into new tensors with zero-padding
    // Both old and new tensors are in the same canonical order
    const uint32_t old_n_layers = old_dims.n_layers;
    const int old_d = static_cast<int>(old_dims.d_model);
    const int new_d = static_cast<int>(new_dims.d_model);
    const int old_d_ff = static_cast<int>(old_dims.d_ff);
    const int new_d_ff = static_cast<int>(new_dims.d_ff);
    const int old_n_slots = static_cast<int>(old_dims.n_slots);
    const int new_n_slots = static_cast<int>(new_dims.n_slots);
    const int vocab = static_cast<int>(dims_.vocab);

    size_t old_offset = 0;

    // Helper: copy a 2D weight matrix from old [old_rows, old_cols] to new [new_rows, new_cols]
    // with zero-padding for the extra rows/cols
    auto copy_2d = [&](int old_rows, int old_cols, int new_rows, int new_cols,
                       const float* src, float* dst) {
        int rows_to_copy = std::min(old_rows, new_rows);
        int cols_to_copy = std::min(old_cols, new_cols);
        for (int r = 0; r < rows_to_copy; r++) {
            std::memcpy(dst + r * new_cols, src + r * old_cols,
                       cols_to_copy * sizeof(float));
        }
    };

    // Helper: copy a 1D weight vector from old [old_size] to new [new_size]
    auto copy_1d = [&](int old_size, int new_size,
                       const float* src, float* dst) {
        int to_copy = std::min(old_size, new_size);
        std::memcpy(dst, src, to_copy * sizeof(float));
    };

    // Token embedding: old [vocab, old_d] -> new [vocab, new_d]
    // ggml stores ne[0]=d, ne[1]=vocab, so data is vocab rows of d
    {
        const float* old_emb = old_weights.data() + old_offset;
        float* new_emb = ggml_get_data_f32(tok_emb_);
        copy_2d(vocab, old_d, vocab, new_d, old_emb, new_emb);
        old_offset += vocab * old_d;
    }

    // For each existing layer, copy weights
    for (uint32_t li = 0; li < old_n_layers; li++) {
        auto& NL = layers_[li];

        // norm1_w: [old_d] -> [new_d]
        copy_1d(old_d, new_d, old_weights.data() + old_offset,
                ggml_get_data_f32(NL.norm1_w));
        old_offset += old_d;

        // norm2_w
        copy_1d(old_d, new_d, old_weights.data() + old_offset,
                ggml_get_data_f32(NL.norm2_w));
        old_offset += old_d;

        // norm3_w
        copy_1d(old_d, new_d, old_weights.data() + old_offset,
                ggml_get_data_f32(NL.norm3_w));
        old_offset += old_d;

        // norm4_w
        copy_1d(old_d, new_d, old_weights.data() + old_offset,
                ggml_get_data_f32(NL.norm4_w));
        old_offset += old_d;

        // conv3_w: [old_d, 3] -> [new_d, 3]
        // ggml ne[0]=3, ne[1]=d, so d rows of 3 elements
        copy_2d(old_d, 3, new_d, 3, old_weights.data() + old_offset,
                ggml_get_data_f32(NL.conv3_w));
        old_offset += old_d * 3;

        // conv7_w: [old_d, 7] -> [new_d, 7]
        copy_2d(old_d, 7, new_d, 7, old_weights.data() + old_offset,
                ggml_get_data_f32(NL.conv7_w));
        old_offset += old_d * 7;

        // conv15_w: [old_d, 15] -> [new_d, 15]
        copy_2d(old_d, 15, new_d, 15, old_weights.data() + old_offset,
                ggml_get_data_f32(NL.conv15_w));
        old_offset += old_d * 15;

        // conv_mix_w: [old_d, old_d] -> [new_d, new_d]
        copy_2d(old_d, old_d, new_d, new_d, old_weights.data() + old_offset,
                ggml_get_data_f32(NL.conv_mix_w));
        old_offset += old_d * old_d;

        // gru_wz: [old_d, old_d] -> [new_d, new_d]
        copy_2d(old_d, old_d, new_d, new_d, old_weights.data() + old_offset,
                ggml_get_data_f32(NL.gru_wz));
        old_offset += old_d * old_d;

        // gru_wh: [old_d, old_d] -> [new_d, new_d]
        copy_2d(old_d, old_d, new_d, new_d, old_weights.data() + old_offset,
                ggml_get_data_f32(NL.gru_wh));
        old_offset += old_d * old_d;

        // gru_bz: [old_d] -> [new_d]
        copy_1d(old_d, new_d, old_weights.data() + old_offset,
                ggml_get_data_f32(NL.gru_bz));
        old_offset += old_d;

        // gru_bh: [old_d] -> [new_d]
        copy_1d(old_d, new_d, old_weights.data() + old_offset,
                ggml_get_data_f32(NL.gru_bh));
        old_offset += old_d;

        // slot_keys: [old_n_slots, old_d] -> [new_n_slots, new_d]
        copy_2d(old_n_slots, old_d, new_n_slots, new_d,
                old_weights.data() + old_offset,
                ggml_get_data_f32(NL.slot_keys));
        old_offset += old_n_slots * old_d;

        // slot_values: [old_n_slots, old_d] -> [new_n_slots, new_d]
        copy_2d(old_n_slots, old_d, new_n_slots, new_d,
                old_weights.data() + old_offset,
                ggml_get_data_f32(NL.slot_values));
        old_offset += old_n_slots * old_d;

        // slot_proj_q: [old_d, old_d] -> [new_d, new_d]
        copy_2d(old_d, old_d, new_d, new_d, old_weights.data() + old_offset,
                ggml_get_data_f32(NL.slot_proj_q));
        old_offset += old_d * old_d;

        // slot_proj_out: [old_d, old_d] -> [new_d, new_d]
        copy_2d(old_d, old_d, new_d, new_d, old_weights.data() + old_offset,
                ggml_get_data_f32(NL.slot_proj_out));
        old_offset += old_d * old_d;

        // ffn_gate_w: [old_d_ff, old_d] -> [new_d_ff, new_d]
        // ggml ne[0]=d, ne[1]=d_ff, so d_ff rows of d elements
        copy_2d(old_d_ff, old_d, new_d_ff, new_d,
                old_weights.data() + old_offset,
                ggml_get_data_f32(NL.ffn_gate_w));
        old_offset += old_d_ff * old_d;

        // ffn_up_w: [old_d_ff, old_d] -> [new_d_ff, new_d]
        copy_2d(old_d_ff, old_d, new_d_ff, new_d,
                old_weights.data() + old_offset,
                ggml_get_data_f32(NL.ffn_up_w));
        old_offset += old_d_ff * old_d;

        // ffn_down_w: [old_d, old_d_ff] -> [new_d, new_d_ff]
        // ggml ne[0]=d_ff, ne[1]=d, so d rows of d_ff elements
        copy_2d(old_d, old_d_ff, new_d, new_d_ff,
                old_weights.data() + old_offset,
                ggml_get_data_f32(NL.ffn_down_w));
        old_offset += old_d * old_d_ff;
    }

    // For new layers (if n_layers grew): initialize with fresh weights
    // Use a deterministic seed derived from the old weights hash
    if (new_dims.n_layers > old_n_layers) {
        // Compute a seed from old model state
        auto old_hash = keccak256(reinterpret_cast<const uint8_t*>(old_weights.data()),
                                   old_weights.size() * sizeof(float));
        uint32_t expansion_seed = 0;
        expansion_seed |= static_cast<uint32_t>(old_hash[0]);
        expansion_seed |= static_cast<uint32_t>(old_hash[1]) << 8;
        expansion_seed |= static_cast<uint32_t>(old_hash[2]) << 16;
        expansion_seed |= static_cast<uint32_t>(old_hash[3]) << 24;

        KeccakPRNG rng(expansion_seed);

        for (uint32_t li = old_n_layers; li < new_dims.n_layers; li++) {
            auto& NL = layers_[li];

            // Initialize norm weights to 1.0
            auto init_norm = [&](ggml_tensor* t) {
                float* data = ggml_get_data_f32(t);
                int64_t n = ggml_nelements(t);
                for (int64_t j = 0; j < n; j++) {
                    data[j] = 1.0f;
                }
            };

            init_norm(NL.norm1_w);
            init_norm(NL.norm2_w);
            init_norm(NL.norm3_w);
            init_norm(NL.norm4_w);

            // Initialize other weights with Xavier
            auto init_xavier = [&](ggml_tensor* t) {
                float* data = ggml_get_data_f32(t);
                int64_t n = ggml_nelements(t);
                int64_t fan_in = t->ne[0];
                float scale = 1.0f / std::sqrt(static_cast<float>(fan_in));
                for (int64_t j = 0; j < n; j++) {
                    data[j] = rng.next_float(scale);
                }
            };

            init_xavier(NL.conv3_w);
            init_xavier(NL.conv7_w);
            init_xavier(NL.conv15_w);
            init_xavier(NL.conv_mix_w);
            init_xavier(NL.gru_wz);
            init_xavier(NL.gru_wh);

            // Biases to zero
            ggml_set_zero(NL.gru_bz);
            ggml_set_zero(NL.gru_bh);

            init_xavier(NL.slot_keys);
            init_xavier(NL.slot_values);
            init_xavier(NL.slot_proj_q);
            init_xavier(NL.slot_proj_out);
            init_xavier(NL.ffn_gate_w);
            init_xavier(NL.ffn_up_w);
            init_xavier(NL.ffn_down_w);
        }
    }

    // Final norm: copy old [old_d] into new [new_d]
    // The old final norm is at old_offset
    {
        float* new_fn = ggml_get_data_f32(final_norm_w_);
        copy_1d(old_d, new_d, old_weights.data() + old_offset, new_fn);
        // For the expanded portion, set to 1.0 (norm scale)
        for (int j = old_d; j < new_d; j++) {
            new_fn[j] = 1.0f;
        }
    }

    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// Validation data generation
// ════════════════════════════════════════════════════════════════════════════

std::vector<uint8_t> generate_validation_data(
    const std::string& seed_str, size_t num_tokens) {

    std::vector<uint8_t> result;
    result.reserve(num_tokens);

    // Convert seed string to bytes
    std::vector<uint8_t> seed_bytes(seed_str.begin(), seed_str.end());

    uint32_t counter = 0;
    while (result.size() < num_tokens) {
        // Build input: seed_bytes || counter_as_le32
        std::vector<uint8_t> input(seed_bytes.size() + 4);
        std::memcpy(input.data(), seed_bytes.data(), seed_bytes.size());

        // Append counter as little-endian uint32
        input[seed_bytes.size()]     = static_cast<uint8_t>(counter & 0xFF);
        input[seed_bytes.size() + 1] = static_cast<uint8_t>((counter >> 8) & 0xFF);
        input[seed_bytes.size() + 2] = static_cast<uint8_t>((counter >> 16) & 0xFF);
        input[seed_bytes.size() + 3] = static_cast<uint8_t>((counter >> 24) & 0xFF);
        counter++;

        // Hash
        uint256 hash = keccak256(input.data(), input.size());

        // Take hash bytes as tokens (32 bytes per hash)
        for (int i = 0; i < 32 && result.size() < num_tokens; i++) {
            result.push_back(hash[i]);
        }
    }

    return result;
}

// ════════════════════════════════════════════════════════════════════════════
// validate_architecture — verify all tensor dimensions
// ════════════════════════════════════════════════════════════════════════════

bool ConsensusModel::validate_architecture() const {
    if (!ctx_) return false;

    // Check embedding tensor
    if (!tok_emb_) return false;
    if (ggml_nelements(tok_emb_) !=
        static_cast<int64_t>(dims_.vocab) * static_cast<int64_t>(dims_.d_model)) {
        return false;
    }

    // Check final norm
    if (!final_norm_w_) return false;
    if (ggml_nelements(final_norm_w_) != static_cast<int64_t>(dims_.d_model)) {
        return false;
    }

    // Check per-layer tensors
    if (layers_.size() != dims_.n_layers) return false;

    for (uint32_t l = 0; l < dims_.n_layers; l++) {
        const auto& layer = layers_[l];

        // RMSNorm weights: 4 per layer, each [d_model]
        if (!layer.norm1_w || ggml_nelements(layer.norm1_w) != static_cast<int64_t>(dims_.d_model)) return false;
        if (!layer.norm2_w || ggml_nelements(layer.norm2_w) != static_cast<int64_t>(dims_.d_model)) return false;
        if (!layer.norm3_w || ggml_nelements(layer.norm3_w) != static_cast<int64_t>(dims_.d_model)) return false;
        if (!layer.norm4_w || ggml_nelements(layer.norm4_w) != static_cast<int64_t>(dims_.d_model)) return false;

        // Conv kernels
        if (!layer.conv3_w || ggml_nelements(layer.conv3_w) != 3 * static_cast<int64_t>(dims_.d_model)) return false;
        if (!layer.conv7_w || ggml_nelements(layer.conv7_w) != 7 * static_cast<int64_t>(dims_.d_model)) return false;
        if (!layer.conv15_w || ggml_nelements(layer.conv15_w) != 15 * static_cast<int64_t>(dims_.d_model)) return false;
        if (!layer.conv_mix_w || ggml_nelements(layer.conv_mix_w) !=
            static_cast<int64_t>(dims_.d_model) * static_cast<int64_t>(dims_.d_model)) return false;

        // MinGRU
        if (!layer.gru_wz || ggml_nelements(layer.gru_wz) !=
            static_cast<int64_t>(dims_.d_model) * static_cast<int64_t>(dims_.d_model)) return false;
        if (!layer.gru_wh || ggml_nelements(layer.gru_wh) !=
            static_cast<int64_t>(dims_.d_model) * static_cast<int64_t>(dims_.d_model)) return false;
        if (!layer.gru_bz || ggml_nelements(layer.gru_bz) != static_cast<int64_t>(dims_.d_model)) return false;
        if (!layer.gru_bh || ggml_nelements(layer.gru_bh) != static_cast<int64_t>(dims_.d_model)) return false;

        // Slot memory
        if (!layer.slot_keys || ggml_nelements(layer.slot_keys) !=
            static_cast<int64_t>(dims_.d_model) * static_cast<int64_t>(dims_.n_slots)) return false;
        if (!layer.slot_values || ggml_nelements(layer.slot_values) !=
            static_cast<int64_t>(dims_.d_model) * static_cast<int64_t>(dims_.n_slots)) return false;
        if (!layer.slot_proj_q || ggml_nelements(layer.slot_proj_q) !=
            static_cast<int64_t>(dims_.d_model) * static_cast<int64_t>(dims_.d_model)) return false;
        if (!layer.slot_proj_out || ggml_nelements(layer.slot_proj_out) !=
            static_cast<int64_t>(dims_.d_model) * static_cast<int64_t>(dims_.d_model)) return false;

        // SwiGLU FFN
        if (!layer.ffn_gate_w || ggml_nelements(layer.ffn_gate_w) !=
            static_cast<int64_t>(dims_.d_model) * static_cast<int64_t>(dims_.d_ff)) return false;
        if (!layer.ffn_up_w || ggml_nelements(layer.ffn_up_w) !=
            static_cast<int64_t>(dims_.d_model) * static_cast<int64_t>(dims_.d_ff)) return false;
        if (!layer.ffn_down_w || ggml_nelements(layer.ffn_down_w) !=
            static_cast<int64_t>(dims_.d_ff) * static_cast<int64_t>(dims_.d_model)) return false;
    }

    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// clone — deep copy
// ════════════════════════════════════════════════════════════════════════════

ConsensusModel ConsensusModel::clone() const {
    std::lock_guard<std::mutex> lock(weights_mutex_);

    ConsensusModel copy;
    copy.init(dims_, 0);  // Allocate with dummy seed

    // Copy all weights
    auto w = get_weights();
    copy.set_weights(w);

    return copy;
}

// ════════════════════════════════════════════════════════════════════════════
// diff — compute element-wise weight difference
// ════════════════════════════════════════════════════════════════════════════

std::vector<float> ConsensusModel::diff(const ConsensusModel& other) const {
    auto w_this = get_weights();
    auto w_other = other.get_weights();

    if (w_this.size() != w_other.size()) {
        return {};  // Dimension mismatch
    }

    std::vector<float> result(w_this.size());
    for (size_t i = 0; i < w_this.size(); i++) {
        result[i] = w_this[i] - w_other[i];
    }
    return result;
}

// ════════════════════════════════════════════════════════════════════════════
// get_layer_stats — per-layer weight statistics
// ════════════════════════════════════════════════════════════════════════════

std::vector<ConsensusModel::LayerStats> ConsensusModel::get_layer_stats() const {
    std::lock_guard<std::mutex> lock(weights_mutex_);

    std::vector<LayerStats> stats;

    auto compute_stats = [](const float* data, size_t n, LayerStats& out) {
        if (n == 0) return;

        double sum = 0.0;
        double sum_sq = 0.0;

        for (size_t i = 0; i < n; i++) {
            double v = static_cast<double>(std::fabs(data[i]));
            sum += v;
            sum_sq += static_cast<double>(data[i]) * static_cast<double>(data[i]);
        }

        out.num_params = n;
        out.mean = sum / static_cast<double>(n);
        out.l2_norm = std::sqrt(sum_sq);

        double variance = (sum_sq / static_cast<double>(n)) - (out.mean * out.mean);
        out.stddev = (variance > 0.0) ? std::sqrt(variance) : 0.0;
    };

    for (uint32_t l = 0; l < static_cast<uint32_t>(layers_.size()); l++) {
        const auto& layer = layers_[l];
        LayerStats ls{};
        ls.layer_index = l;

        // Collect all layer tensor data into one buffer for aggregate stats
        std::vector<float> all_weights;

        auto collect_tensor = [&all_weights](const ggml_tensor* t) {
            if (!t) return;
            int64_t n = ggml_nelements(t);
            const float* data = static_cast<const float*>(t->data);
            all_weights.insert(all_weights.end(), data, data + n);
        };

        collect_tensor(layer.norm1_w);
        collect_tensor(layer.norm2_w);
        collect_tensor(layer.norm3_w);
        collect_tensor(layer.norm4_w);
        collect_tensor(layer.conv3_w);
        collect_tensor(layer.conv7_w);
        collect_tensor(layer.conv15_w);
        collect_tensor(layer.conv_mix_w);
        collect_tensor(layer.gru_wz);
        collect_tensor(layer.gru_wh);
        collect_tensor(layer.gru_bz);
        collect_tensor(layer.gru_bh);
        collect_tensor(layer.slot_keys);
        collect_tensor(layer.slot_values);
        collect_tensor(layer.slot_proj_q);
        collect_tensor(layer.slot_proj_out);
        collect_tensor(layer.ffn_gate_w);
        collect_tensor(layer.ffn_up_w);
        collect_tensor(layer.ffn_down_w);

        compute_stats(all_weights.data(), all_weights.size(), ls);
        stats.push_back(ls);
    }

    return stats;
}

// ════════════════════════════════════════════════════════════════════════════
// memory_usage — total bytes used by the model
// ════════════════════════════════════════════════════════════════════════════

size_t ConsensusModel::memory_usage() const {
    if (!ctx_) return 0;

    size_t total = ggml_used_mem(ctx_);

    // Add metadata overhead
    total += sizeof(ConsensusModel);
    total += layers_.capacity() * sizeof(LayerTensors);

    return total;
}

// ════════════════════════════════════════════════════════════════════════════
// quantize_weights_int8 — compact representation for storage
// ════════════════════════════════════════════════════════════════════════════

std::vector<uint8_t> ConsensusModel::quantize_weights_int8() const {
    std::lock_guard<std::mutex> lock(weights_mutex_);

    std::vector<uint8_t> output;
    auto tensors = weight_tensors();

    for (const auto* tensor : tensors) {
        if (!tensor) continue;

        int64_t n = ggml_nelements(tensor);
        const float* data = static_cast<const float*>(tensor->data);

        // Find min and max for this tensor
        float vmin = data[0];
        float vmax = data[0];
        for (int64_t i = 1; i < n; i++) {
            if (data[i] < vmin) vmin = data[i];
            if (data[i] > vmax) vmax = data[i];
        }

        // Compute scale and zero point for symmetric quantization
        float absmax = std::max(std::fabs(vmin), std::fabs(vmax));
        float scale = (absmax > 0.0f) ? (absmax / 127.0f) : 1.0f;

        // Write scale (4 bytes, float32)
        uint8_t scale_bytes[4];
        std::memcpy(scale_bytes, &scale, 4);
        output.insert(output.end(), scale_bytes, scale_bytes + 4);

        // Write element count (4 bytes LE)
        uint32_t count = static_cast<uint32_t>(n);
        output.push_back(static_cast<uint8_t>(count));
        output.push_back(static_cast<uint8_t>(count >> 8));
        output.push_back(static_cast<uint8_t>(count >> 16));
        output.push_back(static_cast<uint8_t>(count >> 24));

        // Write quantized int8 values
        for (int64_t i = 0; i < n; i++) {
            float val = data[i] / scale;
            int8_t q = static_cast<int8_t>(std::max(-127.0f, std::min(127.0f, std::round(val))));
            output.push_back(static_cast<uint8_t>(q));
        }
    }

    return output;
}

// ════════════════════════════════════════════════════════════════════════════
// load_quantized_int8 — restore from compact representation
// ════════════════════════════════════════════════════════════════════════════

bool ConsensusModel::load_quantized_int8(const std::vector<uint8_t>& quantized) {
    std::lock_guard<std::mutex> lock(weights_mutex_);

    auto tensors = weight_tensors();
    size_t pos = 0;

    for (auto* tensor : tensors) {
        if (!tensor) continue;

        int64_t n = ggml_nelements(tensor);
        float* data = static_cast<float*>(tensor->data);

        // Read scale (4 bytes)
        if (pos + 4 > quantized.size()) return false;
        float scale;
        std::memcpy(&scale, &quantized[pos], 4);
        pos += 4;

        // Read element count (4 bytes LE)
        if (pos + 4 > quantized.size()) return false;
        uint32_t count = static_cast<uint32_t>(quantized[pos])
                       | (static_cast<uint32_t>(quantized[pos + 1]) << 8)
                       | (static_cast<uint32_t>(quantized[pos + 2]) << 16)
                       | (static_cast<uint32_t>(quantized[pos + 3]) << 24);
        pos += 4;

        if (static_cast<int64_t>(count) != n) return false;

        // Read and dequantize int8 values
        if (pos + count > quantized.size()) return false;
        for (uint32_t i = 0; i < count; i++) {
            int8_t q = static_cast<int8_t>(quantized[pos + i]);
            data[i] = static_cast<float>(q) * scale;
        }
        pos += count;
    }

    return true;
}

} // namespace flow

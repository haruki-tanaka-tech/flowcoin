// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// ResonanceNet V5 consensus model implemented in ggml.
// Deterministic: single thread, float32, fixed accumulation order.
// Every conforming node produces identical results for identical inputs.

#ifndef FLOWCOIN_CONSENSUS_MODEL_H
#define FLOWCOIN_CONSENSUS_MODEL_H

#include "params.h"
#include "../util/types.h"
#include <vector>
#include <string>
#include <cstdint>

struct ggml_context;
struct ggml_tensor;

namespace flow {

// The consensus model: ResonanceNet V5 implemented in ggml
// Deterministic: single thread, float32, fixed accumulation order
// Every conforming node produces identical results for identical inputs
class ConsensusModel {
public:
    ConsensusModel();
    ~ConsensusModel();

    // Non-copyable, movable
    ConsensusModel(const ConsensusModel&) = delete;
    ConsensusModel& operator=(const ConsensusModel&) = delete;
    ConsensusModel(ConsensusModel&& other) noexcept;
    ConsensusModel& operator=(ConsensusModel&& other) noexcept;

    // Initialize model with given dimensions, deterministic seed
    // All weights initialized from seed via Keccak-256 PRNG
    bool init(const consensus::ModelDimensions& dims, uint32_t seed);

    // Get current model dimensions
    const consensus::ModelDimensions& dims() const { return dims_; }

    // Get total parameter count
    size_t param_count() const;

    // ════════════════════════════════════════════════════════════
    // Weight management
    // ════════════════════════════════════════════════════════════

    // Serialize all weights to a flat float32 buffer
    std::vector<float> get_weights() const;

    // Load weights from a flat float32 buffer
    bool set_weights(const std::vector<float>& weights);

    // Apply a delta (weight update) from a block
    // delta_weights has same layout as get_weights()
    bool apply_delta(const std::vector<float>& delta_weights);

    // Compute hash of current weights: keccak256(weight_bytes)
    uint256 get_weights_hash() const;

    // ════════════════════════════════════════════════════════════
    // Forward evaluation (consensus-critical, deterministic)
    // ════════════════════════════════════════════════════════════

    // Run forward pass on validation data, compute cross-entropy loss
    // data: byte tokens [EVAL_TOKENS]
    // Returns: average cross-entropy loss (float32)
    // MUST be single-threaded, float32, deterministic
    float forward_eval(const std::vector<uint8_t>& data) const;

    // ════════════════════════════════════════════════════════════
    // Persistence
    // ════════════════════════════════════════════════════════════

    // Save model to file
    bool save_to_file(const std::string& path) const;

    // Load model from file
    bool load_from_file(const std::string& path);

    // ════════════════════════════════════════════════════════════
    // Growth: expand dimensions at plateau transitions
    // ════════════════════════════════════════════════════════════

    // Expand model to new dimensions (zero-pad new weights, copy existing)
    bool expand_to(const consensus::ModelDimensions& new_dims);

private:
    consensus::ModelDimensions dims_{};

    // ggml context for weight storage
    struct ggml_context* ctx_ = nullptr;

    // ─── Model tensors (per-layer) ──────────────────────────────
    // Embedding
    struct ggml_tensor* tok_emb_ = nullptr;      // [vocab, d_model]

    // Per-layer tensors (indexed by layer)
    struct LayerTensors {
        // RMSNorm weights (4 per layer: before conv, gru, slot, ffn)
        ggml_tensor* norm1_w;    // [d_model]
        ggml_tensor* norm2_w;    // [d_model]
        ggml_tensor* norm3_w;    // [d_model]
        ggml_tensor* norm4_w;    // [d_model]

        // Multi-scale causal convolution
        ggml_tensor* conv3_w;    // [3, d_model] depthwise kernel=3
        ggml_tensor* conv7_w;    // [7, d_model] depthwise kernel=7
        ggml_tensor* conv15_w;   // [15, d_model] depthwise kernel=15
        ggml_tensor* conv_mix_w; // [d_model, d_model] mix after sum

        // MinGRU
        ggml_tensor* gru_wz;    // [d_model, d_model] gate weights
        ggml_tensor* gru_wh;    // [d_model, d_model] candidate weights
        ggml_tensor* gru_bz;    // [d_model] gate bias
        ggml_tensor* gru_bh;    // [d_model] candidate bias

        // Slot memory (cross-attention)
        ggml_tensor* slot_keys;    // [d_model, n_slots]
        ggml_tensor* slot_values;  // [d_model, n_slots]
        ggml_tensor* slot_proj_q;  // [d_model, d_model] query projection
        ggml_tensor* slot_proj_out;// [d_model, d_model] output projection

        // SwiGLU FFN
        ggml_tensor* ffn_gate_w; // [d_model, d_ff] gate projection
        ggml_tensor* ffn_up_w;   // [d_model, d_ff] up projection
        ggml_tensor* ffn_down_w; // [d_ff, d_model] down projection
    };

    std::vector<LayerTensors> layers_;

    // Final norm
    ggml_tensor* final_norm_w_ = nullptr;  // [d_model]

    // Helper: allocate ggml context with enough memory for all tensors
    bool allocate_context();

    // Helper: create all tensor objects in the context
    void create_tensors();

    // Helper: initialize weights deterministically from seed
    void init_weights(uint32_t seed);

    // Helper: count params in one layer
    size_t layer_param_count() const;

    // Helper: collect all weight tensors in serialization order
    std::vector<ggml_tensor*> weight_tensors() const;

    // Helper: run forward pass for a single sequence, return logits
    // tokens: [seq_len] byte tokens
    // logits_out: [seq_len * vocab] float32 output
    void forward_sequence(const uint8_t* tokens, int seq_len,
                          float* logits_out) const;
};

// ════════════════════════════════════════════════════════════════
// Validation data generation (deterministic Keccak-256 PRNG)
// ════════════════════════════════════════════════════════════════

// Generate deterministic validation data from seed string
// Uses Keccak-256 in counter mode:
//   block_i = keccak256(seed || i_as_le32)
// Concatenate blocks, take first num_tokens bytes
std::vector<uint8_t> generate_validation_data(
    const std::string& seed_str, size_t num_tokens);

// Default seed for consensus validation
const std::string VALIDATION_SEED = "flowcoin validation dataset v1";

} // namespace flow
#endif // FLOWCOIN_CONSENSUS_MODEL_H

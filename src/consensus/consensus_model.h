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
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

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
    // Text Generation (non-consensus, for model usage)
    // ════════════════════════════════════════════════════════════

    struct GenerationConfig {
        int max_tokens = 1024;
        float temperature = 0.8f;
        int top_k = 40;
        float top_p = 0.95f;
        float repetition_penalty = 1.1f;
        int repetition_window = 64;
        uint64_t seed = 0;
        bool greedy = false;
    };

    struct GenerationResult {
        std::vector<uint8_t> tokens;
        float avg_logprob;
        int64_t generation_time_ms;
        float tokens_per_second;
    };

    GenerationResult generate(const std::vector<uint8_t>& prompt,
                               const GenerationConfig& config) const;

    // ════════════════════════════════════════════════════════════
    // Perplexity evaluation
    // ════════════════════════════════════════════════════════════

    struct PerplexityResult {
        float perplexity;
        float bits_per_byte;
        float cross_entropy;
        int num_tokens;
        int64_t eval_time_ms;
        std::vector<float> per_token_logprobs;
    };

    PerplexityResult evaluate_perplexity(const std::vector<uint8_t>& text) const;

    // ════════════════════════════════════════════════════════════
    // Embedding extraction
    // ════════════════════════════════════════════════════════════

    std::vector<float> get_embedding(const std::vector<uint8_t>& text) const;

    // ════════════════════════════════════════════════════════════
    // Token probabilities
    // ════════════════════════════════════════════════════════════

    std::vector<float> get_next_token_probs(const std::vector<uint8_t>& context) const;

    // ════════════════════════════════════════════════════════════
    // Interactive session
    // ════════════════════════════════════════════════════════════

    class InferenceSession {
    public:
        explicit InferenceSession(const ConsensusModel& model);

        void feed(const std::vector<uint8_t>& tokens);
        std::vector<uint8_t> generate(int n_tokens, const GenerationConfig& config);
        std::vector<float> get_probs();
        void reset();
        std::vector<float> get_state() const;
        void set_state(const std::vector<float>& state);

    private:
        const ConsensusModel& model_;
        std::vector<std::vector<float>> layer_states_;
        bool has_state_ = false;
    };

    // ════════════════════════════════════════════════════════════
    // Persistence
    // ════════════════════════════════════════════════════════════

    // Save model to file
    bool save_to_file(const std::string& path) const;

    // Load model from file
    bool load_from_file(const std::string& path);

    // ════════════════════════════════════════════════════════════
    // Growth: expand dimensions (continuous growth)
    // ════════════════════════════════════════════════════════════

    // Expand model to new dimensions (zero-pad new weights, copy existing)
    bool expand_to(const consensus::ModelDimensions& new_dims);

    // ════════════════════════════════════════════════════════════
    // Architecture validation and introspection
    // ════════════════════════════════════════════════════════════

    /// Validate that all model tensors match the expected dimensions.
    /// Returns true if every tensor has the correct shape for dims_.
    bool validate_architecture() const;

    /// Deep-copy all weights into a new ConsensusModel instance.
    /// The clone is independent: modifying it does not affect the original.
    ConsensusModel clone() const;

    /// Compute the element-wise difference (this - other) of all weights.
    /// Both models must have the same dimensions. Returns the diff as
    /// a flat float32 vector in serialization order.
    std::vector<float> diff(const ConsensusModel& other) const;

    /// Per-layer weight statistics for debugging and monitoring.
    struct LayerStats {
        uint32_t layer_index;
        double mean;        // Mean of absolute weight values
        double stddev;      // Standard deviation
        double l2_norm;     // L2 norm (sqrt of sum of squares)
        size_t num_params;  // Number of parameters in this layer
    };

    /// Get per-layer statistics for all model weights.
    std::vector<LayerStats> get_layer_stats() const;

    /// Get total memory usage of the model (bytes).
    /// Includes ggml context overhead, tensor data, and metadata.
    size_t memory_usage() const;

    /// Quantize weights to int8 for compact storage.
    /// Returns a packed buffer: [scale:float32][zero_point:int8][data:int8*N]
    /// per tensor, where N is the number of elements.
    /// The model weights are NOT modified (read-only operation).
    std::vector<uint8_t> quantize_weights_int8() const;

    /// Load weights from an int8 quantized buffer (reverses quantize_weights_int8).
    bool load_quantized_int8(const std::vector<uint8_t>& quantized);

    // ════════════════════════════════════════════════════════════
    // Training support: expose tensors to GPUMiner
    // ════════════════════════════════════════════════════════════

    /// Get token embedding tensor (lives in model ggml context)
    struct ggml_tensor* get_tok_emb() { return tok_emb_; }

    /// Get final norm weight tensor
    struct ggml_tensor* get_final_norm_w() { return final_norm_w_; }

    /// Per-layer tensor accessors for training graph construction.
    /// These are the same LayerTensors stored internally.
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

    /// Get number of layers
    uint32_t num_layers() const { return dims_.n_layers; }

    /// Get mutable reference to layer tensors for training
    LayerTensors& get_layer(uint32_t i) { return layers_[i]; }
    const LayerTensors& get_layer(uint32_t i) const { return layers_[i]; }

    /// Get all weight tensors in serialization order (public for training)
    std::vector<ggml_tensor*> get_weight_tensors() const { return weight_tensors(); }

private:
    consensus::ModelDimensions dims_{};

    // ggml context for weight storage
    struct ggml_context* ctx_ = nullptr;

    // ─── Model tensors (per-layer) ──────────────────────────────
    // Embedding
    struct ggml_tensor* tok_emb_ = nullptr;      // [vocab, d_model]

    // Per-layer tensors use the public LayerTensors struct
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

    // Thread safety: protects weight modification operations
    mutable std::mutex weights_mutex_;
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

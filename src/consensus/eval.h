// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Deterministic forward evaluation wrapper that connects ConsensusModel
// to block validation. EvalEngine manages the consensus model state and
// provides the EvalFunction callback for check_block()'s Check 15.
//
// Only one EvalEngine may exist per process (singleton pattern via
// set_instance / instance_). This is enforced by the static adapter
// function that check_block() calls.

#ifndef FLOWCOIN_CONSENSUS_EVAL_H
#define FLOWCOIN_CONSENSUS_EVAL_H

#include "consensus_model.h"
#include "params.h"
#include "validation.h"
#include "../util/types.h"

#include <cstdint>
#include <deque>
#include <string>
#include <vector>

namespace flow::consensus {

class EvalEngine {
public:
    EvalEngine();
    ~EvalEngine();

    // Non-copyable, non-movable (singleton semantics)
    EvalEngine(const EvalEngine&) = delete;
    EvalEngine& operator=(const EvalEngine&) = delete;
    EvalEngine(EvalEngine&&) = delete;
    EvalEngine& operator=(EvalEngine&&) = delete;

    // Initialize from genesis (seed=42)
    bool init_genesis();

    // Load from checkpoint file
    bool load_checkpoint(const std::string& path);

    // Save checkpoint
    bool save_checkpoint(const std::string& path) const;

    // Get current model dimensions
    const ModelDimensions& dims() const;

    // Get model weight hash
    uint256 get_model_hash() const;

    // Get parameter count
    size_t param_count() const;

    // Get reference to underlying model (for testing / direct access)
    ConsensusModel& model() { return model_; }
    const ConsensusModel& model() const { return model_; }

    // ═══ Block processing ═══

    // Apply a block's delta to the consensus model
    // 1. Decompress delta_payload (zstd)
    // 2. Deserialize to float32 array
    // 3. Apply delta to model weights
    // Returns false if delta is malformed
    bool apply_block_delta(const std::vector<uint8_t>& compressed_delta);

    // Undo a block's delta (for reorg)
    // Requires stored delta from delta_history_
    bool undo_last_delta();

    // Expand model dimensions (continuous growth)
    bool expand_model(const ModelDimensions& new_dims);

    // ═══ Evaluation (consensus-critical) ═══

    // Evaluate the model with a given delta applied, return val_loss
    // This is Check 15: the most expensive validation step
    // 1. Clone current model weights
    // 2. Decompress delta
    // 3. Apply delta to cloned weights
    // 4. Create temporary ConsensusModel with cloned weights
    // 5. Generate validation data
    // 6. Forward eval on validation data
    // 7. Return cross-entropy loss
    float evaluate_with_delta(const std::vector<uint8_t>& compressed_delta,
                               const uint256& dataset_hash) const;

    // Generate the standard validation dataset
    static std::vector<uint8_t> generate_validation_data();

    // Compute dataset hash for consensus verification
    static uint256 compute_dataset_hash();

    // ═══ EvalFunction adapter for validation.cpp ═══
    // Returns a function pointer compatible with check_block()'s EvalFunction
    // Captures 'this' via static instance_ pointer
    static float eval_function_adapter(const std::vector<uint8_t>& delta,
                                        const uint256& dataset_hash);

    // Set the global eval engine instance
    static void set_instance(EvalEngine* engine);

    // Get the global instance (may be nullptr)
    static EvalEngine* instance();

private:
    ConsensusModel model_;

    // Delta history for undo (circular buffer, last 10 deltas)
    struct DeltaRecord {
        std::vector<float> delta_weights;
        uint64_t height;
    };
    std::deque<DeltaRecord> delta_history_;
    static constexpr size_t MAX_DELTA_HISTORY = 10;

    static EvalEngine* instance_;

    // Decompress a zstd-compressed delta payload into a float32 vector
    // Returns empty vector on failure
    static std::vector<float> decompress_delta(
        const std::vector<uint8_t>& compressed,
        size_t expected_floats);
};

// ═══ Evaluation metrics ═══

/// Compute additional evaluation metrics beyond val_loss.
/// These are not consensus-critical but useful for monitoring.
struct EvalMetrics {
    float val_loss;          // Cross-entropy loss (consensus-critical)
    float perplexity;        // exp(val_loss)
    float bits_per_byte;     // val_loss / ln(2)
    float accuracy_top1;     // Top-1 prediction accuracy
    float accuracy_top5;     // Top-5 prediction accuracy
    size_t total_tokens;     // Number of tokens evaluated
    double eval_time_ms;     // Time taken for evaluation in milliseconds
};

/// Verify that two evaluation results are bit-identical.
/// Used for debugging determinism issues across different hardware.
bool verify_determinism(float loss_a, float loss_b);

// ═══ Extended evaluation functions ═══

/// Compute comprehensive evaluation metrics (non-consensus).
EvalMetrics compute_eval_metrics(const ConsensusModel& model,
                                  const std::vector<uint8_t>& val_data);

/// Human-readable summary of model quality.
std::string model_quality_summary(const EvalMetrics& metrics);

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_EVAL_H

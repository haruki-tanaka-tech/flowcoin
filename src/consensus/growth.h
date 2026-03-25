// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Model growth schedule for ResonanceNet V5.
//
// The model grows CONTINUOUSLY — every block adds parameters.
//
// Dimensions grow linearly then freeze:
//   d_model(h)  = 512 + h           (capped at 1024 when h >= 512)
//   n_layers(h) = 8 + h/32          (capped at 24)
//   d_ff(h)     = 2 * d_model(h)
//   n_heads(h)  = d_model(h) / 64
//   gru_dim(h)  = d_model(h)
//
// Slots grow EVERY block, NO CAP:
//   n_slots(h)  = 1024 + h * 4      (1028 at h=1, 401024 at h=100000)
//
// Inference remains O(1) because only top_k=2 slots are active per token.

#ifndef FLOWCOIN_CONSENSUS_GROWTH_H
#define FLOWCOIN_CONSENSUS_GROWTH_H

#include "params.h"
#include <cstdint>
#include <string>

namespace flow::consensus {

// Compute the model dimensions at a given block height.
//
// Every block grows the model. No phases, no plateaus.
// Dimensions grow linearly then freeze; slots grow forever.
//
// @param height  The block height (0-indexed).
// @return        The ModelDimensions for this height.
ModelDimensions compute_growth(uint64_t height);

// Count parameters for given dimensions.
//
// @param dims  The model dimensions.
// @return      Total number of float32 parameters.
size_t compute_param_count(const ModelDimensions& dims);

// Compute model size in bytes (float32).
//
// @param dims  The model dimensions.
// @return      Total bytes for all model weights.
size_t compute_model_size_bytes(const ModelDimensions& dims);

// Check if dimensions changed between two heights.
// During early blocks (h < 512), dimensions change every block.
// After h >= 512, dimensions are frozen — only slots grow.
//
// @param height_a  First height.
// @param height_b  Second height.
// @return          true if any dimension field differs.
bool dimensions_changed(uint64_t height_a, uint64_t height_b);

// Get human-readable description of the growth state.
//
// @param height  Block height.
// @return        Description string.
std::string describe_growth(uint64_t height);

// Active parameters per token (for inference cost estimation).
// Only top_k=2 slots are active, not all n_slots, so this is O(1).
//
// @param dims  The model dimensions.
// @return      Active parameter count per token.
size_t compute_active_params_per_token(const ModelDimensions& dims);

// Growth rate: approximate params added per block at given height.
//
// @param height  Block height.
// @return        Approximate parameter delta from height to height+1.
size_t compute_growth_rate(uint64_t height);

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_GROWTH_H

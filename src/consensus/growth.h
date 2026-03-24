// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Model growth schedule for ResonanceNet V5.
//
// The model architecture grows in two phases:
//
// Phase 1 (blocks 0-499): Staircase growth across 5 plateaus of 100 blocks.
//   Plateau 0 (  0- 99): d=512,  L=8,   d_ff=1024, heads=8
//   Plateau 1 (100-199): d=640,  L=12,  d_ff=1280, heads=10
//   Plateau 2 (200-299): d=768,  L=16,  d_ff=1536, heads=12
//   Plateau 3 (300-399): d=896,  L=20,  d_ff=1792, heads=14
//   Plateau 4 (400-499): d=1024, L=24,  d_ff=2048, heads=16
//
// Phase 2 (blocks 500+): Architecture is frozen at maximum dimensions.
//   Only n_slots grows: 1024 + improving_blocks * 4, capped at 65536.
//
// Minimum training steps also grow with height to ensure increasingly
// useful work per block as the network matures.

#ifndef FLOWCOIN_CONSENSUS_GROWTH_H
#define FLOWCOIN_CONSENSUS_GROWTH_H

#include "params.h"
#include <cstdint>

namespace flow::consensus {

/// Compute the model dimensions at a given block height.
///
/// @param height            The block height (0-indexed).
/// @param improving_blocks  Number of blocks in Phase 2 that improved val_loss.
///                          Used to grow n_slots. Ignored during Phase 1.
/// @return                  The ModelDimensions for this height.
ModelDimensions compute_growth(uint64_t height, uint32_t improving_blocks);

/// Compute the minimum required training steps for a block at given height.
///
/// Phase 1 (h < 500): Linear ramp from 1000 to 3000 steps.
///   min_steps = 1000 + 4 * h
///   At h=0:   1000 steps
///   At h=499: 2996 steps
///
/// Phase 2 (h >= 500): Square-root growth from 3000 upward.
///   min_steps = 3000 * sqrt(h / 500)
///   At h=500:  3000 steps
///   At h=2000: 6000 steps
///   At h=8000: 12000 steps
///
/// @param height  The block height.
/// @return        Minimum number of SGD training steps required.
uint32_t compute_min_steps(uint64_t height);

/// Check if a height is at a plateau transition boundary.
/// A plateau transition occurs at heights that are multiples of
/// GROWTH_PLATEAU_LEN (100), within Phase 1 (height < DIM_GROWTH_END).
///
/// @param height  The block height to check.
/// @return        true if this height starts a new plateau.
bool is_plateau_transition(uint64_t height);

/// Get the plateau index for a given height.
/// Returns 0 for heights 0-99, 1 for 100-199, etc.
/// For heights >= DIM_GROWTH_END (500), returns NUM_GROWTH_PLATEAUS-1 (4).
///
/// @param height  The block height.
/// @return        Plateau index (0-4).
uint32_t get_plateau(uint64_t height);

/// Check if the architecture dimensions change between two consecutive heights.
/// This is true at plateau transition boundaries within Phase 1.
///
/// @param height  The block height (the child block).
/// @return        true if dims at height differ from dims at height-1.
bool dimensions_change_at(uint64_t height);

/// Compute the total parameter count for a model at the given dimensions.
/// This accounts for all weights across all layers plus embedding and norms.
///
/// @param dims  The model dimensions.
/// @return      Total number of float32 parameters.
size_t compute_param_count(const ModelDimensions& dims);

/// Compute the expected model size in bytes (float32 weights).
///
/// @param dims  The model dimensions.
/// @return      Total bytes for all model weights.
size_t compute_model_size_bytes(const ModelDimensions& dims);

/// Check if a given set of dimensions is valid (matches some height's growth).
/// Returns true if there exists a height where compute_growth() would produce
/// these exact dimensions (ignoring n_slots which varies by improving_blocks).
///
/// @param dims  The dimensions to validate.
/// @return      true if the dimensions correspond to a valid plateau.
bool is_valid_architecture(const ModelDimensions& dims);

/// Get a human-readable description of the growth phase for a height.
/// Returns "Phase 1, Plateau N" or "Phase 2 (frozen architecture)".
///
/// @param height  Block height.
/// @return        Human-readable phase description.
const char* get_growth_phase_name(uint64_t height);

/// Compute the model dimensions delta between two heights.
/// Returns the difference in each dimension field.
/// Useful for determining how much expansion is needed at plateau transitions.
///
/// @param from_height  Starting height.
/// @param to_height    Target height.
/// @return             Dimension differences (to - from).
ModelDimensions compute_growth_delta(uint64_t from_height, uint64_t to_height);

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_GROWTH_H

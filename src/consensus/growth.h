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

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_GROWTH_H

// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Two-phase model growth:
//   Phase 1 (blocks 0-500): grow d_model 512→1024, n_layers 8→24
//   Phase 2 (blocks 500+):  grow experts 1024→65536 (+4 per improving block)

#pragma once

#include <cstdint>

namespace flow::consensus {

struct ModelDimensions {
    uint32_t d_model;
    uint32_t n_layers;
    uint32_t d_ff;
    uint32_t n_experts;
    uint32_t n_heads;
    uint32_t rank;
};

// Compute expected model dimensions at a given height.
// stagnation_count: consecutive blocks without loss improvement.
// improving_blocks: total blocks where val_loss < prev_val_loss.
ModelDimensions compute_growth(uint64_t height, uint32_t improving_blocks);

} // namespace flow::consensus

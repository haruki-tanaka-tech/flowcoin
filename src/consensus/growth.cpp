// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "growth.h"
#include "params.h"

#include <algorithm>

namespace flow::consensus {

ModelDimensions compute_growth(uint64_t height, uint32_t improving_blocks) {
    ModelDimensions dims;

    if (height <= DIM_GROWTH_PHASE) {
        // Phase 1: linear interpolation of d_model, n_layers
        double t = static_cast<double>(height) / DIM_GROWTH_PHASE;

        dims.d_model = static_cast<uint32_t>(
            GENESIS_D_MODEL + t * (MAX_D_MODEL - GENESIS_D_MODEL));
        dims.n_layers = static_cast<uint32_t>(
            GENESIS_N_LAYERS + t * (MAX_N_LAYERS - GENESIS_N_LAYERS));
        dims.n_experts = GENESIS_N_EXPERTS;
        dims.n_heads = GENESIS_N_HEADS;
        dims.rank = GENESIS_RANK;
    } else {
        // Phase 2: dimensions fixed at max, experts grow
        dims.d_model = MAX_D_MODEL;
        dims.n_layers = MAX_N_LAYERS;
        dims.n_heads = GENESIS_N_HEADS;
        dims.rank = GENESIS_RANK;

        // Experts grow by BASE_EXPERT_GROWTH per improving block
        uint32_t expert_growth = improving_blocks * BASE_EXPERT_GROWTH;
        dims.n_experts = std::min(
            GENESIS_N_EXPERTS + expert_growth,
            MAX_N_EXPERTS);
    }

    // d_ff is always 2 * d_model
    dims.d_ff = dims.d_model * 2;

    return dims;
}

} // namespace flow::consensus

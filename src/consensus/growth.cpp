// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "growth.h"
#include "params.h"

#include <algorithm>
#include <cmath>

namespace flow::consensus {

// ---------------------------------------------------------------------------
// Staircase growth tables
// ---------------------------------------------------------------------------
// Pre-computed dimensions for each of the 5 plateaus.
// Derivation:
//   d_model:  512 + plateau * 128  (128 = (1024 - 512) / 4)
//   n_layers: 8   + plateau * 4    (4   = (24 - 8) / 4)
//   d_ff:     1024 + plateau * 256  (256 = (2048 - 1024) / 4)
//   n_heads:  d_model / 64         (d_head is always 64)
//   gru_dim:  d_model              (minGRU state matches hidden dim)

static constexpr uint32_t PLATEAU_D_MODEL[NUM_GROWTH_PLATEAUS]  = { 512,  640,  768,  896,  1024 };
static constexpr uint32_t PLATEAU_N_LAYERS[NUM_GROWTH_PLATEAUS] = {   8,   12,   16,   20,    24 };
static constexpr uint32_t PLATEAU_D_FF[NUM_GROWTH_PLATEAUS]     = { 1024, 1280, 1536, 1792, 2048 };
static constexpr uint32_t PLATEAU_N_HEADS[NUM_GROWTH_PLATEAUS]  = {   8,   10,   12,   14,    16 };

// ---------------------------------------------------------------------------
// compute_growth
// ---------------------------------------------------------------------------

ModelDimensions compute_growth(uint64_t height, uint32_t improving_blocks) {
    ModelDimensions dims{};

    // Invariant parameters (never change across heights)
    dims.d_head      = GENESIS_D_HEAD;       // Always 64
    dims.top_k       = GENESIS_TOP_K;        // Always 2
    dims.conv_kernel = GENESIS_CONV_KERNEL;  // Always 4
    dims.vocab       = GENESIS_VOCAB;        // Always 256 (byte-level)
    dims.seq_len     = GENESIS_SEQ_LEN;      // Always 256

    if (height < DIM_GROWTH_END) {
        // Phase 1: staircase growth within plateaus
        // Plateau index: 0 for blocks 0-99, 1 for 100-199, etc.
        uint32_t plateau = static_cast<uint32_t>(height / GROWTH_PLATEAU_LEN);

        // Clamp to last plateau (defensive; height < 500 guarantees plateau <= 4)
        if (plateau >= NUM_GROWTH_PLATEAUS) {
            plateau = NUM_GROWTH_PLATEAUS - 1;
        }

        dims.d_model  = PLATEAU_D_MODEL[plateau];
        dims.n_layers = PLATEAU_N_LAYERS[plateau];
        dims.d_ff     = PLATEAU_D_FF[plateau];
        dims.n_heads  = PLATEAU_N_HEADS[plateau];
        dims.gru_dim  = dims.d_model;  // minGRU hidden state = d_model

        // Slots are fixed during Phase 1 to avoid instability during arch growth
        dims.n_slots  = GENESIS_N_SLOTS;  // 1024
    } else {
        // Phase 2: architecture frozen at maximum dimensions
        dims.d_model  = MAX_D_MODEL;   // 1024
        dims.n_layers = MAX_N_LAYERS;   // 24
        dims.d_ff     = MAX_D_FF;       // 2048
        dims.n_heads  = MAX_D_MODEL / GENESIS_D_HEAD;  // 1024 / 64 = 16
        dims.gru_dim  = MAX_D_MODEL;   // 1024

        // Slots grow based on how many blocks improved val_loss.
        // Start from GENESIS_N_SLOTS (1024), grow by SLOT_GROWTH_RATE (4) per
        // improving block, capped at MAX_N_SLOTS (65536).
        //
        // Rationale: slot memory should only expand when the model is actually
        // learning (improving loss), not just when blocks are mined.
        uint64_t slot_count = static_cast<uint64_t>(GENESIS_N_SLOTS)
                            + static_cast<uint64_t>(improving_blocks) * SLOT_GROWTH_RATE;

        if (slot_count > MAX_N_SLOTS) {
            slot_count = MAX_N_SLOTS;
        }
        dims.n_slots = static_cast<uint32_t>(slot_count);
    }

    return dims;
}

// ---------------------------------------------------------------------------
// compute_min_steps
// ---------------------------------------------------------------------------

uint32_t compute_min_steps(uint64_t height) {
    if (height < DIM_GROWTH_END) {
        // Phase 1: linear ramp from 1000 to ~3000 steps.
        //
        // Formula: min_steps = MIN_TRAIN_STEPS_BASE * (1 + 2*h/DIM_GROWTH_END)
        //        = 1000 * (1 + 2*h/500)
        //        = 1000 + 4*h
        //
        // At h=0:   1000 + 0    = 1000
        // At h=250: 1000 + 1000 = 2000
        // At h=499: 1000 + 1996 = 2996
        uint32_t steps = MIN_TRAIN_STEPS_BASE
                       + static_cast<uint32_t>((2ULL * MIN_TRAIN_STEPS_BASE * height)
                                               / DIM_GROWTH_END);
        return steps;
    }

    // Phase 2: square-root growth.
    //
    // Formula: min_steps = 3000 * sqrt(h / 500)
    //
    // The 3000 factor is: MIN_TRAIN_STEPS_BASE * 3 (the plateau-end value).
    // This ensures continuity at h=500: 3000 * sqrt(500/500) = 3000.
    //
    // Growth examples:
    //   h=500:   3000 * 1.0    = 3000
    //   h=2000:  3000 * 2.0    = 6000
    //   h=8000:  3000 * 4.0    = 12000
    //   h=32000: 3000 * 8.0    = 24000
    //   h=500000: 3000 * 31.6  = 94868
    double base_at_transition = static_cast<double>(MIN_TRAIN_STEPS_BASE) * 3.0;
    double ratio = static_cast<double>(height) / static_cast<double>(DIM_GROWTH_END);
    double result = base_at_transition * std::sqrt(ratio);

    return static_cast<uint32_t>(result);
}

} // namespace flow::consensus

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

// ---------------------------------------------------------------------------
// is_plateau_transition
// ---------------------------------------------------------------------------

bool is_plateau_transition(uint64_t height) {
    if (height == 0) return false;
    if (height >= DIM_GROWTH_END) return false;
    return (height % GROWTH_PLATEAU_LEN) == 0;
}

// ---------------------------------------------------------------------------
// get_plateau
// ---------------------------------------------------------------------------

uint32_t get_plateau(uint64_t height) {
    if (height >= DIM_GROWTH_END) {
        return NUM_GROWTH_PLATEAUS - 1;
    }
    uint32_t plateau = static_cast<uint32_t>(height / GROWTH_PLATEAU_LEN);
    if (plateau >= NUM_GROWTH_PLATEAUS) {
        plateau = NUM_GROWTH_PLATEAUS - 1;
    }
    return plateau;
}

// ---------------------------------------------------------------------------
// dimensions_change_at
// ---------------------------------------------------------------------------

bool dimensions_change_at(uint64_t height) {
    if (height == 0) return false;
    if (height >= DIM_GROWTH_END) return false;

    // Dimensions change when the plateau index changes
    uint32_t prev_plateau = get_plateau(height - 1);
    uint32_t curr_plateau = get_plateau(height);
    return prev_plateau != curr_plateau;
}

// ---------------------------------------------------------------------------
// compute_param_count
// ---------------------------------------------------------------------------

size_t compute_param_count(const ModelDimensions& dims) {
    size_t d = dims.d_model;
    size_t L = dims.n_layers;
    size_t dff = dims.d_ff;
    size_t nslots = dims.n_slots;
    size_t V = dims.vocab;

    // Embedding: [V, d]
    size_t total = V * d;

    // Per layer:
    size_t per_layer = 0;

    // 4 RMSNorm weights: each [d]
    per_layer += 4 * d;

    // Multi-scale conv: [3,d] + [7,d] + [15,d] + [d,d]
    per_layer += 3 * d + 7 * d + 15 * d + d * d;

    // MinGRU: [d,d] gate + [d,d] candidate + [d] bias_z + [d] bias_h
    per_layer += d * d + d * d + d + d;

    // Slot memory: [d, nslots] keys + [d, nslots] values + [d,d] proj_q + [d,d] proj_out
    per_layer += d * nslots + d * nslots + d * d + d * d;

    // SwiGLU FFN: [d, dff] gate + [d, dff] up + [dff, d] down
    per_layer += d * dff + d * dff + dff * d;

    total += L * per_layer;

    // Final norm: [d]
    total += d;

    return total;
}

// ---------------------------------------------------------------------------
// compute_model_size_bytes
// ---------------------------------------------------------------------------

size_t compute_model_size_bytes(const ModelDimensions& dims) {
    return compute_param_count(dims) * sizeof(float);
}

// ---------------------------------------------------------------------------
// is_valid_architecture
// ---------------------------------------------------------------------------

bool is_valid_architecture(const ModelDimensions& dims) {
    // Check against each plateau's dimensions
    for (uint32_t p = 0; p < NUM_GROWTH_PLATEAUS; p++) {
        ModelDimensions expected = compute_growth(
            static_cast<uint64_t>(p) * GROWTH_PLATEAU_LEN, 0);

        if (dims.d_model  == expected.d_model  &&
            dims.n_layers == expected.n_layers &&
            dims.d_ff     == expected.d_ff     &&
            dims.n_heads  == expected.n_heads  &&
            dims.gru_dim  == expected.gru_dim) {
            return true;
        }
    }

    // Also check Phase 2 dimensions
    ModelDimensions phase2 = compute_growth(DIM_GROWTH_END, 0);
    if (dims.d_model  == phase2.d_model  &&
        dims.n_layers == phase2.n_layers &&
        dims.d_ff     == phase2.d_ff     &&
        dims.n_heads  == phase2.n_heads  &&
        dims.gru_dim  == phase2.gru_dim) {
        return true;
    }

    return false;
}

// ---------------------------------------------------------------------------
// get_growth_phase_name
// ---------------------------------------------------------------------------

const char* get_growth_phase_name(uint64_t height) {
    if (height < DIM_GROWTH_END) {
        uint32_t plateau = get_plateau(height);
        // Static strings for each plateau
        static const char* names[] = {
            "Phase 1, Plateau 0 (d=512, L=8)",
            "Phase 1, Plateau 1 (d=640, L=12)",
            "Phase 1, Plateau 2 (d=768, L=16)",
            "Phase 1, Plateau 3 (d=896, L=20)",
            "Phase 1, Plateau 4 (d=1024, L=24)"
        };
        if (plateau < 5) return names[plateau];
        return "Phase 1, Unknown Plateau";
    }
    return "Phase 2 (frozen architecture, slot growth)";
}

// ---------------------------------------------------------------------------
// compute_growth_delta
// ---------------------------------------------------------------------------

ModelDimensions compute_growth_delta(uint64_t from_height, uint64_t to_height) {
    ModelDimensions from_dims = compute_growth(from_height, 0);
    ModelDimensions to_dims = compute_growth(to_height, 0);

    ModelDimensions delta{};
    delta.d_model  = to_dims.d_model  - from_dims.d_model;
    delta.n_layers = to_dims.n_layers - from_dims.n_layers;
    delta.n_heads  = to_dims.n_heads  - from_dims.n_heads;
    delta.d_head   = to_dims.d_head   - from_dims.d_head;
    delta.d_ff     = to_dims.d_ff     - from_dims.d_ff;
    delta.n_slots  = to_dims.n_slots  - from_dims.n_slots;
    delta.top_k    = to_dims.top_k    - from_dims.top_k;
    delta.gru_dim  = to_dims.gru_dim  - from_dims.gru_dim;
    delta.conv_kernel = to_dims.conv_kernel - from_dims.conv_kernel;
    delta.vocab    = to_dims.vocab    - from_dims.vocab;
    delta.seq_len  = to_dims.seq_len  - from_dims.seq_len;

    return delta;
}

} // namespace flow::consensus

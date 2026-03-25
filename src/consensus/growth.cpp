// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "growth.h"
#include "params.h"

#include <algorithm>
#include <cmath>
#include <sstream>

namespace flow::consensus {

// ---------------------------------------------------------------------------
// compute_growth
// ---------------------------------------------------------------------------

ModelDimensions compute_growth(uint64_t height) {
    ModelDimensions dims{};

    // Dimensions grow linearly, then freeze at max
    uint32_t raw_d = 512 + static_cast<uint32_t>(std::min(height, static_cast<uint64_t>(512)));
    dims.d_model = std::min(raw_d, 1024u);

    // Layers grow 1 per 32 blocks, max 24
    dims.n_layers = std::min(8u + static_cast<uint32_t>(height / 32), 24u);

    // Derived
    dims.d_ff = 2 * dims.d_model;
    dims.n_heads = dims.d_model / 64;  // 8 at 512, 16 at 1024
    dims.gru_dim = dims.d_model;
    dims.d_head = 64;  // always 64

    // Slots grow EVERY block, NO CAP
    dims.n_slots = 1024 + static_cast<uint32_t>(height * 4);

    // Fixed
    dims.top_k = 2;
    dims.conv_kernel = 4;
    dims.vocab = 256;
    dims.seq_len = 256;

    return dims;
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
// dimensions_changed
// ---------------------------------------------------------------------------

bool dimensions_changed(uint64_t height_a, uint64_t height_b) {
    ModelDimensions a = compute_growth(height_a);
    ModelDimensions b = compute_growth(height_b);

    return a.d_model  != b.d_model  ||
           a.n_layers != b.n_layers ||
           a.d_ff     != b.d_ff     ||
           a.n_heads  != b.n_heads  ||
           a.gru_dim  != b.gru_dim  ||
           a.n_slots  != b.n_slots;
}

// ---------------------------------------------------------------------------
// describe_growth
// ---------------------------------------------------------------------------

std::string describe_growth(uint64_t height) {
    ModelDimensions dims = compute_growth(height);
    size_t params = compute_param_count(dims);

    std::ostringstream ss;
    ss << "Block " << height
       << ": d=" << dims.d_model
       << " L=" << dims.n_layers
       << " slots=" << dims.n_slots
       << " params=" << params;

    if (height < DIM_FREEZE_HEIGHT) {
        ss << " (dimensions growing)";
    } else {
        ss << " (dimensions frozen, slots growing)";
    }

    return ss.str();
}

// ---------------------------------------------------------------------------
// compute_active_params_per_token
// ---------------------------------------------------------------------------

size_t compute_active_params_per_token(const ModelDimensions& dims) {
    size_t d = dims.d_model;
    size_t dff = dims.d_ff;

    // Only top_k=2 slots are active, not all n_slots
    size_t per_layer =
        4 * d +                                     // norms
        d * 25 + d * d +                            // conv
        2 * d * d + 2 * d +                         // gru
        dims.top_k * d * 2 + 2 * d * d +            // slot (only top_k)
        3 * d * dff;                                 // ffn

    return dims.n_layers * per_layer + dims.vocab * d;
}

// ---------------------------------------------------------------------------
// compute_growth_rate
// ---------------------------------------------------------------------------

size_t compute_growth_rate(uint64_t height) {
    size_t params_now = compute_param_count(compute_growth(height));
    size_t params_next = compute_param_count(compute_growth(height + 1));

    if (params_next > params_now) {
        return params_next - params_now;
    }
    return 0;
}

} // namespace flow::consensus

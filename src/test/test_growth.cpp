// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "consensus/growth.h"
#include "consensus/params.h"
#include <cassert>
#include <cmath>
#include <stdexcept>

void test_growth() {
    using namespace flow::consensus;

    // Plateau 0: blocks 0-99
    auto d0 = compute_growth(0, 0);
    assert(d0.d_model == 512);
    assert(d0.n_layers == 8);
    assert(d0.d_ff == 1024);
    assert(d0.n_heads == 8);
    assert(d0.gru_dim == 512);
    assert(d0.n_slots == 1024);
    assert(d0.d_head == 64);
    assert(d0.top_k == 2);
    assert(d0.vocab == 256);
    assert(d0.seq_len == 256);
    assert(d0.conv_kernel == 4);

    // Middle of plateau 0
    auto d50 = compute_growth(50, 0);
    assert(d50.d_model == 512);
    assert(d50.n_layers == 8);
    assert(d50.d_ff == 1024);

    // Last block of plateau 0
    auto d99 = compute_growth(99, 0);
    assert(d99.d_model == 512);
    assert(d99.n_layers == 8);

    // Plateau 1: blocks 100-199
    auto d100 = compute_growth(100, 0);
    assert(d100.d_model == 640);
    assert(d100.n_layers == 12);
    assert(d100.d_ff == 1280);
    assert(d100.n_heads == 10);
    assert(d100.gru_dim == 640);
    assert(d100.n_slots == 1024);  // slots fixed in phase 1

    // Plateau 2: blocks 200-299
    auto d200 = compute_growth(200, 0);
    assert(d200.d_model == 768);
    assert(d200.n_layers == 16);
    assert(d200.d_ff == 1536);
    assert(d200.n_heads == 12);

    // Plateau 3: blocks 300-399
    auto d300 = compute_growth(300, 0);
    assert(d300.d_model == 896);
    assert(d300.n_layers == 20);
    assert(d300.d_ff == 1792);
    assert(d300.n_heads == 14);

    // Plateau 4: blocks 400-499
    auto d400 = compute_growth(400, 0);
    assert(d400.d_model == 1024);
    assert(d400.n_layers == 24);
    assert(d400.d_ff == 2048);
    assert(d400.n_heads == 16);
    assert(d400.gru_dim == 1024);

    // Phase 2: blocks 500+, dims frozen at max, slots grow
    auto d500 = compute_growth(500, 0);
    assert(d500.d_model == 1024);
    assert(d500.n_layers == 24);
    assert(d500.d_ff == 2048);
    assert(d500.n_heads == 16);
    assert(d500.gru_dim == 1024);
    assert(d500.n_slots == 1024);  // 0 improving blocks

    // Slot growth: 1024 + improving_blocks * 4
    auto d500_100 = compute_growth(500, 100);
    assert(d500_100.n_slots == 1024 + 100 * 4);  // 1424

    auto d500_1000 = compute_growth(500, 1000);
    assert(d500_1000.n_slots == 1024 + 1000 * 4);  // 5024

    // Slot cap at MAX_N_SLOTS = 65536
    auto d_cap = compute_growth(500, 100000);
    assert(d_cap.n_slots == 65536);

    // Exact boundary: (65536 - 1024) / 4 = 16128 improving blocks to reach cap
    auto d_exact = compute_growth(500, 16128);
    assert(d_exact.n_slots == 65536);

    auto d_below = compute_growth(500, 16127);
    assert(d_below.n_slots == 1024 + 16127 * 4);  // 65532

    // Invariant parameters should be constant across all heights
    for (uint64_t h : {0ULL, 100ULL, 250ULL, 499ULL, 500ULL, 10000ULL}) {
        auto dims = compute_growth(h, 0);
        assert(dims.d_head == 64);
        assert(dims.top_k == 2);
        assert(dims.conv_kernel == 4);
        assert(dims.vocab == 256);
        assert(dims.seq_len == 256);
    }

    // compute_min_steps
    // Phase 1: min_steps = 1000 + 4*h
    assert(compute_min_steps(0) == 1000);
    assert(compute_min_steps(1) == 1004);
    assert(compute_min_steps(250) == 2000);  // 1000 + 4*250

    // Phase 1/Phase 2 boundary
    // At h=499: 1000 + 4*499 = 2996 (but formula is 1000*(1+2*h/500) = 1000+2*1000*499/500)
    // Exact: 1000 + (2*1000*499)/500 = 1000 + 1996 = 2996
    assert(compute_min_steps(499) == 2996);

    // Phase 2: min_steps = 3000 * sqrt(h / 500)
    // At h=500: 3000 * sqrt(1.0) = 3000
    assert(compute_min_steps(500) == 3000);

    // At h=2000: 3000 * sqrt(4.0) = 6000
    assert(compute_min_steps(2000) == 6000);

    // At h=8000: 3000 * sqrt(16.0) = 12000
    assert(compute_min_steps(8000) == 12000);

    // Monotonically non-decreasing
    uint32_t prev = compute_min_steps(0);
    for (uint64_t h = 1; h <= 1000; h += 7) {
        uint32_t cur = compute_min_steps(h);
        assert(cur >= prev);
        prev = cur;
    }
}

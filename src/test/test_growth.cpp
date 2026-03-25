// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "consensus/growth.h"
#include "consensus/params.h"
#include <cassert>
#include <cmath>
#include <stdexcept>

void test_growth() {
    using namespace flow::consensus;

    // ── Block 0: genesis dimensions ──────────────────────────────
    auto d0 = compute_growth(0);
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

    // ── Block 1: dimensions grow immediately ─────────────────────
    auto d1 = compute_growth(1);
    assert(d1.d_model == 513);
    assert(d1.n_layers == 8);   // layers change every 32 blocks
    assert(d1.d_ff == 1026);    // 2 * 513
    assert(d1.n_slots == 1028); // 1024 + 1*4
    assert(d1.n_heads == 8);    // 513 / 64 = 8 (floor)
    assert(d1.gru_dim == 513);

    // ── Block 100: continuous growth ─────────────────────────────
    auto d100 = compute_growth(100);
    assert(d100.d_model == 612);
    assert(d100.n_layers == 11);  // 8 + 100/32 = 8 + 3 = 11
    assert(d100.d_ff == 1224);    // 2 * 612
    assert(d100.n_heads == 9);    // 612 / 64 = 9 (floor)
    assert(d100.n_slots == 1424); // 1024 + 100*4
    assert(d100.gru_dim == 612);

    // ── Block 512: dimensions reach max ──────────────────────────
    auto d512 = compute_growth(512);
    assert(d512.d_model == 1024);
    assert(d512.n_layers == 24);   // 8 + 512/32 = 8 + 16 = 24
    assert(d512.d_ff == 2048);
    assert(d512.n_heads == 16);    // 1024 / 64
    assert(d512.n_slots == 3072);  // 1024 + 512*4
    assert(d512.gru_dim == 1024);

    // ── Block 1000: dimensions frozen, slots keep growing ────────
    auto d1000 = compute_growth(1000);
    assert(d1000.d_model == 1024);
    assert(d1000.n_layers == 24);
    assert(d1000.d_ff == 2048);
    assert(d1000.n_heads == 16);
    assert(d1000.n_slots == 5024);  // 1024 + 1000*4
    assert(d1000.gru_dim == 1024);

    // ── Block 100000: massive slot growth, no cap ────────────────
    auto d100k = compute_growth(100000);
    assert(d100k.d_model == 1024);
    assert(d100k.n_layers == 24);
    assert(d100k.n_slots == 401024); // 1024 + 100000*4

    // ── No cap: slots at block 1M > slots at block 100K ──────────
    auto d1M = compute_growth(1000000);
    assert(d1M.n_slots > d100k.n_slots);
    assert(d1M.n_slots == 4001024);  // 1024 + 1000000*4

    // ── Invariant parameters constant across all heights ─────────
    for (uint64_t h : {0ULL, 1ULL, 100ULL, 512ULL, 1000ULL, 100000ULL}) {
        auto dims = compute_growth(h);
        assert(dims.d_head == 64);
        assert(dims.top_k == 2);
        assert(dims.conv_kernel == 4);
        assert(dims.vocab == 256);
        assert(dims.seq_len == 256);
    }

    // ── compute_active_params_per_token: constant regardless of slots ──
    // Active params should not depend on n_slots (only top_k matters)
    auto active_1000 = compute_active_params_per_token(d1000);
    auto active_100k = compute_active_params_per_token(d100k);
    // Both have same d_model/n_layers/d_ff, so active params are identical
    assert(active_1000 == active_100k);

    // ── compute_growth_rate returns positive for any height ──────
    for (uint64_t h : {0ULL, 1ULL, 100ULL, 512ULL, 1000ULL, 100000ULL}) {
        size_t rate = compute_growth_rate(h);
        assert(rate > 0);
    }

    // ── dimensions_changed: true for early blocks, false after freeze ──
    assert(dimensions_changed(0, 1));      // d_model changes (512 -> 513)
    assert(dimensions_changed(100, 101));  // d_model changes (612 -> 613)
    // After dimension freeze, d_model/n_layers are same but slots differ
    assert(dimensions_changed(1000, 1001)); // slots still change

    // ── compute_min_steps removed (difficulty alone regulates mining) ──

    // ── compute_param_count grows with height ────────────────────
    size_t p0 = compute_param_count(d0);
    size_t p100 = compute_param_count(d100);
    size_t p512 = compute_param_count(d512);
    size_t p1000 = compute_param_count(d1000);
    size_t p100k = compute_param_count(d100k);
    assert(p100 > p0);
    assert(p512 > p100);
    assert(p1000 > p512);
    assert(p100k > p1000);

    // ── describe_growth returns non-empty string ─────────────────
    std::string desc = describe_growth(0);
    assert(!desc.empty());
    std::string desc_frozen = describe_growth(1000);
    assert(!desc_frozen.empty());
}

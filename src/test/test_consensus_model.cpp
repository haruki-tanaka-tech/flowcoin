// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for the ConsensusModel (ResonanceNet V5 ggml implementation).
// Verifies weight init determinism, round-trip serialization, forward
// evaluation, delta application, and model hashing.

#include "consensus/consensus_model.h"
#include "consensus/params.h"
#include "hash/keccak.h"
#include <cassert>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <vector>

// Helper: create genesis model dimensions
static flow::consensus::ModelDimensions genesis_dims() {
    using namespace flow::consensus;
    ModelDimensions dims{};
    dims.d_model     = GENESIS_D_MODEL;
    dims.n_layers    = GENESIS_N_LAYERS;
    dims.n_heads     = GENESIS_N_HEADS;
    dims.d_head      = GENESIS_D_HEAD;
    dims.d_ff        = GENESIS_D_FF;
    dims.n_slots     = GENESIS_N_SLOTS;
    dims.top_k       = GENESIS_TOP_K;
    dims.gru_dim     = GENESIS_GRU_DIM;
    dims.conv_kernel = GENESIS_CONV_KERNEL;
    dims.vocab       = GENESIS_VOCAB;
    dims.seq_len     = GENESIS_SEQ_LEN;
    return dims;
}

void test_consensus_model() {
    using namespace flow;
    using namespace flow::consensus;

    // Test 1: Init with genesis dims, verify param count is positive
    {
        ConsensusModel model;
        auto dims = genesis_dims();
        bool ok = model.init(dims, GENESIS_SEED);
        assert(ok);
        assert(model.param_count() > 0);

        // Verify dimensions are stored correctly
        assert(model.dims().d_model == GENESIS_D_MODEL);
        assert(model.dims().n_layers == GENESIS_N_LAYERS);
        assert(model.dims().d_ff == GENESIS_D_FF);
        assert(model.dims().n_slots == GENESIS_N_SLOTS);
        assert(model.dims().vocab == GENESIS_VOCAB);
    }

    // Test 2: get_weights / set_weights round-trip
    {
        ConsensusModel model;
        auto dims = genesis_dims();
        model.init(dims, GENESIS_SEED);

        // Get weights
        auto weights = model.get_weights();
        assert(weights.size() == model.param_count());

        // Verify weights are finite and not all zero
        bool has_nonzero = false;
        for (size_t i = 0; i < weights.size(); i++) {
            assert(std::isfinite(weights[i]));
            if (weights[i] != 0.0f) has_nonzero = true;
        }
        assert(has_nonzero);

        // Set weights and verify they round-trip
        ConsensusModel model2;
        model2.init(dims, 999);  // Different seed
        bool set_ok = model2.set_weights(weights);
        assert(set_ok);

        auto weights2 = model2.get_weights();
        assert(weights2.size() == weights.size());
        for (size_t i = 0; i < weights.size(); i++) {
            assert(weights2[i] == weights[i]);
        }
    }

    // Test 3: forward_eval produces finite, positive loss
    {
        ConsensusModel model;
        auto dims = genesis_dims();
        model.init(dims, GENESIS_SEED);

        // Generate validation data
        auto val_data = generate_validation_data(VALIDATION_SEED, EVAL_TOKENS);
        assert(val_data.size() == static_cast<size_t>(EVAL_TOKENS));

        // Run forward evaluation
        float loss = model.forward_eval(val_data);
        assert(std::isfinite(loss));
        assert(loss > 0.0f);

        // Loss should be near ln(256) ~ 5.545 for a randomly initialized model
        // Allow a generous range since weights are deterministic but not random
        assert(loss < 100.0f);
    }

    // Test 4: apply_delta changes weights
    {
        ConsensusModel model;
        auto dims = genesis_dims();
        model.init(dims, GENESIS_SEED);

        auto original_weights = model.get_weights();
        auto original_hash = model.get_weights_hash();

        // Create a small delta (mostly zeros with a few non-zero values)
        std::vector<float> delta(model.param_count(), 0.0f);
        delta[0] = 0.1f;
        delta[1] = -0.05f;
        delta[100] = 0.001f;

        bool ok = model.apply_delta(delta);
        assert(ok);

        auto new_weights = model.get_weights();
        auto new_hash = model.get_weights_hash();

        // Weights should have changed at the modified positions
        assert(new_weights[0] != original_weights[0]);
        assert(std::abs(new_weights[0] - original_weights[0] - 0.1f) < 1e-6f);
        assert(std::abs(new_weights[1] - original_weights[1] + 0.05f) < 1e-6f);

        // Hash should have changed
        assert(new_hash != original_hash);
    }

    // Test 5: get_weights_hash changes after apply_delta
    {
        ConsensusModel model;
        auto dims = genesis_dims();
        model.init(dims, GENESIS_SEED);

        auto hash1 = model.get_weights_hash();

        // Apply a delta
        std::vector<float> delta(model.param_count(), 0.0f);
        delta[0] = 1.0f;
        model.apply_delta(delta);

        auto hash2 = model.get_weights_hash();
        assert(hash1 != hash2);

        // Apply the inverse delta to restore
        delta[0] = -1.0f;
        model.apply_delta(delta);

        auto hash3 = model.get_weights_hash();
        // Hash should be identical to original after restoring weights
        assert(hash1 == hash3);
    }

    // Test 6: Two models with same seed produce identical weights
    {
        ConsensusModel model1;
        auto dims = genesis_dims();
        model1.init(dims, GENESIS_SEED);

        ConsensusModel model2;
        model2.init(dims, GENESIS_SEED);

        auto w1 = model1.get_weights();
        auto w2 = model2.get_weights();
        assert(w1.size() == w2.size());

        for (size_t i = 0; i < w1.size(); i++) {
            assert(w1[i] == w2[i]);
        }

        // Weight hashes must also match
        assert(model1.get_weights_hash() == model2.get_weights_hash());
    }

    // Test 7: generate_validation_data is deterministic
    {
        auto data1 = generate_validation_data(VALIDATION_SEED, EVAL_TOKENS);
        auto data2 = generate_validation_data(VALIDATION_SEED, EVAL_TOKENS);

        assert(data1.size() == data2.size());
        assert(data1.size() == static_cast<size_t>(EVAL_TOKENS));
        assert(std::memcmp(data1.data(), data2.data(), data1.size()) == 0);

        // Different seed should produce different data
        auto data3 = generate_validation_data("different seed", EVAL_TOKENS);
        assert(data3.size() == data1.size());
        // Overwhelmingly likely to differ
        bool differs = false;
        for (size_t i = 0; i < data1.size(); i++) {
            if (data1[i] != data3[i]) {
                differs = true;
                break;
            }
        }
        assert(differs);
    }

    // Test 8: Different seeds produce different weights
    {
        ConsensusModel model1;
        auto dims = genesis_dims();
        model1.init(dims, 42);

        ConsensusModel model2;
        model2.init(dims, 43);

        auto w1 = model1.get_weights();
        auto w2 = model2.get_weights();
        assert(w1.size() == w2.size());

        // Should differ somewhere
        bool differs = false;
        for (size_t i = 0; i < w1.size(); i++) {
            if (w1[i] != w2[i]) {
                differs = true;
                break;
            }
        }
        assert(differs);
        assert(model1.get_weights_hash() != model2.get_weights_hash());
    }

    // Test 9: set_weights rejects wrong-size buffer
    {
        ConsensusModel model;
        auto dims = genesis_dims();
        model.init(dims, GENESIS_SEED);

        // Too short
        std::vector<float> short_weights(10, 0.0f);
        bool ok = model.set_weights(short_weights);
        assert(!ok);

        // Too long
        std::vector<float> long_weights(model.param_count() + 100, 0.0f);
        ok = model.set_weights(long_weights);
        assert(!ok);
    }

    // Test 10: apply_delta rejects wrong-size buffer
    {
        ConsensusModel model;
        auto dims = genesis_dims();
        model.init(dims, GENESIS_SEED);

        std::vector<float> bad_delta(10, 0.0f);
        bool ok = model.apply_delta(bad_delta);
        assert(!ok);
    }

    // Test 11: Forward eval is deterministic (same model + same data = same loss)
    {
        ConsensusModel model;
        auto dims = genesis_dims();
        model.init(dims, GENESIS_SEED);

        auto val_data = generate_validation_data(VALIDATION_SEED, EVAL_TOKENS);

        float loss1 = model.forward_eval(val_data);
        float loss2 = model.forward_eval(val_data);
        // Bit-identical because we use deterministic single-thread float32
        assert(loss1 == loss2);
    }

    // Test 12: Move semantics
    {
        ConsensusModel model1;
        auto dims = genesis_dims();
        model1.init(dims, GENESIS_SEED);
        auto hash1 = model1.get_weights_hash();
        size_t params1 = model1.param_count();

        // Move construct
        ConsensusModel model2(std::move(model1));
        assert(model2.param_count() == params1);
        assert(model2.get_weights_hash() == hash1);
    }
}

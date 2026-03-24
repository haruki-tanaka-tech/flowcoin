// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for the EvalEngine: consensus model state management,
// delta application/undo, and deterministic evaluation.

#include "consensus/eval.h"
#include "consensus/consensus_model.h"
#include "consensus/params.h"
#include "primitives/delta.h"
#include "hash/keccak.h"
#include <cassert>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <vector>

void test_eval_engine() {
    using namespace flow;
    using namespace flow::consensus;

    // Test 1: init_genesis creates model with correct dimensions
    {
        EvalEngine engine;
        bool ok = engine.init_genesis();
        assert(ok);

        auto& dims = engine.dims();
        assert(dims.d_model == GENESIS_D_MODEL);
        assert(dims.n_layers == GENESIS_N_LAYERS);
        assert(dims.d_ff == GENESIS_D_FF);
        assert(dims.n_slots == GENESIS_N_SLOTS);
        assert(dims.vocab == GENESIS_VOCAB);

        assert(engine.param_count() > 0);

        // Model hash should be non-null
        auto hash = engine.get_model_hash();
        assert(!hash.is_null());
    }

    // Test 2: evaluate_with_delta returns finite loss
    {
        EvalEngine engine;
        engine.init_genesis();

        // Create a minimal delta: all zeros means no weight change
        size_t num_floats = engine.param_count();
        std::vector<float> delta_floats(num_floats, 0.0f);
        // Add a tiny perturbation to make it a real delta
        if (num_floats > 0) {
            delta_floats[0] = 0.001f;
        }

        // Serialize to bytes
        std::vector<uint8_t> delta_bytes(num_floats * sizeof(float));
        std::memcpy(delta_bytes.data(), delta_floats.data(),
                     num_floats * sizeof(float));

        // Compress with zstd
        auto compressed = flow::compress_delta(delta_bytes);
        assert(!compressed.empty());

        // Compute dataset hash
        auto dataset_hash = EvalEngine::compute_dataset_hash();
        assert(!dataset_hash.is_null());

        // Evaluate
        float loss = engine.evaluate_with_delta(compressed, dataset_hash);
        assert(std::isfinite(loss));
        assert(loss > 0.0f);
        assert(loss < MAX_VAL_LOSS);
    }

    // Test 3: apply_block_delta changes model hash
    {
        EvalEngine engine;
        engine.init_genesis();

        auto hash_before = engine.get_model_hash();

        // Create a delta with some non-zero values
        size_t num_floats = engine.param_count();
        std::vector<float> delta_floats(num_floats, 0.0f);
        delta_floats[0] = 0.01f;
        delta_floats[1] = -0.005f;

        std::vector<uint8_t> delta_bytes(num_floats * sizeof(float));
        std::memcpy(delta_bytes.data(), delta_floats.data(),
                     num_floats * sizeof(float));

        auto compressed = flow::compress_delta(delta_bytes);

        bool ok = engine.apply_block_delta(compressed);
        assert(ok);

        auto hash_after = engine.get_model_hash();
        assert(hash_before != hash_after);
    }

    // Test 4: undo_last_delta restores previous hash
    {
        EvalEngine engine;
        engine.init_genesis();

        auto hash_original = engine.get_model_hash();

        // Apply a delta
        size_t num_floats = engine.param_count();
        std::vector<float> delta_floats(num_floats, 0.0f);
        delta_floats[0] = 0.1f;
        delta_floats[50] = -0.05f;

        std::vector<uint8_t> delta_bytes(num_floats * sizeof(float));
        std::memcpy(delta_bytes.data(), delta_floats.data(),
                     num_floats * sizeof(float));

        auto compressed = flow::compress_delta(delta_bytes);
        engine.apply_block_delta(compressed);

        auto hash_after = engine.get_model_hash();
        assert(hash_original != hash_after);

        // Undo should restore original hash
        bool ok = engine.undo_last_delta();
        assert(ok);

        auto hash_restored = engine.get_model_hash();
        assert(hash_restored == hash_original);
    }

    // Test 5: compute_dataset_hash is deterministic
    {
        auto hash1 = EvalEngine::compute_dataset_hash();
        auto hash2 = EvalEngine::compute_dataset_hash();
        assert(hash1 == hash2);
        assert(!hash1.is_null());
    }

    // Test 6: generate_validation_data is deterministic
    {
        auto data1 = EvalEngine::generate_validation_data();
        auto data2 = EvalEngine::generate_validation_data();
        assert(data1.size() == data2.size());
        assert(data1.size() == static_cast<size_t>(EVAL_TOKENS));
        assert(std::memcmp(data1.data(), data2.data(), data1.size()) == 0);
    }

    // Test 7: undo_last_delta on fresh engine returns false (no history)
    {
        EvalEngine engine;
        engine.init_genesis();

        bool ok = engine.undo_last_delta();
        assert(!ok);
    }

    // Test 8: Multiple apply + undo cycles
    {
        EvalEngine engine;
        engine.init_genesis();

        auto hash0 = engine.get_model_hash();
        size_t num_floats = engine.param_count();

        // Apply delta 1
        std::vector<float> d1(num_floats, 0.0f);
        d1[0] = 0.1f;
        std::vector<uint8_t> d1_bytes(num_floats * sizeof(float));
        std::memcpy(d1_bytes.data(), d1.data(), num_floats * sizeof(float));
        engine.apply_block_delta(flow::compress_delta(d1_bytes));
        auto hash1 = engine.get_model_hash();

        // Apply delta 2
        std::vector<float> d2(num_floats, 0.0f);
        d2[1] = -0.2f;
        std::vector<uint8_t> d2_bytes(num_floats * sizeof(float));
        std::memcpy(d2_bytes.data(), d2.data(), num_floats * sizeof(float));
        engine.apply_block_delta(flow::compress_delta(d2_bytes));
        auto hash2 = engine.get_model_hash();

        // All three hashes should differ
        assert(hash0 != hash1);
        assert(hash1 != hash2);
        assert(hash0 != hash2);

        // Undo delta 2 -> back to hash1
        engine.undo_last_delta();
        assert(engine.get_model_hash() == hash1);

        // Undo delta 1 -> back to hash0
        engine.undo_last_delta();
        assert(engine.get_model_hash() == hash0);
    }

    // Test 9: apply_block_delta rejects corrupt data
    {
        EvalEngine engine;
        engine.init_genesis();

        auto hash_before = engine.get_model_hash();

        // Corrupt compressed data
        std::vector<uint8_t> garbage = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB};
        bool ok = engine.apply_block_delta(garbage);
        assert(!ok);

        // Model should be unchanged
        assert(engine.get_model_hash() == hash_before);
    }

    // Test 10: Singleton management
    {
        EvalEngine engine;
        engine.init_genesis();

        EvalEngine::set_instance(&engine);
        assert(EvalEngine::instance() == &engine);

        EvalEngine::set_instance(nullptr);
        assert(EvalEngine::instance() == nullptr);
    }
}

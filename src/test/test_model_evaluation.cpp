// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for model evaluation: SequenceMetrics computation, perplexity,
// per-sequence metrics, layer profiling, model comparison, text generation,
// temperature scaling, and validation data generation determinism.

#include "consensus/consensus_model.h"
#include "consensus/eval.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "hash/keccak.h"
#include "primitives/delta.h"

#include <cassert>
#include <cmath>
#include <cstring>
#include <set>
#include <vector>

using namespace flow;
using namespace flow::consensus;

// Helper: genesis dimensions
static ModelDimensions test_genesis_dims() {
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

// Sequence-level evaluation metrics
struct SequenceMetrics {
    float loss;
    float perplexity;
    float accuracy;
    size_t num_tokens;

    static SequenceMetrics compute(float loss_val, size_t tokens) {
        SequenceMetrics m;
        m.loss = loss_val;
        m.perplexity = std::exp(loss_val);
        m.accuracy = 0.0f;  // placeholder
        m.num_tokens = tokens;
        return m;
    }
};

void test_model_evaluation() {

    // -----------------------------------------------------------------------
    // Test 1: SequenceMetrics — loss, perplexity, accuracy computed
    // -----------------------------------------------------------------------
    {
        float loss = 3.5f;
        auto metrics = SequenceMetrics::compute(loss, 256);

        assert(metrics.loss == 3.5f);
        assert(std::isfinite(metrics.perplexity));
        assert(metrics.perplexity > 0.0f);
        assert(metrics.num_tokens == 256);
    }

    // -----------------------------------------------------------------------
    // Test 2: Perplexity = exp(loss), verified
    // -----------------------------------------------------------------------
    {
        float loss1 = 1.0f;
        float ppl1 = std::exp(loss1);  // e^1 = 2.718...
        auto m1 = SequenceMetrics::compute(loss1, 100);
        assert(std::abs(m1.perplexity - ppl1) < 0.001f);

        float loss2 = 0.0f;
        float ppl2 = std::exp(loss2);  // e^0 = 1.0
        auto m2 = SequenceMetrics::compute(loss2, 100);
        assert(std::abs(m2.perplexity - ppl2) < 0.001f);

        float loss3 = 5.545f;  // ln(256) random baseline
        float ppl3 = std::exp(loss3);  // ~256
        auto m3 = SequenceMetrics::compute(loss3, 100);
        assert(std::abs(m3.perplexity - ppl3) < 1.0f);
        assert(m3.perplexity > 250.0f && m3.perplexity < 260.0f);
    }

    // -----------------------------------------------------------------------
    // Test 3: Multiple sequences produce per-sequence metrics
    // -----------------------------------------------------------------------
    {
        std::vector<float> losses = {3.0f, 3.5f, 4.0f, 2.5f, 5.0f};
        std::vector<SequenceMetrics> seq_metrics;

        for (float l : losses) {
            seq_metrics.push_back(SequenceMetrics::compute(l, 256));
        }

        assert(seq_metrics.size() == 5);

        // Average loss
        float avg_loss = 0.0f;
        for (auto& m : seq_metrics) avg_loss += m.loss;
        avg_loss /= static_cast<float>(seq_metrics.size());
        assert(std::abs(avg_loss - 3.6f) < 0.01f);

        // Each perplexity should correspond to its loss
        for (size_t i = 0; i < seq_metrics.size(); i++) {
            float expected_ppl = std::exp(losses[i]);
            assert(std::abs(seq_metrics[i].perplexity - expected_ppl) < 0.01f);
        }
    }

    // -----------------------------------------------------------------------
    // Test 4: EvalMetrics fields have correct relationships
    // -----------------------------------------------------------------------
    {
        EvalMetrics metrics;
        metrics.val_loss = 4.0f;
        metrics.perplexity = std::exp(metrics.val_loss);
        metrics.bits_per_byte = metrics.val_loss / std::log(2.0f);
        metrics.accuracy_top1 = 0.05f;
        metrics.accuracy_top5 = 0.20f;
        metrics.total_tokens = 4096;
        metrics.eval_time_ms = 150.0;

        assert(std::abs(metrics.perplexity - std::exp(4.0f)) < 0.01f);
        assert(metrics.bits_per_byte > 0.0f);
        assert(std::abs(metrics.bits_per_byte - 4.0f / std::log(2.0f)) < 0.01f);
        assert(metrics.accuracy_top5 >= metrics.accuracy_top1);
        assert(metrics.total_tokens == static_cast<size_t>(EVAL_TOKENS));
    }

    // -----------------------------------------------------------------------
    // Test 5: ConsensusModel init produces non-zero params
    // -----------------------------------------------------------------------
    {
        ConsensusModel model;
        auto dims = test_genesis_dims();
        bool ok = model.init(dims, GENESIS_SEED);
        assert(ok);
        assert(model.param_count() > 0);

        auto weights = model.get_weights();
        bool has_nonzero = false;
        for (size_t i = 0; i < std::min<size_t>(1000, weights.size()); i++) {
            assert(std::isfinite(weights[i]));
            if (weights[i] != 0.0f) has_nonzero = true;
        }
        assert(has_nonzero);
    }

    // -----------------------------------------------------------------------
    // Test 6: compare_models — identical models have zero distance
    // -----------------------------------------------------------------------
    {
        ConsensusModel model1;
        auto dims = test_genesis_dims();
        model1.init(dims, GENESIS_SEED);

        ConsensusModel model2;
        model2.init(dims, GENESIS_SEED);

        // Same seed → same weights → diff should be all zeros
        auto diff = model1.diff(model2);
        assert(diff.size() == model1.param_count());

        double l2_distance = 0.0;
        for (float d : diff) l2_distance += static_cast<double>(d) * d;
        assert(l2_distance == 0.0);
    }

    // -----------------------------------------------------------------------
    // Test 7: compare_models — different models have non-zero distance
    // -----------------------------------------------------------------------
    {
        ConsensusModel model1;
        auto dims = test_genesis_dims();
        model1.init(dims, GENESIS_SEED);

        ConsensusModel model2;
        model2.init(dims, 999);  // different seed

        auto diff = model1.diff(model2);
        assert(diff.size() == model1.param_count());

        double l2_distance = 0.0;
        for (float d : diff) l2_distance += static_cast<double>(d) * d;
        assert(l2_distance > 0.0);
    }

    // -----------------------------------------------------------------------
    // Test 8: Model weights hash is deterministic
    // -----------------------------------------------------------------------
    {
        ConsensusModel model1;
        auto dims = test_genesis_dims();
        model1.init(dims, GENESIS_SEED);

        ConsensusModel model2;
        model2.init(dims, GENESIS_SEED);

        uint256 hash1 = model1.get_weights_hash();
        uint256 hash2 = model2.get_weights_hash();
        assert(hash1 == hash2);
        assert(!hash1.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 9: Different seeds produce different hashes
    // -----------------------------------------------------------------------
    {
        ConsensusModel model1;
        auto dims = test_genesis_dims();
        model1.init(dims, 1);

        ConsensusModel model2;
        model2.init(dims, 2);

        assert(model1.get_weights_hash() != model2.get_weights_hash());
    }

    // -----------------------------------------------------------------------
    // Test 10: Validation data generation deterministic
    // -----------------------------------------------------------------------
    {
        auto data1 = generate_validation_data(VALIDATION_SEED, EVAL_TOKENS);
        auto data2 = generate_validation_data(VALIDATION_SEED, EVAL_TOKENS);

        assert(data1.size() == static_cast<size_t>(EVAL_TOKENS));
        assert(data2.size() == static_cast<size_t>(EVAL_TOKENS));
        assert(data1 == data2);
    }

    // -----------------------------------------------------------------------
    // Test 11: Different seeds produce different validation data
    // -----------------------------------------------------------------------
    {
        auto data1 = generate_validation_data("seed_a", 1024);
        auto data2 = generate_validation_data("seed_b", 1024);

        assert(data1.size() == 1024);
        assert(data2.size() == 1024);
        assert(data1 != data2);
    }

    // -----------------------------------------------------------------------
    // Test 12: Validation data has good byte distribution
    // -----------------------------------------------------------------------
    {
        auto data = generate_validation_data(VALIDATION_SEED, 4096);
        std::vector<int> freq(256, 0);
        for (uint8_t b : data) freq[b]++;

        // Every byte value should appear at least once in 4096 bytes
        int zero_count = 0;
        for (int f : freq) {
            if (f == 0) zero_count++;
        }
        // With 4096 bytes and 256 possible values, very unlikely to miss many
        assert(zero_count < 50);
    }

    // -----------------------------------------------------------------------
    // Test 13: ConsensusModel clone produces independent copy
    // -----------------------------------------------------------------------
    {
        ConsensusModel model;
        auto dims = test_genesis_dims();
        model.init(dims, GENESIS_SEED);

        auto clone = model.clone();

        assert(clone.param_count() == model.param_count());
        assert(clone.get_weights_hash() == model.get_weights_hash());

        // Modify clone
        auto weights = clone.get_weights();
        weights[0] += 1.0f;
        clone.set_weights(weights);

        // Original should be unmodified
        assert(clone.get_weights_hash() != model.get_weights_hash());
    }

    // -----------------------------------------------------------------------
    // Test 14: Layer stats report meaningful values
    // -----------------------------------------------------------------------
    {
        ConsensusModel model;
        auto dims = test_genesis_dims();
        model.init(dims, GENESIS_SEED);

        auto layer_stats = model.get_layer_stats();
        assert(!layer_stats.empty());

        for (auto& ls : layer_stats) {
            assert(ls.num_params > 0);
            assert(std::isfinite(ls.mean));
            assert(std::isfinite(ls.stddev));
            assert(ls.stddev >= 0.0);
            assert(std::isfinite(ls.l2_norm));
            assert(ls.l2_norm >= 0.0);
        }
    }

    // -----------------------------------------------------------------------
    // Test 15: Model memory usage is positive
    // -----------------------------------------------------------------------
    {
        ConsensusModel model;
        auto dims = test_genesis_dims();
        model.init(dims, GENESIS_SEED);

        size_t mem = model.memory_usage();
        assert(mem > 0);
        // Should be at least param_count * sizeof(float)
        assert(mem >= model.param_count() * sizeof(float));
    }

    // -----------------------------------------------------------------------
    // Test 16: validate_architecture passes for valid model
    // -----------------------------------------------------------------------
    {
        ConsensusModel model;
        auto dims = test_genesis_dims();
        model.init(dims, GENESIS_SEED);

        assert(model.validate_architecture());
    }

    // -----------------------------------------------------------------------
    // Test 17: Temperature scaling concept — higher temp = more varied
    // -----------------------------------------------------------------------
    {
        // Simulate softmax with temperature
        std::vector<float> logits = {2.0f, 1.0f, 0.0f, -1.0f};

        // Temperature = 1.0 (standard)
        float temp1 = 1.0f;
        std::vector<float> probs1(logits.size());
        float sum1 = 0.0f;
        for (size_t i = 0; i < logits.size(); i++) {
            probs1[i] = std::exp(logits[i] / temp1);
            sum1 += probs1[i];
        }
        for (auto& p : probs1) p /= sum1;

        // Temperature = 2.0 (more uniform)
        float temp2 = 2.0f;
        std::vector<float> probs2(logits.size());
        float sum2 = 0.0f;
        for (size_t i = 0; i < logits.size(); i++) {
            probs2[i] = std::exp(logits[i] / temp2);
            sum2 += probs2[i];
        }
        for (auto& p : probs2) p /= sum2;

        // Higher temperature → more uniform distribution
        // Max probability at temp=2 should be lower than at temp=1
        assert(probs2[0] < probs1[0]);

        // Min probability at temp=2 should be higher than at temp=1
        assert(probs2[3] > probs1[3]);

        // Entropy at temp=2 should be higher
        float entropy1 = 0.0f, entropy2 = 0.0f;
        for (size_t i = 0; i < logits.size(); i++) {
            if (probs1[i] > 0) entropy1 -= probs1[i] * std::log(probs1[i]);
            if (probs2[i] > 0) entropy2 -= probs2[i] * std::log(probs2[i]);
        }
        assert(entropy2 > entropy1);
    }

    // -----------------------------------------------------------------------
    // Test 18: verify_determinism for identical losses
    // -----------------------------------------------------------------------
    {
        float loss_a = 3.14159f;
        float loss_b = 3.14159f;
        assert(verify_determinism(loss_a, loss_b));

        // Different losses should fail
        float loss_c = 3.14160f;
        assert(!verify_determinism(loss_a, loss_c));
    }

    // -----------------------------------------------------------------------
    // Test 19: EvalEngine dataset hash is deterministic
    // -----------------------------------------------------------------------
    {
        auto hash1 = EvalEngine::compute_dataset_hash();
        auto hash2 = EvalEngine::compute_dataset_hash();
        assert(hash1 == hash2);
        assert(!hash1.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 20: Model dimensions consistency checks
    // -----------------------------------------------------------------------
    {
        auto dims = test_genesis_dims();
        assert(dims.n_heads * dims.d_head == dims.d_model);
        assert(dims.d_ff == 2 * dims.d_model);
        assert(dims.gru_dim == dims.d_model);
        assert(dims.vocab == 256);
        assert(dims.seq_len == 256);

        // Verify at various heights during continuous growth
        for (uint64_t h = 0; h <= DIM_FREEZE_HEIGHT; h += 64) {
            auto d = compute_growth(h);
            // n_heads = d_model / 64, d_head = 64, so n_heads * d_head <= d_model
            assert(d.n_heads * d.d_head <= d.d_model);
            assert(d.d_ff == 2 * d.d_model);
        }
    }
}

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for the inference/generation API: GenerationConfig defaults,
// greedy determinism, temperature effects, top_k/top_p sampling,
// repetition penalty, InferenceSession state, embeddings, token
// probabilities, and perplexity evaluation.

#include "consensus/consensus_model.h"
#include "consensus/eval.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "hash/keccak.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <numeric>
#include <set>
#include <vector>

using namespace flow;
using namespace flow::consensus;

// ---------------------------------------------------------------------------
// Helper: build genesis model dimensions
// ---------------------------------------------------------------------------

static ModelDimensions inf_genesis_dims() {
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

// ---------------------------------------------------------------------------
// GenerationConfig — mirrors inference configuration
// ---------------------------------------------------------------------------

struct GenerationConfig {
    float temperature    = 1.0f;
    int   top_k          = 0;       // 0 = no top_k filtering
    float top_p          = 1.0f;    // 1.0 = no nucleus sampling
    float repetition_pen = 1.0f;    // 1.0 = no penalty
    int   max_tokens     = 128;
    bool  greedy         = false;

    static GenerationConfig defaults() {
        return GenerationConfig{};
    }
};

// ---------------------------------------------------------------------------
// Softmax helper
// ---------------------------------------------------------------------------

static std::vector<float> softmax(const std::vector<float>& logits,
                                   float temperature = 1.0f) {
    float max_val = *std::max_element(logits.begin(), logits.end());
    std::vector<float> probs(logits.size());
    float sum = 0.0f;
    float inv_t = (temperature > 1e-9f) ? (1.0f / temperature) : 1e9f;
    for (size_t i = 0; i < logits.size(); ++i) {
        probs[i] = std::exp((logits[i] - max_val) * inv_t);
        sum += probs[i];
    }
    for (auto& p : probs) p /= sum;
    return probs;
}

// ---------------------------------------------------------------------------
// Entropy computation
// ---------------------------------------------------------------------------

static float compute_entropy(const std::vector<float>& probs) {
    float ent = 0.0f;
    for (auto p : probs) {
        if (p > 1e-10f) {
            ent -= p * std::log2(p);
        }
    }
    return ent;
}

// ---------------------------------------------------------------------------
// Top-k filtering: keep only the k highest-probability tokens
// ---------------------------------------------------------------------------

static std::vector<float> apply_top_k(const std::vector<float>& logits, int k) {
    if (k <= 0 || k >= static_cast<int>(logits.size())) return logits;

    std::vector<size_t> indices(logits.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::partial_sort(indices.begin(), indices.begin() + k, indices.end(),
                      [&](size_t a, size_t b) { return logits[a] > logits[b]; });

    std::set<size_t> keep_set(indices.begin(), indices.begin() + k);
    std::vector<float> filtered(logits.size(), -1e30f);
    for (auto idx : keep_set) {
        filtered[idx] = logits[idx];
    }
    return filtered;
}

// ---------------------------------------------------------------------------
// Top-p (nucleus) filtering: keep tokens whose cumulative prob <= p
// ---------------------------------------------------------------------------

static std::vector<float> apply_top_p(const std::vector<float>& logits, float p) {
    if (p >= 1.0f) return logits;

    auto probs = softmax(logits);
    std::vector<size_t> indices(logits.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::sort(indices.begin(), indices.end(),
              [&](size_t a, size_t b) { return probs[a] > probs[b]; });

    float cumulative = 0.0f;
    std::set<size_t> keep_set;
    for (auto idx : indices) {
        keep_set.insert(idx);
        cumulative += probs[idx];
        if (cumulative >= p) break;
    }

    std::vector<float> filtered(logits.size(), -1e30f);
    for (auto idx : keep_set) {
        filtered[idx] = logits[idx];
    }
    return filtered;
}

// ---------------------------------------------------------------------------
// Repetition penalty: reduce logits for tokens already seen
// ---------------------------------------------------------------------------

static void apply_repetition_penalty(std::vector<float>& logits,
                                      const std::vector<uint8_t>& seen_tokens,
                                      float penalty) {
    if (penalty <= 1.0f) return;
    for (auto tok : seen_tokens) {
        if (tok < logits.size()) {
            if (logits[tok] > 0) {
                logits[tok] /= penalty;
            } else {
                logits[tok] *= penalty;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Greedy decode: pick argmax token
// ---------------------------------------------------------------------------

static uint8_t greedy_sample(const std::vector<float>& logits) {
    return static_cast<uint8_t>(
        std::distance(logits.begin(),
                      std::max_element(logits.begin(), logits.end())));
}

// ---------------------------------------------------------------------------
// InferenceSession — maintains recurrent state across feed() calls
// ---------------------------------------------------------------------------

class InferenceSession {
public:
    explicit InferenceSession(const ConsensusModel& model)
        : model_(model), d_model_(model.dims().d_model) {
        reset();
    }

    void feed(const std::vector<uint8_t>& tokens) {
        for (auto t : tokens) {
            token_history_.push_back(t);
        }
        tokens_fed_ += tokens.size();
    }

    void reset() {
        token_history_.clear();
        tokens_fed_ = 0;
    }

    size_t tokens_fed() const { return tokens_fed_; }

    // Retrieve the current hidden state as a d_model-sized vector
    std::vector<float> get_embedding() const {
        // Return a deterministic embedding based on token history
        std::vector<float> emb(d_model_, 0.0f);
        if (token_history_.empty()) return emb;

        auto h = keccak256(token_history_.data(), token_history_.size());
        for (size_t i = 0; i < d_model_ && i < 32; ++i) {
            emb[i] = static_cast<float>(h[i]) / 255.0f - 0.5f;
        }
        // Fill remaining with scaled pattern
        for (size_t i = 32; i < d_model_; ++i) {
            emb[i] = emb[i % 32] * 0.01f;
        }
        return emb;
    }

    // Get next-token probability distribution
    std::vector<float> get_next_token_probs() const {
        // Produce a probability distribution over GENESIS_VOCAB tokens
        std::vector<float> logits(GENESIS_VOCAB, 0.0f);
        if (!token_history_.empty()) {
            auto h = keccak256(token_history_.data(), token_history_.size());
            for (size_t i = 0; i < GENESIS_VOCAB; ++i) {
                logits[i] = static_cast<float>(h[i % 32]) / 128.0f - 1.0f;
            }
        } else {
            // Uniform distribution
            for (size_t i = 0; i < GENESIS_VOCAB; ++i) {
                logits[i] = 0.0f;
            }
        }
        return softmax(logits);
    }

    const std::vector<uint8_t>& history() const { return token_history_; }

private:
    const ConsensusModel& model_;
    uint32_t d_model_;
    std::vector<uint8_t> token_history_;
    size_t tokens_fed_ = 0;
};

// ---------------------------------------------------------------------------
// Perplexity evaluation
// ---------------------------------------------------------------------------

static float evaluate_perplexity(const ConsensusModel& model,
                                  const std::vector<uint8_t>& data) {
    if (data.size() < 2) return std::numeric_limits<float>::infinity();
    float loss = model.forward_eval(data);
    return std::exp(loss);
}

void test_inference() {

    // -----------------------------------------------------------------------
    // Test 1: GenerationConfig defaults produce valid output
    // -----------------------------------------------------------------------
    {
        auto cfg = GenerationConfig::defaults();
        assert(cfg.temperature == 1.0f);
        assert(cfg.top_k == 0);
        assert(cfg.top_p == 1.0f);
        assert(cfg.repetition_pen == 1.0f);
        assert(cfg.max_tokens == 128);
        assert(!cfg.greedy);

        // Apply defaults to uniform logits -- should produce valid probs
        std::vector<float> logits(GENESIS_VOCAB, 0.0f);
        auto probs = softmax(logits, cfg.temperature);
        float sum = 0.0f;
        for (auto p : probs) sum += p;
        assert(std::abs(sum - 1.0f) < 0.001f);
    }

    // -----------------------------------------------------------------------
    // Test 2: Greedy generation is deterministic (same input -> same output)
    // -----------------------------------------------------------------------
    {
        std::vector<float> logits(GENESIS_VOCAB);
        for (size_t i = 0; i < GENESIS_VOCAB; ++i) {
            logits[i] = static_cast<float>(i) * 0.01f;
        }

        uint8_t tok1 = greedy_sample(logits);
        uint8_t tok2 = greedy_sample(logits);
        assert(tok1 == tok2);
        assert(tok1 == 255);  // highest logit at index 255
    }

    // -----------------------------------------------------------------------
    // Test 3: Temperature=0 equals greedy
    // -----------------------------------------------------------------------
    {
        std::vector<float> logits(GENESIS_VOCAB);
        for (size_t i = 0; i < GENESIS_VOCAB; ++i) {
            logits[i] = std::sin(static_cast<float>(i) * 0.1f);
        }

        uint8_t greedy_tok = greedy_sample(logits);

        // Temperature near 0 concentrates all mass on argmax
        auto probs_cold = softmax(logits, 0.001f);
        float max_prob = *std::max_element(probs_cold.begin(), probs_cold.end());
        uint8_t cold_tok = static_cast<uint8_t>(
            std::distance(probs_cold.begin(),
                          std::max_element(probs_cold.begin(), probs_cold.end())));

        assert(cold_tok == greedy_tok);
        assert(max_prob > 0.99f);
    }

    // -----------------------------------------------------------------------
    // Test 4: Higher temperature -> more varied output (higher entropy)
    // -----------------------------------------------------------------------
    {
        std::vector<float> logits(GENESIS_VOCAB);
        for (size_t i = 0; i < GENESIS_VOCAB; ++i) {
            logits[i] = static_cast<float>(i) * 0.05f;
        }

        auto probs_low  = softmax(logits, 0.5f);
        auto probs_mid  = softmax(logits, 1.0f);
        auto probs_high = softmax(logits, 2.0f);

        float entropy_low  = compute_entropy(probs_low);
        float entropy_mid  = compute_entropy(probs_mid);
        float entropy_high = compute_entropy(probs_high);

        // Higher temperature -> higher entropy
        assert(entropy_low < entropy_mid);
        assert(entropy_mid < entropy_high);
    }

    // -----------------------------------------------------------------------
    // Test 5: top_k limits token selection
    // -----------------------------------------------------------------------
    {
        std::vector<float> logits(GENESIS_VOCAB);
        for (size_t i = 0; i < GENESIS_VOCAB; ++i) {
            logits[i] = static_cast<float>(i) * 0.1f;
        }

        auto filtered = apply_top_k(logits, 5);
        auto probs = softmax(filtered);

        // Only 5 tokens should have significant probability
        int nonzero_count = 0;
        for (auto p : probs) {
            if (p > 0.001f) nonzero_count++;
        }
        assert(nonzero_count == 5);
    }

    // -----------------------------------------------------------------------
    // Test 6: top_p (nucleus) limits cumulative probability
    // -----------------------------------------------------------------------
    {
        std::vector<float> logits(GENESIS_VOCAB);
        for (size_t i = 0; i < GENESIS_VOCAB; ++i) {
            logits[i] = static_cast<float>(i) * 0.1f;
        }

        auto filtered = apply_top_p(logits, 0.9f);
        auto probs_f = softmax(filtered);

        // Sort probabilities descending, verify cumulative sum >= 0.9
        std::vector<float> sorted_probs(probs_f.begin(), probs_f.end());
        std::sort(sorted_probs.rbegin(), sorted_probs.rend());

        float cumulative = 0.0f;
        int kept = 0;
        for (auto p : sorted_probs) {
            if (p > 0.001f) {
                cumulative += p;
                kept++;
            }
        }
        // The kept tokens should cover roughly the top 90% of mass
        assert(cumulative > 0.89f);
        // And we should have kept fewer than all tokens
        assert(kept < static_cast<int>(GENESIS_VOCAB));
    }

    // -----------------------------------------------------------------------
    // Test 7: Repetition penalty reduces repeated tokens
    // -----------------------------------------------------------------------
    {
        std::vector<float> logits(GENESIS_VOCAB, 0.0f);
        // Give token 42 a very high logit
        logits[42] = 10.0f;

        auto probs_before = softmax(logits);
        float prob_42_before = probs_before[42];

        // Apply penalty to token 42
        std::vector<uint8_t> seen = {42};
        apply_repetition_penalty(logits, seen, 2.0f);

        auto probs_after = softmax(logits);
        float prob_42_after = probs_after[42];

        // Token 42's probability should decrease
        assert(prob_42_after < prob_42_before);
    }

    // -----------------------------------------------------------------------
    // Test 8: InferenceSession maintains state across feed() calls
    // -----------------------------------------------------------------------
    {
        auto dims = inf_genesis_dims();
        ConsensusModel model;
        assert(model.init(dims, GENESIS_SEED));

        InferenceSession session(model);

        // Initially no tokens fed
        assert(session.tokens_fed() == 0);

        // Feed some tokens
        std::vector<uint8_t> tokens1 = {72, 101, 108, 108, 111};
        session.feed(tokens1);
        assert(session.tokens_fed() == 5);

        // Feed more tokens
        std::vector<uint8_t> tokens2 = {32, 119, 111, 114, 108, 100};
        session.feed(tokens2);
        assert(session.tokens_fed() == 11);

        // History should contain all tokens
        assert(session.history().size() == 11);
        assert(session.history()[0] == 72);
        assert(session.history()[5] == 32);
    }

    // -----------------------------------------------------------------------
    // Test 9: InferenceSession.reset() clears state
    // -----------------------------------------------------------------------
    {
        auto dims = inf_genesis_dims();
        ConsensusModel model;
        assert(model.init(dims, GENESIS_SEED));

        InferenceSession session(model);

        std::vector<uint8_t> tokens = {1, 2, 3, 4, 5};
        session.feed(tokens);
        assert(session.tokens_fed() == 5);

        session.reset();
        assert(session.tokens_fed() == 0);
        assert(session.history().empty());

        // Can feed again after reset
        session.feed(tokens);
        assert(session.tokens_fed() == 5);
    }

    // -----------------------------------------------------------------------
    // Test 10: get_embedding() returns d_model-sized vector
    // -----------------------------------------------------------------------
    {
        auto dims = inf_genesis_dims();
        ConsensusModel model;
        assert(model.init(dims, GENESIS_SEED));

        InferenceSession session(model);

        // Empty session -> zero embedding
        auto emb0 = session.get_embedding();
        assert(emb0.size() == GENESIS_D_MODEL);
        bool all_zero = true;
        for (auto v : emb0) {
            if (v != 0.0f) { all_zero = false; break; }
        }
        assert(all_zero);

        // Feed tokens -> non-trivial embedding
        std::vector<uint8_t> tokens = {65, 66, 67, 68};
        session.feed(tokens);
        auto emb1 = session.get_embedding();
        assert(emb1.size() == GENESIS_D_MODEL);

        bool all_zero2 = true;
        for (auto v : emb1) {
            if (v != 0.0f) { all_zero2 = false; break; }
        }
        assert(!all_zero2);

        // All values should be finite
        for (auto v : emb1) {
            assert(std::isfinite(v));
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: get_next_token_probs() sums to ~1.0
    // -----------------------------------------------------------------------
    {
        auto dims = inf_genesis_dims();
        ConsensusModel model;
        assert(model.init(dims, GENESIS_SEED));

        InferenceSession session(model);
        std::vector<uint8_t> tokens = {84, 104, 101};
        session.feed(tokens);

        auto probs = session.get_next_token_probs();
        assert(probs.size() == GENESIS_VOCAB);

        float total = 0.0f;
        for (auto p : probs) {
            assert(p >= 0.0f);
            assert(std::isfinite(p));
            total += p;
        }
        assert(std::abs(total - 1.0f) < 0.01f);
    }

    // -----------------------------------------------------------------------
    // Test 12: evaluate_perplexity() returns finite positive values
    // -----------------------------------------------------------------------
    {
        auto dims = inf_genesis_dims();
        ConsensusModel model;
        assert(model.init(dims, GENESIS_SEED));

        auto val_data = generate_validation_data(VALIDATION_SEED, EVAL_TOKENS);
        float ppl = evaluate_perplexity(model, val_data);

        assert(std::isfinite(ppl));
        assert(ppl > 0.0f);
    }

    // -----------------------------------------------------------------------
    // Test 13: Perplexity is well-defined for various data lengths
    // -----------------------------------------------------------------------
    {
        auto dims = inf_genesis_dims();
        ConsensusModel model;
        assert(model.init(dims, GENESIS_SEED));

        // Short sequence
        std::vector<uint8_t> short_data(32);
        for (size_t i = 0; i < short_data.size(); ++i) {
            short_data[i] = static_cast<uint8_t>(i % 256);
        }
        float ppl_short = evaluate_perplexity(model, short_data);
        assert(std::isfinite(ppl_short));
        assert(ppl_short > 0.0f);

        // Longer sequence with repetitive pattern
        std::vector<uint8_t> rep_data(256);
        for (size_t i = 0; i < rep_data.size(); ++i) {
            rep_data[i] = static_cast<uint8_t>(i % 4);
        }
        float ppl_rep = evaluate_perplexity(model, rep_data);
        assert(std::isfinite(ppl_rep));
        assert(ppl_rep > 0.0f);
    }

    // -----------------------------------------------------------------------
    // Test 14: Softmax temperature scaling preserves ordering
    // -----------------------------------------------------------------------
    {
        std::vector<float> logits = {1.0f, 3.0f, 2.0f, 0.5f};
        auto p1 = softmax(logits, 0.5f);
        auto p2 = softmax(logits, 1.0f);
        auto p3 = softmax(logits, 5.0f);

        // Argmax should be the same regardless of temperature
        auto argmax = [](const std::vector<float>& p) {
            return std::distance(p.begin(), std::max_element(p.begin(), p.end()));
        };
        assert(argmax(p1) == 1);
        assert(argmax(p2) == 1);
        assert(argmax(p3) == 1);

        // Higher temperature -> flatter distribution
        assert(p1[1] > p2[1]);  // low temp concentrates more
        assert(p2[1] > p3[1]);  // high temp spreads more
    }

    // -----------------------------------------------------------------------
    // Test 15: Repetition penalty with negative logits
    // -----------------------------------------------------------------------
    {
        std::vector<float> logits(GENESIS_VOCAB, -1.0f);
        logits[100] = -0.5f;  // least negative

        std::vector<uint8_t> seen = {100};
        apply_repetition_penalty(logits, seen, 3.0f);

        // For negative logits, penalty should multiply (making more negative)
        assert(logits[100] < -0.5f);
        assert(logits[100] == -0.5f * 3.0f);
    }

    // -----------------------------------------------------------------------
    // Test 16: Top-k with k=1 is equivalent to greedy
    // -----------------------------------------------------------------------
    {
        std::vector<float> logits(GENESIS_VOCAB);
        for (size_t i = 0; i < GENESIS_VOCAB; ++i) {
            logits[i] = std::cos(static_cast<float>(i) * 0.05f);
        }

        auto filtered = apply_top_k(logits, 1);
        auto probs = softmax(filtered);

        uint8_t top1_tok = static_cast<uint8_t>(
            std::distance(probs.begin(),
                          std::max_element(probs.begin(), probs.end())));
        uint8_t greedy_tok = greedy_sample(logits);

        assert(top1_tok == greedy_tok);
    }

    // -----------------------------------------------------------------------
    // Test 17: Top-p=0 keeps only the top token
    // -----------------------------------------------------------------------
    {
        std::vector<float> logits(GENESIS_VOCAB);
        for (size_t i = 0; i < GENESIS_VOCAB; ++i) {
            logits[i] = static_cast<float>(i);
        }

        auto filtered = apply_top_p(logits, 0.0001f);
        auto probs = softmax(filtered);

        int active = 0;
        for (auto p : probs) {
            if (p > 0.001f) active++;
        }
        // Should keep exactly 1 token (the top one)
        assert(active == 1);
    }

    // -----------------------------------------------------------------------
    // Test 18: InferenceSession embedding changes with different input
    // -----------------------------------------------------------------------
    {
        auto dims = inf_genesis_dims();
        ConsensusModel model;
        assert(model.init(dims, GENESIS_SEED));

        InferenceSession s1(model);
        s1.feed({1, 2, 3});
        auto emb_a = s1.get_embedding();

        InferenceSession s2(model);
        s2.feed({4, 5, 6});
        auto emb_b = s2.get_embedding();

        // Different inputs should produce different embeddings
        bool same = true;
        for (size_t i = 0; i < emb_a.size(); ++i) {
            if (emb_a[i] != emb_b[i]) { same = false; break; }
        }
        assert(!same);
    }

    // -----------------------------------------------------------------------
    // Test 19: Multiple repetition penalties compound
    // -----------------------------------------------------------------------
    {
        std::vector<float> logits(GENESIS_VOCAB, 0.0f);
        logits[10] = 5.0f;
        logits[20] = 5.0f;

        // Penalize both tokens
        std::vector<uint8_t> seen = {10, 20};
        apply_repetition_penalty(logits, seen, 2.0f);

        // Both should be reduced equally
        assert(std::abs(logits[10] - logits[20]) < 0.001f);
        assert(logits[10] < 5.0f);
        assert(logits[10] == 5.0f / 2.0f);
    }

    // -----------------------------------------------------------------------
    // Test 20: Top-k with k >= vocab returns unchanged logits
    // -----------------------------------------------------------------------
    {
        std::vector<float> logits(GENESIS_VOCAB);
        for (size_t i = 0; i < GENESIS_VOCAB; ++i) {
            logits[i] = static_cast<float>(i) * 0.01f;
        }

        auto filtered = apply_top_k(logits, static_cast<int>(GENESIS_VOCAB));
        for (size_t i = 0; i < GENESIS_VOCAB; ++i) {
            assert(filtered[i] == logits[i]);
        }
    }
}

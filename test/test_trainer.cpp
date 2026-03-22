// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include <gtest/gtest.h>
#include "mining/trainer.h"

using namespace flow;
using namespace flow::mining;

// Small model for testing: vocab=64, d_model=16, d_ff=32
static constexpr uint32_t TEST_VOCAB = 64;
static constexpr uint32_t TEST_DIM = 16;
static constexpr uint32_t TEST_FF = 32;

TEST(TrainerTest, InitAndEval) {
    Trainer trainer(TEST_DIM, TEST_FF, TEST_VOCAB);

    // Random tokens
    std::vector<int32_t> tokens = {1, 5, 10, 20, 30, 15, 3, 7};
    float loss = trainer.eval_loss(tokens);

    // Random model should have high loss (roughly log(vocab) ≈ 4.15)
    EXPECT_GT(loss, 0.0f);
    EXPECT_LT(loss, 100.0f);
}

TEST(TrainerTest, EvalDeterministic) {
    Trainer trainer(TEST_DIM, TEST_FF, TEST_VOCAB);
    std::vector<int32_t> tokens = {1, 5, 10, 20, 30};

    float loss1 = trainer.eval_loss(tokens);
    float loss2 = trainer.eval_loss(tokens);

    // Same model + same data = same loss (bit-identical)
    EXPECT_EQ(loss1, loss2);
}

TEST(TrainerTest, TrainReducesLoss) {
    Trainer trainer(TEST_DIM, TEST_FF, TEST_VOCAB);

    // Simple pattern: 1→2→3→4→1→2→3→4
    std::vector<int32_t> tokens = {1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4};

    float loss_before = trainer.eval_loss(tokens);

    // Train for several steps
    for (int i = 0; i < 5; ++i) {
        trainer.train_step(tokens, tokens, 0.01f);
    }

    float loss_after = trainer.eval_loss(tokens);

    // Training should reduce loss
    EXPECT_LT(loss_after, loss_before);
}

TEST(TrainerTest, ModelHashChangesAfterTraining) {
    Trainer trainer(TEST_DIM, TEST_FF, TEST_VOCAB);
    std::vector<int32_t> tokens = {1, 2, 3, 4, 5};

    Hash256 hash_before = trainer.model_hash();
    trainer.train_step(tokens, tokens, 0.01f);
    Hash256 hash_after = trainer.model_hash();

    EXPECT_NE(hash_before, hash_after);
}

TEST(TrainerTest, DeltasNonEmpty) {
    Trainer trainer(TEST_DIM, TEST_FF, TEST_VOCAB);
    std::vector<int32_t> tokens = {1, 2, 3};

    trainer.train_step(tokens, tokens, 0.01f);
    auto deltas = trainer.get_deltas();

    EXPECT_GT(deltas.size(), 0u);
}

TEST(TrainerTest, TrainingResultComplete) {
    Trainer trainer(TEST_DIM, TEST_FF, TEST_VOCAB);
    std::vector<int32_t> tokens = {5, 10, 15, 20, 25};

    auto result = trainer.train_step(tokens, tokens, 0.01f);

    EXPECT_GT(result.loss_before, 0.0f);
    EXPECT_EQ(result.steps, 1u);
    EXPECT_FALSE(result.model_hash_before.is_zero());
    EXPECT_FALSE(result.model_hash_after.is_zero());
    EXPECT_NE(result.model_hash_before, result.model_hash_after);
    EXPECT_GT(result.weight_deltas.size(), 0u);
}

// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include <gtest/gtest.h>
#include <iomanip>
#include "consensus/validation.h"
#include "consensus/params.h"
#include "consensus/difficulty.h"
#include "consensus/growth.h"
#include "consensus/reward.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "core/hash.h"

using namespace flow;
using namespace flow::consensus;
using namespace flow::crypto;

// Helper: create a valid block + context pair for testing.
// The block passes all 14 checks against the returned context.
struct ValidBlockFixture {
    CBlock block;
    BlockContext ctx;
    KeyPair miner_kp;

    ValidBlockFixture() {
        miner_kp = generate_keypair();

        // Parent state
        ctx.parent_hash = Hash256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001");
        ctx.parent_height = 0;
        ctx.parent_timestamp = GENESIS_TIMESTAMP;
        ctx.parent_val_loss = GENESIS_VAL_LOSS;
        // Use very easy difficulty for testing (exponent=0x20 = all bytes can be non-zero)
        // 0x207fffff: target bytes [29]=0x7f, [30]=0xff, [31]=0xff — nearly all hashes pass
        ctx.parent_nbits = 0x207fffff;
        ctx.current_time = GENESIS_TIMESTAMP + 700;
        ctx.improving_blocks = 0;

        // Expected growth at height 1
        auto dims = compute_growth(1, 0);
        ctx.parent_d_model = dims.d_model;
        ctx.parent_n_layers = dims.n_layers;

        // Build block at height 1
        auto& h = block.header;
        h.prev_hash = ctx.parent_hash;
        h.height = 1;
        h.timestamp = GENESIS_TIMESTAMP + 600;
        h.val_loss = 9.5f; // improved from 10.0
        h.prev_val_loss = GENESIS_VAL_LOSS;
        h.nbits = 0x207fffff;
        h.train_steps = 100;

        // Growth
        h.d_model = dims.d_model;
        h.n_layers = dims.n_layers;
        h.d_ff = dims.d_ff;
        h.n_experts = dims.n_experts;
        h.n_heads = dims.n_heads;
        h.rank = dims.rank;

        // We need delta_hash and dataset_hash such that
        // keccak256d(delta_hash || dataset_hash) < target
        // For testing, we brute-force a delta_hash that works
        ctx.expected_dataset_hash = Hash256::from_hex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        h.dataset_hash = ctx.expected_dataset_hash;

        // Find a delta_hash that meets the (easy) target
        find_valid_delta_hash();

        // Sign
        h.miner_pubkey = miner_kp.pubkey;
        auto ub = h.unsigned_bytes();
        h.miner_sig = sign(miner_kp.privkey, miner_kp.pubkey, ub.data(), ub.size());

        // Coinbase tx
        Hash256 pk_hash = keccak256d(miner_kp.pubkey.bytes(), 32);
        Blob<20> miner_hash;
        std::memcpy(miner_hash.bytes(), pk_hash.bytes(), 20);
        block.vtx.push_back(make_coinbase(get_block_subsidy(1), miner_hash, 1));
        block.header.merkle_root = block.compute_merkle_root();

        // Re-sign after setting merkle root
        auto ub2 = block.header.unsigned_bytes();
        block.header.miner_sig = sign(miner_kp.privkey, miner_kp.pubkey,
                                      ub2.data(), ub2.size());
    }

private:
    void find_valid_delta_hash() {
        // With INITIAL_NBITS = 0x1f00ffff, the target is very easy.
        // Almost any hash will pass. Just try a few.
        for (uint32_t i = 0; i < 10000; ++i) {
            uint8_t data[4];
            write_le32(data, i);
            block.header.delta_hash = keccak256(data, 4);

            // H = Keccak256(D || V) per whitepaper §3
            Keccak256Hasher hasher;
            hasher.update(block.header.delta_hash.bytes(), 32);
            hasher.update(block.header.dataset_hash.bytes(), 32);
            Hash256 training_hash = hasher.finalize();

            if (meets_target(training_hash, block.header.nbits)) {
                return;
            }
        }
    }
};

// ─── Baseline: valid block passes ────────────────────────────

TEST(ValidationTest, ValidBlockPasses) {
    ValidBlockFixture f;
    auto state = check_block(f.block, f.ctx);
    EXPECT_TRUE(state.valid) << state.reject_reason;
}

// ─── Check 1: bad prev_hash ─────────────────────────────────

TEST(ValidationTest, Check1_BadPrevHash) {
    ValidBlockFixture f;
    f.block.header.prev_hash[0] ^= 0xFF;
    // Re-sign
    auto ub = f.block.header.unsigned_bytes();
    f.block.header.miner_sig = sign(f.miner_kp.privkey, f.miner_kp.pubkey,
                                    ub.data(), ub.size());
    auto state = check_block(f.block, f.ctx);
    EXPECT_FALSE(state.valid);
    EXPECT_EQ(state.reject_reason, "bad-prevhash");
}

// ─── Check 2: bad height ────────────────────────────────────

TEST(ValidationTest, Check2_BadHeight) {
    ValidBlockFixture f;
    f.block.header.height = 5; // should be 1
    auto ub = f.block.header.unsigned_bytes();
    f.block.header.miner_sig = sign(f.miner_kp.privkey, f.miner_kp.pubkey,
                                    ub.data(), ub.size());
    auto state = check_block(f.block, f.ctx);
    EXPECT_FALSE(state.valid);
    EXPECT_EQ(state.reject_reason, "bad-height");
}

// ─── Check 3: timestamp not advancing ───────────────────────

TEST(ValidationTest, Check3_TimeNotAdvancing) {
    ValidBlockFixture f;
    f.block.header.timestamp = GENESIS_TIMESTAMP; // same as parent
    auto ub = f.block.header.unsigned_bytes();
    f.block.header.miner_sig = sign(f.miner_kp.privkey, f.miner_kp.pubkey,
                                    ub.data(), ub.size());
    auto state = check_block(f.block, f.ctx);
    EXPECT_FALSE(state.valid);
    EXPECT_EQ(state.reject_reason, "time-not-advancing");
}

// ─── Check 4: too soon ──────────────────────────────────────

TEST(ValidationTest, Check4_TooSoon) {
    ValidBlockFixture f;
    f.block.header.timestamp = GENESIS_TIMESTAMP + 299; // < 300
    auto ub = f.block.header.unsigned_bytes();
    f.block.header.miner_sig = sign(f.miner_kp.privkey, f.miner_kp.pubkey,
                                    ub.data(), ub.size());
    auto state = check_block(f.block, f.ctx);
    EXPECT_FALSE(state.valid);
    EXPECT_EQ(state.reject_reason, "time-too-soon");
}

// ─── Check 5: too far in future ─────────────────────────────

TEST(ValidationTest, Check5_TooFarFuture) {
    ValidBlockFixture f;
    f.block.header.timestamp = f.ctx.current_time + 7201;
    auto ub = f.block.header.unsigned_bytes();
    f.block.header.miner_sig = sign(f.miner_kp.privkey, f.miner_kp.pubkey,
                                    ub.data(), ub.size());
    auto state = check_block(f.block, f.ctx);
    EXPECT_FALSE(state.valid);
    EXPECT_EQ(state.reject_reason, "time-too-far-future");
}

// ─── Check 6: invalid val_loss ──────────────────────────────

TEST(ValidationTest, Check6_ValLossNaN) {
    ValidBlockFixture f;
    f.block.header.val_loss = std::numeric_limits<float>::quiet_NaN();
    auto ub = f.block.header.unsigned_bytes();
    f.block.header.miner_sig = sign(f.miner_kp.privkey, f.miner_kp.pubkey,
                                    ub.data(), ub.size());
    auto state = check_block(f.block, f.ctx);
    EXPECT_FALSE(state.valid);
    EXPECT_EQ(state.reject_reason, "bad-val-loss");
}

TEST(ValidationTest, Check6_ValLossZero) {
    ValidBlockFixture f;
    f.block.header.val_loss = 0.0f;
    auto ub = f.block.header.unsigned_bytes();
    f.block.header.miner_sig = sign(f.miner_kp.privkey, f.miner_kp.pubkey,
                                    ub.data(), ub.size());
    auto state = check_block(f.block, f.ctx);
    EXPECT_FALSE(state.valid);
    EXPECT_EQ(state.reject_reason, "bad-val-loss");
}

// ─── Check 7: val_loss too high ─────────────────────────────

TEST(ValidationTest, Check7_ValLossTooHigh) {
    ValidBlockFixture f;
    f.block.header.val_loss = 1000.0f;
    auto ub = f.block.header.unsigned_bytes();
    f.block.header.miner_sig = sign(f.miner_kp.privkey, f.miner_kp.pubkey,
                                    ub.data(), ub.size());
    auto state = check_block(f.block, f.ctx);
    EXPECT_FALSE(state.valid);
    EXPECT_EQ(state.reject_reason, "val-loss-too-high");
}

// ─── Check 8: prev_val_loss mismatch ────────────────────────

TEST(ValidationTest, Check8_PrevValLossMismatch) {
    ValidBlockFixture f;
    f.block.header.prev_val_loss = 9.9f; // should be 10.0
    auto ub = f.block.header.unsigned_bytes();
    f.block.header.miner_sig = sign(f.miner_kp.privkey, f.miner_kp.pubkey,
                                    ub.data(), ub.size());
    auto state = check_block(f.block, f.ctx);
    EXPECT_FALSE(state.valid);
    EXPECT_EQ(state.reject_reason, "bad-prev-val-loss");
}

// ─── Check 9: severe regression ─────────────────────────────

TEST(ValidationTest, Check9_SevereRegression) {
    ValidBlockFixture f;
    f.block.header.val_loss = 21.0f; // > 2.0 * 10.0
    auto ub = f.block.header.unsigned_bytes();
    f.block.header.miner_sig = sign(f.miner_kp.privkey, f.miner_kp.pubkey,
                                    ub.data(), ub.size());
    auto state = check_block(f.block, f.ctx);
    EXPECT_FALSE(state.valid);
    EXPECT_EQ(state.reject_reason, "val-loss-regression");
}

// ─── Check 14: bad signature ────────────────────────────────

TEST(ValidationTest, Check14_BadSignature) {
    ValidBlockFixture f;
    f.block.header.miner_sig[0] ^= 0xFF; // corrupt signature
    auto state = check_block(f.block, f.ctx);
    EXPECT_FALSE(state.valid);
    EXPECT_EQ(state.reject_reason, "bad-signature");
}

// ─── Difficulty Tests ────────────────────────────────────────

TEST(DifficultyTest, NbitsTargetRoundTrip) {
    uint32_t nbits = 0x1d00ffff;
    uint256 target = nbits_to_target(nbits);
    uint32_t nbits2 = target_to_nbits(target);
    EXPECT_EQ(nbits, nbits2);
}

TEST(DifficultyTest, MeetsEasyTarget) {
    // With very easy nbits, almost any hash should pass
    Hash256 hash;
    hash[31] = 0x00; // low high byte
    hash[0] = 0xFF;
    EXPECT_TRUE(meets_target(hash, INITIAL_NBITS));
}

TEST(DifficultyTest, TwiceFasterDoublesDifficulty) {
    uint32_t nbits = 0x1d00ffff;
    // If blocks came twice as fast, actual_timespan = target/2
    int64_t actual = RETARGET_TIMESPAN / 2;
    uint32_t new_nbits = calculate_next_work(nbits, actual);

    // New target should be half the old target (harder)
    uint256 old_target = nbits_to_target(nbits);
    uint256 new_target = nbits_to_target(new_nbits);

    // Compare: new_target should be roughly half of old_target
    // Just verify it's smaller
    bool new_is_smaller = false;
    for (int i = 31; i >= 0; --i) {
        if (new_target[i] < old_target[i]) { new_is_smaller = true; break; }
        if (new_target[i] > old_target[i]) { break; }
    }
    EXPECT_TRUE(new_is_smaller);
}

TEST(DifficultyTest, TwiceSlowerHalvesDifficulty) {
    uint32_t nbits = 0x1d00ffff;
    int64_t actual = RETARGET_TIMESPAN * 2;
    uint32_t new_nbits = calculate_next_work(nbits, actual);

    uint256 old_target = nbits_to_target(nbits);
    uint256 new_target = nbits_to_target(new_nbits);

    // New target should be larger (easier)
    bool new_is_larger = false;
    for (int i = 31; i >= 0; --i) {
        if (new_target[i] > old_target[i]) { new_is_larger = true; break; }
        if (new_target[i] < old_target[i]) { break; }
    }
    EXPECT_TRUE(new_is_larger);
}

TEST(DifficultyTest, ClampedAt4x) {
    uint32_t nbits = 0x1d00ffff;
    // Very slow blocks: actual = 100 * target (clamped to 4x)
    int64_t actual_very_slow = RETARGET_TIMESPAN * 100;
    uint32_t new_4x = calculate_next_work(nbits, actual_very_slow);

    // Should be same as exactly 4x
    int64_t actual_4x = RETARGET_TIMESPAN * 4;
    uint32_t new_exact_4x = calculate_next_work(nbits, actual_4x);

    EXPECT_EQ(new_4x, new_exact_4x);
}

TEST(DifficultyTest, NbitsRoundTripMultipleValues) {
    // Test several known nbits values round-trip correctly
    uint32_t test_values[] = {
        0x1d00ffff, // Bitcoin genesis
        0x1b0404cb, // Bitcoin block 32256
        0x1a05db8b, // harder
        0x17034267, // much harder
        0x207fffff, // very easy (our test value)
    };
    for (auto nbits : test_values) {
        uint256 target = nbits_to_target(nbits);
        uint32_t nbits2 = target_to_nbits(target);
        EXPECT_EQ(nbits, nbits2) << "Round-trip failed for nbits=0x"
            << std::hex << nbits;
    }
}

TEST(DifficultyTest, ExactTimeMeansNoChange) {
    // If blocks arrived exactly on schedule, difficulty stays the same
    uint32_t nbits = 0x1d00ffff;
    uint32_t new_nbits = calculate_next_work(nbits, RETARGET_TIMESPAN);
    EXPECT_EQ(nbits, new_nbits);
}

TEST(DifficultyTest, PrecisionHalfTimespan) {
    // Blocks in half the time → target halves (difficulty doubles)
    // new_target = old_target * (RETARGET_TIMESPAN/2) / RETARGET_TIMESPAN
    //            = old_target / 2
    uint32_t nbits = 0x1d00ffff;
    uint32_t new_nbits = calculate_next_work(nbits, RETARGET_TIMESPAN / 2);

    arith_uint256 old_t = arith_uint256::from_uint256(nbits_to_target(nbits));
    arith_uint256 new_t = arith_uint256::from_uint256(nbits_to_target(new_nbits));

    // old / 2 should equal new (within compact encoding precision)
    arith_uint256 half = old_t;
    half /= 2;
    uint32_t half_nbits = target_to_nbits(half.to_uint256());
    EXPECT_EQ(new_nbits, half_nbits);
}

TEST(DifficultyTest, TenMinuteGuarantee) {
    // Simulate: 2016 blocks at 5 min each (600s → 300s, network doubled)
    // actual = 2016 * 300 = 604800 (half of 1209600)
    // new_target = old * 604800/1209600 = old/2
    // Next period: if same power, each step has P/2 chance → takes 2x longer → back to 10 min
    uint32_t nbits = 0x1d00ffff;
    int64_t actual_5min = 2016 * 300; // 5 min blocks
    uint32_t new_nbits = calculate_next_work(nbits, actual_5min);

    // New target is smaller → harder → blocks take longer → back toward 10 min
    arith_uint256 old_t = arith_uint256::from_uint256(nbits_to_target(nbits));
    arith_uint256 new_t = arith_uint256::from_uint256(nbits_to_target(new_nbits));
    EXPECT_TRUE(new_t <= old_t); // harder (smaller target)

    // Simulate the reverse: blocks at 20 min each
    int64_t actual_20min = 2016 * 1200;
    uint32_t easier_nbits = calculate_next_work(nbits, actual_20min);
    arith_uint256 easier_t = arith_uint256::from_uint256(nbits_to_target(easier_nbits));
    EXPECT_TRUE(easier_t > old_t); // easier (larger target)
}

TEST(DifficultyTest, ClampedAt4xDown) {
    // Very fast blocks — clamped to 4x harder
    uint32_t nbits = 0x1d00ffff;
    int64_t very_fast = RETARGET_TIMESPAN / 100; // 100x faster
    uint32_t clamped = calculate_next_work(nbits, very_fast);

    // Should equal exactly timespan/4
    uint32_t exact_4x = calculate_next_work(nbits, RETARGET_TIMESPAN / 4);
    EXPECT_EQ(clamped, exact_4x);
}

// ─── Reward Tests ────────────────────────────────────────────

TEST(RewardTest, InitialReward) {
    EXPECT_EQ(get_block_subsidy(0).value, 50 * COIN);
    EXPECT_EQ(get_block_subsidy(1).value, 50 * COIN);
}

TEST(RewardTest, FirstHalving) {
    EXPECT_EQ(get_block_subsidy(HALVING_INTERVAL).value, 25 * COIN);
}

TEST(RewardTest, SecondHalving) {
    EXPECT_EQ(get_block_subsidy(HALVING_INTERVAL * 2).value, 1250000000LL);
}

TEST(RewardTest, EventuallyZero) {
    // After 64 halvings, reward is 0
    EXPECT_EQ(get_block_subsidy(static_cast<uint64_t>(HALVING_INTERVAL) * 64).value, 0);
}

// ─── Growth Tests ────────────────────────────────────────────

TEST(GrowthTest, GenesisModel) {
    auto dims = compute_growth(0, 0);
    EXPECT_EQ(dims.d_model, GENESIS_D_MODEL);
    EXPECT_EQ(dims.n_layers, GENESIS_N_LAYERS);
    EXPECT_EQ(dims.n_experts, GENESIS_N_EXPERTS);
}

TEST(GrowthTest, MaxDimsAtPhase1End) {
    auto dims = compute_growth(DIM_GROWTH_PHASE, 0);
    EXPECT_EQ(dims.d_model, MAX_D_MODEL);
    EXPECT_EQ(dims.n_layers, MAX_N_LAYERS);
}

TEST(GrowthTest, Phase2ExpertGrowth) {
    auto dims = compute_growth(DIM_GROWTH_PHASE + 1, 100);
    EXPECT_EQ(dims.d_model, MAX_D_MODEL);
    EXPECT_EQ(dims.n_layers, MAX_N_LAYERS);
    EXPECT_EQ(dims.n_experts, GENESIS_N_EXPERTS + 100 * BASE_EXPERT_GROWTH);
}

TEST(GrowthTest, ExpertsCapped) {
    auto dims = compute_growth(DIM_GROWTH_PHASE + 1, 1'000'000);
    EXPECT_EQ(dims.n_experts, MAX_N_EXPERTS);
}

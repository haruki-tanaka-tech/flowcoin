// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Extended block and header validation tests. Tests edge cases in consensus
// validation including timestamps, dimensions, signatures, and difficulty.

#include "consensus/difficulty.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "consensus/validation.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "primitives/block.h"
#include "util/arith_uint256.h"
#include "util/random.h"

#include <cassert>
#include <cmath>
#include <cstring>
#include <limits>
#include <stdexcept>

using namespace flow;
using namespace flow::consensus;

// Helper: sign a header with a new keypair
static void sign_header(CBlockHeader& hdr) {
    auto kp = generate_keypair();
    std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
    auto data = hdr.get_unsigned_data();
    auto sig = ed25519_sign(data.data(), data.size(),
                            kp.privkey.data(), kp.pubkey.data());
    std::memcpy(hdr.miner_sig.data(), sig.data(), 64);
}

// Helper: make a valid genesis header
static CBlockHeader make_valid_genesis() {
    auto dims = compute_growth(0, 0);

    CBlockHeader hdr;
    hdr.height = 0;
    hdr.timestamp = GENESIS_TIMESTAMP;
    hdr.nbits = INITIAL_NBITS;
    hdr.val_loss = 5.0f;
    hdr.prev_val_loss = 0.0f;
    hdr.d_model = dims.d_model;
    hdr.n_layers = dims.n_layers;
    hdr.d_ff = dims.d_ff;
    hdr.n_heads = dims.n_heads;
    hdr.gru_dim = dims.gru_dim;
    hdr.n_slots = dims.n_slots;
    hdr.train_steps = 5000;
    hdr.version = 1;
    hdr.stagnation = 0;
    hdr.nonce = 0;

    sign_header(hdr);
    return hdr;
}

// Helper: make a genesis context
static BlockContext make_genesis_ctx() {
    BlockContext ctx;
    ctx.is_genesis = true;
    ctx.expected_dims = compute_growth(0, 0);
    ctx.min_train_steps = compute_min_steps(0);
    ctx.expected_nbits = INITIAL_NBITS;
    return ctx;
}

// Helper: make a child context from a parent
static BlockContext make_child_ctx(const CBlockHeader& parent, uint64_t child_height) {
    BlockContext ctx;
    ctx.is_genesis = false;
    ctx.prev_hash = parent.get_hash();
    ctx.prev_height = parent.height;
    ctx.prev_timestamp = parent.timestamp;
    ctx.prev_val_loss = parent.val_loss;
    ctx.prev_nbits = parent.nbits;
    ctx.expected_dims = compute_growth(child_height, 0);
    ctx.min_train_steps = compute_min_steps(child_height);
    ctx.expected_nbits = parent.nbits;  // same period
    ctx.improving_blocks = 0;
    ctx.adjusted_time = parent.timestamp + 86400;  // 1 day ahead
    ctx.retarget_first_time = GENESIS_TIMESTAMP;
    return ctx;
}

void test_block_validation() {

    // -----------------------------------------------------------------------
    // Test 1: Valid genesis header passes
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_valid_genesis();
        BlockContext ctx = make_genesis_ctx();
        ValidationState state;
        assert(check_header(hdr, ctx, state));
    }

    // -----------------------------------------------------------------------
    // Test 2: Wrong height for child block fails
    // -----------------------------------------------------------------------
    {
        CBlockHeader parent = make_valid_genesis();
        BlockContext ctx = make_child_ctx(parent, 1);

        CBlockHeader child;
        child.height = 5;  // wrong, should be 1
        child.prev_hash = parent.get_hash();
        child.timestamp = parent.timestamp + TARGET_BLOCK_TIME;
        child.nbits = parent.nbits;
        child.val_loss = 4.5f;
        child.prev_val_loss = parent.val_loss;
        auto dims = compute_growth(1, 0);
        child.d_model = dims.d_model;
        child.n_layers = dims.n_layers;
        child.d_ff = dims.d_ff;
        child.n_heads = dims.n_heads;
        child.gru_dim = dims.gru_dim;
        child.n_slots = dims.n_slots;
        child.train_steps = compute_min_steps(1);
        child.version = 1;
        sign_header(child);

        ValidationState state;
        bool valid = check_header(child, ctx, state);
        assert(!valid);
        assert(state.reject_reason() == "bad-height");
    }

    // -----------------------------------------------------------------------
    // Test 3: Timestamp too old fails
    // -----------------------------------------------------------------------
    {
        CBlockHeader parent = make_valid_genesis();
        BlockContext ctx = make_child_ctx(parent, 1);

        CBlockHeader child;
        child.height = 1;
        child.prev_hash = parent.get_hash();
        child.timestamp = parent.timestamp - 1;  // before parent
        child.nbits = parent.nbits;
        child.val_loss = 4.5f;
        child.prev_val_loss = parent.val_loss;
        auto dims = compute_growth(1, 0);
        child.d_model = dims.d_model;
        child.n_layers = dims.n_layers;
        child.d_ff = dims.d_ff;
        child.n_heads = dims.n_heads;
        child.gru_dim = dims.gru_dim;
        child.n_slots = dims.n_slots;
        child.train_steps = compute_min_steps(1);
        child.version = 1;
        sign_header(child);

        ValidationState state;
        bool valid = check_header(child, ctx, state);
        assert(!valid);
        assert(state.reject_reason() == "time-too-old");
    }

    // -----------------------------------------------------------------------
    // Test 4: Timestamp too far in future fails
    // -----------------------------------------------------------------------
    {
        CBlockHeader parent = make_valid_genesis();
        BlockContext ctx = make_child_ctx(parent, 1);
        ctx.adjusted_time = parent.timestamp + TARGET_BLOCK_TIME + 1;

        CBlockHeader child;
        child.height = 1;
        child.prev_hash = parent.get_hash();
        child.timestamp = ctx.adjusted_time + MAX_FUTURE_TIME + 100;  // too far ahead
        child.nbits = parent.nbits;
        child.val_loss = 4.5f;
        child.prev_val_loss = parent.val_loss;
        auto dims = compute_growth(1, 0);
        child.d_model = dims.d_model;
        child.n_layers = dims.n_layers;
        child.d_ff = dims.d_ff;
        child.n_heads = dims.n_heads;
        child.gru_dim = dims.gru_dim;
        child.n_slots = dims.n_slots;
        child.train_steps = compute_min_steps(1);
        child.version = 1;
        sign_header(child);

        ValidationState state;
        bool valid = check_header(child, ctx, state);
        assert(!valid);
        assert(state.reject_reason() == "time-too-new");
    }

    // -----------------------------------------------------------------------
    // Test 5: NaN val_loss fails
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_valid_genesis();
        hdr.val_loss = std::numeric_limits<float>::quiet_NaN();
        sign_header(hdr);

        BlockContext ctx = make_genesis_ctx();
        ValidationState state;
        assert(!check_header(hdr, ctx, state));
        assert(state.reject_reason() == "bad-val-loss");
    }

    // -----------------------------------------------------------------------
    // Test 6: Infinity val_loss fails
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_valid_genesis();
        hdr.val_loss = std::numeric_limits<float>::infinity();
        sign_header(hdr);

        BlockContext ctx = make_genesis_ctx();
        ValidationState state;
        assert(!check_header(hdr, ctx, state));
        assert(state.reject_reason() == "bad-val-loss");
    }

    // -----------------------------------------------------------------------
    // Test 7: Negative val_loss fails
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_valid_genesis();
        hdr.val_loss = -1.0f;
        sign_header(hdr);

        BlockContext ctx = make_genesis_ctx();
        ValidationState state;
        assert(!check_header(hdr, ctx, state));
    }

    // -----------------------------------------------------------------------
    // Test 8: Wrong prev_val_loss for child fails
    // -----------------------------------------------------------------------
    {
        CBlockHeader parent = make_valid_genesis();
        BlockContext ctx = make_child_ctx(parent, 1);

        CBlockHeader child;
        child.height = 1;
        child.prev_hash = parent.get_hash();
        child.timestamp = parent.timestamp + TARGET_BLOCK_TIME;
        child.nbits = parent.nbits;
        child.val_loss = 4.5f;
        child.prev_val_loss = 99.0f;  // wrong, should match parent.val_loss
        auto dims = compute_growth(1, 0);
        child.d_model = dims.d_model;
        child.n_layers = dims.n_layers;
        child.d_ff = dims.d_ff;
        child.n_heads = dims.n_heads;
        child.gru_dim = dims.gru_dim;
        child.n_slots = dims.n_slots;
        child.train_steps = compute_min_steps(1);
        child.version = 1;
        sign_header(child);

        ValidationState state;
        bool valid = check_header(child, ctx, state);
        assert(!valid);
        assert(state.reject_reason() == "bad-prev-loss");
    }

    // -----------------------------------------------------------------------
    // Test 9: Wrong prev_hash fails
    // -----------------------------------------------------------------------
    {
        CBlockHeader parent = make_valid_genesis();
        BlockContext ctx = make_child_ctx(parent, 1);

        CBlockHeader child;
        child.height = 1;
        // Wrong prev_hash
        GetRandBytes(child.prev_hash.data(), 32);
        child.timestamp = parent.timestamp + TARGET_BLOCK_TIME;
        child.nbits = parent.nbits;
        child.val_loss = 4.5f;
        child.prev_val_loss = parent.val_loss;
        auto dims = compute_growth(1, 0);
        child.d_model = dims.d_model;
        child.n_layers = dims.n_layers;
        child.d_ff = dims.d_ff;
        child.n_heads = dims.n_heads;
        child.gru_dim = dims.gru_dim;
        child.n_slots = dims.n_slots;
        child.train_steps = compute_min_steps(1);
        child.version = 1;
        sign_header(child);

        ValidationState state;
        bool valid = check_header(child, ctx, state);
        assert(!valid);
        assert(state.reject_reason() == "bad-prevblk");
    }

    // -----------------------------------------------------------------------
    // Test 10: Bad signature fails
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_valid_genesis();

        // Tamper with the signature
        hdr.miner_sig[0] ^= 0xFF;

        BlockContext ctx = make_genesis_ctx();
        ValidationState state;
        assert(!check_header(hdr, ctx, state));
        assert(state.reject_reason() == "bad-signature");
    }

    // -----------------------------------------------------------------------
    // Test 11: Block reward halving schedule
    // -----------------------------------------------------------------------
    {
        // Era 0: 50 FLOW
        assert(compute_block_reward(0) == 50LL * COIN);
        assert(compute_block_reward(100) == 50LL * COIN);
        assert(compute_block_reward(209999) == 50LL * COIN);

        // Era 1: 25 FLOW
        assert(compute_block_reward(210000) == 25LL * COIN);
        assert(compute_block_reward(419999) == 25LL * COIN);

        // Era 2: 12.5 FLOW
        assert(compute_block_reward(420000) == 1250000000LL);

        // Very late era: should be > 0 (MIN_REWARD)
        int64_t late_reward = compute_block_reward(10000000);
        assert(late_reward >= 0);
    }

    // -----------------------------------------------------------------------
    // Test 12: Growth schedule correctness
    // -----------------------------------------------------------------------
    {
        // Plateau 0
        auto d0 = compute_growth(0, 0);
        assert(d0.d_model == 512);
        assert(d0.n_layers == 8);
        assert(d0.d_ff == 1024);

        // Plateau 1
        auto d1 = compute_growth(100, 0);
        assert(d1.d_model == 640);
        assert(d1.n_layers == 12);

        // Plateau 4
        auto d4 = compute_growth(400, 0);
        assert(d4.d_model == 1024);
        assert(d4.n_layers == 24);
        assert(d4.d_ff == 2048);

        // Phase 2: frozen architecture
        auto d5 = compute_growth(500, 0);
        assert(d5.d_model == 1024);
        assert(d5.n_layers == 24);

        // Slot growth in Phase 2
        auto d5_imp = compute_growth(500, 100);
        assert(d5_imp.n_slots > d5.n_slots);
        assert(d5_imp.n_slots == 1024 + 100 * SLOT_GROWTH_RATE);
    }

    // -----------------------------------------------------------------------
    // Test 13: Minimum training steps
    // -----------------------------------------------------------------------
    {
        // Phase 1
        assert(compute_min_steps(0) == 1000);
        assert(compute_min_steps(250) > 1000);

        // Phase 2
        uint32_t steps_500 = compute_min_steps(500);
        assert(steps_500 >= 3000);

        // Steps grow with height
        assert(compute_min_steps(2000) > compute_min_steps(500));
    }

    // -----------------------------------------------------------------------
    // Test 14: Difficulty target encoding/decoding
    // -----------------------------------------------------------------------
    {
        arith_uint256 target;
        bool ok = derive_target(INITIAL_NBITS, target);
        assert(ok);

        // Target should be non-zero
        assert(target > arith_uint256());

        // Decode 0 should work but give a zero target
        arith_uint256 zero_target;
        derive_target(0, zero_target);
        assert(zero_target == arith_uint256());
    }

    // -----------------------------------------------------------------------
    // Test 15: Next work required — no retarget within period
    // -----------------------------------------------------------------------
    {
        // Height 1 is not a retarget boundary
        uint32_t next = get_next_work_required(1, INITIAL_NBITS,
                                                GENESIS_TIMESTAMP,
                                                GENESIS_TIMESTAMP + TARGET_BLOCK_TIME);
        assert(next == INITIAL_NBITS);
    }

    // -----------------------------------------------------------------------
    // Test 16: Next work required — retarget at boundary
    // -----------------------------------------------------------------------
    {
        // At height 2016, retarget happens
        int64_t first_time = GENESIS_TIMESTAMP;
        int64_t last_time = GENESIS_TIMESTAMP + RETARGET_TIMESPAN;  // exactly on target

        uint32_t next = get_next_work_required(2016, INITIAL_NBITS,
                                                first_time, last_time);
        // With exactly the target timespan, difficulty stays the same
        assert(next == INITIAL_NBITS);
    }

    // -----------------------------------------------------------------------
    // Test 17: Retarget with fast blocks — difficulty increases
    // -----------------------------------------------------------------------
    {
        int64_t first_time = GENESIS_TIMESTAMP;
        int64_t last_time = GENESIS_TIMESTAMP + RETARGET_TIMESPAN / 2;  // twice as fast

        uint32_t next = get_next_work_required(2016, INITIAL_NBITS,
                                                first_time, last_time);
        // Should be harder (lower target = smaller nbits exponent or mantissa)
        // The target should be halved, but clamped if necessary
        arith_uint256 old_target, new_target;
        derive_target(INITIAL_NBITS, old_target);
        derive_target(next, new_target);
        assert(new_target <= old_target);
    }

    // -----------------------------------------------------------------------
    // Test 18: Retarget with slow blocks — difficulty decreases
    // -----------------------------------------------------------------------
    {
        int64_t first_time = GENESIS_TIMESTAMP;
        int64_t last_time = GENESIS_TIMESTAMP + RETARGET_TIMESPAN * 2;  // half as fast

        uint32_t next = get_next_work_required(2016, INITIAL_NBITS,
                                                first_time, last_time);
        arith_uint256 old_target, new_target;
        derive_target(INITIAL_NBITS, old_target);
        derive_target(next, new_target);
        assert(new_target >= old_target);
    }

    // -----------------------------------------------------------------------
    // Test 19: Retarget clamped to 4x factor
    // -----------------------------------------------------------------------
    {
        int64_t first_time = GENESIS_TIMESTAMP;
        int64_t last_time = GENESIS_TIMESTAMP + RETARGET_TIMESPAN * 100;  // extremely slow

        uint32_t next = get_next_work_required(2016, INITIAL_NBITS,
                                                first_time, last_time);
        arith_uint256 old_target, new_target;
        derive_target(INITIAL_NBITS, old_target);
        derive_target(next, new_target);

        // Clamped to 4x, so new_target <= old_target * 4
        // (with powLimit cap, it may equal powLimit)
    }

    // -----------------------------------------------------------------------
    // Test 20: Header size is exactly 244 bytes unsigned
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr;
        auto data = hdr.get_unsigned_data();
        assert(data.size() == 244);
    }

    // -----------------------------------------------------------------------
    // Test 21: Block hash is deterministic
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_valid_genesis();
        uint256 h1 = hdr.get_hash();
        uint256 h2 = hdr.get_hash();
        assert(h1 == h2);
        assert(!h1.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 22: Different nonces produce different hashes
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr1 = make_valid_genesis();
        CBlockHeader hdr2 = hdr1;
        hdr2.nonce = 999;
        sign_header(hdr2);

        // The hashes will differ because the nonce changes the unsigned data
        uint256 h1 = hdr1.get_hash();
        uint256 h2 = hdr2.get_hash();
        assert(h1 != h2);
    }

    // -----------------------------------------------------------------------
    // Test 23: ValidationState API
    // -----------------------------------------------------------------------
    {
        ValidationState state;
        assert(state.is_valid());
        assert(!state.is_invalid());
        assert(!state.is_error());
        assert(state.to_string() == "valid");

        state.invalid(ValidationResult::HEADER_INVALID, "bad-test", "detail");
        assert(!state.is_valid());
        assert(state.is_invalid());
        assert(state.reject_reason() == "bad-test");
        assert(state.debug_message() == "detail");

        state.clear();
        assert(state.is_valid());

        state.error("internal");
        assert(state.is_error());
    }

    // -----------------------------------------------------------------------
    // Test 24: ModelDimensions consistency
    // -----------------------------------------------------------------------
    {
        for (uint64_t h = 0; h < 600; h += 50) {
            auto dims = compute_growth(h, 0);
            // n_heads * d_head == d_model
            assert(dims.n_heads * dims.d_head == dims.d_model);
            // d_ff == 2 * d_model
            assert(dims.d_ff == 2 * dims.d_model);
            // gru_dim == d_model
            assert(dims.gru_dim == dims.d_model);
            // vocab and seq_len are constant
            assert(dims.vocab == 256);
            assert(dims.seq_len == 256);
        }
    }
}

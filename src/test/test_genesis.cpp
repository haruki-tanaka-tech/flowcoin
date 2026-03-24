// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for genesis block creation and validation.

#include "consensus/growth.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "consensus/validation.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "primitives/block.h"

#include <cassert>
#include <cmath>
#include <cstring>
#include <stdexcept>

using namespace flow;

// Helper: create a minimal genesis block header
static CBlockHeader make_genesis_header() {
    using namespace consensus;

    auto kp = generate_keypair();
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

    std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);

    auto unsigned_data = hdr.get_unsigned_data();
    auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                            kp.privkey.data(), kp.pubkey.data());
    std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

    return hdr;
}

void test_genesis() {
    using namespace consensus;

    // -----------------------------------------------------------------------
    // Test 1: Genesis block header is exactly 308 bytes
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_genesis_header();
        auto data = hdr.get_unsigned_data();
        // Unsigned portion is 244 bytes. Full header is 244 + 64 (sig) = 308.
        assert(data.size() == 244);
    }

    // -----------------------------------------------------------------------
    // Test 2: Genesis height is 0
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_genesis_header();
        assert(hdr.height == 0);
    }

    // -----------------------------------------------------------------------
    // Test 3: Genesis timestamp matches constant
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_genesis_header();
        assert(hdr.timestamp == GENESIS_TIMESTAMP);
    }

    // -----------------------------------------------------------------------
    // Test 4: Genesis reward is INITIAL_REWARD (50 FLOW)
    // -----------------------------------------------------------------------
    {
        Amount reward = compute_block_reward(0);
        assert(reward == INITIAL_REWARD);
        assert(reward == 50LL * COIN);
    }

    // -----------------------------------------------------------------------
    // Test 5: Genesis model dimensions match GENESIS_* constants
    // -----------------------------------------------------------------------
    {
        auto dims = compute_growth(0, 0);
        assert(dims.d_model == GENESIS_D_MODEL);
        assert(dims.n_layers == GENESIS_N_LAYERS);
        assert(dims.n_heads == GENESIS_N_HEADS);
        assert(dims.d_head == GENESIS_D_HEAD);
        assert(dims.d_ff == GENESIS_D_FF);
        assert(dims.n_slots == GENESIS_N_SLOTS);
        assert(dims.top_k == GENESIS_TOP_K);
        assert(dims.gru_dim == GENESIS_GRU_DIM);
        assert(dims.conv_kernel == GENESIS_CONV_KERNEL);
        assert(dims.vocab == GENESIS_VOCAB);
        assert(dims.seq_len == GENESIS_SEQ_LEN);
    }

    // -----------------------------------------------------------------------
    // Test 6: Genesis nbits is INITIAL_NBITS
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_genesis_header();
        assert(hdr.nbits == INITIAL_NBITS);
    }

    // -----------------------------------------------------------------------
    // Test 7: Genesis prev_hash is null (all zeros)
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_genesis_header();
        assert(hdr.prev_hash.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 8: Genesis hash is non-zero
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_genesis_header();
        uint256 hash = hdr.get_hash();
        assert(!hash.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 9: Genesis is accepted by check_header with genesis context
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_genesis_header();

        BlockContext ctx;
        ctx.is_genesis = true;
        ctx.expected_dims = compute_growth(0, 0);
        ctx.min_train_steps = compute_min_steps(0);
        ctx.expected_nbits = INITIAL_NBITS;

        ValidationState state;
        bool valid = check_header(hdr, ctx, state);
        assert(valid);
    }

    // -----------------------------------------------------------------------
    // Test 10: Genesis with wrong dimensions fails
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_genesis_header();
        hdr.d_model = 256;  // wrong

        // Re-sign with the wrong dimensions
        auto kp = generate_keypair();
        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
        auto unsigned_data = hdr.get_unsigned_data();
        auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                                kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        BlockContext ctx;
        ctx.is_genesis = true;
        ctx.expected_dims = compute_growth(0, 0);
        ctx.min_train_steps = compute_min_steps(0);
        ctx.expected_nbits = INITIAL_NBITS;

        ValidationState state;
        bool valid = check_header(hdr, ctx, state);
        assert(!valid);
        assert(state.reject_reason() == "bad-growth");
    }

    // -----------------------------------------------------------------------
    // Test 11: Genesis val_loss must be positive
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_genesis_header();
        hdr.val_loss = 0.0f;  // invalid: must be > 0

        auto kp = generate_keypair();
        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
        auto unsigned_data = hdr.get_unsigned_data();
        auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                                kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        BlockContext ctx;
        ctx.is_genesis = true;
        ctx.expected_dims = compute_growth(0, 0);
        ctx.min_train_steps = compute_min_steps(0);
        ctx.expected_nbits = INITIAL_NBITS;

        ValidationState state;
        bool valid = check_header(hdr, ctx, state);
        assert(!valid);
    }

    // -----------------------------------------------------------------------
    // Test 12: Genesis val_loss must be < MAX_VAL_LOSS
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_genesis_header();
        hdr.val_loss = MAX_VAL_LOSS + 1.0f;

        auto kp = generate_keypair();
        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
        auto unsigned_data = hdr.get_unsigned_data();
        auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                                kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        BlockContext ctx;
        ctx.is_genesis = true;
        ctx.expected_dims = compute_growth(0, 0);
        ctx.min_train_steps = compute_min_steps(0);
        ctx.expected_nbits = INITIAL_NBITS;

        ValidationState state;
        bool valid = check_header(hdr, ctx, state);
        assert(!valid);
    }

    // -----------------------------------------------------------------------
    // Test 13: Signature verification — tampered header fails
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_genesis_header();

        // Tamper with a field after signing
        hdr.nonce = 12345;

        BlockContext ctx;
        ctx.is_genesis = true;
        ctx.expected_dims = compute_growth(0, 0);
        ctx.min_train_steps = compute_min_steps(0);
        ctx.expected_nbits = INITIAL_NBITS;

        ValidationState state;
        bool valid = check_header(hdr, ctx, state);
        assert(!valid);
        assert(state.reject_reason() == "bad-signature");
    }
}

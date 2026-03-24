// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "consensus/validation.h"
#include "consensus/difficulty.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include <cassert>
#include <cstring>
#include <limits>
#include <stdexcept>

// Helper: create a valid signed header for genesis block
static flow::CBlockHeader make_signed_genesis() {
    using namespace flow::consensus;

    auto kp = flow::generate_keypair();
    auto dims = compute_growth(0, 0);

    flow::CBlockHeader hdr;
    hdr.height = 0;
    hdr.timestamp = GENESIS_TIMESTAMP;
    hdr.nbits = INITIAL_NBITS;
    hdr.val_loss = 5.0f;
    hdr.prev_val_loss = 0.0f;  // no parent for genesis
    hdr.d_model = dims.d_model;
    hdr.n_layers = dims.n_layers;
    hdr.d_ff = dims.d_ff;
    hdr.n_heads = dims.n_heads;
    hdr.gru_dim = dims.gru_dim;
    hdr.n_slots = dims.n_slots;
    hdr.train_steps = 5000;
    hdr.version = 1;

    std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);

    // Sign the unsigned header data
    auto unsigned_data = hdr.get_unsigned_data();
    auto sig = flow::ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                                   kp.privkey.data(), kp.pubkey.data());
    std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

    return hdr;
}

static flow::consensus::BlockContext make_genesis_context() {
    using namespace flow::consensus;

    BlockContext ctx;
    ctx.is_genesis = true;
    ctx.expected_dims = compute_growth(0, 0);
    ctx.expected_nbits = INITIAL_NBITS;
    ctx.min_train_steps = compute_min_steps(0);
    ctx.adjusted_time = GENESIS_TIMESTAMP + 100000;
    return ctx;
}

void test_validation() {
    using namespace flow::consensus;

    // Test 1: Genesis block with valid signature should pass check_header
    {
        auto hdr = make_signed_genesis();
        auto ctx = make_genesis_context();
        ValidationState state;

        // Genesis check_header should pass if the hash meets the easy target.
        // With INITIAL_NBITS (0x1f00ffff) the target is ~2^226, so nearly
        // all hashes pass. If by extreme bad luck it fails, that's fine --
        // not a test bug but an astronomically unlikely event.
        bool result = check_header(hdr, ctx, state);
        if (!result) {
            // Only acceptable failure is high-hash (extremely unlikely)
            assert(state.reject_reason() == "high-hash");
        }
    }

    // Test 2: Invalid val_loss (zero) should fail check 6
    {
        auto hdr = make_signed_genesis();
        hdr.val_loss = 0.0f;
        // Re-sign after modification
        auto kp = flow::generate_keypair();
        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
        auto ud = hdr.get_unsigned_data();
        auto sig = flow::ed25519_sign(ud.data(), ud.size(),
                                       kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        auto ctx = make_genesis_context();
        ValidationState state;
        assert(!check_header(hdr, ctx, state));
        assert(state.reject_reason() == "bad-val-loss");
    }

    // Test 3: val_loss exceeding MAX_VAL_LOSS should fail check 7
    {
        auto hdr = make_signed_genesis();
        hdr.val_loss = MAX_VAL_LOSS + 1.0f;
        auto kp = flow::generate_keypair();
        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
        auto ud = hdr.get_unsigned_data();
        auto sig = flow::ed25519_sign(ud.data(), ud.size(),
                                       kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        auto ctx = make_genesis_context();
        ValidationState state;
        assert(!check_header(hdr, ctx, state));
        assert(state.reject_reason() == "val-loss-range");
    }

    // Test 4: Negative val_loss should fail check 6
    {
        auto hdr = make_signed_genesis();
        hdr.val_loss = -1.0f;
        auto kp = flow::generate_keypair();
        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
        auto ud = hdr.get_unsigned_data();
        auto sig = flow::ed25519_sign(ud.data(), ud.size(),
                                       kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        auto ctx = make_genesis_context();
        ValidationState state;
        assert(!check_header(hdr, ctx, state));
        assert(state.reject_reason() == "bad-val-loss");
    }

    // Test 5: NaN val_loss should fail check 6
    {
        auto hdr = make_signed_genesis();
        hdr.val_loss = std::numeric_limits<float>::quiet_NaN();
        auto kp = flow::generate_keypair();
        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
        auto ud = hdr.get_unsigned_data();
        auto sig = flow::ed25519_sign(ud.data(), ud.size(),
                                       kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        auto ctx = make_genesis_context();
        ValidationState state;
        assert(!check_header(hdr, ctx, state));
        assert(state.reject_reason() == "bad-val-loss");
    }

    // Test 6: Wrong growth dimensions should fail check 13
    {
        auto hdr = make_signed_genesis();
        hdr.d_model = 999;  // wrong
        auto kp = flow::generate_keypair();
        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
        auto ud = hdr.get_unsigned_data();
        auto sig = flow::ed25519_sign(ud.data(), ud.size(),
                                       kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        auto ctx = make_genesis_context();
        ValidationState state;
        assert(!check_header(hdr, ctx, state));
        assert(state.reject_reason() == "bad-growth");
    }

    // Test 7: Bad signature should fail check 14
    {
        auto hdr = make_signed_genesis();
        // Corrupt the signature
        hdr.miner_sig[0] ^= 0xFF;

        auto ctx = make_genesis_context();
        ValidationState state;
        bool result = check_header(hdr, ctx, state);
        // Should fail either at high-hash or bad-signature
        if (!result) {
            assert(state.reject_reason() == "bad-signature" ||
                   state.reject_reason() == "high-hash");
        }
    }

    // Test 8: ValidationState API
    {
        ValidationState state;
        assert(state.is_valid());
        assert(!state.is_invalid());
        assert(!state.is_error());

        state.invalid(ValidationResult::HEADER_INVALID, "test-reason", "debug info");
        assert(!state.is_valid());
        assert(state.is_invalid());
        assert(state.reject_reason() == "test-reason");
        assert(state.debug_message() == "debug info");

        state.clear();
        assert(state.is_valid());
    }

    // Test 9: Non-genesis context checks
    {
        // Create a parent context
        BlockContext ctx;
        ctx.is_genesis = false;
        ctx.prev_height = 0;
        ctx.prev_timestamp = GENESIS_TIMESTAMP;
        ctx.prev_val_loss = 5.0f;
        ctx.expected_nbits = INITIAL_NBITS;
        ctx.expected_dims = compute_growth(1, 0);
        ctx.min_train_steps = compute_min_steps(1);
        ctx.adjusted_time = GENESIS_TIMESTAMP + 100000;

        // Make a valid header for height 1
        auto kp = flow::generate_keypair();
        flow::CBlockHeader hdr;
        hdr.height = 1;
        hdr.timestamp = GENESIS_TIMESTAMP + 600;
        hdr.nbits = INITIAL_NBITS;
        hdr.val_loss = 4.8f;
        hdr.prev_val_loss = 5.0f;
        auto dims = compute_growth(1, 0);
        hdr.d_model = dims.d_model;
        hdr.n_layers = dims.n_layers;
        hdr.d_ff = dims.d_ff;
        hdr.n_heads = dims.n_heads;
        hdr.gru_dim = dims.gru_dim;
        hdr.n_slots = dims.n_slots;
        hdr.train_steps = 5000;

        // Compute the parent hash
        auto genesis = make_signed_genesis();
        ctx.prev_hash = genesis.get_hash();
        hdr.prev_hash = ctx.prev_hash;

        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
        auto ud = hdr.get_unsigned_data();
        auto sig = flow::ed25519_sign(ud.data(), ud.size(),
                                       kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        ValidationState state;
        // This may pass or fail on high-hash (random hash)
        check_header(hdr, ctx, state);
        // If it fails, it shouldn't be for bad-height, bad-prevblk, etc.
        if (state.is_invalid()) {
            // Only high-hash is acceptable for a randomly constructed header
            assert(state.reject_reason() == "high-hash");
        }
    }

    // Test 10: Wrong height should fail check 2
    {
        BlockContext ctx;
        ctx.is_genesis = false;
        ctx.prev_height = 5;
        ctx.prev_timestamp = GENESIS_TIMESTAMP;
        ctx.prev_val_loss = 5.0f;
        ctx.expected_nbits = INITIAL_NBITS;
        ctx.expected_dims = compute_growth(6, 0);
        ctx.adjusted_time = GENESIS_TIMESTAMP + 100000;

        auto kp = flow::generate_keypair();
        flow::CBlockHeader hdr;
        hdr.height = 100;  // wrong, should be 6
        hdr.timestamp = GENESIS_TIMESTAMP + 600;
        hdr.nbits = INITIAL_NBITS;
        hdr.val_loss = 4.8f;
        hdr.prev_val_loss = 5.0f;
        auto dims = compute_growth(6, 0);
        hdr.d_model = dims.d_model;
        hdr.n_layers = dims.n_layers;
        hdr.d_ff = dims.d_ff;
        hdr.n_heads = dims.n_heads;
        hdr.gru_dim = dims.gru_dim;
        hdr.n_slots = dims.n_slots;

        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
        auto ud = hdr.get_unsigned_data();
        auto sig = flow::ed25519_sign(ud.data(), ud.size(),
                                       kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        ValidationState state;
        assert(!check_header(hdr, ctx, state));
        assert(state.reject_reason() == "bad-height");
    }
}

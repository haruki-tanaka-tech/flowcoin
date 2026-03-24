// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for block template creation (mining/blocktemplate.h).
// Since create_block_template requires a ChainState with a block tree,
// these tests focus on the structural properties of templates that can be
// verified without a full chain (by checking template fields against
// consensus parameters).

#include "consensus/difficulty.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "consensus/validation.h"
#include "crypto/bech32.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "hash/merkle.h"
#include "mining/blocktemplate.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/arith_uint256.h"
#include "util/types.h"

#include <cassert>
#include <cmath>
#include <cstring>
#include <vector>

using namespace flow;
using namespace flow::consensus;

// Helper: build a coinbase transaction for a given height and reward
static CTransaction make_coinbase(uint64_t height, Amount reward) {
    CTransaction tx;
    tx.version = 1;
    tx.locktime = 0;

    CTxIn cb_in;
    cb_in.prevout = COutPoint();  // null = coinbase
    tx.vin.push_back(cb_in);

    CTxOut cb_out;
    cb_out.amount = reward;
    tx.vout.push_back(cb_out);

    return tx;
}

// Helper: build a simple genesis-like block
static CBlock make_genesis_block() {
    CBlock block;
    block.version = 1;
    block.height = 0;
    block.timestamp = GENESIS_TIMESTAMP;
    block.nbits = INITIAL_NBITS;
    block.val_loss = 5.0f;
    block.prev_val_loss = 0.0f;

    auto dims = compute_growth(0, 0);
    block.d_model = dims.d_model;
    block.n_layers = dims.n_layers;
    block.d_ff = dims.d_ff;
    block.n_heads = dims.n_heads;
    block.gru_dim = dims.gru_dim;
    block.n_slots = dims.n_slots;
    block.train_steps = 5000;
    block.stagnation = 0;
    block.nonce = 0;

    Amount reward = compute_block_reward(0);
    block.vtx.push_back(make_coinbase(0, reward));

    // Compute merkle root from transaction IDs
    std::vector<uint256> txids;
    for (const auto& tx : block.vtx) {
        txids.push_back(tx.get_txid());
    }
    block.merkle_root = compute_merkle_root(txids);

    // Sign the block
    auto kp = generate_keypair();
    std::memcpy(block.miner_pubkey.data(), kp.pubkey.data(), 32);
    auto unsigned_data = block.get_unsigned_data();
    auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                            kp.privkey.data(), kp.pubkey.data());
    std::memcpy(block.miner_sig.data(), sig.data(), 64);

    return block;
}

void test_blocktemplate() {
    // -----------------------------------------------------------------------
    // Test 1: Genesis coinbase has correct reward
    // -----------------------------------------------------------------------
    {
        Amount expected_reward = compute_block_reward(0);
        assert(expected_reward == INITIAL_REWARD);  // 50 FLOW

        auto coinbase = make_coinbase(0, expected_reward);
        assert(coinbase.is_coinbase());
        assert(coinbase.vout.size() == 1);
        assert(coinbase.vout[0].amount == expected_reward);
    }

    // -----------------------------------------------------------------------
    // Test 2: Coinbase is identified correctly
    // -----------------------------------------------------------------------
    {
        auto coinbase = make_coinbase(0, INITIAL_REWARD);
        assert(coinbase.is_coinbase());
        assert(coinbase.vin.size() == 1);
        assert(coinbase.vin[0].is_coinbase());
        assert(coinbase.vin[0].prevout.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 3: Genesis block has correct model dimensions
    // -----------------------------------------------------------------------
    {
        auto dims = compute_growth(0, 0);
        assert(dims.d_model == GENESIS_D_MODEL);     // 512
        assert(dims.n_layers == GENESIS_N_LAYERS);    // 8
        assert(dims.d_ff == GENESIS_D_FF);            // 1024
        assert(dims.n_heads == GENESIS_N_HEADS);      // 8
        assert(dims.gru_dim == GENESIS_GRU_DIM);      // 512
        assert(dims.n_slots == GENESIS_N_SLOTS);      // 1024
    }

    // -----------------------------------------------------------------------
    // Test 4: Model dimensions match growth schedule at various heights
    // -----------------------------------------------------------------------
    {
        // Plateau 0 (0-99)
        auto dims0 = compute_growth(50, 0);
        assert(dims0.d_model == 512);
        assert(dims0.n_layers == 8);
        assert(dims0.d_ff == 1024);

        // Plateau 1 (100-199)
        auto dims1 = compute_growth(150, 0);
        assert(dims1.d_model == 640);
        assert(dims1.n_layers == 12);
        assert(dims1.d_ff == 1280);

        // Plateau 2 (200-299)
        auto dims2 = compute_growth(250, 0);
        assert(dims2.d_model == 768);
        assert(dims2.n_layers == 16);
        assert(dims2.d_ff == 1536);

        // Plateau 3 (300-399)
        auto dims3 = compute_growth(350, 0);
        assert(dims3.d_model == 896);
        assert(dims3.n_layers == 20);
        assert(dims3.d_ff == 1792);

        // Plateau 4 (400-499)
        auto dims4 = compute_growth(450, 0);
        assert(dims4.d_model == 1024);
        assert(dims4.n_layers == 24);
        assert(dims4.d_ff == 2048);

        // Phase 2 (500+): frozen at max
        auto dims5 = compute_growth(1000, 0);
        assert(dims5.d_model == MAX_D_MODEL);
        assert(dims5.n_layers == MAX_N_LAYERS);
        assert(dims5.d_ff == MAX_D_FF);
    }

    // -----------------------------------------------------------------------
    // Test 5: Target matches difficulty at initial nbits
    // -----------------------------------------------------------------------
    {
        arith_uint256 target;
        bool ok = derive_target(INITIAL_NBITS, target);
        assert(ok);
        assert(!target.IsZero());

        // Verify target matches powLimit
        arith_uint256 pow_limit = GetPowLimit();
        assert(target == pow_limit);
    }

    // -----------------------------------------------------------------------
    // Test 6: Coinbase value at different heights
    // -----------------------------------------------------------------------
    {
        // Era 0: 50 FLOW
        assert(compute_block_reward(0) == 50LL * COIN);
        assert(compute_block_reward(209999) == 50LL * COIN);

        // Era 1: 25 FLOW
        assert(compute_block_reward(210000) == 25LL * COIN);
        assert(compute_block_reward(419999) == 25LL * COIN);

        // Era 2: 12.5 FLOW
        assert(compute_block_reward(420000) == static_cast<Amount>(12.5 * COIN));
    }

    // -----------------------------------------------------------------------
    // Test 7: Merkle root of single transaction
    // -----------------------------------------------------------------------
    {
        auto coinbase = make_coinbase(0, INITIAL_REWARD);
        std::vector<uint256> txids = {coinbase.get_txid()};
        uint256 root = compute_merkle_root(txids);
        // Single leaf: merkle root equals the leaf
        assert(root == coinbase.get_txid());
    }

    // -----------------------------------------------------------------------
    // Test 8: Merkle root of two transactions
    // -----------------------------------------------------------------------
    {
        auto cb = make_coinbase(0, INITIAL_REWARD);
        auto cb2 = make_coinbase(1, INITIAL_REWARD);

        std::vector<uint256> txids = {cb.get_txid(), cb2.get_txid()};
        uint256 root = compute_merkle_root(txids);
        // Two leaves: root = keccak256d(left || right)
        assert(!root.is_null());
        assert(root != cb.get_txid());
        assert(root != cb2.get_txid());
    }

    // -----------------------------------------------------------------------
    // Test 9: Merkle root of empty list
    // -----------------------------------------------------------------------
    {
        std::vector<uint256> empty;
        uint256 root = compute_merkle_root(empty);
        assert(root.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 10: Block header unsigned data is 244 bytes
    // -----------------------------------------------------------------------
    {
        CBlock block = make_genesis_block();
        auto data = block.get_unsigned_data();
        assert(data.size() == 244);
    }

    // -----------------------------------------------------------------------
    // Test 11: Block hash is non-null
    // -----------------------------------------------------------------------
    {
        CBlock block = make_genesis_block();
        uint256 hash = block.get_hash();
        assert(!hash.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 12: Block hash is deterministic
    // -----------------------------------------------------------------------
    {
        CBlock block = make_genesis_block();
        uint256 hash1 = block.get_hash();
        uint256 hash2 = block.get_hash();
        assert(hash1 == hash2);
    }

    // -----------------------------------------------------------------------
    // Test 13: Block hash changes with nonce
    // -----------------------------------------------------------------------
    {
        CBlock block = make_genesis_block();
        block.nonce = 0;
        uint256 hash1 = block.get_hash();
        block.nonce = 1;
        uint256 hash2 = block.get_hash();
        assert(hash1 != hash2);
    }

    // -----------------------------------------------------------------------
    // Test 14: Training hash equals block hash
    // -----------------------------------------------------------------------
    {
        CBlock block = make_genesis_block();
        uint256 block_hash = block.get_hash();
        uint256 training_hash = block.get_training_hash();
        assert(block_hash == training_hash);
    }

    // -----------------------------------------------------------------------
    // Test 15: Minimum training steps increase with height
    // -----------------------------------------------------------------------
    {
        uint32_t steps_0 = compute_min_steps(0);
        uint32_t steps_100 = compute_min_steps(100);
        uint32_t steps_499 = compute_min_steps(499);
        uint32_t steps_500 = compute_min_steps(500);
        uint32_t steps_2000 = compute_min_steps(2000);

        assert(steps_0 == MIN_TRAIN_STEPS_BASE);  // 1000
        assert(steps_100 > steps_0);
        assert(steps_499 > steps_100);
        assert(steps_500 >= steps_499);
        assert(steps_2000 > steps_500);
    }

    // -----------------------------------------------------------------------
    // Test 16: Block size within limits
    // -----------------------------------------------------------------------
    {
        CBlock block = make_genesis_block();
        // A genesis block with one coinbase and no delta should be small
        auto data = block.get_unsigned_data();
        assert(data.size() < MAX_BLOCK_SIZE);
    }

    // -----------------------------------------------------------------------
    // Test 17: CTransaction::get_value_out sums outputs correctly
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;

        CTxOut out1;
        out1.amount = 100 * COIN;
        CTxOut out2;
        out2.amount = 50 * COIN;

        tx.vout.push_back(out1);
        tx.vout.push_back(out2);

        assert(tx.get_value_out() == 150 * COIN);
    }

    // -----------------------------------------------------------------------
    // Test 18: Merkle root with odd number of transactions
    // -----------------------------------------------------------------------
    {
        // With 3 transactions, the last is duplicated: H(H(t0,t1), H(t2,t2))
        auto cb0 = make_coinbase(0, INITIAL_REWARD);
        auto cb1 = make_coinbase(1, INITIAL_REWARD);
        auto cb2 = make_coinbase(2, INITIAL_REWARD);

        std::vector<uint256> txids = {
            cb0.get_txid(), cb1.get_txid(), cb2.get_txid()
        };
        uint256 root = compute_merkle_root(txids);
        assert(!root.is_null());

        // Verify determinism
        uint256 root2 = compute_merkle_root(txids);
        assert(root == root2);
    }

    // -----------------------------------------------------------------------
    // Test 19: Ed25519 signature is valid on block header
    // -----------------------------------------------------------------------
    {
        CBlock block = make_genesis_block();
        auto unsigned_data = block.get_unsigned_data();
        bool valid = ed25519_verify(unsigned_data.data(), unsigned_data.size(),
                                     block.miner_pubkey.data(),
                                     block.miner_sig.data());
        assert(valid);
    }

    // -----------------------------------------------------------------------
    // Test 20: Tampered header fails signature verification
    // -----------------------------------------------------------------------
    {
        CBlock block = make_genesis_block();
        block.nonce = 12345;  // Change nonce after signing
        auto unsigned_data = block.get_unsigned_data();
        bool valid = ed25519_verify(unsigned_data.data(), unsigned_data.size(),
                                     block.miner_pubkey.data(),
                                     block.miner_sig.data());
        assert(!valid);
    }

    // -----------------------------------------------------------------------
    // Test 21: Coinbase total value matches expected reward
    // -----------------------------------------------------------------------
    {
        for (uint64_t h = 0; h < 5; h++) {
            Amount expected = compute_block_reward(h);
            auto cb = make_coinbase(h, expected);
            assert(cb.is_coinbase());
            assert(cb.get_value_out() == expected);
        }
    }

    // -----------------------------------------------------------------------
    // Test 22: Block with delta payload
    // -----------------------------------------------------------------------
    {
        CBlock block = make_genesis_block();
        block.delta_payload = {1, 2, 3, 4, 5, 6, 7, 8};
        block.delta_length = 8;
        block.delta_offset = 0;

        assert(block.delta_payload.size() == 8);
    }

    // -----------------------------------------------------------------------
    // Test 23: Multiple blocks have distinct hashes
    // -----------------------------------------------------------------------
    {
        std::vector<uint256> hashes;
        for (uint32_t nonce = 0; nonce < 100; nonce++) {
            CBlock block = make_genesis_block();
            block.nonce = nonce;
            // Re-sign
            auto kp = generate_keypair();
            std::memcpy(block.miner_pubkey.data(), kp.pubkey.data(), 32);
            auto data = block.get_unsigned_data();
            auto sig = ed25519_sign(data.data(), data.size(),
                                     kp.privkey.data(), kp.pubkey.data());
            std::memcpy(block.miner_sig.data(), sig.data(), 64);

            hashes.push_back(block.get_hash());
        }

        // All hashes should be unique
        for (size_t i = 0; i < hashes.size(); i++) {
            for (size_t j = i + 1; j < hashes.size(); j++) {
                assert(hashes[i] != hashes[j]);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 24: CTransaction serialization produces non-empty output
    // -----------------------------------------------------------------------
    {
        auto cb = make_coinbase(0, INITIAL_REWARD);
        auto bytes = cb.serialize();
        assert(!bytes.empty());

        auto hash_bytes = cb.serialize_for_hash();
        assert(!hash_bytes.empty());
    }

    // -----------------------------------------------------------------------
    // Test 25: Different coinbase addresses produce different tx IDs
    // -----------------------------------------------------------------------
    {
        auto kp1 = generate_keypair();
        auto kp2 = generate_keypair();

        CTransaction cb1;
        cb1.version = 1;
        cb1.locktime = 0;
        CTxIn in1;
        cb1.vin.push_back(in1);
        CTxOut out1;
        out1.amount = INITIAL_REWARD;
        out1.pubkey_hash = kp1.pubkey;
        cb1.vout.push_back(out1);

        CTransaction cb2;
        cb2.version = 1;
        cb2.locktime = 0;
        CTxIn in2;
        cb2.vin.push_back(in2);
        CTxOut out2;
        out2.amount = INITIAL_REWARD;
        out2.pubkey_hash = kp2.pubkey;
        cb2.vout.push_back(out2);

        assert(cb1.get_txid() != cb2.get_txid());
    }

    // -----------------------------------------------------------------------
    // Test 26: Merkle root with power-of-2 leaves
    // -----------------------------------------------------------------------
    {
        // 4 leaves: balanced tree
        std::vector<uint256> leaves;
        for (int i = 0; i < 4; i++) {
            auto cb = make_coinbase(i, INITIAL_REWARD);
            leaves.push_back(cb.get_txid());
        }
        uint256 root4 = compute_merkle_root(leaves);
        assert(!root4.is_null());

        // 8 leaves
        for (int i = 4; i < 8; i++) {
            auto cb = make_coinbase(i, INITIAL_REWARD);
            leaves.push_back(cb.get_txid());
        }
        uint256 root8 = compute_merkle_root(leaves);
        assert(!root8.is_null());
        assert(root4 != root8);
    }

    // -----------------------------------------------------------------------
    // Test 27: Block version field
    // -----------------------------------------------------------------------
    {
        CBlock block = make_genesis_block();
        assert(block.version == 1);
    }

    // -----------------------------------------------------------------------
    // Test 28: Growth schedule timing — min steps monotonically increase
    // -----------------------------------------------------------------------
    {
        uint32_t prev_steps = 0;
        for (uint64_t h = 0; h < 1000; h += 50) {
            uint32_t steps = compute_min_steps(h);
            assert(steps >= prev_steps);
            prev_steps = steps;
        }
    }

    // -----------------------------------------------------------------------
    // Test 29: Reward halving boundary values
    // -----------------------------------------------------------------------
    {
        Amount before_halving = compute_block_reward(209999);
        Amount at_halving = compute_block_reward(210000);
        assert(before_halving == 50 * COIN);
        assert(at_halving == 25 * COIN);
        assert(at_halving == before_halving / 2);
    }

    // -----------------------------------------------------------------------
    // Test 30: Total supply after era 0
    // -----------------------------------------------------------------------
    {
        Amount supply = compute_total_supply(209999);
        // 210,000 blocks * 50 FLOW
        Amount expected = 210000LL * 50 * COIN;
        assert(supply == expected);
    }

    // -----------------------------------------------------------------------
    // Test 31: compute_remaining_supply is non-negative
    // -----------------------------------------------------------------------
    {
        Amount remaining = compute_remaining_supply(0);
        assert(remaining > 0);
        assert(remaining < MAX_SUPPLY);

        Amount remaining_late = compute_remaining_supply(210000);
        assert(remaining_late < remaining);
        assert(remaining_late >= 0);
    }

    // -----------------------------------------------------------------------
    // Test 32: estimate_param_count increases with plateaus
    // -----------------------------------------------------------------------
    {
        size_t prev_count = 0;
        for (uint32_t p = 0; p < NUM_GROWTH_PLATEAUS; p++) {
            auto dims = compute_growth(p * GROWTH_PLATEAU_LEN, 0);
            size_t count = estimate_param_count(dims.d_model, dims.n_layers,
                                                 dims.d_ff, dims.n_slots);
            assert(count > prev_count);
            prev_count = count;
        }
    }

    // -----------------------------------------------------------------------
    // Test 33: Valid d_model and n_layers checks
    // -----------------------------------------------------------------------
    {
        assert(is_valid_d_model(GENESIS_D_MODEL));
        assert(is_valid_d_model(MAX_D_MODEL));
        assert(is_valid_d_model(640));
        assert(is_valid_d_model(768));
        assert(is_valid_d_model(896));
        assert(!is_valid_d_model(500));  // not multiple of 64
        assert(!is_valid_d_model(100));  // below minimum

        assert(is_valid_n_layers(GENESIS_N_LAYERS));
        assert(is_valid_n_layers(MAX_N_LAYERS));
        assert(is_valid_n_layers(12));
        assert(!is_valid_n_layers(7));   // not multiple of 4
        assert(!is_valid_n_layers(3));   // below minimum
    }

    // -----------------------------------------------------------------------
    // Test 34: COutPoint::is_null
    // -----------------------------------------------------------------------
    {
        COutPoint null_op;
        assert(null_op.is_null());

        COutPoint non_null(flow::GetRandUint256(), 0);
        assert(!non_null.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 35: CTxOut::is_null
    // -----------------------------------------------------------------------
    {
        CTxOut null_out;
        assert(null_out.is_null());

        CTxOut non_null;
        non_null.amount = 1;
        assert(!non_null.is_null());
    }
}

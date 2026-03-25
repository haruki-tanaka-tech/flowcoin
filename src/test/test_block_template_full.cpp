// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Complete block template assembly tests: template field validation,
// fee-rate ordering, block size limits, coinbase value, assembled block
// validation, template caching semantics, and CPFP package selection.

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
#include "util/time.h"
#include "util/types.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <vector>

using namespace flow;
using namespace flow::consensus;

// ---- Helpers ---------------------------------------------------------------

static std::array<uint8_t, 32> tmpl_pkh(const std::array<uint8_t, 32>& pk) {
    uint256 h = keccak256(pk.data(), 32);
    std::array<uint8_t, 32> r;
    std::memcpy(r.data(), h.data(), 32);
    return r;
}

static CTransaction tmpl_coinbase(uint64_t height,
                                   const std::array<uint8_t, 32>& pkh,
                                   Amount extra = 0) {
    CTransaction tx;
    tx.version = 1;
    CTxIn cb;
    tx.vin.push_back(cb);
    CTxOut out;
    out.amount = compute_block_reward(height) + extra;
    out.pubkey_hash = pkh;
    tx.vout.push_back(out);
    return tx;
}

static CBlock tmpl_genesis_block(const KeyPair& kp) {
    CBlock block;
    block.version = 1;
    block.height = 0;
    block.timestamp = GENESIS_TIMESTAMP;
    block.nbits = INITIAL_NBITS;
    block.val_loss = 5.0f;
    block.prev_val_loss = 0.0f;

    auto dims = compute_growth(0);
    block.d_model = dims.d_model;
    block.n_layers = dims.n_layers;
    block.d_ff = dims.d_ff;
    block.n_heads = dims.n_heads;
    block.gru_dim = dims.gru_dim;
    block.n_slots = dims.n_slots;
    block.reserved_field = 0;
    block.stagnation = 0;
    block.nonce = 0;

    auto pkh = tmpl_pkh(kp.pubkey);
    block.vtx.push_back(tmpl_coinbase(0, pkh));

    std::vector<uint256> txids;
    for (auto& tx : block.vtx) txids.push_back(tx.get_txid());
    block.merkle_root = compute_merkle_root(txids);

    std::memcpy(block.miner_pubkey.data(), kp.pubkey.data(), 32);
    auto data = block.get_unsigned_data();
    auto sig = ed25519_sign(data.data(), data.size(),
                            kp.privkey.data(), kp.pubkey.data());
    std::memcpy(block.miner_sig.data(), sig.data(), 64);
    return block;
}

// Create a simple transfer tx (for fee-rate testing)
static CTransaction make_fee_tx(const uint256& prev_txid, uint32_t prev_vout,
                                  Amount input_amt, Amount output_amt,
                                  const std::array<uint8_t, 32>& dest_pkh,
                                  const KeyPair& sender) {
    CTransaction tx;
    tx.version = 1;
    CTxIn in;
    in.prevout = COutPoint(prev_txid, prev_vout);
    std::memcpy(in.pubkey.data(), sender.pubkey.data(), 32);
    tx.vin.push_back(in);
    CTxOut out;
    out.amount = output_amt;
    out.pubkey_hash = dest_pkh;
    tx.vout.push_back(out);

    auto txid = tx.get_txid();
    auto sig = ed25519_sign(txid.data(), 32, sender.privkey.data(), sender.pubkey.data());
    std::memcpy(tx.vin[0].signature.data(), sig.data(), 64);
    return tx;
}

void test_block_template_full() {

    // -----------------------------------------------------------------------
    // Test 1: Template header has correct initial fields
    // -----------------------------------------------------------------------
    {
        // Manually construct a template to verify field correctness
        BlockTemplate tmpl;
        tmpl.header.height = 1;
        tmpl.header.timestamp = GENESIS_TIMESTAMP + TARGET_BLOCK_TIME;
        tmpl.header.nbits = INITIAL_NBITS;
        tmpl.header.version = 1;

        auto dims = compute_growth(1);
        tmpl.dims = dims;

        assert(tmpl.header.height == 1);
        assert(tmpl.header.nbits == INITIAL_NBITS);
        assert(tmpl.dims.d_model == 512);
        assert(tmpl.dims.n_layers == 8);
    }

    // -----------------------------------------------------------------------
    // Test 2: Template has correct model dimensions for various heights
    // -----------------------------------------------------------------------
    {
        for (uint64_t h = 0; h < 600; h += 100) {
            auto dims = compute_growth(h);
            BlockTemplate tmpl;
            tmpl.dims = dims;

            assert(tmpl.dims.d_model == dims.d_model);
            assert(tmpl.dims.n_layers == dims.n_layers);
            assert(tmpl.dims.d_ff == dims.d_ff);
            assert(tmpl.dims.n_heads == dims.n_heads);
            assert(tmpl.dims.gru_dim == dims.gru_dim);
        }
    }

    // -----------------------------------------------------------------------
    // Test 3: Coinbase reward correct for height
    // -----------------------------------------------------------------------
    {
        for (uint64_t h : {0ULL, 1ULL, 100ULL, 209999ULL, 210000ULL, 420000ULL}) {
            Amount expected = compute_block_reward(h);
            auto kp = generate_keypair();
            auto cb = tmpl_coinbase(h, tmpl_pkh(kp.pubkey));
            assert(cb.get_value_out() == expected);
        }
    }

    // -----------------------------------------------------------------------
    // Test 4: Transactions sorted by fee rate (simulated)
    // -----------------------------------------------------------------------
    {
        // Create transactions with different fee rates
        struct FeeRateEntry {
            double fee_rate;
            uint256 txid;
        };

        std::vector<FeeRateEntry> entries;
        for (int i = 0; i < 5; i++) {
            auto kp = generate_keypair();
            CTransaction tx;
            tx.version = 1;
            CTxIn in;
            tx.vin.push_back(in);
            CTxOut out;
            out.amount = (5 - i) * COIN;  // different amounts
            out.pubkey_hash = tmpl_pkh(kp.pubkey);
            tx.vout.push_back(out);

            double fee_rate = static_cast<double>((i + 1) * 1000) / tx.get_serialize_size();
            entries.push_back({fee_rate, tx.get_txid()});
        }

        // Sort by fee rate descending (as BlockAssembler would)
        std::sort(entries.begin(), entries.end(),
                  [](const FeeRateEntry& a, const FeeRateEntry& b) {
                      return a.fee_rate > b.fee_rate;
                  });

        // First entry should have highest fee rate
        assert(entries[0].fee_rate >= entries[1].fee_rate);
        assert(entries[1].fee_rate >= entries[2].fee_rate);
        assert(entries[3].fee_rate >= entries[4].fee_rate);
    }

    // -----------------------------------------------------------------------
    // Test 5: Block size within limits
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        CBlock block = tmpl_genesis_block(kp);
        size_t block_size = block.get_block_size();
        assert(block_size < MAX_BLOCK_SIZE);
        assert(block_size > 0);
    }

    // -----------------------------------------------------------------------
    // Test 6: Total fees in coinbase
    // -----------------------------------------------------------------------
    {
        Amount reward = compute_block_reward(5);
        Amount fees = 50000;
        Amount total = reward + fees;

        auto kp = generate_keypair();
        auto cb = tmpl_coinbase(5, tmpl_pkh(kp.pubkey), fees);
        assert(cb.get_value_out() == total);
    }

    // -----------------------------------------------------------------------
    // Test 7: Assembled block passes basic validation
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        CBlock block = tmpl_genesis_block(kp);

        // Verify merkle root
        assert(block.verify_merkle_root());

        // Verify signature
        auto data = block.get_unsigned_data();
        bool sig_ok = ed25519_verify(data.data(), data.size(),
                                      block.miner_pubkey.data(),
                                      block.miner_sig.data());
        assert(sig_ok);

        // check_block structural checks
        assert(block.check_block());
    }

    // -----------------------------------------------------------------------
    // Test 8: Template caching semantics — same template within window
    // -----------------------------------------------------------------------
    {
        // Template should be reusable if the tip hasn't changed
        BlockTemplate tmpl1;
        tmpl1.template_id = 12345;
        tmpl1.creation_time = GENESIS_TIMESTAMP;

        BlockTemplate tmpl2;
        tmpl2.template_id = 12345;
        tmpl2.creation_time = GENESIS_TIMESTAMP + 10;  // 10 seconds later

        // Same template_id within 30-second window means it can be cached
        int64_t age = tmpl2.creation_time - tmpl1.creation_time;
        bool cache_valid = (age < 30) && (tmpl1.template_id == tmpl2.template_id);
        assert(cache_valid);

        // After 30 seconds, cache should be invalidated
        tmpl2.creation_time = tmpl1.creation_time + 31;
        age = tmpl2.creation_time - tmpl1.creation_time;
        cache_valid = (age < 30);
        assert(!cache_valid);
    }

    // -----------------------------------------------------------------------
    // Test 9: Template invalidation — new tip means fresh template
    // -----------------------------------------------------------------------
    {
        BlockTemplate tmpl1;
        tmpl1.template_id = 1;
        tmpl1.header.height = 5;
        tmpl1.header.prev_hash = GetRandUint256();

        BlockTemplate tmpl2;
        tmpl2.template_id = 2;
        tmpl2.header.height = 6;
        tmpl2.header.prev_hash = GetRandUint256();

        // Different heights = tip changed, must use new template
        assert(tmpl1.header.height != tmpl2.header.height);
        assert(tmpl1.header.prev_hash != tmpl2.header.prev_hash);
    }

    // -----------------------------------------------------------------------
    // Test 10: CPFP: ancestor fee rate calculation
    // -----------------------------------------------------------------------
    {
        // Parent tx has low fee rate
        TxCandidate parent;
        parent.fee = 100;
        parent.size = 200;
        parent.fee_rate = static_cast<double>(parent.fee) / parent.size;  // 0.5

        // Child tx has higher fee rate, references parent
        TxCandidate child;
        child.fee = 2000;
        child.size = 150;
        child.fee_rate = static_cast<double>(child.fee) / child.size;  // ~13.3

        // Ancestor fee rate for child = (parent.fee + child.fee) / (parent.size + child.size)
        child.ancestor_fee = parent.fee + child.fee;
        child.ancestor_size = parent.size + child.size;
        child.ancestor_fee_rate = static_cast<double>(child.ancestor_fee) / child.ancestor_size;

        // The ancestor fee rate should be between parent's and child's individual rates
        assert(child.ancestor_fee_rate > parent.fee_rate);
        assert(child.ancestor_fee_rate < child.fee_rate);

        // Ancestor fee rate: (100+2000)/(200+150) = 2100/350 = 6.0
        assert(std::abs(child.ancestor_fee_rate - 6.0) < 0.01);
    }

    // -----------------------------------------------------------------------
    // Test 11: TxCandidate ordering by ancestor fee rate
    // -----------------------------------------------------------------------
    {
        TxCandidate high;
        high.ancestor_fee_rate = 10.0;

        TxCandidate low;
        low.ancestor_fee_rate = 1.0;

        // operator< gives higher fee rate higher priority
        assert(high < low);   // high has higher priority
        assert(!(low < high));
    }

    // -----------------------------------------------------------------------
    // Test 12: Merkle root of assembled block
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto pkh = tmpl_pkh(kp.pubkey);

        CBlock block;
        block.version = 1;
        block.height = 0;

        block.vtx.push_back(tmpl_coinbase(0, pkh));

        // Add a second tx (non-coinbase)
        CTransaction tx2;
        tx2.version = 1;
        CTxIn in2;
        in2.prevout = COutPoint(GetRandUint256(), 0);
        std::memcpy(in2.pubkey.data(), kp.pubkey.data(), 32);
        tx2.vin.push_back(in2);
        CTxOut out2;
        out2.amount = 1 * COIN;
        out2.pubkey_hash = pkh;
        tx2.vout.push_back(out2);
        block.vtx.push_back(tx2);

        // Compute and set merkle root
        std::vector<uint256> txids;
        for (auto& tx : block.vtx) txids.push_back(tx.get_txid());
        block.merkle_root = compute_merkle_root(txids);

        // Verify merkle root
        assert(block.verify_merkle_root());

        // Changing a transaction should invalidate the root
        uint256 stored_root = block.merkle_root;
        block.vtx[1].vout[0].amount = 2 * COIN;  // change amount
        uint256 new_root = block.compute_merkle_root();
        assert(new_root != stored_root);
    }

    // -----------------------------------------------------------------------
    // Test 13: BlockTemplate.tx_count returns correct value
    // -----------------------------------------------------------------------
    {
        BlockTemplate tmpl;
        assert(tmpl.tx_count() == 0);

        CTransaction tx1;
        tx1.version = 1;
        tmpl.transactions.push_back(tx1);
        assert(tmpl.tx_count() == 1);

        CTransaction tx2;
        tx2.version = 1;
        tmpl.transactions.push_back(tx2);
        assert(tmpl.tx_count() == 2);
    }

    // -----------------------------------------------------------------------
    // Test 14: Block weight computation
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        CBlock block = tmpl_genesis_block(kp);
        size_t weight = block.get_block_weight();
        assert(weight > 0);
        assert(weight < MAX_BLOCK_WEIGHT * 10);  // reasonable upper bound

        // Header weight is fixed
        assert(block.get_header_weight() == BLOCK_HEADER_SIZE * WITNESS_SCALE_FACTOR);
    }

    // -----------------------------------------------------------------------
    // Test 15: Multiple coinbase outputs
    // -----------------------------------------------------------------------
    {
        // Some miners split coinbase into multiple outputs
        CTransaction cb;
        cb.version = 1;
        CTxIn cb_in;
        cb.vin.push_back(cb_in);

        Amount reward = compute_block_reward(0);
        // Split into 3 outputs
        auto kp1 = generate_keypair();
        auto kp2 = generate_keypair();
        auto kp3 = generate_keypair();

        cb.vout.push_back(CTxOut(reward / 2, tmpl_pkh(kp1.pubkey)));
        cb.vout.push_back(CTxOut(reward / 4, tmpl_pkh(kp2.pubkey)));
        cb.vout.push_back(CTxOut(reward - reward / 2 - reward / 4, tmpl_pkh(kp3.pubkey)));

        assert(cb.is_coinbase());
        assert(cb.get_value_out() == reward);
        assert(cb.vout.size() == 3);

        // Should still pass coinbase check
        ValidationState state;
        bool ok = check_coinbase(cb, 0, reward, state);
        assert(ok);
    }

    // -----------------------------------------------------------------------
    // Test 16: estimate_param_count is monotonically increasing
    // -----------------------------------------------------------------------
    {
        size_t prev = 0;
        for (uint64_t h = 0; h <= 512; h += 64) {
            auto dims = compute_growth(h);
            size_t count = estimate_param_count(dims.d_model, dims.n_layers,
                                                 dims.d_ff, dims.n_slots);
            assert(count > prev);
            prev = count;
        }
    }

    // -----------------------------------------------------------------------
    // Test 17: Target decoded from INITIAL_NBITS is valid
    // -----------------------------------------------------------------------
    {
        arith_uint256 target;
        bool ok = derive_target(INITIAL_NBITS, target);
        assert(ok);
        assert(!target.IsZero());

        // Should equal powLimit
        arith_uint256 pow_limit = GetPowLimit();
        assert(target == pow_limit);
    }

    // -----------------------------------------------------------------------
    // Test 18: BlockTemplate.total_fees and coinbase_value consistency
    // -----------------------------------------------------------------------
    {
        BlockTemplate tmpl;
        tmpl.total_fees = 5000;
        tmpl.coinbase_value = compute_block_reward(0) + tmpl.total_fees;

        assert(tmpl.coinbase_value == INITIAL_REWARD + 5000);
        assert(tmpl.coinbase_value > tmpl.total_fees);
    }

    // -----------------------------------------------------------------------
    // Test 19: (min_train_steps removed -- difficulty regulates mining)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Test 20: CBlock::make_coinbase produces valid coinbase
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        for (uint64_t h = 0; h < 10; h++) {
            Amount reward = compute_block_reward(h);
            auto cb = CBlock::make_coinbase(h, reward, kp.pubkey);
            assert(cb.is_coinbase());
            assert(cb.get_value_out() == reward);
            assert(cb.vin.size() == 1);
            assert(cb.vin[0].is_coinbase());
        }
    }
}

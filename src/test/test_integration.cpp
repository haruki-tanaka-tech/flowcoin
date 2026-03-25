// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// End-to-end integration tests for FlowCoin consensus.
// Tests chain construction, UTXO tracking, transaction validation,
// and block template/submission flow without requiring network or disk I/O.

#include "consensus/difficulty.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "consensus/pow.h"
#include "consensus/reward.h"
#include "consensus/validation.h"
#include "crypto/bech32.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "hash/merkle.h"
#include "primitives/block.h"
#include "primitives/delta.h"
#include "primitives/transaction.h"
#include "util/arith_uint256.h"
#include "util/types.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <cstring>
#include <map>
#include <string>
#include <vector>

using namespace flow;
using namespace flow::consensus;

// Simple in-memory UTXO set for integration testing
struct TestUTXO {
    Amount amount;
    std::array<uint8_t, 32> pubkey_hash;
    uint64_t height;
    bool is_coinbase;
};

struct TestUTXOKey {
    uint256 txid;
    uint32_t vout;

    bool operator<(const TestUTXOKey& o) const {
        if (txid < o.txid) return true;
        if (o.txid < txid) return false;
        return vout < o.vout;
    }
};

class TestUTXOSet {
public:
    std::map<TestUTXOKey, TestUTXO> utxos;

    void add(const uint256& txid, uint32_t vout, const TestUTXO& entry) {
        utxos[{txid, vout}] = entry;
    }

    bool remove(const uint256& txid, uint32_t vout) {
        return utxos.erase({txid, vout}) > 0;
    }

    bool exists(const uint256& txid, uint32_t vout) const {
        return utxos.count({txid, vout}) > 0;
    }

    const TestUTXO& get(const uint256& txid, uint32_t vout) const {
        return utxos.at({txid, vout});
    }

    Amount balance_for(const std::array<uint8_t, 32>& pkh) const {
        Amount total = 0;
        for (auto& [k, v] : utxos) {
            if (v.pubkey_hash == pkh) {
                total += v.amount;
            }
        }
        return total;
    }
};

// Helper: compute pubkey hash from public key
static std::array<uint8_t, 32> compute_pkh(const std::array<uint8_t, 32>& pubkey) {
    uint256 hash = keccak256(pubkey.data(), 32);
    std::array<uint8_t, 32> pkh;
    std::memcpy(pkh.data(), hash.data(), 32);
    return pkh;
}

// Helper: create a coinbase transaction
static CTransaction make_coinbase(uint64_t height,
                                   const std::array<uint8_t, 32>& recipient_pkh,
                                   Amount extra_fees = 0) {
    CTransaction tx;
    tx.version = 1;
    tx.locktime = 0;

    CTxIn cb_in;
    cb_in.prevout = COutPoint();
    tx.vin.push_back(cb_in);

    Amount reward = compute_block_reward(height) + extra_fees;
    CTxOut cb_out;
    cb_out.amount = reward;
    cb_out.pubkey_hash = recipient_pkh;
    tx.vout.push_back(cb_out);

    return tx;
}

// Helper: create a signed block at given height
static CBlock make_block(uint64_t height, const uint256& prev_hash,
                          const std::vector<CTransaction>& txs,
                          const KeyPair& miner_kp) {
    CBlock block;
    block.version = 1;
    block.height = height;
    block.prev_hash = prev_hash;
    block.timestamp = GENESIS_TIMESTAMP + static_cast<int64_t>(height) * TARGET_BLOCK_TIME;
    block.nbits = INITIAL_NBITS;
    block.val_loss = 5.0f - static_cast<float>(height) * 0.001f;
    if (block.val_loss < 0.5f) block.val_loss = 0.5f;
    block.prev_val_loss = (height == 0) ? 0.0f : 5.0f - static_cast<float>(height - 1) * 0.001f;
    if (block.prev_val_loss < 0.5f) block.prev_val_loss = 0.5f;

    auto dims = compute_growth(height);
    block.d_model = dims.d_model;
    block.n_layers = dims.n_layers;
    block.d_ff = dims.d_ff;
    block.n_heads = dims.n_heads;
    block.gru_dim = dims.gru_dim;
    block.n_slots = dims.n_slots;
    block.train_steps = compute_min_steps(height) + 1000;
    block.stagnation = 0;
    block.nonce = 0;

    block.vtx = txs;

    // Compute merkle root
    std::vector<uint256> txids;
    for (const auto& tx : block.vtx) {
        txids.push_back(tx.get_txid());
    }
    block.merkle_root = compute_merkle_root(txids);

    // Sign block
    std::memcpy(block.miner_pubkey.data(), miner_kp.pubkey.data(), 32);
    auto unsigned_data = block.get_unsigned_data();
    auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                            miner_kp.privkey.data(), miner_kp.pubkey.data());
    std::memcpy(block.miner_sig.data(), sig.data(), 64);

    return block;
}

// Helper: create a signed spending transaction
static CTransaction make_spend_tx(const uint256& prev_txid, uint32_t prev_vout,
                                    Amount input_amount,
                                    const std::array<uint8_t, 32>& recipient_pkh,
                                    Amount output_amount,
                                    const KeyPair& sender_kp) {
    CTransaction tx;
    tx.version = 1;
    tx.locktime = 0;

    CTxIn input;
    input.prevout = COutPoint(prev_txid, prev_vout);
    std::memcpy(input.pubkey.data(), sender_kp.pubkey.data(), 32);
    tx.vin.push_back(input);

    // Main output
    CTxOut out;
    out.amount = output_amount;
    out.pubkey_hash = recipient_pkh;
    tx.vout.push_back(out);

    // Change output (if any)
    Amount fee = 1000;  // minimal fee
    Amount change = input_amount - output_amount - fee;
    if (change > 0) {
        CTxOut change_out;
        change_out.amount = change;
        change_out.pubkey_hash = compute_pkh(sender_kp.pubkey);
        tx.vout.push_back(change_out);
    }

    // Sign: the tx hash covers everything except signatures
    auto tx_hash = tx.get_txid();
    auto sig = ed25519_sign(tx_hash.data(), 32,
                            sender_kp.privkey.data(), sender_kp.pubkey.data());
    std::memcpy(tx.vin[0].signature.data(), sig.data(), 64);

    return tx;
}

// Helper: apply block to in-memory UTXO set
static void apply_block(TestUTXOSet& utxos, const CBlock& block) {
    for (size_t tx_idx = 0; tx_idx < block.vtx.size(); tx_idx++) {
        const auto& tx = block.vtx[tx_idx];

        // Remove spent UTXOs (skip coinbase inputs)
        if (!tx.is_coinbase()) {
            for (const auto& input : tx.vin) {
                utxos.remove(input.prevout.txid, input.prevout.index);
            }
        }

        // Add new UTXOs
        uint256 txid = tx.get_txid();
        for (uint32_t i = 0; i < tx.vout.size(); i++) {
            TestUTXO entry;
            entry.amount = tx.vout[i].amount;
            entry.pubkey_hash = tx.vout[i].pubkey_hash;
            entry.height = block.height;
            entry.is_coinbase = tx.is_coinbase();
            utxos.add(txid, i, entry);
        }
    }
}

void test_integration() {
    // -----------------------------------------------------------------------
    // Test 1: Create genesis block and verify basic properties
    // -----------------------------------------------------------------------
    auto miner1 = generate_keypair();
    auto miner2 = generate_keypair();
    auto miner1_pkh = compute_pkh(miner1.pubkey);
    auto miner2_pkh = compute_pkh(miner2.pubkey);

    TestUTXOSet utxos;

    // Genesis block
    auto genesis_cb = make_coinbase(0, miner1_pkh);
    auto genesis = make_block(0, uint256(), {genesis_cb}, miner1);

    assert(genesis.height == 0);
    assert(genesis.prev_hash.is_null());
    assert(genesis.vtx.size() == 1);
    assert(genesis.vtx[0].is_coinbase());

    uint256 genesis_hash = genesis.get_hash();
    assert(!genesis_hash.is_null());

    apply_block(utxos, genesis);

    // Verify UTXO set: miner1 has genesis reward
    uint256 genesis_txid = genesis.vtx[0].get_txid();
    assert(utxos.exists(genesis_txid, 0));
    assert(utxos.get(genesis_txid, 0).amount == INITIAL_REWARD);
    assert(utxos.get(genesis_txid, 0).is_coinbase);
    assert(utxos.balance_for(miner1_pkh) == INITIAL_REWARD);

    // -----------------------------------------------------------------------
    // Test 2: Build block 1 on top of genesis
    // -----------------------------------------------------------------------
    auto block1_cb = make_coinbase(1, miner2_pkh);
    auto block1 = make_block(1, genesis_hash, {block1_cb}, miner2);

    assert(block1.height == 1);
    assert(block1.prev_hash == genesis_hash);

    uint256 block1_hash = block1.get_hash();
    assert(block1_hash != genesis_hash);

    apply_block(utxos, block1);

    // Verify UTXO set
    uint256 block1_txid = block1.vtx[0].get_txid();
    assert(utxos.exists(block1_txid, 0));
    assert(utxos.get(block1_txid, 0).amount == INITIAL_REWARD);
    assert(utxos.balance_for(miner2_pkh) == INITIAL_REWARD);
    // Genesis reward still exists
    assert(utxos.balance_for(miner1_pkh) == INITIAL_REWARD);

    // -----------------------------------------------------------------------
    // Test 3: Build block 2 with a spending transaction
    // -----------------------------------------------------------------------
    {
        // Miner1 spends genesis coinbase to miner2
        // (In reality, coinbase needs COINBASE_MATURITY confirmations,
        //  but here we test the UTXO bookkeeping logic)
        Amount send_amount = 30 * COIN;
        auto spend_tx = make_spend_tx(genesis_txid, 0,
                                       INITIAL_REWARD,
                                       miner2_pkh,
                                       send_amount,
                                       miner1);

        auto block2_cb = make_coinbase(2, miner1_pkh);
        auto block2 = make_block(2, block1_hash, {block2_cb, spend_tx}, miner1);

        assert(block2.height == 2);
        assert(block2.prev_hash == block1_hash);
        assert(block2.vtx.size() == 2);

        uint256 block2_hash = block2.get_hash();

        apply_block(utxos, block2);

        // Genesis UTXO should be spent
        assert(!utxos.exists(genesis_txid, 0));

        // New UTXOs from spend_tx
        uint256 spend_txid = spend_tx.get_txid();
        assert(utxos.exists(spend_txid, 0));  // miner2 output
        assert(utxos.get(spend_txid, 0).amount == send_amount);

        // Check for change output
        if (spend_tx.vout.size() > 1) {
            assert(utxos.exists(spend_txid, 1));  // change back to miner1
        }

        // Miner1 got block2 coinbase reward
        uint256 block2_txid = block2.vtx[0].get_txid();
        assert(utxos.exists(block2_txid, 0));
    }

    // -----------------------------------------------------------------------
    // Test 4: Block hashes chain correctly
    // -----------------------------------------------------------------------
    {
        assert(genesis.prev_hash.is_null());
        assert(block1.prev_hash == genesis_hash);
        assert(block1_hash != genesis_hash);
    }

    // -----------------------------------------------------------------------
    // Test 5: Each block uses a different address per coinbase
    // -----------------------------------------------------------------------
    {
        auto addr1_kp = generate_keypair();
        auto addr2_kp = generate_keypair();
        auto addr3_kp = generate_keypair();

        auto pkh1 = compute_pkh(addr1_kp.pubkey);
        auto pkh2 = compute_pkh(addr2_kp.pubkey);
        auto pkh3 = compute_pkh(addr3_kp.pubkey);

        // All three pubkey hashes should be different
        assert(pkh1 != pkh2);
        assert(pkh2 != pkh3);
        assert(pkh1 != pkh3);
    }

    // -----------------------------------------------------------------------
    // Test 6: Reward schedule across eras
    // -----------------------------------------------------------------------
    {
        // Era 0
        Amount era0_reward = compute_block_reward(0);
        assert(era0_reward == 50 * COIN);

        // Era 1
        Amount era1_reward = compute_block_reward(210000);
        assert(era1_reward == 25 * COIN);

        // Era 2
        Amount era2_reward = compute_block_reward(420000);
        assert(era2_reward == static_cast<Amount>(12.5 * COIN));

        // Subsidy decreases monotonically
        assert(era0_reward > era1_reward);
        assert(era1_reward > era2_reward);
    }

    // -----------------------------------------------------------------------
    // Test 7: Merkle root with multiple transactions
    // -----------------------------------------------------------------------
    {
        auto cb = make_coinbase(10, miner1_pkh);
        auto tx1 = make_spend_tx(genesis_txid, 0, INITIAL_REWARD,
                                  miner2_pkh, 10 * COIN, miner1);

        std::vector<uint256> txids = {cb.get_txid(), tx1.get_txid()};
        uint256 root = compute_merkle_root(txids);

        assert(!root.is_null());
        assert(root != cb.get_txid());
        assert(root != tx1.get_txid());

        // Deterministic
        uint256 root2 = compute_merkle_root(txids);
        assert(root == root2);
    }

    // -----------------------------------------------------------------------
    // Test 8: Ed25519 signatures on blocks verify correctly
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto cb = make_coinbase(5, compute_pkh(kp.pubkey));
        auto blk = make_block(5, genesis_hash, {cb}, kp);

        auto unsigned_data = blk.get_unsigned_data();
        bool valid = ed25519_verify(unsigned_data.data(), unsigned_data.size(),
                                     blk.miner_pubkey.data(),
                                     blk.miner_sig.data());
        assert(valid);
    }

    // -----------------------------------------------------------------------
    // Test 9: Tampered block header fails signature check
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto cb = make_coinbase(5, compute_pkh(kp.pubkey));
        auto blk = make_block(5, genesis_hash, {cb}, kp);

        // Tamper with nonce
        blk.nonce = 99999;
        auto unsigned_data = blk.get_unsigned_data();
        bool valid = ed25519_verify(unsigned_data.data(), unsigned_data.size(),
                                     blk.miner_pubkey.data(),
                                     blk.miner_sig.data());
        assert(!valid);
    }

    // -----------------------------------------------------------------------
    // Test 10: Model dimensions grow continuously
    // -----------------------------------------------------------------------
    {
        for (uint64_t h = 0; h <= DIM_FREEZE_HEIGHT; h += 64) {
            auto dims = compute_growth(h);

            uint32_t expected_d_model = std::min(512u + static_cast<uint32_t>(h), 1024u);
            uint32_t expected_n_layers = std::min(8u + static_cast<uint32_t>(h / 32), 24u);
            uint32_t expected_d_ff = 2 * expected_d_model;

            assert(dims.d_model == expected_d_model);
            assert(dims.n_layers == expected_n_layers);
            assert(dims.d_ff == expected_d_ff);
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: Difficulty at initial nbits is exactly 1.0
    // -----------------------------------------------------------------------
    {
        double diff = GetDifficulty(INITIAL_NBITS);
        assert(diff >= 0.99 && diff <= 1.01);
    }

    // -----------------------------------------------------------------------
    // Test 12: ValidationState works correctly
    // -----------------------------------------------------------------------
    {
        ValidationState state;
        assert(state.is_valid());
        assert(!state.is_invalid());
        assert(state.to_string() == "valid");

        state.invalid(ValidationResult::BLOCK_INVALID, "bad-height", "height mismatch");
        assert(!state.is_valid());
        assert(state.is_invalid());
        assert(state.reject_reason() == "bad-height");
        assert(state.debug_message() == "height mismatch");

        state.clear();
        assert(state.is_valid());
    }

    // -----------------------------------------------------------------------
    // Test 13: BlockContext construction
    // -----------------------------------------------------------------------
    {
        BlockContext ctx;
        ctx.prev_height = 0;
        ctx.prev_timestamp = GENESIS_TIMESTAMP;
        ctx.prev_val_loss = 5.0f;
        ctx.prev_nbits = INITIAL_NBITS;
        ctx.adjusted_time = GENESIS_TIMESTAMP + TARGET_BLOCK_TIME + 10;
        ctx.expected_nbits = INITIAL_NBITS;
        ctx.is_genesis = false;
        ctx.expected_dims = compute_growth(1);
        ctx.min_train_steps = compute_min_steps(1);

        assert(ctx.expected_dims.d_model == GENESIS_D_MODEL);
        assert(ctx.min_train_steps > 0);
    }

    // -----------------------------------------------------------------------
    // Test 14: Delta compress/decompress in block context
    // -----------------------------------------------------------------------
    {
        // Simulate a delta payload (model weight updates)
        std::vector<float> deltas(1000, 0.0f);
        deltas[42] = 0.01f;
        deltas[100] = -0.005f;

        std::vector<uint8_t> raw(deltas.size() * sizeof(float));
        std::memcpy(raw.data(), deltas.data(), raw.size());

        auto compressed = compress_delta(raw);
        assert(!compressed.empty());
        assert(compressed.size() < raw.size());

        auto decompressed = decompress_delta(compressed);
        assert(decompressed == raw);
    }

    // -----------------------------------------------------------------------
    // Test 15: Transaction serialization is deterministic
    // -----------------------------------------------------------------------
    {
        auto cb = make_coinbase(0, miner1_pkh);
        auto bytes1 = cb.serialize_for_hash();
        auto bytes2 = cb.serialize_for_hash();
        assert(bytes1 == bytes2);
        assert(!bytes1.empty());
    }

    // -----------------------------------------------------------------------
    // Test 16: Transaction ID is deterministic
    // -----------------------------------------------------------------------
    {
        auto cb = make_coinbase(0, miner1_pkh);
        uint256 txid1 = cb.get_txid();
        uint256 txid2 = cb.get_txid();
        assert(txid1 == txid2);
        assert(!txid1.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 17: Different transactions have different IDs
    // -----------------------------------------------------------------------
    {
        auto cb1 = make_coinbase(0, miner1_pkh);
        auto cb2 = make_coinbase(1, miner2_pkh);
        assert(cb1.get_txid() != cb2.get_txid());
    }

    // -----------------------------------------------------------------------
    // Test 18: Full block signing and verification
    // -----------------------------------------------------------------------
    {
        // Build a 3-block chain with distinct miners
        auto kp_a = generate_keypair();
        auto kp_b = generate_keypair();
        auto kp_c = generate_keypair();

        auto pkh_a = compute_pkh(kp_a.pubkey);
        auto pkh_b = compute_pkh(kp_b.pubkey);
        auto pkh_c = compute_pkh(kp_c.pubkey);

        auto blk0 = make_block(0, uint256(),
                                {make_coinbase(0, pkh_a)}, kp_a);
        auto blk1 = make_block(1, blk0.get_hash(),
                                {make_coinbase(1, pkh_b)}, kp_b);
        auto blk2 = make_block(2, blk1.get_hash(),
                                {make_coinbase(2, pkh_c)}, kp_c);

        // Verify chain linkage
        assert(blk1.prev_hash == blk0.get_hash());
        assert(blk2.prev_hash == blk1.get_hash());

        // Verify all signatures
        for (const auto* blk : {&blk0, &blk1, &blk2}) {
            auto data = blk->get_unsigned_data();
            bool ok = ed25519_verify(data.data(), data.size(),
                                      blk->miner_pubkey.data(),
                                      blk->miner_sig.data());
            assert(ok);
        }
    }

    // -----------------------------------------------------------------------
    // Test 19: COutPoint equality and comparison
    // -----------------------------------------------------------------------
    {
        uint256 txid;
        txid.m_data.fill(0x42);

        COutPoint a(txid, 0);
        COutPoint b(txid, 0);
        COutPoint c(txid, 1);

        assert(a == b);
        assert(a != c);
        assert(a < c);
    }

    // -----------------------------------------------------------------------
    // Test 20: Halving era computation
    // -----------------------------------------------------------------------
    {
        assert(get_halving_era(0) == 0);
        assert(get_halving_era(209999) == 0);
        assert(get_halving_era(210000) == 1);
        assert(get_halving_era(419999) == 1);
        assert(get_halving_era(420000) == 2);
    }

    // -----------------------------------------------------------------------
    // Test 21: Total supply convergence
    // -----------------------------------------------------------------------
    {
        // After enough halvings, reward drops to minimum and eventually 0
        // Era 63+: reward would be < 1 atomic unit -> 0
        Amount late_reward = compute_block_reward(210000ULL * 64);
        assert(late_reward == 0);
    }

    // -----------------------------------------------------------------------
    // Test 22: 10-block chain build with UTXO tracking
    // -----------------------------------------------------------------------
    {
        TestUTXOSet chain_utxos;
        uint256 prev_hash;
        prev_hash.set_null();

        std::vector<KeyPair> miners;
        std::vector<uint256> block_hashes;

        for (int i = 0; i < 10; i++) {
            auto kp = generate_keypair();
            miners.push_back(kp);
            auto pkh = compute_pkh(kp.pubkey);
            auto cb = make_coinbase(static_cast<uint64_t>(i), pkh);
            auto blk = make_block(static_cast<uint64_t>(i), prev_hash, {cb}, kp);

            apply_block(chain_utxos, blk);
            prev_hash = blk.get_hash();
            block_hashes.push_back(prev_hash);
        }

        // Verify all 10 coinbase UTXOs exist
        assert(chain_utxos.utxos.size() == 10);

        // Verify block hashes are all unique
        for (int i = 0; i < 10; i++) {
            for (int j = i + 1; j < 10; j++) {
                assert(block_hashes[i] != block_hashes[j]);
            }
        }

        // Verify each miner has exactly one UTXO with INITIAL_REWARD
        for (int i = 0; i < 10; i++) {
            auto pkh = compute_pkh(miners[i].pubkey);
            Amount bal = chain_utxos.balance_for(pkh);
            assert(bal == INITIAL_REWARD);
        }
    }

    // -----------------------------------------------------------------------
    // Test 23: Spending chain — each block spends previous coinbase
    // -----------------------------------------------------------------------
    {
        TestUTXOSet chain_utxos;
        auto sender = generate_keypair();
        auto receiver = generate_keypair();
        auto sender_pkh = compute_pkh(sender.pubkey);
        auto receiver_pkh = compute_pkh(receiver.pubkey);

        // Block 0: coinbase to sender
        auto cb0 = make_coinbase(0, sender_pkh);
        auto blk0 = make_block(0, uint256(), {cb0}, sender);
        apply_block(chain_utxos, blk0);

        uint256 cb0_txid = cb0.get_txid();
        assert(chain_utxos.exists(cb0_txid, 0));

        // Block 1: send half of coinbase to receiver
        Amount half = INITIAL_REWARD / 2;
        Amount fee = 1000;
        auto spend1 = make_spend_tx(cb0_txid, 0, INITIAL_REWARD,
                                     receiver_pkh, half, sender);

        auto cb1 = make_coinbase(1, sender_pkh);
        auto blk1 = make_block(1, blk0.get_hash(), {cb1, spend1}, sender);
        apply_block(chain_utxos, blk1);

        // Original coinbase UTXO should be gone
        assert(!chain_utxos.exists(cb0_txid, 0));

        // Receiver should have half
        uint256 spend1_txid = spend1.get_txid();
        assert(chain_utxos.exists(spend1_txid, 0));
        assert(chain_utxos.get(spend1_txid, 0).amount == half);

        // Sender should have change + new coinbase
        // Change = INITIAL_REWARD - half - fee
        Amount expected_change = INITIAL_REWARD - half - fee;
        if (spend1.vout.size() > 1) {
            assert(chain_utxos.exists(spend1_txid, 1));
            assert(chain_utxos.get(spend1_txid, 1).amount == expected_change);
        }

        // Block 2: receiver sends to a third party
        auto third = generate_keypair();
        auto third_pkh = compute_pkh(third.pubkey);

        auto spend2 = make_spend_tx(spend1_txid, 0, half,
                                     third_pkh, half / 2, receiver);

        auto cb2 = make_coinbase(2, sender_pkh);
        auto blk2 = make_block(2, blk1.get_hash(), {cb2, spend2}, sender);
        apply_block(chain_utxos, blk2);

        // Receiver's UTXO should be spent
        assert(!chain_utxos.exists(spend1_txid, 0));

        // Third party should have half/2
        uint256 spend2_txid = spend2.get_txid();
        assert(chain_utxos.exists(spend2_txid, 0));
        assert(chain_utxos.get(spend2_txid, 0).amount == half / 2);
    }

    // -----------------------------------------------------------------------
    // Test 24: Multiple outputs in a single transaction
    // -----------------------------------------------------------------------
    {
        auto sender = generate_keypair();
        auto r1 = generate_keypair();
        auto r2 = generate_keypair();
        auto r3 = generate_keypair();

        CTransaction tx;
        tx.version = 1;
        tx.locktime = 0;

        CTxIn input;
        input.prevout = COutPoint(GetRandUint256(), 0);
        std::memcpy(input.pubkey.data(), sender.pubkey.data(), 32);
        tx.vin.push_back(input);

        CTxOut out1;
        out1.amount = 10 * COIN;
        out1.pubkey_hash = compute_pkh(r1.pubkey);
        tx.vout.push_back(out1);

        CTxOut out2;
        out2.amount = 20 * COIN;
        out2.pubkey_hash = compute_pkh(r2.pubkey);
        tx.vout.push_back(out2);

        CTxOut out3;
        out3.amount = 5 * COIN;
        out3.pubkey_hash = compute_pkh(r3.pubkey);
        tx.vout.push_back(out3);

        assert(tx.vout.size() == 3);
        assert(tx.get_value_out() == 35 * COIN);

        // txid should be deterministic
        uint256 txid = tx.get_txid();
        assert(!txid.is_null());
        assert(tx.get_txid() == txid);
    }

    // -----------------------------------------------------------------------
    // Test 25: Consensus params are self-consistent
    // -----------------------------------------------------------------------
    {
        // RETARGET_TIMESPAN = RETARGET_INTERVAL * TARGET_BLOCK_TIME
        assert(RETARGET_TIMESPAN == static_cast<int64_t>(RETARGET_INTERVAL) * TARGET_BLOCK_TIME);

        // MAX_PEERS = MAX_OUTBOUND + MAX_INBOUND
        assert(MAX_PEERS == MAX_OUTBOUND_PEERS + MAX_INBOUND_PEERS);

        // Genesis dimensions match constants
        auto g = compute_growth(0);
        assert(g.d_model == GENESIS_D_MODEL);
        assert(g.n_layers == GENESIS_N_LAYERS);
        assert(g.d_ff == GENESIS_D_FF);
        assert(g.n_heads == GENESIS_N_HEADS);
        assert(g.gru_dim == GENESIS_GRU_DIM);
        assert(g.n_slots == GENESIS_N_SLOTS);
        assert(g.vocab == GENESIS_VOCAB);
        assert(g.seq_len == GENESIS_SEQ_LEN);

        // Max dimensions match constants (at DIM_FREEZE_HEIGHT)
        auto m = compute_growth(DIM_FREEZE_HEIGHT);
        assert(m.d_model == MAX_D_MODEL);
        assert(m.n_layers == MAX_N_LAYERS);

        // COIN constant matches types.h
        assert(static_cast<int64_t>(consensus::COIN) == flow::COIN);
    }

    // -----------------------------------------------------------------------
    // Test 26: Block header field preservation through signing
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto dims = compute_growth(42);

        CBlockHeader hdr;
        hdr.height = 42;
        hdr.timestamp = GENESIS_TIMESTAMP + 42 * TARGET_BLOCK_TIME;
        hdr.nbits = INITIAL_NBITS;
        hdr.val_loss = 3.5f;
        hdr.prev_val_loss = 3.6f;
        hdr.d_model = dims.d_model;
        hdr.n_layers = dims.n_layers;
        hdr.d_ff = dims.d_ff;
        hdr.n_heads = dims.n_heads;
        hdr.gru_dim = dims.gru_dim;
        hdr.n_slots = dims.n_slots;
        hdr.train_steps = 5000;
        hdr.stagnation = 3;
        hdr.nonce = 99;
        hdr.version = 1;
        hdr.delta_offset = 100;
        hdr.delta_length = 200;
        hdr.sparse_count = 50;
        hdr.sparse_threshold = 0.01f;

        std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);

        auto unsigned_data = hdr.get_unsigned_data();
        assert(unsigned_data.size() == 244);

        auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                                kp.privkey.data(), kp.pubkey.data());
        std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

        // Verify signature
        bool valid = ed25519_verify(unsigned_data.data(), unsigned_data.size(),
                                     hdr.miner_pubkey.data(), hdr.miner_sig.data());
        assert(valid);

        // Hash should include all unsigned fields
        uint256 hash = hdr.get_hash();
        assert(!hash.is_null());

        // Changing any field invalidates the hash
        float saved = hdr.val_loss;
        hdr.val_loss = 4.0f;
        uint256 hash2 = hdr.get_hash();
        assert(hash != hash2);
        hdr.val_loss = saved;
        assert(hdr.get_hash() == hash);
    }

    // -----------------------------------------------------------------------
    // Test 27: Difficulty derivation and comparison
    // -----------------------------------------------------------------------
    {
        arith_uint256 target;
        bool ok = derive_target(INITIAL_NBITS, target);
        assert(ok);

        // Initial difficulty should be 1.0
        double diff = GetDifficulty(INITIAL_NBITS);
        assert(diff >= 0.99 && diff <= 1.01);

        // validate_nbits should accept initial nbits
        assert(validate_nbits(INITIAL_NBITS));

        // compare_difficulty: same difficulty
        assert(compare_difficulty(INITIAL_NBITS, INITIAL_NBITS) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 28: Growth description
    // -----------------------------------------------------------------------
    {
        std::string desc0 = describe_growth(0);
        assert(!desc0.empty());
        assert(desc0.find("growing") != std::string::npos);

        std::string desc1000 = describe_growth(1000);
        assert(!desc1000.empty());
        assert(desc1000.find("frozen") != std::string::npos);
    }

    // -----------------------------------------------------------------------
    // Test 29: Continuous growth — dimensions change every early block
    // -----------------------------------------------------------------------
    {
        // Every block in the growth phase has different dimensions
        assert(dimensions_changed(0, 1));
        assert(dimensions_changed(1, 2));
        assert(dimensions_changed(99, 100));
        assert(dimensions_changed(100, 101));
    }

    // -----------------------------------------------------------------------
    // Test 30: dimensions_changed after freeze — only slots differ
    // -----------------------------------------------------------------------
    {
        // After DIM_FREEZE_HEIGHT, d_model/n_layers are same but slots differ
        assert(dimensions_changed(1000, 1001));   // slots still change
        assert(dimensions_changed(10000, 10001)); // slots still change
    }

    // -----------------------------------------------------------------------
    // Test 31: Growth rate positive for any height
    // -----------------------------------------------------------------------
    {
        assert(compute_growth_rate(0) > 0);
        assert(compute_growth_rate(100) > 0);
        assert(compute_growth_rate(512) > 0);
        assert(compute_growth_rate(10000) > 0);
        assert(compute_growth_rate(100000) > 0);
    }

    // -----------------------------------------------------------------------
    // Test 32: Next halving height
    // -----------------------------------------------------------------------
    {
        assert(get_next_halving_height(0) == 210000);
        assert(get_next_halving_height(100000) == 210000);
        assert(get_next_halving_height(209999) == 210000);
        assert(get_next_halving_height(210000) == 420000);
    }

    // -----------------------------------------------------------------------
    // Test 33: Blocks until halving
    // -----------------------------------------------------------------------
    {
        assert(blocks_until_halving(0) == 210000);
        assert(blocks_until_halving(100000) == 110000);
        assert(blocks_until_halving(209999) == 1);
        assert(blocks_until_halving(210000) == 210000);
    }

    // -----------------------------------------------------------------------
    // Test 34: Subsidy exhaustion check
    // -----------------------------------------------------------------------
    {
        assert(!is_subsidy_exhausted(0));
        assert(!is_subsidy_exhausted(210000));
        assert(is_subsidy_exhausted(210000ULL * 64));
    }

    // -----------------------------------------------------------------------
    // Test 35: Keccak hash properties
    // -----------------------------------------------------------------------
    {
        // Empty input produces a known non-null hash
        uint256 empty_hash = keccak256(nullptr, 0);
        assert(!empty_hash.is_null());

        // Same input produces same hash
        uint8_t data[] = {1, 2, 3};
        uint256 h1 = keccak256(data, 3);
        uint256 h2 = keccak256(data, 3);
        assert(h1 == h2);

        // Different input produces different hash
        uint8_t data2[] = {1, 2, 4};
        uint256 h3 = keccak256(data2, 3);
        assert(h1 != h3);

        // Double hash differs from single hash
        uint256 dh = keccak256d(data, 3);
        assert(dh != h1);
    }

    // -----------------------------------------------------------------------
    // Test 36: Incremental keccak hasher
    // -----------------------------------------------------------------------
    {
        uint8_t data[] = {0x41, 0x42, 0x43, 0x44, 0x45};

        // Single-shot hash
        uint256 single = keccak256(data, 5);

        // Incremental: feed in parts
        CKeccak256 hasher;
        hasher.update(data, 2);
        hasher.update(data + 2, 3);
        uint256 incremental = hasher.finalize();

        assert(single == incremental);
    }

    // -----------------------------------------------------------------------
    // Test 37: Merkle root properties
    // -----------------------------------------------------------------------
    {
        uint256 a = keccak256(reinterpret_cast<const uint8_t*>("a"), 1);
        uint256 b = keccak256(reinterpret_cast<const uint8_t*>("b"), 1);
        uint256 c = keccak256(reinterpret_cast<const uint8_t*>("c"), 1);

        // Order matters
        std::vector<uint256> ab = {a, b};
        std::vector<uint256> ba = {b, a};
        uint256 root_ab = compute_merkle_root(ab);
        uint256 root_ba = compute_merkle_root(ba);
        assert(root_ab != root_ba);

        // Adding a leaf changes the root
        std::vector<uint256> abc = {a, b, c};
        uint256 root_abc = compute_merkle_root(abc);
        assert(root_abc != root_ab);
    }

    // -----------------------------------------------------------------------
    // Test 38: Slot growth — every block, no cap
    // -----------------------------------------------------------------------
    {
        // Slots grow with height, no cap
        auto dims_0 = compute_growth(0);
        assert(dims_0.n_slots == GENESIS_N_SLOTS);

        auto dims_600 = compute_growth(600);
        assert(dims_600.n_slots == GENESIS_N_SLOTS + 600 * SLOT_GROWTH_PER_BLOCK);
        assert(dims_600.n_slots > dims_0.n_slots);

        // No cap — slots at 100K are huge
        auto dims_100k = compute_growth(100000);
        assert(dims_100k.n_slots == GENESIS_N_SLOTS + 100000 * SLOT_GROWTH_PER_BLOCK);
        assert(dims_100k.n_slots > dims_600.n_slots);
    }

    // -----------------------------------------------------------------------
    // Test 39: Compute parameter count is positive and grows
    // -----------------------------------------------------------------------
    {
        auto dims0 = compute_growth(0);
        auto dims4 = compute_growth(400);

        size_t params0 = compute_param_count(dims0);
        size_t params4 = compute_param_count(dims4);

        assert(params0 > 0);
        assert(params4 > params0);  // larger model has more parameters
    }

    // -----------------------------------------------------------------------
    // Test 40: Arith256 basic operations
    // -----------------------------------------------------------------------
    {
        arith_uint256 zero(0);
        arith_uint256 one(1);
        arith_uint256 two(2);

        assert(zero.IsZero());
        assert(!one.IsZero());
        assert(one < two);
        assert(two > one);
        assert(one <= one);
        assert(one >= one);

        arith_uint256 sum = one;
        sum += one;
        assert(sum == two);

        arith_uint256 neg = ~zero;
        assert(!neg.IsZero());
    }
}

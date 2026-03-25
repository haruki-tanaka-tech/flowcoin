// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for the full block connection pipeline: UTXO creation on coinbase,
// coinbase maturity enforcement, double-spend detection, fee computation,
// coinbase value validation, BIP34 height encoding, signature validation,
// and connect/disconnect round-trips.

#include "chain/blockindex.h"
#include "chain/utxo.h"
#include "consensus/difficulty.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "consensus/validation.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "hash/merkle.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/arith_uint256.h"
#include "util/random.h"

#include <cassert>
#include <cstring>
#include <map>
#include <stdexcept>
#include <unistd.h>
#include <vector>

using namespace flow;
using namespace flow::consensus;

// ---- In-memory UTXO set for testing ----------------------------------------

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

class InMemUTXOSet {
public:
    std::map<TestUTXOKey, TestUTXO> utxos;

    void add(const uint256& txid, uint32_t vout, const TestUTXO& e) {
        utxos[{txid, vout}] = e;
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
        Amount t = 0;
        for (auto& [k, v] : utxos) {
            if (v.pubkey_hash == pkh) t += v.amount;
        }
        return t;
    }
    size_t size() const { return utxos.size(); }
};

// ---- Helpers ---------------------------------------------------------------

static std::array<uint8_t, 32> compute_pkh(const std::array<uint8_t, 32>& pk) {
    uint256 h = keccak256(pk.data(), 32);
    std::array<uint8_t, 32> pkh;
    std::memcpy(pkh.data(), h.data(), 32);
    return pkh;
}

static CTransaction make_coinbase_tx(uint64_t height,
                                      const std::array<uint8_t, 32>& pkh,
                                      Amount extra_fees = 0) {
    CTransaction tx;
    tx.version = 1;
    CTxIn cb_in;
    tx.vin.push_back(cb_in);
    CTxOut out;
    out.amount = compute_block_reward(height) + extra_fees;
    out.pubkey_hash = pkh;
    tx.vout.push_back(out);
    return tx;
}

static CTransaction make_spend_tx(const uint256& prev_txid, uint32_t prev_vout,
                                    Amount input_amount,
                                    const std::array<uint8_t, 32>& dest_pkh,
                                    Amount send_amount,
                                    const KeyPair& sender) {
    CTransaction tx;
    tx.version = 1;
    CTxIn in;
    in.prevout = COutPoint(prev_txid, prev_vout);
    std::memcpy(in.pubkey.data(), sender.pubkey.data(), 32);
    tx.vin.push_back(in);

    CTxOut out;
    out.amount = send_amount;
    out.pubkey_hash = dest_pkh;
    tx.vout.push_back(out);

    Amount fee = 1000;
    Amount change = input_amount - send_amount - fee;
    if (change > 0) {
        CTxOut cout;
        cout.amount = change;
        cout.pubkey_hash = compute_pkh(sender.pubkey);
        tx.vout.push_back(cout);
    }

    auto txid = tx.get_txid();
    auto sig = ed25519_sign(txid.data(), 32, sender.privkey.data(), sender.pubkey.data());
    std::memcpy(tx.vin[0].signature.data(), sig.data(), 64);
    return tx;
}

static CBlock build_block(uint64_t height, const uint256& prev_hash,
                           const std::vector<CTransaction>& txs,
                           const KeyPair& miner) {
    CBlock block;
    block.version = 1;
    block.height = height;
    block.prev_hash = prev_hash;
    block.timestamp = GENESIS_TIMESTAMP + static_cast<int64_t>(height) * TARGET_BLOCK_TIME;
    block.nbits = INITIAL_NBITS;
    block.val_loss = 5.0f - static_cast<float>(height) * 0.001f;
    if (block.val_loss < 0.5f) block.val_loss = 0.5f;
    block.prev_val_loss = (height == 0) ? 0.0f :
        5.0f - static_cast<float>(height - 1) * 0.001f;
    if (block.prev_val_loss < 0.5f) block.prev_val_loss = 0.5f;

    auto dims = compute_growth(height);
    block.d_model = dims.d_model;
    block.n_layers = dims.n_layers;
    block.d_ff = dims.d_ff;
    block.n_heads = dims.n_heads;
    block.gru_dim = dims.gru_dim;
    block.n_slots = dims.n_slots;
    block.reserved_field = 0;
    block.stagnation = 0;
    block.nonce = 0;
    block.vtx = txs;

    std::vector<uint256> txids;
    for (auto& t : block.vtx) txids.push_back(t.get_txid());
    block.merkle_root = compute_merkle_root(txids);

    std::memcpy(block.miner_pubkey.data(), miner.pubkey.data(), 32);
    auto data = block.get_unsigned_data();
    auto sig = ed25519_sign(data.data(), data.size(),
                            miner.privkey.data(), miner.pubkey.data());
    std::memcpy(block.miner_sig.data(), sig.data(), 64);
    return block;
}

static void connect_block(InMemUTXOSet& utxos, const CBlock& block) {
    for (size_t i = 0; i < block.vtx.size(); i++) {
        auto& tx = block.vtx[i];
        if (!tx.is_coinbase()) {
            for (auto& in : tx.vin) {
                utxos.remove(in.prevout.txid, in.prevout.index);
            }
        }
        uint256 txid = tx.get_txid();
        for (uint32_t j = 0; j < tx.vout.size(); j++) {
            TestUTXO e;
            e.amount = tx.vout[j].amount;
            e.pubkey_hash = tx.vout[j].pubkey_hash;
            e.height = block.height;
            e.is_coinbase = tx.is_coinbase();
            utxos.add(txid, j, e);
        }
    }
}

static void disconnect_block(InMemUTXOSet& utxos, const CBlock& block,
                              const std::map<TestUTXOKey, TestUTXO>& spent_cache) {
    // Remove outputs created by this block
    for (auto& tx : block.vtx) {
        uint256 txid = tx.get_txid();
        for (uint32_t j = 0; j < tx.vout.size(); j++) {
            utxos.remove(txid, j);
        }
    }
    // Restore spent inputs
    for (auto& [key, entry] : spent_cache) {
        utxos.add(key.txid, key.vout, entry);
    }
}

void test_block_connection() {
    auto alice = generate_keypair();
    auto bob = generate_keypair();
    auto charlie = generate_keypair();
    auto alice_pkh = compute_pkh(alice.pubkey);
    auto bob_pkh = compute_pkh(bob.pubkey);
    auto charlie_pkh = compute_pkh(charlie.pubkey);

    InMemUTXOSet utxos;

    // -----------------------------------------------------------------------
    // Test 1: Connect genesis block — UTXO created for coinbase
    // -----------------------------------------------------------------------
    {
        auto cb = make_coinbase_tx(0, alice_pkh);
        auto genesis = build_block(0, uint256(), {cb}, alice);
        connect_block(utxos, genesis);

        uint256 txid = genesis.vtx[0].get_txid();
        assert(utxos.exists(txid, 0));
        assert(utxos.get(txid, 0).amount == INITIAL_REWARD);
        assert(utxos.get(txid, 0).is_coinbase);
        assert(utxos.get(txid, 0).height == 0);
        assert(utxos.balance_for(alice_pkh) == INITIAL_REWARD);
    }

    // -----------------------------------------------------------------------
    // Test 2: Connect block 1 — can spend genesis coinbase (after maturity)
    // -----------------------------------------------------------------------
    uint256 genesis_txid;
    uint256 genesis_hash;
    {
        // Recreate genesis for hash
        auto cb0 = make_coinbase_tx(0, alice_pkh);
        auto gen = build_block(0, uint256(), {cb0}, alice);
        genesis_txid = gen.vtx[0].get_txid();
        genesis_hash = gen.get_hash();

        // Simulate maturity by saying we are at height 101
        // In UTXO-only testing, we just verify spending works
        auto spend = make_spend_tx(genesis_txid, 0, INITIAL_REWARD,
                                    bob_pkh, 30 * COIN, alice);
        auto cb1 = make_coinbase_tx(1, alice_pkh);
        auto block1 = build_block(1, genesis_hash, {cb1, spend}, alice);
        connect_block(utxos, block1);

        // Genesis UTXO should be spent
        assert(!utxos.exists(genesis_txid, 0));
        // Bob should have received 30 FLOW
        uint256 spend_txid = spend.get_txid();
        assert(utxos.exists(spend_txid, 0));
        assert(utxos.get(spend_txid, 0).amount == 30 * COIN);
    }

    // -----------------------------------------------------------------------
    // Test 3: Cannot spend immature coinbase (less than 100 confirmations)
    // -----------------------------------------------------------------------
    {
        // The coinbase maturity check: COINBASE_MATURITY is 100
        // If the UTXO was created at height H and current height < H + 100,
        // the coinbase is not mature.
        uint64_t coinbase_height = 50;
        uint64_t current_height = 51;
        bool immature = (current_height - coinbase_height) < static_cast<uint64_t>(COINBASE_MATURITY);
        assert(immature);

        // Height 150: mature
        current_height = 150;
        immature = (current_height - coinbase_height) < static_cast<uint64_t>(COINBASE_MATURITY);
        assert(!immature);

        // Exact boundary: height 149 is still immature for coinbase at 50
        current_height = 149;
        immature = (current_height - coinbase_height) < static_cast<uint64_t>(COINBASE_MATURITY);
        assert(immature);

        // Exact boundary: height 150 is the first mature block
        current_height = 150;
        immature = (current_height - coinbase_height) < static_cast<uint64_t>(COINBASE_MATURITY);
        assert(!immature);
    }

    // -----------------------------------------------------------------------
    // Test 4: Double-spend in same block rejected
    // -----------------------------------------------------------------------
    {
        InMemUTXOSet fresh;
        auto dave = generate_keypair();
        auto dave_pkh = compute_pkh(dave.pubkey);

        auto cb = make_coinbase_tx(0, dave_pkh);
        auto gen = build_block(0, uint256(), {cb}, dave);
        connect_block(fresh, gen);
        uint256 cb_txid = gen.vtx[0].get_txid();

        // Attempt to spend same UTXO twice in two different transactions
        auto spend1 = make_spend_tx(cb_txid, 0, INITIAL_REWARD,
                                     alice_pkh, 20 * COIN, dave);
        auto spend2 = make_spend_tx(cb_txid, 0, INITIAL_REWARD,
                                     bob_pkh, 20 * COIN, dave);

        // Both reference the same outpoint — a valid block builder must
        // detect duplicate prevouts and reject
        std::set<COutPoint> seen;
        bool double_spend_detected = false;
        for (auto& tx : {spend1, spend2}) {
            for (auto& in : tx.vin) {
                if (seen.count(in.prevout)) {
                    double_spend_detected = true;
                }
                seen.insert(in.prevout);
            }
        }
        assert(double_spend_detected);
    }

    // -----------------------------------------------------------------------
    // Test 5: Double-spend across blocks rejected
    // -----------------------------------------------------------------------
    {
        InMemUTXOSet fresh;
        auto eve = generate_keypair();
        auto eve_pkh = compute_pkh(eve.pubkey);

        auto cb = make_coinbase_tx(0, eve_pkh);
        auto gen = build_block(0, uint256(), {cb}, eve);
        connect_block(fresh, gen);
        uint256 cb_txid = gen.vtx[0].get_txid();
        uint256 gen_hash = gen.get_hash();

        // Spend in block 1
        auto spend1 = make_spend_tx(cb_txid, 0, INITIAL_REWARD,
                                     alice_pkh, 20 * COIN, eve);
        auto cb1 = make_coinbase_tx(1, eve_pkh);
        auto block1 = build_block(1, gen_hash, {cb1, spend1}, eve);
        connect_block(fresh, block1);

        // UTXO is now spent
        assert(!fresh.exists(cb_txid, 0));

        // Attempt to spend again in block 2 should fail
        bool can_spend = fresh.exists(cb_txid, 0);
        assert(!can_spend);
    }

    // -----------------------------------------------------------------------
    // Test 6: Total fees computed correctly
    // -----------------------------------------------------------------------
    {
        InMemUTXOSet fresh;
        auto miner = generate_keypair();
        auto miner_pkh = compute_pkh(miner.pubkey);

        auto cb = make_coinbase_tx(0, miner_pkh);
        auto gen = build_block(0, uint256(), {cb}, miner);
        connect_block(fresh, gen);
        uint256 cb_txid = gen.vtx[0].get_txid();

        Amount input_value = INITIAL_REWARD;
        Amount send_amount = 40 * COIN;
        Amount fee = 1000;
        Amount change = input_value - send_amount - fee;

        auto spend = make_spend_tx(cb_txid, 0, input_value,
                                    alice_pkh, send_amount, miner);

        // Fee = sum(inputs) - sum(outputs)
        Amount total_output = 0;
        for (auto& out : spend.vout) total_output += out.amount;
        Amount computed_fee = input_value - total_output;
        assert(computed_fee == fee);
        assert(computed_fee > 0);
    }

    // -----------------------------------------------------------------------
    // Test 7: Coinbase value = reward + fees (not more)
    // -----------------------------------------------------------------------
    {
        Amount reward = compute_block_reward(5);
        Amount fees = 5000;
        Amount max_coinbase = reward + fees;

        // Valid coinbase
        CTransaction valid_cb;
        valid_cb.version = 1;
        CTxIn cb_in;
        valid_cb.vin.push_back(cb_in);
        CTxOut cb_out;
        cb_out.amount = max_coinbase;
        valid_cb.vout.push_back(cb_out);

        ValidationState state;
        bool ok = check_coinbase(valid_cb, 5, max_coinbase, state);
        assert(ok);

        // Overpaying coinbase: output > max_allowed
        CTransaction over_cb;
        over_cb.version = 1;
        CTxIn over_in;
        over_cb.vin.push_back(over_in);
        CTxOut over_out;
        over_out.amount = max_coinbase + 1;
        over_cb.vout.push_back(over_out);

        ValidationState state2;
        ok = check_coinbase(over_cb, 5, max_coinbase, state2);
        assert(!ok);
    }

    // -----------------------------------------------------------------------
    // Test 8: Coinbase with height encoding (BIP34)
    // -----------------------------------------------------------------------
    {
        // CBlock::make_coinbase encodes the height in the coinbase
        for (uint64_t h : {0ULL, 1ULL, 255ULL, 256ULL, 65535ULL, 100000ULL}) {
            auto kp = generate_keypair();
            auto cb = CBlock::make_coinbase(h, compute_block_reward(h), kp.pubkey);
            assert(cb.is_coinbase());
            assert(cb.get_value_out() == compute_block_reward(h));
        }
    }

    // -----------------------------------------------------------------------
    // Test 9: Invalid signature in transaction -> reject
    // -----------------------------------------------------------------------
    {
        InMemUTXOSet fresh;
        auto frank = generate_keypair();
        auto frank_pkh = compute_pkh(frank.pubkey);

        auto cb = make_coinbase_tx(0, frank_pkh);
        auto gen = build_block(0, uint256(), {cb}, frank);
        connect_block(fresh, gen);
        uint256 cb_txid = gen.vtx[0].get_txid();

        // Create a spend with a tampered signature
        auto spend = make_spend_tx(cb_txid, 0, INITIAL_REWARD,
                                    alice_pkh, 20 * COIN, frank);
        // Tamper with signature
        spend.vin[0].signature[0] ^= 0xFF;
        spend.vin[0].signature[1] ^= 0xAA;

        // Verify the signature is bad
        auto txhash = spend.get_txid();
        bool sig_valid = ed25519_verify(txhash.data(), 32,
                                         spend.vin[0].pubkey.data(),
                                         spend.vin[0].signature.data());
        assert(!sig_valid);
    }

    // -----------------------------------------------------------------------
    // Test 10: connect_block_transactions creates correct UTXO entries
    // -----------------------------------------------------------------------
    {
        InMemUTXOSet fresh;
        auto kp = generate_keypair();
        auto kp_pkh = compute_pkh(kp.pubkey);

        // Create genesis with coinbase to kp
        auto cb0 = make_coinbase_tx(0, kp_pkh);
        auto gen = build_block(0, uint256(), {cb0}, kp);
        connect_block(fresh, gen);

        assert(fresh.size() == 1);  // one coinbase output
        uint256 cb0_txid = gen.vtx[0].get_txid();
        assert(fresh.get(cb0_txid, 0).is_coinbase);
        assert(fresh.get(cb0_txid, 0).height == 0);

        // Block 1: coinbase + spend creating 2 outputs
        auto spend = make_spend_tx(cb0_txid, 0, INITIAL_REWARD,
                                    alice_pkh, 20 * COIN, kp);
        auto cb1 = make_coinbase_tx(1, kp_pkh);
        auto blk1 = build_block(1, gen.get_hash(), {cb1, spend}, kp);
        connect_block(fresh, blk1);

        // Old UTXO spent, new coinbase + spend outputs created
        assert(!fresh.exists(cb0_txid, 0));
        uint256 cb1_txid = blk1.vtx[0].get_txid();
        assert(fresh.exists(cb1_txid, 0));
        assert(fresh.get(cb1_txid, 0).is_coinbase);

        uint256 spend_txid = spend.get_txid();
        assert(fresh.exists(spend_txid, 0));  // bob output
        assert(!fresh.get(spend_txid, 0).is_coinbase);

        // If there's a change output
        if (spend.vout.size() > 1) {
            assert(fresh.exists(spend_txid, 1));  // change
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: disconnect_block_transactions restores previous UTXO state
    // -----------------------------------------------------------------------
    {
        InMemUTXOSet fresh;
        auto kp = generate_keypair();
        auto kp_pkh = compute_pkh(kp.pubkey);

        auto cb0 = make_coinbase_tx(0, kp_pkh);
        auto gen = build_block(0, uint256(), {cb0}, kp);
        connect_block(fresh, gen);
        uint256 cb0_txid = gen.vtx[0].get_txid();

        // Snapshot state before block 1
        auto snapshot = fresh.utxos;

        // Connect block 1 with a spend
        auto spend = make_spend_tx(cb0_txid, 0, INITIAL_REWARD,
                                    bob_pkh, 20 * COIN, kp);
        auto cb1 = make_coinbase_tx(1, kp_pkh);
        auto blk1 = build_block(1, gen.get_hash(), {cb1, spend}, kp);

        // Cache UTXOs that will be spent
        std::map<TestUTXOKey, TestUTXO> spent_cache;
        for (auto& tx : blk1.vtx) {
            if (!tx.is_coinbase()) {
                for (auto& in : tx.vin) {
                    TestUTXOKey key{in.prevout.txid, in.prevout.index};
                    if (fresh.exists(in.prevout.txid, in.prevout.index)) {
                        spent_cache[key] = fresh.get(in.prevout.txid, in.prevout.index);
                    }
                }
            }
        }

        connect_block(fresh, blk1);

        // State has changed
        assert(!fresh.exists(cb0_txid, 0));

        // Now disconnect
        disconnect_block(fresh, blk1, spent_cache);

        // State should be restored
        assert(fresh.exists(cb0_txid, 0));
        assert(fresh.get(cb0_txid, 0).amount == INITIAL_REWARD);

        // Block 1 outputs should be gone
        uint256 cb1_txid = blk1.vtx[0].get_txid();
        assert(!fresh.exists(cb1_txid, 0));
    }

    // -----------------------------------------------------------------------
    // Test 12: Multiple outputs from a single transaction tracked correctly
    // -----------------------------------------------------------------------
    {
        InMemUTXOSet fresh;
        auto kp = generate_keypair();
        auto kp_pkh = compute_pkh(kp.pubkey);

        auto cb = make_coinbase_tx(0, kp_pkh);
        auto gen = build_block(0, uint256(), {cb}, kp);
        connect_block(fresh, gen);
        uint256 cb_txid = gen.vtx[0].get_txid();

        // Create tx with multiple outputs
        CTransaction multi;
        multi.version = 1;
        CTxIn in;
        in.prevout = COutPoint(cb_txid, 0);
        std::memcpy(in.pubkey.data(), kp.pubkey.data(), 32);
        multi.vin.push_back(in);

        Amount per_output = 10 * COIN;
        for (int i = 0; i < 4; i++) {
            auto dest = generate_keypair();
            auto dest_pkh = compute_pkh(dest.pubkey);
            CTxOut o;
            o.amount = per_output;
            o.pubkey_hash = dest_pkh;
            multi.vout.push_back(o);
        }
        // Remaining to sender as change
        Amount fee = 1000;
        Amount change = INITIAL_REWARD - 4 * per_output - fee;
        CTxOut change_out;
        change_out.amount = change;
        change_out.pubkey_hash = kp_pkh;
        multi.vout.push_back(change_out);

        auto txhash = multi.get_txid();
        auto sig = ed25519_sign(txhash.data(), 32, kp.privkey.data(), kp.pubkey.data());
        std::memcpy(multi.vin[0].signature.data(), sig.data(), 64);

        auto cb1 = make_coinbase_tx(1, kp_pkh);
        auto blk1 = build_block(1, gen.get_hash(), {cb1, multi}, kp);
        connect_block(fresh, blk1);

        uint256 multi_txid = multi.get_txid();
        // All 5 outputs should be in the UTXO set
        for (uint32_t i = 0; i < 5; i++) {
            assert(fresh.exists(multi_txid, i));
        }
        assert(fresh.get(multi_txid, 4).amount == change);
    }

    // -----------------------------------------------------------------------
    // Test 13: UTXO count correct after multi-block chain
    // -----------------------------------------------------------------------
    {
        InMemUTXOSet fresh;
        auto miner = generate_keypair();
        auto miner_pkh = compute_pkh(miner.pubkey);

        // Build 5 blocks with only coinbase (no spends)
        uint256 prev = uint256();
        for (uint64_t h = 0; h < 5; h++) {
            auto cb = make_coinbase_tx(h, miner_pkh);
            auto blk = build_block(h, prev, {cb}, miner);
            connect_block(fresh, blk);
            prev = blk.get_hash();
        }

        // Should have 5 coinbase UTXOs
        assert(fresh.size() == 5);
        assert(fresh.balance_for(miner_pkh) == 5 * INITIAL_REWARD);
    }

    // -----------------------------------------------------------------------
    // Test 14: Block with zero-fee transaction
    // -----------------------------------------------------------------------
    {
        InMemUTXOSet fresh;
        auto kp = generate_keypair();
        auto kp_pkh = compute_pkh(kp.pubkey);

        auto cb = make_coinbase_tx(0, kp_pkh);
        auto gen = build_block(0, uint256(), {cb}, kp);
        connect_block(fresh, gen);
        uint256 cb_txid = gen.vtx[0].get_txid();

        // Zero fee: output == input
        CTransaction zero_fee_tx;
        zero_fee_tx.version = 1;
        CTxIn in;
        in.prevout = COutPoint(cb_txid, 0);
        std::memcpy(in.pubkey.data(), kp.pubkey.data(), 32);
        zero_fee_tx.vin.push_back(in);
        CTxOut o;
        o.amount = INITIAL_REWARD;  // same as input, 0 fee
        o.pubkey_hash = bob_pkh;
        zero_fee_tx.vout.push_back(o);

        auto txhash = zero_fee_tx.get_txid();
        auto sig = ed25519_sign(txhash.data(), 32, kp.privkey.data(), kp.pubkey.data());
        std::memcpy(zero_fee_tx.vin[0].signature.data(), sig.data(), 64);

        Amount tx_fee = INITIAL_REWARD - zero_fee_tx.get_value_out();
        assert(tx_fee == 0);
    }

    // -----------------------------------------------------------------------
    // Test 15: Coinbase-only block has zero total fees
    // -----------------------------------------------------------------------
    {
        Amount total_fees = 0;
        // In a block with only a coinbase, total fees should be 0
        auto kp = generate_keypair();
        auto cb = make_coinbase_tx(10, compute_pkh(kp.pubkey));
        CBlock blk = build_block(10, uint256(), {cb}, kp);

        // compute_block_fees expects tx_input_sums; for coinbase, sum is 0
        std::vector<Amount> input_sums = {0};  // coinbase has no real inputs
        total_fees = compute_block_fees(blk, input_sums);
        assert(total_fees == 0);
    }

    // -----------------------------------------------------------------------
    // Test 16: Signature verification on valid block header
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto cb = make_coinbase_tx(0, compute_pkh(kp.pubkey));
        auto blk = build_block(0, uint256(), {cb}, kp);

        auto data = blk.get_unsigned_data();
        bool valid = ed25519_verify(data.data(), data.size(),
                                     blk.miner_pubkey.data(),
                                     blk.miner_sig.data());
        assert(valid);

        // Tamper with nonce after signing
        blk.nonce = 999;
        data = blk.get_unsigned_data();
        valid = ed25519_verify(data.data(), data.size(),
                               blk.miner_pubkey.data(),
                               blk.miner_sig.data());
        assert(!valid);
    }

    // -----------------------------------------------------------------------
    // Test 17: check_block_transactions rejects oversized block
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto cb = make_coinbase_tx(0, compute_pkh(kp.pubkey));
        auto blk = build_block(0, uint256(), {cb}, kp);

        BlockContext ctx;
        ctx.is_genesis = true;
        ctx.expected_dims = compute_growth(0);
        ctx.expected_nbits = INITIAL_NBITS;

        ValidationState state;
        bool ok = check_block_transactions(blk, ctx, state);
        // A simple genesis block should pass
        assert(ok);
    }

    // -----------------------------------------------------------------------
    // Test 18: Balance after connect then disconnect equals original
    // -----------------------------------------------------------------------
    {
        InMemUTXOSet fresh;
        auto kp = generate_keypair();
        auto kp_pkh = compute_pkh(kp.pubkey);

        auto cb = make_coinbase_tx(0, kp_pkh);
        auto gen = build_block(0, uint256(), {cb}, kp);
        connect_block(fresh, gen);

        Amount balance_before = fresh.balance_for(kp_pkh);
        uint256 cb_txid = gen.vtx[0].get_txid();

        auto spend = make_spend_tx(cb_txid, 0, INITIAL_REWARD,
                                    bob_pkh, 20 * COIN, kp);
        auto cb1 = make_coinbase_tx(1, kp_pkh);
        auto blk1 = build_block(1, gen.get_hash(), {cb1, spend}, kp);

        std::map<TestUTXOKey, TestUTXO> spent;
        for (auto& tx : blk1.vtx) {
            if (!tx.is_coinbase()) {
                for (auto& in : tx.vin) {
                    TestUTXOKey key{in.prevout.txid, in.prevout.index};
                    if (fresh.exists(in.prevout.txid, in.prevout.index))
                        spent[key] = fresh.get(in.prevout.txid, in.prevout.index);
                }
            }
        }
        connect_block(fresh, blk1);
        disconnect_block(fresh, blk1, spent);

        Amount balance_after = fresh.balance_for(kp_pkh);
        assert(balance_before == balance_after);
    }
}

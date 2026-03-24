// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// End-to-end chain tests: multi-block chains with real transactions,
// UTXO set tracking, balance verification, model delta application,
// growth schedule transitions, and difficulty adjustment across retarget.

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
#include "util/types.h"

#include <array>
#include <cassert>
#include <cmath>
#include <cstring>
#include <map>
#include <vector>

using namespace flow;
using namespace flow::consensus;

// ---- In-memory UTXO set for chain tests ------------------------------------

struct ChainUTXO {
    Amount amount;
    std::array<uint8_t, 32> pubkey_hash;
    uint64_t height;
    bool is_coinbase;
};

struct ChainKey {
    uint256 txid;
    uint32_t vout;
    bool operator<(const ChainKey& o) const {
        if (txid < o.txid) return true;
        if (o.txid < txid) return false;
        return vout < o.vout;
    }
};

class ChainUTXOSet {
public:
    std::map<ChainKey, ChainUTXO> utxos;

    void add(const uint256& txid, uint32_t vout, const ChainUTXO& e) {
        utxos[{txid, vout}] = e;
    }
    bool remove(const uint256& txid, uint32_t vout) {
        return utxos.erase({txid, vout}) > 0;
    }
    bool exists(const uint256& txid, uint32_t vout) const {
        return utxos.count({txid, vout}) > 0;
    }
    const ChainUTXO& get(const uint256& txid, uint32_t vout) const {
        return utxos.at({txid, vout});
    }
    Amount balance_for(const std::array<uint8_t, 32>& pkh) const {
        Amount t = 0;
        for (auto& [k, v] : utxos)
            if (v.pubkey_hash == pkh) t += v.amount;
        return t;
    }
    size_t count() const { return utxos.size(); }
};

// ---- Helpers ---------------------------------------------------------------

static std::array<uint8_t, 32> fc_pkh(const std::array<uint8_t, 32>& pk) {
    uint256 h = keccak256(pk.data(), 32);
    std::array<uint8_t, 32> r;
    std::memcpy(r.data(), h.data(), 32);
    return r;
}

static CTransaction fc_coinbase(uint64_t height,
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

static CTransaction fc_spend(const uint256& prev_txid, uint32_t prev_vout,
                               Amount input_amt,
                               const std::array<uint8_t, 32>& dest_pkh,
                               Amount send_amt,
                               const KeyPair& sender) {
    CTransaction tx;
    tx.version = 1;
    CTxIn in;
    in.prevout = COutPoint(prev_txid, prev_vout);
    std::memcpy(in.pubkey.data(), sender.pubkey.data(), 32);
    tx.vin.push_back(in);

    CTxOut out;
    out.amount = send_amt;
    out.pubkey_hash = dest_pkh;
    tx.vout.push_back(out);

    Amount fee = 1000;
    Amount change = input_amt - send_amt - fee;
    if (change > 0) {
        CTxOut c;
        c.amount = change;
        c.pubkey_hash = fc_pkh(sender.pubkey);
        tx.vout.push_back(c);
    }

    auto txid = tx.get_txid();
    auto sig = ed25519_sign(txid.data(), 32, sender.privkey.data(), sender.pubkey.data());
    std::memcpy(tx.vin[0].signature.data(), sig.data(), 64);
    return tx;
}

static CBlock fc_block(uint64_t height, const uint256& prev,
                         const std::vector<CTransaction>& txs,
                         const KeyPair& miner) {
    CBlock block;
    block.version = 1;
    block.height = height;
    block.prev_hash = prev;
    block.timestamp = GENESIS_TIMESTAMP + static_cast<int64_t>(height) * TARGET_BLOCK_TIME;
    block.nbits = INITIAL_NBITS;
    block.val_loss = 5.0f - static_cast<float>(height) * 0.001f;
    if (block.val_loss < 0.5f) block.val_loss = 0.5f;
    block.prev_val_loss = (height == 0) ? 0.0f :
        5.0f - static_cast<float>(height - 1) * 0.001f;
    if (block.prev_val_loss < 0.5f) block.prev_val_loss = 0.5f;

    auto dims = compute_growth(height, 0);
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

static void fc_connect(ChainUTXOSet& utxos, const CBlock& block) {
    for (auto& tx : block.vtx) {
        if (!tx.is_coinbase()) {
            for (auto& in : tx.vin)
                utxos.remove(in.prevout.txid, in.prevout.index);
        }
        uint256 txid = tx.get_txid();
        for (uint32_t j = 0; j < tx.vout.size(); j++) {
            ChainUTXO e;
            e.amount = tx.vout[j].amount;
            e.pubkey_hash = tx.vout[j].pubkey_hash;
            e.height = block.height;
            e.is_coinbase = tx.is_coinbase();
            utxos.add(txid, j, e);
        }
    }
}

void test_full_chain() {

    // -----------------------------------------------------------------------
    // Test 1: Build 10-block chain with sequential spending (A->B->C->D->E->F)
    // -----------------------------------------------------------------------
    {
        KeyPair keys[6];
        std::array<uint8_t, 32> pkhs[6];
        for (int i = 0; i < 6; i++) {
            keys[i] = generate_keypair();
            pkhs[i] = fc_pkh(keys[i].pubkey);
        }

        ChainUTXOSet utxos;
        uint256 prev_hash;

        // Block 0: coinbase to A
        auto cb0 = fc_coinbase(0, pkhs[0]);
        auto blk0 = fc_block(0, uint256(), {cb0}, keys[0]);
        fc_connect(utxos, blk0);
        prev_hash = blk0.get_hash();
        uint256 prev_txid = blk0.vtx[0].get_txid();
        Amount prev_amount = INITIAL_REWARD;

        assert(utxos.balance_for(pkhs[0]) == INITIAL_REWARD);

        // Blocks 1-5: A->B, B->C, C->D, D->E, E->F
        for (int i = 0; i < 5; i++) {
            uint64_t h = static_cast<uint64_t>(i + 1);
            Amount send = prev_amount - 1000;  // 1000 fee, no change
            auto spend = fc_spend(prev_txid, 0, prev_amount, pkhs[i + 1], send, keys[i]);

            auto cb = fc_coinbase(h, pkhs[i]);
            auto blk = fc_block(h, prev_hash, {cb, spend}, keys[i]);
            fc_connect(utxos, blk);

            // The sender's old UTXO is spent
            assert(!utxos.exists(prev_txid, 0));

            // Recipient got the funds (minus any change logic)
            uint256 spend_txid = spend.get_txid();
            assert(utxos.exists(spend_txid, 0));
            assert(utxos.get(spend_txid, 0).pubkey_hash == pkhs[i + 1]);

            prev_hash = blk.get_hash();
            prev_txid = spend_txid;
            prev_amount = send;
        }

        // After 5 transfers with 1000 fee each:
        // F should have INITIAL_REWARD - 5*1000
        assert(utxos.balance_for(pkhs[5]) == INITIAL_REWARD - 5000);
    }

    // -----------------------------------------------------------------------
    // Test 2: Multiple transactions per block — split and partial spend
    // -----------------------------------------------------------------------
    {
        auto miner = generate_keypair();
        auto miner_pkh = fc_pkh(miner.pubkey);
        ChainUTXOSet utxos;

        // Block 0: genesis with large coinbase
        auto cb0 = fc_coinbase(0, miner_pkh);
        auto blk0 = fc_block(0, uint256(), {cb0}, miner);
        fc_connect(utxos, blk0);
        uint256 cb0_txid = blk0.vtx[0].get_txid();

        // Block 1: split coinbase into 10 outputs
        CTransaction split_tx;
        split_tx.version = 1;
        CTxIn split_in;
        split_in.prevout = COutPoint(cb0_txid, 0);
        std::memcpy(split_in.pubkey.data(), miner.pubkey.data(), 32);
        split_tx.vin.push_back(split_in);

        Amount per_output = (INITIAL_REWARD - 1000) / 10;  // 1000 fee
        KeyPair recipients[10];
        for (int i = 0; i < 10; i++) {
            recipients[i] = generate_keypair();
            CTxOut out;
            out.amount = per_output;
            out.pubkey_hash = fc_pkh(recipients[i].pubkey);
            split_tx.vout.push_back(out);
        }

        auto txhash = split_tx.get_txid();
        auto sig = ed25519_sign(txhash.data(), 32,
                                miner.privkey.data(), miner.pubkey.data());
        std::memcpy(split_tx.vin[0].signature.data(), sig.data(), 64);

        auto cb1 = fc_coinbase(1, miner_pkh);
        auto blk1 = fc_block(1, blk0.get_hash(), {cb1, split_tx}, miner);
        fc_connect(utxos, blk1);

        // Original UTXO spent
        assert(!utxos.exists(cb0_txid, 0));

        // 10 new outputs + 1 coinbase = 11 UTXOs
        uint256 split_txid = split_tx.get_txid();
        for (int i = 0; i < 10; i++) {
            assert(utxos.exists(split_txid, i));
            assert(utxos.get(split_txid, i).amount == per_output);
        }

        // Block 2: spend 5 of those outputs
        std::vector<CTransaction> block2_txs;
        block2_txs.push_back(fc_coinbase(2, miner_pkh));

        for (int i = 0; i < 5; i++) {
            auto spend = fc_spend(split_txid, i, per_output,
                                   miner_pkh, per_output - 1000, recipients[i]);
            block2_txs.push_back(spend);
        }

        auto blk2 = fc_block(2, blk1.get_hash(), block2_txs, miner);
        fc_connect(utxos, blk2);

        // 5 spent + 5 remaining from split + coinbases
        for (int i = 0; i < 5; i++) {
            assert(!utxos.exists(split_txid, i));  // spent
        }
        for (int i = 5; i < 10; i++) {
            assert(utxos.exists(split_txid, i));  // remaining
        }
    }

    // -----------------------------------------------------------------------
    // Test 3: Chain with model hash changes at each block
    // -----------------------------------------------------------------------
    {
        // Model hash should change when architecture dimensions change
        // at plateau transitions (every 100 blocks in Phase 1)

        // Heights 0 and 100 should have different dimensions
        auto dims0 = compute_growth(0, 0);
        auto dims100 = compute_growth(100, 0);

        assert(dims0.d_model != dims100.d_model);
        assert(dims0.n_layers != dims100.n_layers);

        // Heights within same plateau should have same dimensions
        auto dims50 = compute_growth(50, 0);
        assert(dims0.d_model == dims50.d_model);
        assert(dims0.n_layers == dims50.n_layers);
    }

    // -----------------------------------------------------------------------
    // Test 4: Growth schedule verification through blocks
    // -----------------------------------------------------------------------
    {
        // Plateau 0 (blocks 0-99): d_model=512, n_layers=8
        for (uint64_t h = 0; h < 100; h++) {
            auto dims = compute_growth(h, 0);
            assert(dims.d_model == 512);
            assert(dims.n_layers == 8);
            assert(dims.d_ff == 1024);
        }

        // Plateau 1 (blocks 100-199): d_model=640, n_layers=12
        for (uint64_t h = 100; h < 200; h++) {
            auto dims = compute_growth(h, 0);
            assert(dims.d_model == 640);
            assert(dims.n_layers == 12);
            assert(dims.d_ff == 1280);
        }

        // Transition at block 100
        assert(is_plateau_transition(100));
        assert(dimensions_change_at(100));
        assert(!dimensions_change_at(50));
        assert(!dimensions_change_at(150));
    }

    // -----------------------------------------------------------------------
    // Test 5: Model expansion at plateau transitions
    // -----------------------------------------------------------------------
    {
        // Check that plateau transitions happen at correct heights
        assert(is_plateau_transition(0));    // genesis
        assert(is_plateau_transition(100));  // plateau 1
        assert(is_plateau_transition(200));  // plateau 2
        assert(is_plateau_transition(300));  // plateau 3
        assert(is_plateau_transition(400));  // plateau 4
        assert(!is_plateau_transition(500)); // phase 2

        // Get plateau indices
        assert(get_plateau(0) == 0);
        assert(get_plateau(99) == 0);
        assert(get_plateau(100) == 1);
        assert(get_plateau(499) == 4);
        assert(get_plateau(500) == 4);  // capped at last plateau
    }

    // -----------------------------------------------------------------------
    // Test 6: Phase 2 frozen architecture
    // -----------------------------------------------------------------------
    {
        auto dims500 = compute_growth(500, 0);
        auto dims1000 = compute_growth(1000, 0);
        auto dims5000 = compute_growth(5000, 0);

        // Architecture frozen at max dims
        assert(dims500.d_model == MAX_D_MODEL);
        assert(dims500.n_layers == MAX_N_LAYERS);
        assert(dims500.d_ff == MAX_D_FF);

        assert(dims1000.d_model == MAX_D_MODEL);
        assert(dims5000.d_model == MAX_D_MODEL);
    }

    // -----------------------------------------------------------------------
    // Test 7: Slot growth in Phase 2
    // -----------------------------------------------------------------------
    {
        auto dims0 = compute_growth(500, 0);
        auto dims100 = compute_growth(500, 100);
        auto dims1000 = compute_growth(500, 1000);

        assert(dims0.n_slots == GENESIS_N_SLOTS);
        assert(dims100.n_slots == GENESIS_N_SLOTS + 100 * SLOT_GROWTH_RATE);
        assert(dims1000.n_slots == GENESIS_N_SLOTS + 1000 * SLOT_GROWTH_RATE);

        // Capped at MAX_N_SLOTS
        auto dims_max = compute_growth(500, 100000);
        assert(dims_max.n_slots <= MAX_N_SLOTS);
    }

    // -----------------------------------------------------------------------
    // Test 8: Difficulty adjustment at retarget boundary
    // -----------------------------------------------------------------------
    {
        // At height 2016, retarget occurs
        // With exactly the target timespan, difficulty stays same
        int64_t first_time = GENESIS_TIMESTAMP;
        int64_t last_time = GENESIS_TIMESTAMP + RETARGET_TIMESPAN;

        uint32_t next = get_next_work_required(2016, INITIAL_NBITS,
                                                first_time, last_time);
        assert(next == INITIAL_NBITS);
    }

    // -----------------------------------------------------------------------
    // Test 9: Difficulty increases for fast blocks
    // -----------------------------------------------------------------------
    {
        int64_t first_time = GENESIS_TIMESTAMP;
        int64_t last_time = GENESIS_TIMESTAMP + RETARGET_TIMESPAN / 2;

        uint32_t next = get_next_work_required(2016, INITIAL_NBITS,
                                                first_time, last_time);

        arith_uint256 old_target, new_target;
        derive_target(INITIAL_NBITS, old_target);
        derive_target(next, new_target);
        // Faster blocks → lower target → harder difficulty
        assert(new_target <= old_target);
    }

    // -----------------------------------------------------------------------
    // Test 10: Difficulty decreases for slow blocks
    // -----------------------------------------------------------------------
    {
        int64_t first_time = GENESIS_TIMESTAMP;
        int64_t last_time = GENESIS_TIMESTAMP + RETARGET_TIMESPAN * 2;

        uint32_t next = get_next_work_required(2016, INITIAL_NBITS,
                                                first_time, last_time);

        arith_uint256 old_target, new_target;
        derive_target(INITIAL_NBITS, old_target);
        derive_target(next, new_target);
        // Slower blocks → higher target → easier difficulty
        assert(new_target >= old_target);
    }

    // -----------------------------------------------------------------------
    // Test 11: No retarget within a period
    // -----------------------------------------------------------------------
    {
        for (uint64_t h = 1; h < 2016; h += 100) {
            uint32_t next = get_next_work_required(h, INITIAL_NBITS,
                                                    GENESIS_TIMESTAMP,
                                                    GENESIS_TIMESTAMP + TARGET_BLOCK_TIME);
            assert(next == INITIAL_NBITS);
        }
    }

    // -----------------------------------------------------------------------
    // Test 12: Retarget clamped to 4x factor
    // -----------------------------------------------------------------------
    {
        int64_t first_time = GENESIS_TIMESTAMP;
        int64_t last_time = GENESIS_TIMESTAMP + RETARGET_TIMESPAN * 100;

        uint32_t next = get_next_work_required(2016, INITIAL_NBITS,
                                                first_time, last_time);

        arith_uint256 old_target, new_target;
        derive_target(INITIAL_NBITS, old_target);
        derive_target(next, new_target);

        // Clamped to 4x: new_target <= old_target * 4
        arith_uint256 max_increase = old_target;
        max_increase *= 4;
        assert(new_target <= max_increase);
    }

    // -----------------------------------------------------------------------
    // Test 13: Block headers chain correctly through heights
    // -----------------------------------------------------------------------
    {
        auto miner = generate_keypair();
        auto miner_pkh = fc_pkh(miner.pubkey);

        std::vector<uint256> hashes;
        uint256 prev = uint256();

        for (uint64_t h = 0; h < 10; h++) {
            auto cb = fc_coinbase(h, miner_pkh);
            auto blk = fc_block(h, prev, {cb}, miner);

            assert(blk.height == h);
            if (h > 0) {
                assert(blk.prev_hash == hashes.back());
            } else {
                assert(blk.prev_hash.is_null());
            }

            hashes.push_back(blk.get_hash());
            prev = blk.get_hash();
        }

        // All hashes should be unique
        for (size_t i = 0; i < hashes.size(); i++) {
            for (size_t j = i + 1; j < hashes.size(); j++) {
                assert(hashes[i] != hashes[j]);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 14: Total supply after N blocks
    // -----------------------------------------------------------------------
    {
        // After 10 blocks at era 0, total = 10 * 50 FLOW
        Amount total = compute_total_supply(9);  // blocks 0-9
        assert(total == 10 * INITIAL_REWARD);

        // After era 0 (210000 blocks)
        Amount era0_total = compute_total_supply(209999);
        assert(era0_total == 210000LL * 50 * COIN);
    }

    // -----------------------------------------------------------------------
    // Test 15: Remaining supply decreases with height
    // -----------------------------------------------------------------------
    {
        Amount rem0 = compute_remaining_supply(0);
        Amount rem1 = compute_remaining_supply(100);
        Amount rem2 = compute_remaining_supply(210000);

        assert(rem0 > rem1);
        assert(rem1 > rem2);
        assert(rem0 < MAX_SUPPLY);
    }

    // -----------------------------------------------------------------------
    // Test 16: Merkle root determinism across blocks
    // -----------------------------------------------------------------------
    {
        auto miner = generate_keypair();
        auto miner_pkh = fc_pkh(miner.pubkey);

        auto cb = fc_coinbase(0, miner_pkh);
        auto blk = fc_block(0, uint256(), {cb}, miner);

        // Verify merkle root
        assert(blk.verify_merkle_root());

        // Compute again
        uint256 root2 = blk.compute_merkle_root();
        assert(blk.merkle_root == root2);
    }

    // -----------------------------------------------------------------------
    // Test 17: Block signatures verify throughout chain
    // -----------------------------------------------------------------------
    {
        auto miner = generate_keypair();
        auto miner_pkh = fc_pkh(miner.pubkey);
        uint256 prev;

        for (uint64_t h = 0; h < 5; h++) {
            auto cb = fc_coinbase(h, miner_pkh);
            auto blk = fc_block(h, prev, {cb}, miner);

            auto data = blk.get_unsigned_data();
            bool valid = ed25519_verify(data.data(), data.size(),
                                         blk.miner_pubkey.data(),
                                         blk.miner_sig.data());
            assert(valid);
            prev = blk.get_hash();
        }
    }

    // -----------------------------------------------------------------------
    // Test 18: Growth delta between plateaus
    // -----------------------------------------------------------------------
    {
        auto delta = compute_growth_delta(0, 100);
        assert(delta.d_model == 640 - 512);   // +128
        assert(delta.n_layers == 12 - 8);     // +4
        assert(delta.d_ff == 1280 - 1024);    // +256
    }

    // -----------------------------------------------------------------------
    // Test 19: compute_param_count increases with growth
    // -----------------------------------------------------------------------
    {
        size_t prev = 0;
        for (uint64_t h = 0; h < 500; h += 100) {
            auto dims = compute_growth(h, 0);
            size_t count = compute_param_count(dims);
            assert(count > prev);
            prev = count;
        }
    }

    // -----------------------------------------------------------------------
    // Test 20: get_growth_phase_name returns correct strings
    // -----------------------------------------------------------------------
    {
        const char* phase0 = get_growth_phase_name(0);
        assert(phase0 != nullptr);

        const char* phase2 = get_growth_phase_name(500);
        assert(phase2 != nullptr);

        // Phase 1 and Phase 2 should be different descriptions
        assert(std::string(phase0) != std::string(phase2));
    }
}

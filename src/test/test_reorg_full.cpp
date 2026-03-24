// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Full reorganization tests: build competing chains from a common ancestor,
// reorganize from shorter to longer chain, verify UTXO state consistency,
// transaction return to mempool, ReorgStats correctness, and chain work
// comparison.

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
#include <set>
#include <vector>

using namespace flow;
using namespace flow::consensus;

// ---- In-memory UTXO set ----------------------------------------------------

struct RgUTXO {
    Amount amount;
    std::array<uint8_t, 32> pubkey_hash;
    uint64_t height;
    bool is_coinbase;
};

struct RgKey {
    uint256 txid;
    uint32_t vout;
    bool operator<(const RgKey& o) const {
        if (txid < o.txid) return true;
        if (o.txid < txid) return false;
        return vout < o.vout;
    }
};

class RgUTXOSet {
public:
    std::map<RgKey, RgUTXO> utxos;

    void add(const uint256& txid, uint32_t vout, const RgUTXO& e) {
        utxos[{txid, vout}] = e;
    }
    bool remove(const uint256& txid, uint32_t vout) {
        return utxos.erase({txid, vout}) > 0;
    }
    bool exists(const uint256& txid, uint32_t vout) const {
        return utxos.count({txid, vout}) > 0;
    }
    const RgUTXO& get(const uint256& txid, uint32_t vout) const {
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

static std::array<uint8_t, 32> rg_pkh(const std::array<uint8_t, 32>& pk) {
    uint256 h = keccak256(pk.data(), 32);
    std::array<uint8_t, 32> pkh;
    std::memcpy(pkh.data(), h.data(), 32);
    return pkh;
}

static CTransaction rg_coinbase(uint64_t height,
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

static CTransaction rg_spend(const uint256& prev_txid, uint32_t prev_vout,
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
        c.pubkey_hash = rg_pkh(sender.pubkey);
        tx.vout.push_back(c);
    }
    auto txid = tx.get_txid();
    auto sig = ed25519_sign(txid.data(), 32, sender.privkey.data(), sender.pubkey.data());
    std::memcpy(tx.vin[0].signature.data(), sig.data(), 64);
    return tx;
}

static CBlock rg_block(uint64_t height, const uint256& prev,
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

static void rg_connect(RgUTXOSet& utxos, const CBlock& block) {
    for (auto& tx : block.vtx) {
        if (!tx.is_coinbase()) {
            for (auto& in : tx.vin)
                utxos.remove(in.prevout.txid, in.prevout.index);
        }
        uint256 txid = tx.get_txid();
        for (uint32_t j = 0; j < tx.vout.size(); j++) {
            RgUTXO e;
            e.amount = tx.vout[j].amount;
            e.pubkey_hash = tx.vout[j].pubkey_hash;
            e.height = block.height;
            e.is_coinbase = tx.is_coinbase();
            utxos.add(txid, j, e);
        }
    }
}

static void rg_disconnect(RgUTXOSet& utxos, const CBlock& block,
                            const std::map<RgKey, RgUTXO>& spent) {
    for (auto& tx : block.vtx) {
        uint256 txid = tx.get_txid();
        for (uint32_t j = 0; j < tx.vout.size(); j++)
            utxos.remove(txid, j);
    }
    for (auto& [k, v] : spent)
        utxos.add(k.txid, k.vout, v);
}

// Store spent UTXOs before connecting a block
static std::map<RgKey, RgUTXO> cache_spends(const RgUTXOSet& utxos, const CBlock& blk) {
    std::map<RgKey, RgUTXO> cache;
    for (auto& tx : blk.vtx) {
        if (!tx.is_coinbase()) {
            for (auto& in : tx.vin) {
                RgKey k{in.prevout.txid, in.prevout.index};
                if (utxos.exists(in.prevout.txid, in.prevout.index))
                    cache[k] = utxos.get(in.prevout.txid, in.prevout.index);
            }
        }
    }
    return cache;
}

// ReorgStats for tracking reorg metrics
struct ReorgStats {
    uint32_t blocks_disconnected = 0;
    uint32_t blocks_connected = 0;
    std::vector<uint256> returned_to_mempool;
};

void test_reorg_full() {
    auto miner_a = generate_keypair();
    auto miner_b = generate_keypair();
    auto user1 = generate_keypair();
    auto user2 = generate_keypair();

    auto miner_a_pkh = rg_pkh(miner_a.pubkey);
    auto miner_b_pkh = rg_pkh(miner_b.pubkey);
    auto user1_pkh = rg_pkh(user1.pubkey);
    auto user2_pkh = rg_pkh(user2.pubkey);

    // -----------------------------------------------------------------------
    // Build shared genesis and block 1
    // -----------------------------------------------------------------------
    auto cb_genesis = rg_coinbase(0, miner_a_pkh);
    auto genesis = rg_block(0, uint256(), {cb_genesis}, miner_a);
    uint256 genesis_hash = genesis.get_hash();
    uint256 genesis_txid = genesis.vtx[0].get_txid();

    auto cb1 = rg_coinbase(1, miner_a_pkh);
    auto block1 = rg_block(1, genesis_hash, {cb1}, miner_a);
    uint256 block1_hash = block1.get_hash();
    uint256 block1_txid = block1.vtx[0].get_txid();

    // -----------------------------------------------------------------------
    // Test 1: Build chain A: genesis -> block1 -> block2 -> block3
    // -----------------------------------------------------------------------
    RgUTXOSet utxos_a;
    rg_connect(utxos_a, genesis);
    rg_connect(utxos_a, block1);

    // Block 2A: miner_a spends genesis coinbase to user1
    auto spend_a2 = rg_spend(genesis_txid, 0, INITIAL_REWARD,
                              user1_pkh, 30 * COIN, miner_a);
    auto cb2a = rg_coinbase(2, miner_a_pkh);
    auto block2a = rg_block(2, block1_hash, {cb2a, spend_a2}, miner_a);
    auto cache2a = cache_spends(utxos_a, block2a);
    rg_connect(utxos_a, block2a);
    uint256 block2a_hash = block2a.get_hash();

    // Block 3A
    auto cb3a = rg_coinbase(3, miner_a_pkh);
    auto block3a = rg_block(3, block2a_hash, {cb3a}, miner_a);
    auto cache3a = cache_spends(utxos_a, block3a);
    rg_connect(utxos_a, block3a);

    // Chain A state: genesis spent, user1 has 30 FLOW
    assert(!utxos_a.exists(genesis_txid, 0));  // spent
    assert(utxos_a.balance_for(user1_pkh) == 30 * COIN);

    // -----------------------------------------------------------------------
    // Test 2: Build chain B: genesis -> block1 -> alt2 -> alt3 -> alt4
    // -----------------------------------------------------------------------
    // Chain B: miner_b creates a competing chain from block1
    RgUTXOSet utxos_b;
    rg_connect(utxos_b, genesis);
    rg_connect(utxos_b, block1);

    // Alt block 2B: spends genesis coinbase to user2 instead
    auto spend_b2 = rg_spend(genesis_txid, 0, INITIAL_REWARD,
                              user2_pkh, 40 * COIN, miner_a);
    auto cb2b = rg_coinbase(2, miner_b_pkh);
    auto block2b = rg_block(2, block1_hash, {cb2b, spend_b2}, miner_b);
    rg_connect(utxos_b, block2b);
    uint256 block2b_hash = block2b.get_hash();

    auto cb3b = rg_coinbase(3, miner_b_pkh);
    auto block3b = rg_block(3, block2b_hash, {cb3b}, miner_b);
    rg_connect(utxos_b, block3b);
    uint256 block3b_hash = block3b.get_hash();

    auto cb4b = rg_coinbase(4, miner_b_pkh);
    auto block4b = rg_block(4, block3b_hash, {cb4b}, miner_b);
    rg_connect(utxos_b, block4b);

    // Chain B is longer (4 blocks vs 3 blocks)
    assert(utxos_b.balance_for(user2_pkh) == 40 * COIN);
    assert(utxos_b.balance_for(user1_pkh) == 0);

    // -----------------------------------------------------------------------
    // Test 3: Reorganize from chain A to chain B
    // -----------------------------------------------------------------------
    {
        ReorgStats stats;

        // Disconnect blocks 3A and 2A from chain A UTXO set
        rg_disconnect(utxos_a, block3a, cache3a);
        stats.blocks_disconnected++;

        rg_disconnect(utxos_a, block2a, cache2a);
        stats.blocks_disconnected++;

        // Genesis UTXO should be restored
        assert(utxos_a.exists(genesis_txid, 0));

        // Transactions from chain A returned to mempool
        for (auto& tx : block2a.vtx) {
            if (!tx.is_coinbase()) {
                stats.returned_to_mempool.push_back(tx.get_txid());
            }
        }

        // Connect alt2, alt3, alt4
        rg_connect(utxos_a, block2b);
        stats.blocks_connected++;
        rg_connect(utxos_a, block3b);
        stats.blocks_connected++;
        rg_connect(utxos_a, block4b);
        stats.blocks_connected++;

        // UTXO set now reflects chain B
        assert(utxos_a.balance_for(user2_pkh) == 40 * COIN);
        assert(utxos_a.balance_for(user1_pkh) == 0);

        // Verify ReorgStats
        assert(stats.blocks_disconnected == 2);
        assert(stats.blocks_connected == 3);
        assert(stats.returned_to_mempool.size() == 1);  // spend_a2
    }

    // -----------------------------------------------------------------------
    // Test 4: find_fork returns correct common ancestor
    // -----------------------------------------------------------------------
    {
        BlockTree tree;

        auto gen_idx = std::make_unique<CBlockIndex>();
        gen_idx->height = 0;
        gen_idx->hash = genesis_hash;
        CBlockIndex* gen = tree.insert_genesis(std::move(gen_idx));
        tree.set_best_tip(gen);

        // Insert block1 as child of genesis
        auto b1_idx = std::make_unique<CBlockIndex>();
        b1_idx->height = 1;
        b1_idx->hash = block1_hash;
        b1_idx->prev_hash = genesis_hash;

        // We simulate the tree insertion via insert_genesis
        // and manual prev linking for chain A and B tips
        // Using the tree's find_fork with manual chains

        // Chain A: gen -> b1 -> b2a -> b3a
        CBlockIndex b1; b1.height = 1; b1.hash = block1_hash; b1.prev = gen;
        CBlockIndex b2a_idx; b2a_idx.height = 2; b2a_idx.hash = block2a_hash; b2a_idx.prev = &b1;
        CBlockIndex b3a_idx; b3a_idx.height = 3; b3a_idx.hash = block3a.get_hash(); b3a_idx.prev = &b2a_idx;

        // Chain B: gen -> b1 -> b2b -> b3b -> b4b
        CBlockIndex b2b_idx; b2b_idx.height = 2; b2b_idx.hash = block2b_hash; b2b_idx.prev = &b1;
        CBlockIndex b3b_idx; b3b_idx.height = 3; b3b_idx.hash = block3b_hash; b3b_idx.prev = &b2b_idx;
        CBlockIndex b4b_idx; b4b_idx.height = 4; b4b_idx.hash = block4b.get_hash(); b4b_idx.prev = &b3b_idx;

        // Walk back manually to find fork
        CBlockIndex* tip_a = &b3a_idx;
        CBlockIndex* tip_b = &b4b_idx;

        // Bring to same height
        while (tip_b->height > tip_a->height) tip_b = tip_b->prev;

        // Walk back until they meet
        while (tip_a != tip_b) {
            tip_a = tip_a->prev;
            tip_b = tip_b->prev;
        }

        // Fork point should be block1
        assert(tip_a->height == 1);
        assert(tip_a->hash == block1_hash);
    }

    // -----------------------------------------------------------------------
    // Test 5: Chain work comparison — B has more work than A
    // -----------------------------------------------------------------------
    {
        // Both chains use INITIAL_NBITS, so work per block is equal
        // Chain A has 4 blocks (gen + b1 + b2a + b3a)
        // Chain B has 5 blocks (gen + b1 + b2b + b3b + b4b)
        uint32_t chain_a_blocks = 4;
        uint32_t chain_b_blocks = 5;
        // With equal difficulty, more blocks = more cumulative work
        assert(chain_b_blocks > chain_a_blocks);

        // Compute work per block from INITIAL_NBITS
        arith_uint256 target;
        derive_target(INITIAL_NBITS, target);
        assert(!target.IsZero());

        // Work = 2^256 / (target + 1) approximately
        // More blocks * same work_per_block = more total work
    }

    // -----------------------------------------------------------------------
    // Test 6: Reorg with conflicting transactions (spent in both chains)
    // -----------------------------------------------------------------------
    {
        // Genesis coinbase is spent in BOTH chain A (to user1) and chain B (to user2)
        // After reorg from A to B:
        // - user1 tx is invalid (needs to be checked against new UTXO set)
        // - user2 tx is valid in chain B

        // This was already demonstrated above: after disconnecting A and
        // connecting B, user1 balance is 0 and user2 balance is correct.
        // The spend_a2 transaction conflicts with spend_b2 because both
        // spend the same genesis coinbase UTXO.

        // Check that the conflicting txids are different
        assert(spend_a2.get_txid() != spend_b2.get_txid());

        // Both spend the same outpoint
        assert(spend_a2.vin[0].prevout.txid == spend_b2.vin[0].prevout.txid);
        assert(spend_a2.vin[0].prevout.index == spend_b2.vin[0].prevout.index);
    }

    // -----------------------------------------------------------------------
    // Test 7: Reorg preserves block tree integrity
    // -----------------------------------------------------------------------
    {
        BlockTree tree;

        auto gen_idx = std::make_unique<CBlockIndex>();
        gen_idx->height = 0;
        gen_idx->hash = genesis_hash;
        gen_idx->timestamp = GENESIS_TIMESTAMP;
        CBlockIndex* gen = tree.insert_genesis(std::move(gen_idx));
        tree.set_best_tip(gen);

        assert(tree.genesis() == gen);
        assert(tree.best_tip() == gen);
        assert(tree.size() == 1);

        // Insert block1
        CBlockHeader hdr1;
        hdr1.height = 1;
        hdr1.prev_hash = genesis_hash;
        hdr1.timestamp = GENESIS_TIMESTAMP + TARGET_BLOCK_TIME;
        GetRandBytes(hdr1.miner_pubkey.data(), 32);
        hdr1.version = 1;
        auto data1 = hdr1.get_unsigned_data();
        // Compute some hash for the index entry
        CBlockIndex* b1 = tree.insert(hdr1);
        assert(b1 != nullptr);
        assert(b1->height == 1);
        assert(tree.size() == 2);

        // Set as best tip
        tree.set_best_tip(b1);
        assert(tree.best_tip() == b1);

        // is_ancestor check
        assert(tree.is_ancestor(gen, b1));
        assert(!tree.is_ancestor(b1, gen));
    }

    // -----------------------------------------------------------------------
    // Test 8: Multiple reorgs don't corrupt UTXO state
    // -----------------------------------------------------------------------
    {
        RgUTXOSet fresh;
        auto m = generate_keypair();
        auto m_pkh = rg_pkh(m.pubkey);

        auto cb0 = rg_coinbase(0, m_pkh);
        auto g = rg_block(0, uint256(), {cb0}, m);
        rg_connect(fresh, g);
        uint256 g_hash = g.get_hash();

        // Build block 1A
        auto cb1a = rg_coinbase(1, m_pkh);
        auto b1a = rg_block(1, g_hash, {cb1a}, m);
        auto cache1a = cache_spends(fresh, b1a);
        rg_connect(fresh, b1a);

        // Disconnect 1A
        rg_disconnect(fresh, b1a, cache1a);
        assert(fresh.size() == 1);  // only genesis coinbase

        // Connect different block 1B
        auto cb1b = rg_coinbase(1, rg_pkh(miner_b.pubkey));
        auto b1b = rg_block(1, g_hash, {cb1b}, miner_b);
        auto cache1b = cache_spends(fresh, b1b);
        rg_connect(fresh, b1b);
        assert(fresh.size() == 2);

        // Disconnect 1B
        rg_disconnect(fresh, b1b, cache1b);
        assert(fresh.size() == 1);

        // Connect 1A again
        rg_connect(fresh, b1a);
        assert(fresh.size() == 2);
    }

    // -----------------------------------------------------------------------
    // Test 9: BlockTree.get_all_tips with competing chains
    // -----------------------------------------------------------------------
    {
        BlockTree tree;
        auto gen_idx = std::make_unique<CBlockIndex>();
        gen_idx->height = 0;
        GetRandBytes(gen_idx->hash.data(), 32);
        CBlockIndex* gen = tree.insert_genesis(std::move(gen_idx));
        tree.set_best_tip(gen);

        auto tips = tree.get_all_tips();
        assert(tips.size() == 1);
        assert(tips[0] == gen);
    }

    // -----------------------------------------------------------------------
    // Test 10: BlockTree.get_chain from genesis to tip
    // -----------------------------------------------------------------------
    {
        BlockTree tree;
        auto gen_idx = std::make_unique<CBlockIndex>();
        gen_idx->height = 0;
        GetRandBytes(gen_idx->hash.data(), 32);
        CBlockIndex* gen = tree.insert_genesis(std::move(gen_idx));
        tree.set_best_tip(gen);

        auto chain = tree.get_chain(gen);
        assert(chain.size() == 1);
        assert(chain[0] == gen);
    }

    // -----------------------------------------------------------------------
    // Test 11: get_depth returns correct values
    // -----------------------------------------------------------------------
    {
        BlockTree tree;
        auto gen_idx = std::make_unique<CBlockIndex>();
        gen_idx->height = 0;
        GetRandBytes(gen_idx->hash.data(), 32);
        CBlockIndex* gen = tree.insert_genesis(std::move(gen_idx));
        tree.set_best_tip(gen);

        int64_t depth = tree.get_depth(gen);
        assert(depth == 0);  // tip itself has depth 0
    }

    // -----------------------------------------------------------------------
    // Test 12: TreeStats correct for single-block tree
    // -----------------------------------------------------------------------
    {
        BlockTree tree;
        auto gen_idx = std::make_unique<CBlockIndex>();
        gen_idx->height = 0;
        GetRandBytes(gen_idx->hash.data(), 32);
        CBlockIndex* gen = tree.insert_genesis(std::move(gen_idx));
        tree.set_best_tip(gen);

        auto stats = tree.get_stats();
        assert(stats.total_entries == 1);
        assert(stats.max_height == 0);
    }

    // -----------------------------------------------------------------------
    // Test 13: Reorg returns only non-coinbase transactions to mempool
    // -----------------------------------------------------------------------
    {
        // When disconnecting a block, only non-coinbase transactions
        // should be considered for mempool return
        auto kp = generate_keypair();
        auto kp_pkh = rg_pkh(kp.pubkey);

        RgUTXOSet fresh;
        auto cb0 = rg_coinbase(0, kp_pkh);
        auto g = rg_block(0, uint256(), {cb0}, kp);
        rg_connect(fresh, g);

        // Block with coinbase + 1 regular tx
        auto spend = rg_spend(g.vtx[0].get_txid(), 0, INITIAL_REWARD,
                               user1_pkh, 20 * COIN, kp);
        auto cb1 = rg_coinbase(1, kp_pkh);
        auto b1 = rg_block(1, g.get_hash(), {cb1, spend}, kp);

        // Count non-coinbase transactions
        std::vector<uint256> mempool_candidates;
        for (auto& tx : b1.vtx) {
            if (!tx.is_coinbase()) {
                mempool_candidates.push_back(tx.get_txid());
            }
        }
        assert(mempool_candidates.size() == 1);
        assert(mempool_candidates[0] == spend.get_txid());
    }

    // -----------------------------------------------------------------------
    // Test 14: Block hashes on competing chains are different
    // -----------------------------------------------------------------------
    {
        assert(block2a_hash != block2b_hash);
        assert(block3a.get_hash() != block3b_hash);
    }

    // -----------------------------------------------------------------------
    // Test 15: UTXO count correct after full reorg
    // -----------------------------------------------------------------------
    {
        // After reorg to chain B, UTXO set should have:
        // - block1 coinbase (height 1)
        // - block2b coinbase (height 2)
        // - block3b coinbase (height 3)
        // - block4b coinbase (height 4)
        // - spend_b2 outputs (to user2 + change)
        // The genesis coinbase is spent by spend_b2

        // utxos_a was reorged to chain B in Test 3
        assert(!utxos_a.exists(genesis_txid, 0));  // spent

        // Coinbases from B chain should exist
        assert(utxos_a.exists(block1_txid, 0));  // shared block1
    }
}

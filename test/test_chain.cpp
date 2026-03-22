// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include <gtest/gtest.h>
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "chain/utxo.h"
#include "chain/blockstore.h"
#include "consensus/params.h"
#include "consensus/growth.h"
#include "consensus/reward.h"
#include "consensus/difficulty.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "core/hash.h"
#include "core/time.h"

#include <filesystem>

using namespace flow;
using namespace flow::consensus;
using namespace flow::crypto;

// Test fixture with a temporary directory
class ChainTest : public ::testing::Test {
protected:
    std::string test_dir;
    KeyPair miner_kp;
    Blob<20> miner_hash;

    void SetUp() override {
        test_dir = "/tmp/flowcoin_test_" + std::to_string(get_time_micros());
        std::filesystem::create_directories(test_dir);
        miner_kp = generate_keypair();
        Hash256 pk_full = keccak256d(miner_kp.pubkey.bytes(), 32);
        std::memcpy(miner_hash.bytes(), pk_full.bytes(), 20);

        // Set time offset for predictable timestamps
        set_time_offset(GENESIS_TIMESTAMP - get_time() + 10000);
    }

    void TearDown() override {
        std::filesystem::remove_all(test_dir);
        set_time_offset(0);
    }

    CBlock make_genesis() {
        CBlock genesis;
        auto& h = genesis.header;
        h.prev_hash = Hash256::ZERO;
        h.height = 0;
        h.timestamp = GENESIS_TIMESTAMP;
        h.val_loss = GENESIS_VAL_LOSS;
        h.prev_val_loss = GENESIS_VAL_LOSS;
        // Easy difficulty for testing — nearly all hashes pass
        h.nbits = 0x207fffff;
        h.d_model = GENESIS_D_MODEL;
        h.n_layers = GENESIS_N_LAYERS;
        h.d_ff = GENESIS_D_FF;
        h.n_experts = GENESIS_N_EXPERTS;
        h.n_heads = GENESIS_N_HEADS;
        h.rank = GENESIS_RANK;

        genesis.vtx.push_back(make_coinbase(get_block_subsidy(0), miner_hash, 0));
        h.merkle_root = genesis.compute_merkle_root();

        h.miner_pubkey = miner_kp.pubkey;
        auto ub = h.unsigned_bytes();
        h.miner_sig = sign(miner_kp.privkey, miner_kp.pubkey, ub.data(), ub.size());

        return genesis;
    }

    CBlock make_block(const ChainState& chain, float val_loss) {
        const CBlockIndex* parent = chain.tip();
        CBlock block;
        auto& h = block.header;

        h.prev_hash = parent->hash;
        h.height = parent->height + 1;
        h.timestamp = parent->timestamp + TARGET_BLOCK_TIME;
        h.val_loss = val_loss;
        h.prev_val_loss = parent->val_loss;
        h.nbits = parent->nbits;

        // Growth
        uint32_t improving = parent->improving_blocks;
        if (val_loss < parent->val_loss) improving++;
        auto dims = compute_growth(h.height, improving);
        h.d_model = dims.d_model;
        h.n_layers = dims.n_layers;
        h.d_ff = dims.d_ff;
        h.n_experts = dims.n_experts;
        h.n_heads = dims.n_heads;
        h.rank = dims.rank;

        // Find valid delta_hash
        h.dataset_hash = Hash256::ZERO;
        for (uint32_t i = 0; i < 100000; ++i) {
            uint8_t data[36];
            write_le32(data, i);
            write_le64(data + 4, h.height);
            std::memcpy(data + 12, parent->hash.bytes(), 24);
            h.delta_hash = keccak256(data, sizeof(data));

            // H = Keccak256(D || V) per whitepaper §3
            Keccak256Hasher hasher;
            hasher.update(h.delta_hash.bytes(), 32);
            hasher.update(h.dataset_hash.bytes(), 32);
            Hash256 training_hash = hasher.finalize();
            if (meets_target(training_hash, h.nbits)) break;
        }

        // Coinbase tx
        block.vtx.push_back(make_coinbase(get_block_subsidy(h.height), miner_hash, h.height));
        h.merkle_root = block.compute_merkle_root();

        // Sign
        h.miner_pubkey = miner_kp.pubkey;
        auto ub = h.unsigned_bytes();
        h.miner_sig = sign(miner_kp.privkey, miner_kp.pubkey, ub.data(), ub.size());

        return block;
    }
};

// ─── Block Tree Tests ────────────────────────────────────────

TEST_F(ChainTest, BlockTreeInsertAndFind) {
    BlockTree tree;
    CBlockIndex idx;
    idx.hash = Hash256::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    idx.height = 0;

    auto* inserted = tree.insert(idx);
    ASSERT_NE(inserted, nullptr);
    EXPECT_EQ(tree.size(), 1u);

    auto* found = tree.find(idx.hash);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->height, 0u);
}

TEST_F(ChainTest, BlockTreeDuplicateRejected) {
    BlockTree tree;
    CBlockIndex idx;
    idx.hash = Hash256::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    tree.insert(idx);
    EXPECT_EQ(tree.insert(idx), nullptr);
}

TEST_F(ChainTest, BlockTreeParentLinking) {
    BlockTree tree;

    CBlockIndex parent;
    parent.hash = Hash256::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    parent.height = 0;
    tree.insert(parent);

    CBlockIndex child;
    child.hash = Hash256::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000002");
    child.prev_hash = parent.hash;
    child.height = 1;
    auto* inserted = tree.insert(child);

    ASSERT_NE(inserted, nullptr);
    ASSERT_NE(inserted->prev, nullptr);
    EXPECT_EQ(inserted->prev->hash, parent.hash);
}

// ─── UTXO Set Tests ─────────────────────────────────────────

TEST_F(ChainTest, UtxoAddAndGet) {
    UtxoSet utxo(test_dir + "/utxo_test.db");

    Hash256 txid = Hash256::from_hex(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    UtxoEntry entry;
    entry.amount = Amount{50 * Amount::COIN};
    entry.height = 0;

    utxo.add(txid, 0, entry);
    EXPECT_EQ(utxo.count(), 1u);

    COutPoint op;
    op.txid = txid;
    op.vout = 0;
    EXPECT_TRUE(utxo.has(op));

    auto got = utxo.get(op);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->amount.value, 50 * Amount::COIN);
}

TEST_F(ChainTest, UtxoSpend) {
    UtxoSet utxo(test_dir + "/utxo_spend.db");

    Hash256 txid = Hash256::from_hex(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    UtxoEntry entry;
    entry.amount = Amount{25 * Amount::COIN};
    entry.height = 0;
    utxo.add(txid, 0, entry);

    COutPoint op;
    op.txid = txid;
    op.vout = 0;
    EXPECT_TRUE(utxo.spend(op));
    EXPECT_FALSE(utxo.has(op));
    EXPECT_EQ(utxo.count(), 0u);
}

TEST_F(ChainTest, UtxoDoubleSpendFails) {
    UtxoSet utxo(test_dir + "/utxo_double.db");

    Hash256 txid = Hash256::from_hex(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    UtxoEntry entry;
    entry.amount = Amount{10 * Amount::COIN};
    entry.height = 0;
    utxo.add(txid, 0, entry);

    COutPoint op;
    op.txid = txid;
    op.vout = 0;
    EXPECT_TRUE(utxo.spend(op));
    EXPECT_FALSE(utxo.spend(op)); // second spend fails
}

// ─── Block Store Tests ───────────────────────────────────────

TEST_F(ChainTest, BlockStoreWriteRead) {
    BlockStore store(test_dir + "/blocks");

    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03};
    auto pos = store.write_block(data);
    auto read = store.read_block(pos);
    EXPECT_EQ(read, data);
}

// ─── ChainState Integration Tests ────────────────────────────

TEST_F(ChainTest, InitGenesis) {
    ChainState chain(test_dir + "/chain");
    auto genesis = make_genesis();
    chain.init_genesis(genesis);

    EXPECT_EQ(chain.height(), 0);
    EXPECT_NE(chain.tip(), nullptr);
    EXPECT_EQ(chain.utxo_set().count(), 1u); // coinbase output
}

TEST_F(ChainTest, AcceptMultipleBlocks) {
    ChainState chain(test_dir + "/chain_multi");
    chain.init_genesis(make_genesis());

    // Build 5 blocks with decreasing val_loss
    float loss = GENESIS_VAL_LOSS;
    for (int i = 0; i < 5; ++i) {
        loss -= 0.5f;
        auto block = make_block(chain, loss);
        auto state = chain.accept_block(block);
        EXPECT_TRUE(state.valid) << "Block " << i + 1 << ": " << state.reject_reason;
    }

    EXPECT_EQ(chain.height(), 5);
    EXPECT_EQ(chain.utxo_set().count(), 6u); // genesis + 5 coinbases
}

TEST_F(ChainTest, RejectOrphanBlock) {
    ChainState chain(test_dir + "/chain_orphan");
    chain.init_genesis(make_genesis());

    CBlock orphan;
    orphan.header.prev_hash = Hash256::from_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    orphan.header.height = 999;

    auto state = chain.accept_block(orphan);
    EXPECT_FALSE(state.valid);
    EXPECT_EQ(state.reject_reason, "orphan-block");
}

// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include <gtest/gtest.h>
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "primitives/delta.h"
#include "crypto/keys.h"
#include "crypto/sign.h"

using namespace flow;
using namespace flow::crypto;

// ─── Block Header Tests ──────────────────────────────────────

TEST(BlockHeaderTest, SerializesTo308Bytes) {
    CBlockHeader h;
    auto buf = h.serialize();
    EXPECT_EQ(buf.size(), 308u);
}

TEST(BlockHeaderTest, SerializeDeserializeRoundTrip) {
    CBlockHeader h;
    h.prev_hash = Hash256::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    h.merkle_root = Hash256::from_hex(
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    h.timestamp = 1742515200;
    h.height = 42;
    h.val_loss = 3.14f;
    h.prev_val_loss = 3.50f;
    h.nbits = 0x1d00ffff;
    h.train_steps = 1000;
    h.d_model = 512;
    h.n_layers = 8;
    h.d_ff = 1024;
    h.n_experts = 1024;
    h.stagnation_count = 0;
    h.n_heads = 8;
    h.rank = 64;

    auto kp = generate_keypair();
    h.miner_pubkey = kp.pubkey;

    auto buf = h.serialize();
    ASSERT_EQ(buf.size(), 308u);

    CBlockHeader h2 = CBlockHeader::deserialize(buf.data());
    EXPECT_EQ(h2.prev_hash, h.prev_hash);
    EXPECT_EQ(h2.merkle_root, h.merkle_root);
    EXPECT_EQ(h2.timestamp, h.timestamp);
    EXPECT_EQ(h2.height, h.height);
    EXPECT_EQ(h2.val_loss, h.val_loss);
    EXPECT_EQ(h2.prev_val_loss, h.prev_val_loss);
    EXPECT_EQ(h2.nbits, h.nbits);
    EXPECT_EQ(h2.train_steps, h.train_steps);
    EXPECT_EQ(h2.d_model, h.d_model);
    EXPECT_EQ(h2.n_layers, h.n_layers);
    EXPECT_EQ(h2.d_ff, h.d_ff);
    EXPECT_EQ(h2.n_experts, h.n_experts);
    EXPECT_EQ(h2.stagnation_count, h.stagnation_count);
    EXPECT_EQ(h2.n_heads, h.n_heads);
    EXPECT_EQ(h2.rank, h.rank);
    EXPECT_EQ(h2.miner_pubkey, h.miner_pubkey);
}

TEST(BlockHeaderTest, HashUsesUnsignedPortion) {
    CBlockHeader h;
    h.height = 1;
    h.timestamp = 100;

    Hash256 hash1 = h.get_hash();

    // Changing the signature should NOT change the hash
    // (hash is computed over [0..243], signature is [244..307])
    h.miner_sig[0] = 0xFF;
    Hash256 hash2 = h.get_hash();
    EXPECT_EQ(hash1, hash2);

    // Changing a field in the unsigned portion SHOULD change the hash
    h.height = 2;
    Hash256 hash3 = h.get_hash();
    EXPECT_NE(hash1, hash3);
}

TEST(BlockHeaderTest, UnsignedBytesIs244) {
    CBlockHeader h;
    auto ub = h.unsigned_bytes();
    EXPECT_EQ(ub.size(), 244u);
}

TEST(BlockHeaderTest, SignAndVerify) {
    CBlockHeader h;
    h.height = 1;
    h.timestamp = 1742515200;
    h.d_model = 512;

    auto kp = generate_keypair();
    h.miner_pubkey = kp.pubkey;

    auto ub = h.unsigned_bytes();
    h.miner_sig = sign(kp.privkey, kp.pubkey, ub.data(), ub.size());

    EXPECT_TRUE(verify(h.miner_pubkey, ub.data(), ub.size(), h.miner_sig));
}

// ─── Transaction Tests ────────────────────────────────────────

TEST(TransactionTest, CoinbaseCreation) {
    Blob<20> miner_hash;
    miner_hash[0] = 0x42;

    auto tx = make_coinbase(Amount{50 * Amount::COIN}, miner_hash, 0);
    EXPECT_TRUE(tx.is_coinbase());
    EXPECT_EQ(tx.vin.size(), 1u);
    EXPECT_EQ(tx.vout.size(), 1u);
    EXPECT_EQ(tx.vout[0].amount.value, 50 * Amount::COIN);
    EXPECT_EQ(tx.vout[0].pubkey_hash, miner_hash);
}

TEST(TransactionTest, SerializeDeserializeRoundTrip) {
    Blob<20> miner_hash;
    auto tx = make_coinbase(Amount{50 * Amount::COIN}, miner_hash, 7);

    auto bytes = tx.serialize();
    SpanReader reader(bytes);
    auto tx2 = CTransaction::deserialize(reader);

    EXPECT_EQ(tx2.version, tx.version);
    EXPECT_EQ(tx2.vin.size(), tx.vin.size());
    EXPECT_EQ(tx2.vout.size(), tx.vout.size());
    EXPECT_EQ(tx2.vout[0].amount, tx.vout[0].amount);
    EXPECT_TRUE(tx2.is_coinbase());
}

TEST(TransactionTest, HashIsCachedAndStable) {
    Blob<20> miner_hash;
    auto tx = make_coinbase(Amount{50 * Amount::COIN}, miner_hash, 0);

    Hash256 h1 = tx.get_hash();
    Hash256 h2 = tx.get_hash();
    EXPECT_EQ(h1, h2);
    EXPECT_FALSE(h1.is_zero());
}

TEST(TransactionTest, DifferentTxsDifferentHashes) {
    Blob<20> hash;
    auto tx1 = make_coinbase(Amount{50 * Amount::COIN}, hash, 0);
    auto tx2 = make_coinbase(Amount{50 * Amount::COIN}, hash, 1);
    EXPECT_NE(tx1.get_hash(), tx2.get_hash());
}

// ─── Delta Payload Tests ─────────────────────────────────────

TEST(DeltaTest, SerializeDeserializeRoundTrip) {
    DeltaPayload d;
    d.parent_model_hash = Hash256::from_hex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    d.child_model_hash = Hash256::from_hex(
        "2222222222222222222222222222222222222222222222222222222222222222");
    d.train_steps = 500;
    d.loss_before = 5.5f;
    d.loss_after = 4.2f;
    d.compressed_delta = {0x01, 0x02, 0x03, 0x04, 0x05};

    auto bytes = d.serialize();
    SpanReader reader(bytes);
    auto d2 = DeltaPayload::deserialize(reader);

    EXPECT_EQ(d2.parent_model_hash, d.parent_model_hash);
    EXPECT_EQ(d2.child_model_hash, d.child_model_hash);
    EXPECT_EQ(d2.train_steps, d.train_steps);
    EXPECT_EQ(d2.loss_before, d.loss_before);
    EXPECT_EQ(d2.loss_after, d.loss_after);
    EXPECT_EQ(d2.compressed_delta, d.compressed_delta);
}

TEST(DeltaTest, HashIsStable) {
    DeltaPayload d;
    d.train_steps = 100;
    d.loss_before = 5.0f;
    d.loss_after = 4.0f;

    Hash256 h1 = d.get_hash();
    Hash256 h2 = d.get_hash();
    EXPECT_EQ(h1, h2);
    EXPECT_FALSE(h1.is_zero());
}

TEST(DeltaTest, EmptyDelta) {
    DeltaPayload d;
    EXPECT_TRUE(d.empty());
    auto bytes = d.serialize();
    SpanReader reader(bytes);
    auto d2 = DeltaPayload::deserialize(reader);
    EXPECT_TRUE(d2.empty());
}

// ─── Merkle Root Tests ────────────────────────────────────────

TEST(MerkleTest, EmptyBlock) {
    CBlock block;
    EXPECT_EQ(block.compute_merkle_root(), Hash256::ZERO);
}

TEST(MerkleTest, SingleTransaction) {
    CBlock block;
    Blob<20> hash;
    block.vtx.push_back(make_coinbase(Amount{50 * Amount::COIN}, hash, 0));
    Hash256 root = block.compute_merkle_root();
    // Merkle root of single tx is its own hash
    EXPECT_EQ(root, block.vtx[0].get_hash());
}

TEST(MerkleTest, TwoTransactions) {
    CBlock block;
    Blob<20> hash;
    block.vtx.push_back(make_coinbase(Amount{50 * Amount::COIN}, hash, 0));
    block.vtx.push_back(make_coinbase(Amount{25 * Amount::COIN}, hash, 1));

    Hash256 root = block.compute_merkle_root();
    EXPECT_NE(root, block.vtx[0].get_hash());
    EXPECT_NE(root, block.vtx[1].get_hash());
    EXPECT_FALSE(root.is_zero());
}

TEST(MerkleTest, OrderMatters) {
    Blob<20> hash;
    auto tx1 = make_coinbase(Amount{50 * Amount::COIN}, hash, 0);
    auto tx2 = make_coinbase(Amount{25 * Amount::COIN}, hash, 1);

    CBlock b1;
    b1.vtx = {tx1, tx2};

    CBlock b2;
    b2.vtx = {tx2, tx1};

    EXPECT_NE(b1.compute_merkle_root(), b2.compute_merkle_root());
}

// ─── Full Block Serialize Test ────────────────────────────────

TEST(BlockTest, SerializeFullBlock) {
    CBlock block;
    block.header.height = 1;
    block.header.timestamp = 1742515200;

    Blob<20> miner_hash;
    block.vtx.push_back(make_coinbase(Amount{50 * Amount::COIN}, miner_hash, 1));
    block.delta_payload = {0xDE, 0xAD, 0xBE, 0xEF};

    auto bytes = block.serialize();
    // Should be: 308 (header) + 1 (tx_count) + tx_bytes + 1 (delta_len) + 4 (delta)
    EXPECT_GT(bytes.size(), 308u + 1u + 1u + 4u);
}

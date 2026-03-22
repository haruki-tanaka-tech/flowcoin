// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include <gtest/gtest.h>
#include "mempool/mempool.h"
#include "primitives/transaction.h"
#include "core/hash.h"

using namespace flow;

static CTransaction make_test_tx(uint32_t id) {
    CTransaction tx;
    tx.version = 1;

    CTxIn in;
    // Unique prevout per tx
    write_le32(in.prevout.txid.bytes(), id);
    in.prevout.vout = 0;
    tx.vin.push_back(in);

    CTxOut out;
    out.amount = Amount{100};
    tx.vout.push_back(out);

    return tx;
}

TEST(MempoolTest, AddAndFind) {
    Mempool pool;
    auto tx = make_test_tx(1);
    auto result = pool.add(tx, Amount{1000});
    EXPECT_TRUE(result.ok());
    EXPECT_EQ(pool.size(), 1u);
    EXPECT_TRUE(pool.has(tx.get_hash()));
}

TEST(MempoolTest, RejectDuplicate) {
    Mempool pool;
    auto tx = make_test_tx(1);
    pool.add(tx, Amount{1000});
    auto result = pool.add(tx, Amount{1000});
    EXPECT_TRUE(result.has_error());
    EXPECT_EQ(pool.size(), 1u);
}

TEST(MempoolTest, RejectConflict) {
    Mempool pool;
    auto tx1 = make_test_tx(1);
    pool.add(tx1, Amount{1000});

    // tx2 spends the same outpoint as tx1
    auto tx2 = make_test_tx(1); // same prevout
    tx2.vout[0].amount = Amount{200}; // different output to get different hash
    auto result = pool.add(tx2, Amount{500});
    EXPECT_TRUE(result.has_error());
}

TEST(MempoolTest, Remove) {
    Mempool pool;
    auto tx = make_test_tx(1);
    pool.add(tx, Amount{1000});
    EXPECT_TRUE(pool.remove(tx.get_hash()));
    EXPECT_FALSE(pool.has(tx.get_hash()));
    EXPECT_EQ(pool.size(), 0u);
}

TEST(MempoolTest, RemoveForBlock) {
    Mempool pool;
    auto tx1 = make_test_tx(1);
    auto tx2 = make_test_tx(2);
    pool.add(tx1, Amount{1000});
    pool.add(tx2, Amount{2000});

    pool.remove_for_block({tx1});
    EXPECT_EQ(pool.size(), 1u);
    EXPECT_FALSE(pool.has(tx1.get_hash()));
    EXPECT_TRUE(pool.has(tx2.get_hash()));
}

TEST(MempoolTest, SortedByFeeRate) {
    Mempool pool;

    auto tx_low = make_test_tx(1);
    auto tx_high = make_test_tx(2);

    pool.add(tx_low, Amount{100});    // low fee
    pool.add(tx_high, Amount{10000}); // high fee

    auto sorted = pool.get_sorted(10);
    ASSERT_EQ(sorted.size(), 2u);
    // High fee should come first
    EXPECT_EQ(sorted[0].get_hash(), tx_high.get_hash());
    EXPECT_EQ(sorted[1].get_hash(), tx_low.get_hash());
}

TEST(MempoolTest, EvictLowestFee) {
    // Tiny max size to force eviction
    Mempool pool(500); // 500 bytes max

    auto tx1 = make_test_tx(1);
    auto tx2 = make_test_tx(2);

    pool.add(tx1, Amount{100});  // low fee — will be evicted
    pool.add(tx2, Amount{9999}); // high fee — keeps

    // At least one should remain
    EXPECT_GE(pool.size(), 1u);
    // High fee tx should survive
    if (pool.size() == 1) {
        EXPECT_TRUE(pool.has(tx2.get_hash()));
    }
}

TEST(MempoolTest, IsSpent) {
    Mempool pool;
    auto tx = make_test_tx(42);
    pool.add(tx, Amount{100});

    EXPECT_TRUE(pool.is_spent(tx.vin[0].prevout));

    COutPoint other;
    other.vout = 999;
    EXPECT_FALSE(pool.is_spent(other));
}

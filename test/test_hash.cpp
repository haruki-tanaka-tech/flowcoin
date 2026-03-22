// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include <gtest/gtest.h>
#include "core/hash.h"
#include "core/types.h"

using namespace flow;

TEST(KeccakTest, EmptyInput) {
    // Keccak-256 with pad=0x01 (NOT SHA-3 pad=0x06)
    // Expected: c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    Hash256 result = keccak256(nullptr, 0);
    EXPECT_EQ(result.to_hex(),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
}

TEST(KeccakTest, AbcInput) {
    // Keccak-256("abc")
    // Expected: 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
    const uint8_t abc[] = {'a', 'b', 'c'};
    Hash256 result = keccak256(abc, 3);
    EXPECT_EQ(result.to_hex(),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
}

TEST(KeccakTest, NotSha3) {
    // SHA-3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    // We must NOT produce this. If we do, the padding is wrong (0x06 instead of 0x01).
    Hash256 result = keccak256(nullptr, 0);
    EXPECT_NE(result.to_hex(),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}

TEST(KeccakTest, DoubleHash) {
    // keccak256d("abc") = keccak256(keccak256("abc"))
    const uint8_t abc[] = {'a', 'b', 'c'};
    Hash256 single = keccak256(abc, 3);
    Hash256 double_hash = keccak256d(abc, 3);
    Hash256 manual_double = keccak256(single.bytes(), 32);
    EXPECT_EQ(double_hash, manual_double);
    EXPECT_NE(double_hash, single);
}

TEST(KeccakTest, IncrementalHasher) {
    // Hash "abc" incrementally: "a" then "bc"
    const uint8_t a[] = {'a'};
    const uint8_t bc[] = {'b', 'c'};
    const uint8_t abc[] = {'a', 'b', 'c'};

    Keccak256Hasher hasher;
    hasher.update(a, 1);
    hasher.update(bc, 2);
    Hash256 incremental = hasher.finalize();

    Hash256 oneshot = keccak256(abc, 3);
    EXPECT_EQ(incremental, oneshot);
}

TEST(KeccakTest, SpanOverload) {
    const uint8_t abc[] = {'a', 'b', 'c'};
    std::span<const uint8_t> s{abc, 3};
    Hash256 a = keccak256(abc, 3);
    Hash256 b = keccak256(s);
    EXPECT_EQ(a, b);
}

TEST(BlobTest, HexRoundTrip) {
    Hash256 h = Hash256::from_hex(
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    EXPECT_EQ(h.to_hex(),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
}

TEST(BlobTest, Zero) {
    Hash256 z;
    EXPECT_TRUE(z.is_zero());
    EXPECT_EQ(z, Hash256::ZERO);

    Hash256 nz = Hash256::from_hex(
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    EXPECT_FALSE(nz.is_zero());
}

TEST(AmountTest, Arithmetic) {
    Amount a{100};
    Amount b{50};
    EXPECT_EQ((a + b).value, 150);
    EXPECT_EQ((a - b).value, 50);
    EXPECT_TRUE(a > b);
    EXPECT_TRUE(b < a);

    a += b;
    EXPECT_EQ(a.value, 150);
}

TEST(AmountTest, CoinConstant) {
    EXPECT_EQ(Amount::COIN, 100'000'000LL);
}

TEST(ResultTest, OkPath) {
    Result<int> r = 42;
    EXPECT_TRUE(r.ok());
    EXPECT_FALSE(r.has_error());
    EXPECT_EQ(r.value(), 42);
}

TEST(ResultTest, ErrorPath) {
    Result<int> r = Error{"something failed"};
    EXPECT_FALSE(r.ok());
    EXPECT_TRUE(r.has_error());
    EXPECT_EQ(r.error_message(), "something failed");
}

// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include <gtest/gtest.h>
#include "crypto/address.h"
#include "crypto/keys.h"
#include "core/hash.h"

using namespace flow;
using namespace flow::crypto;

TEST(AddressTest, EncodeDecodeRoundTrip) {
    // Create a 20-byte hash
    uint8_t hash[20] = {};
    for (int i = 0; i < 20; ++i) hash[i] = static_cast<uint8_t>(i);

    std::string addr = encode_address("fl", 0, hash, 20);
    EXPECT_FALSE(addr.empty());
    EXPECT_TRUE(addr.starts_with("fl1"));

    auto decoded = decode_address(addr);
    ASSERT_TRUE(decoded.ok());
    EXPECT_EQ(decoded.value().hrp, "fl");
    EXPECT_EQ(decoded.value().witness_version, 0);
    ASSERT_EQ(decoded.value().pubkey_hash.size(), 20u);
    for (int i = 0; i < 20; ++i) {
        EXPECT_EQ(decoded.value().pubkey_hash[i], hash[i]);
    }
}

TEST(AddressTest, TestnetHRP) {
    uint8_t hash[20] = {1, 2, 3};
    std::string addr = encode_address("tfl", 0, hash, 20);
    EXPECT_TRUE(addr.starts_with("tfl1"));

    auto decoded = decode_address(addr);
    ASSERT_TRUE(decoded.ok());
    EXPECT_EQ(decoded.value().hrp, "tfl");
}

TEST(AddressTest, InvalidChecksumRejected) {
    uint8_t hash[20] = {};
    std::string addr = encode_address("fl", 0, hash, 20);
    // Corrupt the last character
    addr.back() = (addr.back() == 'q') ? 'p' : 'q';

    auto decoded = decode_address(addr);
    EXPECT_TRUE(decoded.has_error());
}

TEST(AddressTest, MixedCaseRejected) {
    auto decoded = decode_address("FL1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqABCDEF");
    // This should fail due to mixed case or invalid checksum
    EXPECT_TRUE(decoded.has_error());
}

TEST(AddressTest, PubkeyToAddress) {
    auto kp = generate_keypair();
    std::string addr = pubkey_to_address(kp.pubkey, "fl");
    EXPECT_TRUE(addr.starts_with("fl1"));
    EXPECT_GT(addr.size(), 10u);

    // Verify decode works
    auto decoded = decode_address(addr);
    ASSERT_TRUE(decoded.ok());
    EXPECT_EQ(decoded.value().pubkey_hash.size(), 20u);

    // Verify the hash matches
    Hash256 full_hash = keccak256d(kp.pubkey.bytes(), 32);
    for (size_t i = 0; i < 20; ++i) {
        EXPECT_EQ(decoded.value().pubkey_hash[i], full_hash[i]);
    }
}

TEST(AddressTest, DifferentKeysDifferentAddresses) {
    auto kp1 = generate_keypair();
    auto kp2 = generate_keypair();
    std::string a1 = pubkey_to_address(kp1.pubkey);
    std::string a2 = pubkey_to_address(kp2.pubkey);
    EXPECT_NE(a1, a2);
}

TEST(AddressTest, SameKeyReproducible) {
    auto kp = generate_keypair();
    std::string a1 = pubkey_to_address(kp.pubkey);
    std::string a2 = pubkey_to_address(kp.pubkey);
    EXPECT_EQ(a1, a2);
}

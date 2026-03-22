// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include <gtest/gtest.h>
#include "wallet/wallet.h"
#include "crypto/sign.h"
#include "core/hash.h"
#include "core/time.h"

#include <filesystem>

using namespace flow;
using namespace flow::crypto;

class WalletTest : public ::testing::Test {
protected:
    std::string test_dir;
    std::string seed_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    void SetUp() override {
        test_dir = "/tmp/flowcoin_wallet_test_" + std::to_string(get_time_micros());
        std::filesystem::create_directories(test_dir);
    }

    void TearDown() override {
        std::filesystem::remove_all(test_dir);
    }
};

TEST_F(WalletTest, GenerateAddress) {
    Wallet w(test_dir + "/wallet.db", seed_hex);
    std::string addr = w.get_new_address();
    EXPECT_TRUE(addr.starts_with("fl1"));
    EXPECT_EQ(w.key_count(), 1u);
}

TEST_F(WalletTest, MultipleAddresses) {
    Wallet w(test_dir + "/wallet.db", seed_hex);
    std::string a1 = w.get_new_address();
    std::string a2 = w.get_new_address();
    std::string a3 = w.get_new_address();
    EXPECT_NE(a1, a2);
    EXPECT_NE(a2, a3);
    EXPECT_EQ(w.key_count(), 3u);
}

TEST_F(WalletTest, DeterministicFromSeed) {
    std::string addr1, addr2;
    {
        Wallet w(test_dir + "/wallet1.db", seed_hex);
        addr1 = w.get_new_address();
    }
    {
        Wallet w(test_dir + "/wallet2.db", seed_hex);
        addr2 = w.get_new_address();
    }
    EXPECT_EQ(addr1, addr2);
}

TEST_F(WalletTest, PersistKeys) {
    std::string addr;
    {
        Wallet w(test_dir + "/wallet.db", seed_hex);
        addr = w.get_new_address();
        w.get_new_address();
        EXPECT_EQ(w.key_count(), 2u);
    }
    {
        Wallet w(test_dir + "/wallet.db", seed_hex);
        EXPECT_EQ(w.key_count(), 2u);
        auto keys = w.get_all_keys();
        EXPECT_EQ(keys[0].address, addr);
    }
}

TEST_F(WalletTest, IsMine) {
    Wallet w(test_dir + "/wallet.db", seed_hex);
    w.get_new_address();

    auto keys = w.get_all_keys();
    EXPECT_TRUE(w.is_mine(keys[0].pubkey_hash));

    Blob<20> unknown;
    unknown[0] = 0xFF;
    EXPECT_FALSE(w.is_mine(unknown));
}

TEST_F(WalletTest, CreateTransaction) {
    Wallet w(test_dir + "/wallet.db", seed_hex);
    w.get_new_address();

    COutPoint input;
    input.txid = Hash256::from_hex(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    input.vout = 0;

    CTxOut output;
    output.amount = Amount{100};
    output.pubkey_hash[0] = 0x42;

    auto result = w.create_transaction({input}, {output});
    ASSERT_TRUE(result.ok()) << result.error_message();

    auto& tx = result.value();
    EXPECT_EQ(tx.vin.size(), 1u);
    EXPECT_EQ(tx.vout.size(), 1u);
    EXPECT_EQ(tx.vout[0].amount.value, 100);

    // Verify the signature is valid
    auto sign_data = tx.signing_data();
    Hash256 sighash = keccak256d(sign_data.data(), sign_data.size());
    EXPECT_TRUE(verify(tx.vin[0].pubkey, sighash.bytes(), 32, tx.vin[0].sig));
}

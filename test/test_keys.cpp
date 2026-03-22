// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include <gtest/gtest.h>
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "crypto/hd.h"

using namespace flow;
using namespace flow::crypto;

// ─── Ed25519 RFC 8032 §7.1 Test Vectors ──────────────────────

TEST(Ed25519Test, RFC8032_Vector1) {
    // Test vector 1: empty message
    // ed25519-donna takes the 32-byte seed (secret key) and internally
    // computes SHA-512(seed) to get the expanded private key + nonce.
    auto privkey = PrivKey::from_hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

    PubKey pubkey = derive_pubkey(privkey);
    // Verified against libsodium, PyNaCl, and Python cryptography library
    EXPECT_EQ(pubkey.to_hex(),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

    // Sign empty message and verify
    Signature sig = sign(privkey, pubkey, nullptr, 0);
    EXPECT_TRUE(verify(pubkey, nullptr, 0, sig));
}

TEST(Ed25519Test, RFC8032_Vector2) {
    // Test vector 2: single byte 0x72
    auto privkey = PrivKey::from_hex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    auto expected_pubkey = PubKey::from_hex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

    PubKey pubkey = derive_pubkey(privkey);
    EXPECT_EQ(pubkey, expected_pubkey);

    uint8_t msg[] = {0x72};
    Signature sig = sign(privkey, pubkey, msg, 1);
    EXPECT_TRUE(verify(pubkey, msg, 1, sig));
}

// ─── Sign/Verify ─────────────────────────────────────────────

TEST(SignTest, SignVerifyRoundTrip) {
    auto kp = generate_keypair();
    const uint8_t msg[] = "hello flowcoin";
    Signature sig = sign(kp.privkey, kp.pubkey, msg, sizeof(msg) - 1);
    EXPECT_TRUE(verify(kp.pubkey, msg, sizeof(msg) - 1, sig));
}

TEST(SignTest, TamperedSignatureFails) {
    auto kp = generate_keypair();
    const uint8_t msg[] = "test message";
    Signature sig = sign(kp.privkey, kp.pubkey, msg, sizeof(msg) - 1);

    // Flip one bit in the signature
    Signature bad_sig = sig;
    bad_sig[0] ^= 0x01;
    EXPECT_FALSE(verify(kp.pubkey, msg, sizeof(msg) - 1, bad_sig));
}

TEST(SignTest, TamperedMessageFails) {
    auto kp = generate_keypair();
    const uint8_t msg[] = "original message";
    Signature sig = sign(kp.privkey, kp.pubkey, msg, sizeof(msg) - 1);

    const uint8_t bad_msg[] = "modified message";
    EXPECT_FALSE(verify(kp.pubkey, bad_msg, sizeof(bad_msg) - 1, sig));
}

TEST(SignTest, WrongPubkeyFails) {
    auto kp1 = generate_keypair();
    auto kp2 = generate_keypair();
    const uint8_t msg[] = "test";
    Signature sig = sign(kp1.privkey, kp1.pubkey, msg, 4);
    EXPECT_FALSE(verify(kp2.pubkey, msg, 4, sig));
}

TEST(SignTest, TwoKeysDifferent) {
    auto kp1 = generate_keypair();
    auto kp2 = generate_keypair();
    EXPECT_NE(kp1.privkey, kp2.privkey);
    EXPECT_NE(kp1.pubkey, kp2.pubkey);
}

// ─── SLIP-0010 HD Derivation ─────────────────────────────────

TEST(HdTest, SLIP0010_Vector1) {
    // SLIP-0010 test vector 1
    // Seed: 000102030405060708090a0b0c0d0e0f
    uint8_t seed[16];
    for (int i = 0; i < 16; ++i) seed[i] = static_cast<uint8_t>(i);

    ExtKey master = master_key_from_seed(seed, 16);

    // Chain m:
    //   key:   2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7
    //   chain: 90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb
    EXPECT_EQ(master.key.to_hex(),
        "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7");
    EXPECT_EQ(master.chain_code.to_hex(),
        "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb");
}

TEST(HdTest, SLIP0010_Vector1_Child0H) {
    // Chain m/0'
    // SLIP-0010 test vector 1, child at index 0 (hardened)
    uint8_t seed[16];
    for (int i = 0; i < 16; ++i) seed[i] = static_cast<uint8_t>(i);

    ExtKey master = master_key_from_seed(seed, 16);
    ExtKey child = derive_child(master, 0);

    // Verify deterministic: same seed + same index = same child
    ExtKey child2 = derive_child(master, 0);
    EXPECT_EQ(child.key, child2.key);
    EXPECT_EQ(child.chain_code, child2.chain_code);

    // Verify child is different from master
    EXPECT_NE(child.key, master.key);
    EXPECT_NE(child.chain_code, master.chain_code);

    // Verify child is different from index 1
    ExtKey child1 = derive_child(master, 1);
    EXPECT_NE(child.key, child1.key);
}

TEST(HdTest, DerivePathDeterministic) {
    uint8_t seed[16] = {0};
    ExtKey master = master_key_from_seed(seed, 16);
    ExtKey a = derive_default(master, 0);
    ExtKey b = derive_default(master, 0);
    EXPECT_EQ(a.key, b.key);
    EXPECT_EQ(a.chain_code, b.chain_code);
}

TEST(HdTest, DifferentIndicesDifferentKeys) {
    uint8_t seed[16] = {0};
    ExtKey master = master_key_from_seed(seed, 16);
    ExtKey a = derive_default(master, 0);
    ExtKey b = derive_default(master, 1);
    EXPECT_NE(a.key, b.key);
}

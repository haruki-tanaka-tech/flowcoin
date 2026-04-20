// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Comprehensive tests for HD key derivation chain: seed initialization,
// deterministic derivation, index management, and key consistency.

#include "wallet/hdchain.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "util/random.h"
#include "util/types.h"

#include <cassert>
#include <cstring>
#include <set>
#include <vector>

using namespace flow;

void test_hdchain() {
    // -----------------------------------------------------------------------
    // Test 1: Init from seed: deterministic
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32, 0x42);
        HDChain chain;
        chain.set_seed(seed);

        assert(chain.seed() == seed);
        assert(chain.next_index() == 0);
    }

    // -----------------------------------------------------------------------
    // Test 2: Same seed → same master key
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32);
        for (int i = 0; i < 32; ++i) seed[i] = static_cast<uint8_t>(i);

        HDChain chain1, chain2;
        chain1.set_seed(seed);
        chain2.set_seed(seed);

        auto kp1 = chain1.derive_key(0);
        auto kp2 = chain2.derive_key(0);

        assert(kp1.privkey == kp2.privkey);
        assert(kp1.pubkey == kp2.pubkey);
    }

    // -----------------------------------------------------------------------
    // Test 3: Different seed → different master key
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed1(32, 0x01);
        std::vector<uint8_t> seed2(32, 0x02);

        HDChain chain1, chain2;
        chain1.set_seed(seed1);
        chain2.set_seed(seed2);

        auto kp1 = chain1.derive_key(0);
        auto kp2 = chain2.derive_key(0);

        assert(kp1.privkey != kp2.privkey);
        assert(kp1.pubkey != kp2.pubkey);
    }

    // -----------------------------------------------------------------------
    // Test 4: derive_key: different index → different key
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32);
        GetRandBytes(seed.data(), 32);

        HDChain chain;
        chain.set_seed(seed);

        auto kp0 = chain.derive_key(0);
        auto kp1 = chain.derive_key(1);
        auto kp2 = chain.derive_key(2);

        assert(kp0.privkey != kp1.privkey);
        assert(kp0.privkey != kp2.privkey);
        assert(kp1.privkey != kp2.privkey);

        assert(kp0.pubkey != kp1.pubkey);
        assert(kp0.pubkey != kp2.pubkey);
        assert(kp1.pubkey != kp2.pubkey);
    }

    // -----------------------------------------------------------------------
    // Test 5: derive_key is deterministic (same index → same key)
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32);
        GetRandBytes(seed.data(), 32);

        HDChain chain;
        chain.set_seed(seed);

        auto kp_a = chain.derive_key(5);
        auto kp_b = chain.derive_key(5);

        assert(kp_a.privkey == kp_b.privkey);
        assert(kp_a.pubkey == kp_b.pubkey);
    }

    // -----------------------------------------------------------------------
    // Test 6: advance() increments next_index
    // -----------------------------------------------------------------------
    {
        HDChain chain;
        std::vector<uint8_t> seed(32, 0xFF);
        chain.set_seed(seed);

        assert(chain.next_index() == 0);
        chain.advance();
        assert(chain.next_index() == 1);
        chain.advance();
        assert(chain.next_index() == 2);
        chain.advance();
        chain.advance();
        chain.advance();
        assert(chain.next_index() == 5);
    }

    // -----------------------------------------------------------------------
    // Test 7: set_index: recovery mode works
    // -----------------------------------------------------------------------
    {
        HDChain chain;
        std::vector<uint8_t> seed(32, 0xAA);
        chain.set_seed(seed);

        chain.set_index(100);
        assert(chain.next_index() == 100);

        chain.set_index(0);
        assert(chain.next_index() == 0);

        chain.set_index(999);
        assert(chain.next_index() == 999);
    }

    // -----------------------------------------------------------------------
    // Test 8: Derived pubkey matches Ed25519 derivation from privkey
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32);
        GetRandBytes(seed.data(), 32);

        HDChain chain;
        chain.set_seed(seed);

        for (uint32_t i = 0; i < 10; ++i) {
            auto kp = chain.derive_key(i);

            // Independently derive pubkey from privkey
            auto expected_pubkey = derive_pubkey(kp.privkey.data());
            assert(kp.pubkey == expected_pubkey);
        }
    }

    // -----------------------------------------------------------------------
    // Test 9: Derived keys can produce valid signatures
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32);
        GetRandBytes(seed.data(), 32);

        HDChain chain;
        chain.set_seed(seed);

        auto kp = chain.derive_key(0);

        // Sign a message
        uint8_t message[] = "test message for HD-derived key";
        size_t msg_len = sizeof(message) - 1;

        auto sig = ed25519_sign(message, msg_len,
                                 kp.privkey.data(), kp.pubkey.data());

        // Verify the signature
        bool valid = ed25519_verify(message, msg_len,
                                     kp.pubkey.data(), sig.data());
        assert(valid);
    }

    // -----------------------------------------------------------------------
    // Test 10: generate_seed produces 32-byte seed
    // -----------------------------------------------------------------------
    {
        HDChain chain;
        chain.generate_seed();

        assert(chain.seed().size() == 32);
        assert(chain.next_index() == 0);

        // Seed should be non-zero (probabilistically)
        bool all_zero = true;
        for (auto b : chain.seed()) {
            if (b != 0) { all_zero = false; break; }
        }
        assert(!all_zero);
    }

    // -----------------------------------------------------------------------
    // Test 11: Two generate_seed calls produce different seeds
    // -----------------------------------------------------------------------
    {
        HDChain chain1, chain2;
        chain1.generate_seed();
        chain2.generate_seed();

        assert(chain1.seed() != chain2.seed());
    }

    // -----------------------------------------------------------------------
    // Test 12: Many consecutive derivations produce unique keys
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32);
        GetRandBytes(seed.data(), 32);

        HDChain chain;
        chain.set_seed(seed);

        std::set<std::array<uint8_t, 32>> pubkeys;
        std::set<std::array<uint8_t, 32>> privkeys;

        for (uint32_t i = 0; i < 100; ++i) {
            auto kp = chain.derive_key(i);
            pubkeys.insert(kp.pubkey);
            privkeys.insert(kp.privkey);
        }

        assert(pubkeys.size() == 100);
        assert(privkeys.size() == 100);
    }

    // -----------------------------------------------------------------------
    // Test 13: High index values work
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32, 0x55);
        HDChain chain;
        chain.set_seed(seed);

        auto kp_high = chain.derive_key(1000000);
        assert(!kp_high.pubkey[0] == 0 || true);  // Just verify it doesn't crash

        // Verify the key is valid (can sign)
        uint8_t msg[] = "high index test";
        auto sig = ed25519_sign(msg, sizeof(msg) - 1,
                                 kp_high.privkey.data(), kp_high.pubkey.data());
        assert(ed25519_verify(msg, sizeof(msg) - 1,
                               kp_high.pubkey.data(), sig.data()));
    }

    // -----------------------------------------------------------------------
    // Test 14: Cached intermediate keys - second derivation still correct
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32);
        GetRandBytes(seed.data(), 32);

        HDChain chain;
        chain.set_seed(seed);

        // Derive keys out of order
        auto kp5 = chain.derive_key(5);
        auto kp2 = chain.derive_key(2);
        auto kp5_again = chain.derive_key(5);
        auto kp2_again = chain.derive_key(2);

        assert(kp5.privkey == kp5_again.privkey);
        assert(kp5.pubkey == kp5_again.pubkey);
        assert(kp2.privkey == kp2_again.privkey);
        assert(kp2.pubkey == kp2_again.pubkey);
    }

    // -----------------------------------------------------------------------
    // Test 15: Seed of all zeros produces valid (non-zero) keys
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32, 0x00);
        HDChain chain;
        chain.set_seed(seed);

        auto kp = chain.derive_key(0);

        bool privkey_nonzero = false;
        for (auto b : kp.privkey) {
            if (b != 0) { privkey_nonzero = true; break; }
        }
        assert(privkey_nonzero);

        bool pubkey_nonzero = false;
        for (auto b : kp.pubkey) {
            if (b != 0) { pubkey_nonzero = true; break; }
        }
        assert(pubkey_nonzero);
    }

    // -----------------------------------------------------------------------
    // Test 16: Seed replacement changes all derived keys
    // -----------------------------------------------------------------------
    {
        HDChain chain;

        std::vector<uint8_t> seed1(32, 0x11);
        chain.set_seed(seed1);
        auto kp_s1 = chain.derive_key(0);

        std::vector<uint8_t> seed2(32, 0x22);
        chain.set_seed(seed2);
        auto kp_s2 = chain.derive_key(0);

        assert(kp_s1.privkey != kp_s2.privkey);
        assert(kp_s1.pubkey != kp_s2.pubkey);
    }

    // -----------------------------------------------------------------------
    // Test 17: Pubkey hash is keccak256(pubkey) for address derivation
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32);
        GetRandBytes(seed.data(), 32);

        HDChain chain;
        chain.set_seed(seed);

        auto kp = chain.derive_key(0);
        auto hash = keccak256(kp.pubkey.data(), 32);

        // The hash should be non-zero
        assert(!hash.is_null());

        // Two different keys should produce different hashes
        auto kp2 = chain.derive_key(1);
        auto hash2 = keccak256(kp2.pubkey.data(), 32);
        assert(hash != hash2);
    }

    // -----------------------------------------------------------------------
    // Test 18: Consecutive advance calls track correctly
    // -----------------------------------------------------------------------
    {
        HDChain chain;
        std::vector<uint8_t> seed(32);
        GetRandBytes(seed.data(), 32);
        chain.set_seed(seed);

        std::vector<KeyPair> keys;
        for (uint32_t i = 0; i < 20; ++i) {
            auto kp = chain.derive_key(chain.next_index());
            keys.push_back(kp);
            chain.advance();
        }

        assert(chain.next_index() == 20);

        // Verify each key is unique
        std::set<std::array<uint8_t, 32>> unique_pubs;
        for (const auto& kp : keys) {
            unique_pubs.insert(kp.pubkey);
        }
        assert(unique_pubs.size() == 20);

        // Re-derive same keys to verify determinism
        HDChain chain2;
        chain2.set_seed(seed);
        for (uint32_t i = 0; i < 20; ++i) {
            auto kp = chain2.derive_key(i);
            assert(kp.pubkey == keys[i].pubkey);
            assert(kp.privkey == keys[i].privkey);
        }
    }

    // -----------------------------------------------------------------------
    // Test 19: Multiple sign/verify with HD-derived keys
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32);
        GetRandBytes(seed.data(), 32);

        HDChain chain;
        chain.set_seed(seed);

        for (uint32_t idx = 0; idx < 5; ++idx) {
            auto kp = chain.derive_key(idx);

            // Sign multiple messages
            for (int m = 0; m < 3; ++m) {
                uint256 msg = GetRandUint256();
                auto sig = ed25519_sign(msg.data(), msg.size(),
                                         kp.privkey.data(), kp.pubkey.data());
                assert(ed25519_verify(msg.data(), msg.size(),
                                       kp.pubkey.data(), sig.data()));

                // Wrong message should fail
                uint256 wrong_msg = GetRandUint256();
                assert(!ed25519_verify(wrong_msg.data(), wrong_msg.size(),
                                        kp.pubkey.data(), sig.data()));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 20: Seed getter returns reference to internal data
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32, 0x77);
        HDChain chain;
        chain.set_seed(seed);

        const auto& ref = chain.seed();
        assert(ref.data() != seed.data());  // Should be a copy
        assert(ref == seed);
    }

    // -----------------------------------------------------------------------
    // Test 21: Derive key with index 0 and index UINT32_MAX
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32, 0x33);
        HDChain chain;
        chain.set_seed(seed);

        auto kp0 = chain.derive_key(0);
        auto kp_max = chain.derive_key(0xFFFFFFFF);

        assert(kp0.pubkey != kp_max.pubkey);

        // Both should produce valid signatures
        uint256 msg = GetRandUint256();

        auto sig0 = ed25519_sign(msg.data(), msg.size(),
                                  kp0.privkey.data(), kp0.pubkey.data());
        assert(ed25519_verify(msg.data(), msg.size(),
                               kp0.pubkey.data(), sig0.data()));

        auto sig_max = ed25519_sign(msg.data(), msg.size(),
                                     kp_max.privkey.data(), kp_max.pubkey.data());
        assert(ed25519_verify(msg.data(), msg.size(),
                               kp_max.pubkey.data(), sig_max.data()));
    }

    // -----------------------------------------------------------------------
    // Test 22: Derivation with sequential indices produces smooth key space
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32);
        GetRandBytes(seed.data(), 32);

        HDChain chain;
        chain.set_seed(seed);

        // Derive 50 keys and verify they're all distinct pairs
        std::vector<KeyPair> keys;
        for (uint32_t i = 0; i < 50; ++i) {
            keys.push_back(chain.derive_key(i));
        }

        for (size_t i = 0; i < keys.size(); ++i) {
            for (size_t j = i + 1; j < keys.size(); ++j) {
                assert(keys[i].pubkey != keys[j].pubkey);
                assert(keys[i].privkey != keys[j].privkey);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 23: advance() does not affect derive_key results
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32, 0xBB);
        HDChain chain;
        chain.set_seed(seed);

        // Derive key at index 5 before any advance
        auto kp_before = chain.derive_key(5);

        // Advance several times
        for (int i = 0; i < 10; ++i) {
            chain.advance();
        }

        // Derive same key at index 5 after advance
        auto kp_after = chain.derive_key(5);

        // Should be identical
        assert(kp_before.pubkey == kp_after.pubkey);
        assert(kp_before.privkey == kp_after.privkey);
    }

    // -----------------------------------------------------------------------
    // Test 24: Keccak256d of derived pubkey produces valid address hash
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32);
        GetRandBytes(seed.data(), 32);

        HDChain chain;
        chain.set_seed(seed);

        for (uint32_t i = 0; i < 5; ++i) {
            auto kp = chain.derive_key(i);

            // keccak256d(pubkey) should produce a unique 32-byte hash
            auto h = keccak256d(kp.pubkey.data(), 32);
            assert(!h.is_null());

            // Verify determinism
            auto h2 = keccak256d(kp.pubkey.data(), 32);
            assert(h == h2);
        }
    }

    // -----------------------------------------------------------------------
    // Test 25: set_index then advance works correctly
    // -----------------------------------------------------------------------
    {
        HDChain chain;
        std::vector<uint8_t> seed(32, 0xCC);
        chain.set_seed(seed);

        chain.set_index(50);
        assert(chain.next_index() == 50);

        chain.advance();
        assert(chain.next_index() == 51);

        chain.advance();
        chain.advance();
        assert(chain.next_index() == 53);
    }
}

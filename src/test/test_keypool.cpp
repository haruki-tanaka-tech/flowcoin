// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for the key pool.

#include "wallet/keypool.h"
#include "wallet/hdchain.h"
#include "wallet/walletdb.h"
#include "crypto/keys.h"
#include "hash/keccak.h"

#include <cassert>
#include <cstring>
#include <set>
#include <stdexcept>
#include <unistd.h>

using namespace flow;

void test_keypool() {
    // Create an in-memory wallet database
    std::string db_path = "/tmp/test_keypool_" + std::to_string(getpid()) + ".dat";
    WalletDB db(db_path);

    // Initialize HD chain with a deterministic seed
    HDChain hd;
    std::vector<uint8_t> seed(32, 0x42);
    hd.set_seed(seed);
    hd.set_index(0);

    // Store master seed
    db.store_master_seed(seed);
    db.store_hd_index(0);

    KeyPool pool(hd, db);

    // -----------------------------------------------------------------------
    // Test 1: fill creates keys
    // -----------------------------------------------------------------------
    {
        assert(pool.size() == 0);
        pool.fill(10);
        assert(pool.size() == 10);
    }

    // -----------------------------------------------------------------------
    // Test 2: get_key returns unique keys
    // -----------------------------------------------------------------------
    {
        std::set<std::array<uint8_t, 32>> seen;
        for (int i = 0; i < 5; ++i) {
            KeyPair kp = pool.get_key();
            assert(seen.find(kp.pubkey) == seen.end());
            seen.insert(kp.pubkey);
        }
        // Pool should have 5 remaining
        assert(pool.size() == 5);
    }

    // -----------------------------------------------------------------------
    // Test 3: return_key makes key available again
    // -----------------------------------------------------------------------
    {
        size_t before = pool.size();
        KeyPair kp = pool.get_key();
        assert(pool.size() == before - 1);

        pool.return_key(kp.pubkey);
        assert(pool.size() == before);

        // The returned key should be available
        assert(pool.contains(kp.pubkey));
    }

    // -----------------------------------------------------------------------
    // Test 4: mark_used removes from pool
    // -----------------------------------------------------------------------
    {
        pool.fill(10);
        size_t before = pool.size();

        KeyPair kp = pool.get_key();
        pool.return_key(kp.pubkey);
        assert(pool.contains(kp.pubkey));

        pool.mark_used(kp.pubkey);
        assert(!pool.contains(kp.pubkey));
    }

    // -----------------------------------------------------------------------
    // Test 5: pool refills when depleted
    // -----------------------------------------------------------------------
    {
        // Drain the pool
        while (pool.size() > 0) {
            pool.get_key();
        }
        assert(pool.size() == 0);

        // get_key should still work (derives on the spot)
        KeyPair kp = pool.get_key();
        // Pubkey should be non-zero
        bool all_zero = true;
        for (auto b : kp.pubkey) {
            if (b != 0) { all_zero = false; break; }
        }
        assert(!all_zero);

        // Refill and verify
        pool.fill(20);
        assert(pool.size() == 20);
    }

    // -----------------------------------------------------------------------
    // Test 6: oldest_index and newest_index
    // -----------------------------------------------------------------------
    {
        // Clear and refill
        while (pool.size() > 0) pool.get_key();
        pool.fill(5);

        uint32_t oldest = pool.oldest_index();
        uint32_t newest = pool.newest_index();
        assert(newest > oldest || pool.size() <= 1);
        assert(oldest > 0 || newest > 0);  // HD indices should advance
    }

    // -----------------------------------------------------------------------
    // Test 7: get_used_keys tracks used keys
    // -----------------------------------------------------------------------
    {
        auto used = pool.get_used_keys();
        // We've consumed several keys in previous tests
        assert(!used.empty());
    }

    // -----------------------------------------------------------------------
    // Test 8: fill is idempotent when already at target
    // -----------------------------------------------------------------------
    {
        pool.fill(5);
        size_t s1 = pool.size();
        pool.fill(5);  // should be a no-op if already >= 5
        size_t s2 = pool.size();
        assert(s1 == s2);
    }

    // Cleanup
    unlink(db_path.c_str());
}

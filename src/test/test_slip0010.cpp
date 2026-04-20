// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "crypto/slip0010.h"
#include "util/strencodings.h"
#include <cassert>
#include <cstring>
#include <stdexcept>

void test_slip0010() {
    // Test that master key derivation is deterministic
    uint8_t seed1[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    auto master1 = flow::slip0010_master(seed1, 16);
    auto master2 = flow::slip0010_master(seed1, 16);

    // Same seed produces same master key
    assert(master1.key == master2.key);
    assert(master1.chain_code == master2.chain_code);

    // Different seed produces different key
    uint8_t seed2[16] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    auto master3 = flow::slip0010_master(seed2, 16);
    assert(master1.key != master3.key);

    // Master key should not be all zeros
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (master1.key[i] != 0) { all_zero = false; break; }
    }
    assert(!all_zero);

    // Chain code should not be all zeros
    all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (master1.chain_code[i] != 0) { all_zero = false; break; }
    }
    assert(!all_zero);

    // Child derivation is deterministic
    auto child1 = flow::slip0010_derive_hardened(master1, 0x80000000);
    auto child2 = flow::slip0010_derive_hardened(master1, 0x80000000);
    assert(child1.key == child2.key);
    assert(child1.chain_code == child2.chain_code);

    // Different index produces different child
    auto child3 = flow::slip0010_derive_hardened(master1, 0x80000001);
    assert(child1.key != child3.key);

    // Child key should differ from master key
    assert(child1.key != master1.key);

    // Full path derivation: m/44'/9555'/0'/0'/0'
    auto path1 = flow::slip0010_derive_path(seed1, 16, 0);
    auto path2 = flow::slip0010_derive_path(seed1, 16, 0);
    assert(path1.key == path2.key);
    assert(path1.chain_code == path2.chain_code);

    // Different address index produces different key
    auto path3 = flow::slip0010_derive_path(seed1, 16, 1);
    assert(path1.key != path3.key);

    // Path-derived key should differ from master
    assert(path1.key != master1.key);

    // Different seeds at same path produce different keys
    auto path_seed2 = flow::slip0010_derive_path(seed2, 16, 0);
    assert(path1.key != path_seed2.key);

    // Longer seed (32 bytes)
    uint8_t seed_long[32];
    for (int i = 0; i < 32; i++) seed_long[i] = static_cast<uint8_t>(i);
    auto master_long = flow::slip0010_master(seed_long, 32);
    assert(master_long.key != master1.key);
}

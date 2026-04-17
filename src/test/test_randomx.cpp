// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Unit tests for the RandomX integration.
//
// Two layers are covered:
//   1. Direct use of the vendored library against tevador's official v1
//      test vectors (proves the submodule builds and links correctly).
//   2. Our wrapper ComputePowHash: determinism, seed sensitivity, and the
//      seed-rotation height formula.

#include "consensus/pow.h"
#include "util/strencodings.h"

#include <randomx.h>

#include <cassert>
#include <cstring>
#include <stdexcept>
#include <string>

namespace {

std::string hash_hex(const uint8_t* bytes, size_t n) {
    return flow::hex_encode(bytes, n);
}

// Compute a RandomX hash using the vendored library directly, matching
// tevador's internal tests.cpp calcStringHash path.
std::string direct_hash(const char* key, const char* input) {
    randomx_flags flags = RANDOMX_FLAG_DEFAULT;
    randomx_cache* cache = randomx_alloc_cache(flags);
    if (!cache) throw std::runtime_error("randomx_alloc_cache failed");

    randomx_init_cache(cache, key, std::strlen(key));

    randomx_vm* vm = randomx_create_vm(flags, cache, nullptr);
    if (!vm) {
        randomx_release_cache(cache);
        throw std::runtime_error("randomx_create_vm failed");
    }

    uint8_t out[RANDOMX_HASH_SIZE];
    randomx_calculate_hash(vm, input, std::strlen(input), out);

    randomx_destroy_vm(vm);
    randomx_release_cache(cache);

    return hash_hex(out, RANDOMX_HASH_SIZE);
}

void assert_eq(const std::string& got, const std::string& expected,
               const char* label) {
    if (got != expected) {
        throw std::runtime_error(
            std::string(label) + " mismatch:\n  got:      " + got +
            "\n  expected: " + expected);
    }
}

} // namespace

void test_randomx() {
    // -----------------------------------------------------------------------
    // Layer 1: tevador's official v1 vectors. These are asserted bit-for-bit
    // in the upstream tests.cpp (`RANDOMX_ARGON_SALT = "RandomX\x03"` branch).
    // A mismatch here means the vendored library was compiled incorrectly.
    // -----------------------------------------------------------------------

    assert_eq(direct_hash("test key 000", "This is a test"),
              "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f",
              "tevador vector A");

    assert_eq(direct_hash("test key 000", "Lorem ipsum dolor sit amet"),
              "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969",
              "tevador vector B");

    assert_eq(direct_hash("test key 000",
                          "sed do eiusmod tempor incididunt ut labore et "
                          "dolore magna aliqua"),
              "c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8",
              "tevador vector C");

    // -----------------------------------------------------------------------
    // Layer 2: our wrapper. ComputePowHash must be deterministic and must
    // depend on both input and seed.
    // -----------------------------------------------------------------------

    flow::uint256 seed_a{};
    seed_a[0] = 0x01;  // non-zero, short enough to avoid any edge case

    flow::uint256 seed_b{};
    seed_b[0] = 0x02;

    const uint8_t input1[] = {'h', 'e', 'l', 'l', 'o'};
    const uint8_t input2[] = {'w', 'o', 'r', 'l', 'd'};

    auto h_a_1 = flow::consensus::ComputePowHash(input1, sizeof(input1), seed_a);
    auto h_a_1_again = flow::consensus::ComputePowHash(input1, sizeof(input1), seed_a);
    auto h_a_2 = flow::consensus::ComputePowHash(input2, sizeof(input2), seed_a);
    auto h_b_1 = flow::consensus::ComputePowHash(input1, sizeof(input1), seed_b);

    // Determinism: same seed + same input ⇒ same hash.
    assert(h_a_1 == h_a_1_again);

    // Input sensitivity: same seed + different input ⇒ different hash.
    assert(h_a_1 != h_a_2);

    // Seed sensitivity: different seed + same input ⇒ different hash.
    assert(h_a_1 != h_b_1);

    // -----------------------------------------------------------------------
    // Layer 3: rx_seed_height formula — the Monero-style seed rotation.
    // -----------------------------------------------------------------------

    using flow::consensus::rx_seed_height;
    using flow::consensus::SEEDHASH_EPOCH_BLOCKS;
    using flow::consensus::SEEDHASH_EPOCH_LAG;

    // First epoch (height <= EPOCH + LAG) uses genesis as seed.
    assert(rx_seed_height(0) == 0);
    assert(rx_seed_height(1) == 0);
    assert(rx_seed_height(SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG) == 0);

    // Just past the first epoch+lag, seed jumps to the first epoch boundary.
    assert(rx_seed_height(SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG + 1) ==
           SEEDHASH_EPOCH_BLOCKS);

    // Within an epoch, seed is stable.
    for (uint64_t h = 2 * SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG + 1;
         h < 3 * SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG + 1;
         ++h) {
        assert(rx_seed_height(h) == 2 * SEEDHASH_EPOCH_BLOCKS);
    }

    // At the next boundary + lag + 1 the seed advances.
    assert(rx_seed_height(3 * SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG + 1) ==
           3 * SEEDHASH_EPOCH_BLOCKS);

    flow::consensus::ShutdownRandomX();
}

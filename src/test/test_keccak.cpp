// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "hash/keccak.h"
#include "util/strencodings.h"
#include <cassert>
#include <cstring>
#include <stdexcept>

static void assert_hash(const char* input, size_t len, const char* expected_hex) {
    auto hash = flow::keccak256(reinterpret_cast<const uint8_t*>(input), len);
    std::string got = flow::hex_encode(hash.data(), 32);
    if (got != expected_hex) {
        throw std::runtime_error(
            std::string("keccak256 mismatch:\n  got:      ") + got +
            "\n  expected: " + expected_hex);
    }
}

void test_keccak() {
    // Empty string -- THE critical test.
    // If this returns a7ffc6f6... that's SHA-3 (pad 0x06), not Keccak (pad 0x01).
    assert_hash("", 0,
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

    // "abc"
    assert_hash("abc", 3,
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");

    // Test keccak256d (double hash): keccak256(keccak256(data))
    auto single = flow::keccak256(reinterpret_cast<const uint8_t*>(""), 0);
    auto double_hash = flow::keccak256d(reinterpret_cast<const uint8_t*>(""), 0);
    auto expected_double = flow::keccak256(single.data(), 32);
    assert(double_hash == expected_double);

    // keccak256d of "abc" should also be keccak(keccak("abc"))
    auto single_abc = flow::keccak256(reinterpret_cast<const uint8_t*>("abc"), 3);
    auto double_abc = flow::keccak256d(reinterpret_cast<const uint8_t*>("abc"), 3);
    auto expected_double_abc = flow::keccak256(single_abc.data(), 32);
    assert(double_abc == expected_double_abc);

    // Incremental hasher: feeding "ab" then "c" must equal one-shot "abc"
    flow::CKeccak256 hasher;
    hasher.update(reinterpret_cast<const uint8_t*>("ab"), 2);
    hasher.update(reinterpret_cast<const uint8_t*>("c"), 1);
    auto incremental = hasher.finalize();
    auto oneshot = flow::keccak256(reinterpret_cast<const uint8_t*>("abc"), 3);
    assert(incremental == oneshot);

    // Reset and reuse
    hasher.reset();
    hasher.update(reinterpret_cast<const uint8_t*>("abc"), 3);
    auto after_reset = hasher.finalize();
    assert(after_reset == oneshot);

    // Vector overload
    std::vector<uint8_t> vec = {'a', 'b', 'c'};
    auto vec_hash = flow::keccak256(vec);
    assert(vec_hash == oneshot);

    // Vector overload for keccak256d
    auto vec_double = flow::keccak256d(vec);
    assert(vec_double == double_abc);
}

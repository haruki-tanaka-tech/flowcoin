// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for cryptographically secure random number generation.

#include "util/random.h"
#include "util/types.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <set>
#include <thread>
#include <vector>

void test_random() {
    // -----------------------------------------------------------------------
    // Test 1: GetRandBytes fills buffer with non-zero data (probabilistically)
    // -----------------------------------------------------------------------
    {
        uint8_t buf[64];
        std::memset(buf, 0, sizeof(buf));
        flow::GetRandBytes(buf, sizeof(buf));

        // It is astronomically unlikely that 64 random bytes are all zero
        bool all_zero = true;
        for (auto b : buf) {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }
        assert(!all_zero);
    }

    // -----------------------------------------------------------------------
    // Test 2: Two successive calls produce different output
    // -----------------------------------------------------------------------
    {
        uint8_t buf1[32], buf2[32];
        flow::GetRandBytes(buf1, sizeof(buf1));
        flow::GetRandBytes(buf2, sizeof(buf2));

        // Probability of collision: 2^-256
        assert(std::memcmp(buf1, buf2, 32) != 0);
    }

    // -----------------------------------------------------------------------
    // Test 3: GetRandUint64 returns values (non-zero probabilistically)
    // -----------------------------------------------------------------------
    {
        // Get several random uint64s and verify they are not all identical
        std::set<uint64_t> values;
        for (int i = 0; i < 100; i++) {
            values.insert(flow::GetRandUint64());
        }
        // With 100 random uint64 values, we expect all to be unique
        // (collision probability is negligible)
        assert(values.size() >= 98);
    }

    // -----------------------------------------------------------------------
    // Test 4: GetRandUint256 produces non-zero values
    // -----------------------------------------------------------------------
    {
        flow::uint256 val = flow::GetRandUint256();
        assert(!val.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 5: GetRandUint256 produces different values each call
    // -----------------------------------------------------------------------
    {
        flow::uint256 a = flow::GetRandUint256();
        flow::uint256 b = flow::GetRandUint256();
        assert(a != b);
    }

    // -----------------------------------------------------------------------
    // Test 6: GetRandBytes with length 0 does not crash
    // -----------------------------------------------------------------------
    {
        uint8_t dummy = 0xAA;
        flow::GetRandBytes(&dummy, 0);
        // dummy should be unchanged (no bytes written)
        assert(dummy == 0xAA);
    }

    // -----------------------------------------------------------------------
    // Test 7: GetRandBytes with length 1 works
    // -----------------------------------------------------------------------
    {
        uint8_t single;
        flow::GetRandBytes(&single, 1);
        // Just verify it doesn't crash; any value is valid
    }

    // -----------------------------------------------------------------------
    // Test 8: Distribution roughly uniform (chi-square test with generous bounds)
    // -----------------------------------------------------------------------
    {
        // Generate a large sample and bucket into 256 bins
        constexpr size_t sample_size = 256000;
        std::vector<uint8_t> data(sample_size);
        flow::GetRandBytes(data.data(), data.size());

        int buckets[256] = {};
        for (uint8_t b : data) {
            buckets[b]++;
        }

        // Expected count per bucket: sample_size / 256 = 1000
        double expected = static_cast<double>(sample_size) / 256.0;
        double chi_squared = 0.0;
        for (int i = 0; i < 256; i++) {
            double diff = static_cast<double>(buckets[i]) - expected;
            chi_squared += (diff * diff) / expected;
        }

        // Chi-squared with 255 degrees of freedom:
        // At p=0.001, critical value is ~310
        // At p=0.999, critical value is ~197
        // We use very generous bounds to avoid flaky tests: < 500
        assert(chi_squared < 500.0);
    }

    // -----------------------------------------------------------------------
    // Test 9: Large buffer fill works correctly
    // -----------------------------------------------------------------------
    {
        // Fill a large buffer (64KB) and verify we get diverse data
        constexpr size_t large_size = 65536;
        std::vector<uint8_t> large_buf(large_size, 0);
        flow::GetRandBytes(large_buf.data(), large_buf.size());

        // Count distinct byte values seen
        std::set<uint8_t> distinct;
        for (uint8_t b : large_buf) {
            distinct.insert(b);
        }
        // With 64K random bytes, we expect to see all 256 byte values
        assert(distinct.size() >= 250);
    }

    // -----------------------------------------------------------------------
    // Test 10: Thread-safe — concurrent access does not crash
    // -----------------------------------------------------------------------
    {
        constexpr int num_threads = 8;
        constexpr int iterations = 1000;

        std::vector<std::thread> threads;
        std::vector<uint64_t> results(num_threads * iterations, 0);

        for (int t = 0; t < num_threads; t++) {
            threads.emplace_back([&results, t]() {
                for (int i = 0; i < iterations; i++) {
                    results[t * iterations + i] = flow::GetRandUint64();
                }
            });
        }

        for (auto& th : threads) {
            th.join();
        }

        // Verify we got diverse results (not all same value)
        std::set<uint64_t> unique_vals(results.begin(), results.end());
        // With 8000 random uint64s, expect essentially all unique
        assert(unique_vals.size() >= static_cast<size_t>(num_threads * iterations - 10));
    }

    // -----------------------------------------------------------------------
    // Test 11: Multiple GetRandUint256 calls produce unique hashes
    // -----------------------------------------------------------------------
    {
        constexpr int count = 50;
        std::vector<flow::uint256> hashes;
        hashes.reserve(count);
        for (int i = 0; i < count; i++) {
            hashes.push_back(flow::GetRandUint256());
        }

        // Check all are unique
        for (int i = 0; i < count; i++) {
            for (int j = i + 1; j < count; j++) {
                assert(hashes[i] != hashes[j]);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 12: GetRandBytes fills exact requested length
    // -----------------------------------------------------------------------
    {
        // Write a sentinel pattern, fill the middle, verify sentinel untouched
        uint8_t buf[34];
        buf[0] = 0xAA;
        buf[33] = 0xBB;
        flow::GetRandBytes(buf + 1, 32);
        assert(buf[0] == 0xAA);
        assert(buf[33] == 0xBB);
    }

    // -----------------------------------------------------------------------
    // Test 13: GetRandUint64 covers wide range
    // -----------------------------------------------------------------------
    {
        // Generate many values and check that both high and low bits are set
        bool high_bit_seen = false;
        bool low_bit_seen = false;
        for (int i = 0; i < 1000; i++) {
            uint64_t v = flow::GetRandUint64();
            if (v & (1ULL << 63)) high_bit_seen = true;
            if (v & 1ULL) low_bit_seen = true;
        }
        assert(high_bit_seen);
        assert(low_bit_seen);
    }

    // -----------------------------------------------------------------------
    // Test 14: GetRandUint256 has all bytes covered
    // -----------------------------------------------------------------------
    {
        // Generate many hashes and verify all 32 byte positions have
        // non-zero values at least once
        bool seen_nonzero[32] = {};
        for (int i = 0; i < 100; i++) {
            flow::uint256 v = flow::GetRandUint256();
            for (int j = 0; j < 32; j++) {
                if (v[j] != 0) seen_nonzero[j] = true;
            }
        }
        for (int j = 0; j < 32; j++) {
            assert(seen_nonzero[j]);
        }
    }

    // -----------------------------------------------------------------------
    // Test 15: Small buffer sizes work (1-16 bytes)
    // -----------------------------------------------------------------------
    {
        for (size_t len = 1; len <= 16; len++) {
            std::vector<uint8_t> buf(len, 0);
            flow::GetRandBytes(buf.data(), len);
            // Just verify no crash
        }
    }

    // -----------------------------------------------------------------------
    // Test 16: Byte-level uniformity at each position
    // -----------------------------------------------------------------------
    {
        constexpr int samples = 10000;
        constexpr int positions = 4;
        int counts[positions][256] = {};

        for (int i = 0; i < samples; i++) {
            uint8_t buf[positions];
            flow::GetRandBytes(buf, positions);
            for (int p = 0; p < positions; p++) {
                counts[p][buf[p]]++;
            }
        }

        // Each position should have all 256 values represented
        // (with 10000 samples, probability of missing any value is negligible)
        for (int p = 0; p < positions; p++) {
            int min_count = samples;
            int max_count = 0;
            for (int v = 0; v < 256; v++) {
                if (counts[p][v] < min_count) min_count = counts[p][v];
                if (counts[p][v] > max_count) max_count = counts[p][v];
            }
            // Expected ~39 per bucket. Min should be > 0, max < 200
            assert(min_count > 0);
            assert(max_count < 200);
        }
    }

    // -----------------------------------------------------------------------
    // Test 17: GetRandUint64 statistical independence test
    // -----------------------------------------------------------------------
    {
        // Check that consecutive values show no obvious correlation
        uint64_t prev = flow::GetRandUint64();
        int same_sign_count = 0;
        constexpr int num_samples = 500;

        for (int i = 0; i < num_samples; i++) {
            uint64_t curr = flow::GetRandUint64();
            // Count how often consecutive values have the same MSB
            if ((prev >> 63) == (curr >> 63)) same_sign_count++;
            prev = curr;
        }

        // Expected ~50% of the time. Allow 40%-60%.
        assert(same_sign_count > num_samples * 40 / 100);
        assert(same_sign_count < num_samples * 60 / 100);
    }

    // -----------------------------------------------------------------------
    // Test 18: Blob comparison operators work with random data
    // -----------------------------------------------------------------------
    {
        flow::uint256 a = flow::GetRandUint256();
        flow::uint256 b = flow::GetRandUint256();

        // Exactly one of these must be true: a < b, a == b, a > b
        bool lt = (a < b);
        bool eq = (a == b);
        bool gt = (a > b);
        int true_count = (lt ? 1 : 0) + (eq ? 1 : 0) + (gt ? 1 : 0);
        assert(true_count == 1);

        // Test consistency
        assert(lt == !(a >= b));
        assert(gt == !(a <= b));
        assert(eq == !(a != b));
    }

    // -----------------------------------------------------------------------
    // Test 19: Large concurrent random generation
    // -----------------------------------------------------------------------
    {
        constexpr int num_threads = 4;
        constexpr size_t bytes_per_thread = 4096;

        std::vector<std::vector<uint8_t>> thread_data(num_threads);
        std::vector<std::thread> threads;

        for (int t = 0; t < num_threads; t++) {
            thread_data[t].resize(bytes_per_thread);
            threads.emplace_back([&thread_data, t]() {
                flow::GetRandBytes(thread_data[t].data(), bytes_per_thread);
            });
        }

        for (auto& th : threads) {
            th.join();
        }

        // All thread outputs should be different
        for (int i = 0; i < num_threads; i++) {
            for (int j = i + 1; j < num_threads; j++) {
                assert(thread_data[i] != thread_data[j]);
            }
        }
    }
}

// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Extended tests for delta payload compression/decompression.
// Covers sparse formats, large payloads, deterministic hashing,
// and edge cases.

#include "primitives/delta.h"
#include "hash/keccak.h"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <vector>

// Helper: create a delta-like payload of float values
static std::vector<uint8_t> make_float_payload(const std::vector<float>& floats) {
    std::vector<uint8_t> data(floats.size() * sizeof(float));
    std::memcpy(data.data(), floats.data(), data.size());
    return data;
}

// Helper: recover floats from a byte payload
static std::vector<float> payload_to_floats(const std::vector<uint8_t>& data) {
    size_t count = data.size() / sizeof(float);
    std::vector<float> result(count);
    std::memcpy(result.data(), data.data(), count * sizeof(float));
    return result;
}

// Helper: compute sparsity ratio (fraction of zeros among floats)
static float compute_sparsity(const std::vector<float>& values) {
    if (values.empty()) return 0.0f;
    int zeros = 0;
    for (float v : values) {
        if (v == 0.0f) zeros++;
    }
    return static_cast<float>(zeros) / static_cast<float>(values.size());
}

void test_delta_full() {
    // -----------------------------------------------------------------------
    // Test 1: Compress/decompress round-trip for float data
    // -----------------------------------------------------------------------
    {
        std::vector<float> weights = {0.1f, -0.2f, 0.0f, 0.3f, -0.001f,
                                       0.0f, 0.5f, 0.0f, 0.0f, 0.01f};
        auto payload = make_float_payload(weights);

        auto compressed = flow::compress_delta(payload);
        assert(!compressed.empty());

        auto decompressed = flow::decompress_delta(compressed);
        assert(decompressed.size() == payload.size());
        assert(decompressed == payload);

        auto recovered = payload_to_floats(decompressed);
        assert(recovered.size() == weights.size());
        for (size_t i = 0; i < weights.size(); i++) {
            assert(recovered[i] == weights[i]);
        }
    }

    // -----------------------------------------------------------------------
    // Test 2: Sparse delta — mostly zeros, compresses very well
    // -----------------------------------------------------------------------
    {
        // 10000 floats, 99% zeros (sparse)
        std::vector<float> sparse_weights(10000, 0.0f);
        // Scatter a few non-zero values
        sparse_weights[42] = 0.5f;
        sparse_weights[100] = -0.3f;
        sparse_weights[9999] = 1.0f;

        auto payload = make_float_payload(sparse_weights);
        auto compressed = flow::compress_delta(payload);

        // Sparse data should compress very well (all those zeros)
        assert(compressed.size() < payload.size() / 5);

        auto decompressed = flow::decompress_delta(compressed);
        assert(decompressed == payload);

        float sparsity = compute_sparsity(sparse_weights);
        assert(sparsity > 0.99f);
    }

    // -----------------------------------------------------------------------
    // Test 3: Dense delta — no zeros, still round-trips
    // -----------------------------------------------------------------------
    {
        std::vector<float> dense_weights(1000);
        for (size_t i = 0; i < dense_weights.size(); i++) {
            // Pseudo-random non-zero values
            dense_weights[i] = static_cast<float>(i) * 0.001f + 0.0001f;
        }

        auto payload = make_float_payload(dense_weights);
        auto compressed = flow::compress_delta(payload);
        assert(!compressed.empty());

        auto decompressed = flow::decompress_delta(compressed);
        assert(decompressed == payload);

        float sparsity = compute_sparsity(dense_weights);
        assert(sparsity < 0.01f);
    }

    // -----------------------------------------------------------------------
    // Test 4: Compression hash is deterministic
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> data(500);
        for (size_t i = 0; i < data.size(); i++) {
            data[i] = static_cast<uint8_t>(i % 256);
        }

        auto comp1 = flow::compress_delta(data);
        auto comp2 = flow::compress_delta(data);

        // Same input produces same compressed output
        assert(comp1 == comp2);

        // Hash of compressed data is deterministic
        auto hash1 = flow::keccak256(comp1);
        auto hash2 = flow::keccak256(comp2);
        assert(hash1 == hash2);
    }

    // -----------------------------------------------------------------------
    // Test 5: Different data produces different compressed output
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> data1(100, 0xAA);
        std::vector<uint8_t> data2(100, 0xBB);

        auto comp1 = flow::compress_delta(data1);
        auto comp2 = flow::compress_delta(data2);

        assert(comp1 != comp2);
    }

    // -----------------------------------------------------------------------
    // Test 6: All-zero delta has minimal compressed size
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> zeros(100000, 0);
        auto compressed = flow::compress_delta(zeros);

        // Zstd should compress 100KB of zeros to well under 1KB
        assert(compressed.size() < 1000);

        auto decompressed = flow::decompress_delta(compressed);
        assert(decompressed.size() == zeros.size());
        for (auto b : decompressed) {
            assert(b == 0);
        }
    }

    // -----------------------------------------------------------------------
    // Test 7: Very large delta (100K floats = 400KB) handled
    // -----------------------------------------------------------------------
    {
        constexpr size_t num_floats = 100000;
        std::vector<float> large_weights(num_floats);

        // Create a pattern that's somewhat compressible
        for (size_t i = 0; i < num_floats; i++) {
            large_weights[i] = (i % 10 == 0) ? static_cast<float>(i) * 0.001f : 0.0f;
        }

        auto payload = make_float_payload(large_weights);
        assert(payload.size() == num_floats * sizeof(float));

        auto compressed = flow::compress_delta(payload);
        assert(!compressed.empty());
        assert(compressed.size() < payload.size());

        auto decompressed = flow::decompress_delta(compressed);
        assert(decompressed == payload);
    }

    // -----------------------------------------------------------------------
    // Test 8: Single byte delta
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> tiny = {0x42};
        auto compressed = flow::compress_delta(tiny);
        assert(!compressed.empty());

        auto decompressed = flow::decompress_delta(compressed);
        assert(decompressed.size() == 1);
        assert(decompressed[0] == 0x42);
    }

    // -----------------------------------------------------------------------
    // Test 9: Decompression of corrupted data returns empty
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> garbage = {0xDE, 0xAD, 0xBE, 0xEF};
        auto result = flow::decompress_delta(garbage);
        assert(result.empty());
    }

    // -----------------------------------------------------------------------
    // Test 10: Decompression of truncated data returns empty
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> data(500, 0xAA);
        auto compressed = flow::compress_delta(data);
        // Truncate the compressed data
        std::vector<uint8_t> truncated(compressed.begin(),
                                        compressed.begin() + compressed.size() / 2);
        auto result = flow::decompress_delta(truncated);
        assert(result.empty());
    }

    // -----------------------------------------------------------------------
    // Test 11: Decompression of empty input returns empty
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> empty;
        auto result = flow::decompress_delta(empty);
        assert(result.empty());
    }

    // -----------------------------------------------------------------------
    // Test 12: Multiple compress/decompress cycles are idempotent
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> original(2000);
        for (size_t i = 0; i < original.size(); i++) {
            original[i] = static_cast<uint8_t>((i * 7 + 13) % 256);
        }

        auto comp = flow::compress_delta(original);
        auto decomp = flow::decompress_delta(comp);
        assert(decomp == original);

        // Re-compress the decompressed data
        auto recomp = flow::compress_delta(decomp);
        auto redecomp = flow::decompress_delta(recomp);
        assert(redecomp == original);

        // Compressed outputs should be identical (deterministic)
        assert(comp == recomp);
    }

    // -----------------------------------------------------------------------
    // Test 13: Float payload with special values (but valid non-NaN/Inf)
    // -----------------------------------------------------------------------
    {
        std::vector<float> special = {
            0.0f, -0.0f,
            1e-38f,    // smallest normal float
            1e+38f,    // large float
            -1e+38f,   // large negative
            1e-7f,     // typical weight delta magnitude
        };

        auto payload = make_float_payload(special);
        auto compressed = flow::compress_delta(payload);
        auto decompressed = flow::decompress_delta(compressed);
        auto recovered = payload_to_floats(decompressed);

        assert(recovered.size() == special.size());
        for (size_t i = 0; i < special.size(); i++) {
            // Bit-exact comparison (including -0.0f vs 0.0f)
            uint32_t orig_bits, recov_bits;
            std::memcpy(&orig_bits, &special[i], sizeof(float));
            std::memcpy(&recov_bits, &recovered[i], sizeof(float));
            assert(orig_bits == recov_bits);
        }
    }

    // -----------------------------------------------------------------------
    // Test 14: Keccak hash of compressed delta is consistent
    // -----------------------------------------------------------------------
    {
        std::vector<float> weights(500, 0.42f);
        auto payload = make_float_payload(weights);

        auto comp1 = flow::compress_delta(payload);
        auto comp2 = flow::compress_delta(payload);

        auto hash1 = flow::keccak256(comp1);
        auto hash2 = flow::keccak256(comp2);
        assert(hash1 == hash2);
        assert(!hash1.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 15: Pointer + length overload matches vector overload
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8};
        auto comp_vec = flow::compress_delta(data);
        auto comp_ptr = flow::compress_delta(data.data(), data.size());
        assert(comp_vec == comp_ptr);

        auto decomp_vec = flow::decompress_delta(comp_vec);
        auto decomp_ptr = flow::decompress_delta(comp_ptr.data(), comp_ptr.size());
        assert(decomp_vec == decomp_ptr);
        assert(decomp_vec == data);
    }
}

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "primitives/delta.h"
#include <cassert>
#include <cstring>
#include <stdexcept>
#include <vector>

void test_delta() {
    // Basic compress/decompress round-trip
    {
        std::vector<uint8_t> original(1000);
        for (size_t i = 0; i < original.size(); i++) {
            original[i] = static_cast<uint8_t>(i % 256);
        }

        auto compressed = flow::compress_delta(original.data(), original.size());
        assert(!compressed.empty());

        // Compressed should be smaller (the pattern is compressible)
        assert(compressed.size() < original.size());

        auto decompressed = flow::decompress_delta(compressed.data(), compressed.size());
        assert(decompressed.size() == original.size());
        assert(std::memcmp(decompressed.data(), original.data(), original.size()) == 0);
    }

    // Vector overloads
    {
        std::vector<uint8_t> original = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        auto compressed = flow::compress_delta(original);
        assert(!compressed.empty());

        auto decompressed = flow::decompress_delta(compressed);
        assert(decompressed == original);
    }

    // Highly compressible data (all zeros)
    {
        std::vector<uint8_t> zeros(100000, 0);
        auto compressed = flow::compress_delta(zeros);
        assert(!compressed.empty());
        // All zeros should compress very well
        assert(compressed.size() < zeros.size() / 10);

        auto decompressed = flow::decompress_delta(compressed);
        assert(decompressed.size() == zeros.size());
        for (auto b : decompressed) {
            assert(b == 0);
        }
    }

    // Small data
    {
        std::vector<uint8_t> small = {0x42};
        auto compressed = flow::compress_delta(small);
        assert(!compressed.empty());

        auto decompressed = flow::decompress_delta(compressed);
        assert(decompressed.size() == 1);
        assert(decompressed[0] == 0x42);
    }

    // Random-ish data (less compressible)
    {
        std::vector<uint8_t> data(5000);
        uint32_t state = 12345;
        for (size_t i = 0; i < data.size(); i++) {
            state = state * 1103515245 + 12345;
            data[i] = static_cast<uint8_t>((state >> 16) & 0xFF);
        }

        auto compressed = flow::compress_delta(data);
        assert(!compressed.empty());

        auto decompressed = flow::decompress_delta(compressed);
        assert(decompressed == data);
    }

    // Invalid compressed data should return empty
    {
        std::vector<uint8_t> garbage = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB};
        auto decompressed = flow::decompress_delta(garbage);
        assert(decompressed.empty());
    }

    // Truncated compressed data should return empty
    {
        std::vector<uint8_t> original(1000, 0x42);
        auto compressed = flow::compress_delta(original);
        assert(compressed.size() > 2);

        // Truncate to half
        std::vector<uint8_t> truncated(compressed.begin(),
                                        compressed.begin() + compressed.size() / 2);
        auto decompressed = flow::decompress_delta(truncated);
        assert(decompressed.empty());
    }

    // Compress/decompress preserves exact content for sparse float delta pattern
    {
        // Simulate a sparse model delta: mostly zeros with occasional non-zero values
        size_t num_floats = 10000;
        std::vector<uint8_t> delta(num_floats * sizeof(float), 0);

        // Set every 100th float to a non-zero value
        for (size_t i = 0; i < num_floats; i += 100) {
            float val = static_cast<float>(i) * 0.001f;
            std::memcpy(&delta[i * sizeof(float)], &val, sizeof(float));
        }

        auto compressed = flow::compress_delta(delta);
        assert(!compressed.empty());
        // Sparse data should compress well
        assert(compressed.size() < delta.size() / 2);

        auto decompressed = flow::decompress_delta(compressed);
        assert(decompressed.size() == delta.size());
        assert(std::memcmp(decompressed.data(), delta.data(), delta.size()) == 0);
    }
}

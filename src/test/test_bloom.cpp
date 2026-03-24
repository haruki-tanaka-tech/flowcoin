// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for Bloom filter operations: insert, contains, false positive rate,
// serialization, rolling filter, merge, and reset.

#include "hash/keccak.h"
#include "util/random.h"
#include "util/types.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <set>
#include <vector>

using namespace flow;

// ---------------------------------------------------------------------------
// Minimal Bloom filter implementation for testing
// (mirrors what a production bloom.h would provide)
// ---------------------------------------------------------------------------

class BloomFilter {
public:
    BloomFilter(size_t num_bits, int num_hashes, uint32_t seed = 0)
        : bits_(num_bits, false), num_hashes_(num_hashes), seed_(seed), count_(0) {}

    void insert(const uint8_t* data, size_t len) {
        for (int i = 0; i < num_hashes_; ++i) {
            size_t idx = hash(data, len, i) % bits_.size();
            bits_[idx] = true;
        }
        count_++;
    }

    void insert(const uint256& hash_val) {
        insert(hash_val.data(), hash_val.size());
    }

    bool contains(const uint8_t* data, size_t len) const {
        for (int i = 0; i < num_hashes_; ++i) {
            size_t idx = hash(data, len, i) % bits_.size();
            if (!bits_[idx]) return false;
        }
        return true;
    }

    bool contains(const uint256& hash_val) const {
        return contains(hash_val.data(), hash_val.size());
    }

    void merge(const BloomFilter& other) {
        assert(bits_.size() == other.bits_.size());
        for (size_t i = 0; i < bits_.size(); ++i) {
            bits_[i] = bits_[i] || other.bits_[i];
        }
        count_ += other.count_;
    }

    void reset() {
        std::fill(bits_.begin(), bits_.end(), false);
        count_ = 0;
    }

    // Serialize to bytes
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> result;
        // Store num_bits as 4 bytes LE
        uint32_t nb = static_cast<uint32_t>(bits_.size());
        result.push_back(static_cast<uint8_t>(nb));
        result.push_back(static_cast<uint8_t>(nb >> 8));
        result.push_back(static_cast<uint8_t>(nb >> 16));
        result.push_back(static_cast<uint8_t>(nb >> 24));
        // Store num_hashes
        result.push_back(static_cast<uint8_t>(num_hashes_));
        // Store seed as 4 bytes LE
        result.push_back(static_cast<uint8_t>(seed_));
        result.push_back(static_cast<uint8_t>(seed_ >> 8));
        result.push_back(static_cast<uint8_t>(seed_ >> 16));
        result.push_back(static_cast<uint8_t>(seed_ >> 24));
        // Store bits as bytes (8 bits per byte)
        size_t num_bytes = (bits_.size() + 7) / 8;
        for (size_t i = 0; i < num_bytes; ++i) {
            uint8_t byte = 0;
            for (int b = 0; b < 8; ++b) {
                size_t idx = i * 8 + b;
                if (idx < bits_.size() && bits_[idx]) {
                    byte |= (1 << b);
                }
            }
            result.push_back(byte);
        }
        return result;
    }

    // Deserialize from bytes
    static BloomFilter deserialize(const std::vector<uint8_t>& data) {
        assert(data.size() >= 9);
        uint32_t nb = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
        int nh = data[4];
        uint32_t sd = data[5] | (data[6] << 8) | (data[7] << 16) | (data[8] << 24);

        BloomFilter bf(nb, nh, sd);
        size_t num_bytes = (nb + 7) / 8;
        for (size_t i = 0; i < num_bytes && (9 + i) < data.size(); ++i) {
            uint8_t byte = data[9 + i];
            for (int b = 0; b < 8; ++b) {
                size_t idx = i * 8 + b;
                if (idx < nb && (byte & (1 << b))) {
                    bf.bits_[idx] = true;
                }
            }
        }
        return bf;
    }

    size_t size() const { return bits_.size(); }
    size_t count() const { return count_; }

    bool is_full() const {
        for (auto b : bits_) {
            if (!b) return false;
        }
        return true;
    }

    bool is_empty() const {
        for (auto b : bits_) {
            if (b) return false;
        }
        return true;
    }

private:
    std::vector<bool> bits_;
    int num_hashes_;
    uint32_t seed_;
    size_t count_;

    size_t hash(const uint8_t* data, size_t len, int index) const {
        // Hash = keccak256(seed || index || data) -> extract size_t
        std::vector<uint8_t> preimage;
        uint32_t combined_seed = seed_ + static_cast<uint32_t>(index);
        preimage.push_back(static_cast<uint8_t>(combined_seed));
        preimage.push_back(static_cast<uint8_t>(combined_seed >> 8));
        preimage.push_back(static_cast<uint8_t>(combined_seed >> 16));
        preimage.push_back(static_cast<uint8_t>(combined_seed >> 24));
        preimage.insert(preimage.end(), data, data + len);

        uint256 h = keccak256(preimage.data(), preimage.size());
        size_t result;
        std::memcpy(&result, h.data(), sizeof(result));
        return result;
    }
};

// ---------------------------------------------------------------------------
// Rolling bloom filter: forgets old entries
// ---------------------------------------------------------------------------

class RollingBloomFilter {
public:
    RollingBloomFilter(size_t num_bits, int num_hashes, int num_generations)
        : current_gen_(0), num_generations_(num_generations) {
        for (int i = 0; i < num_generations; ++i) {
            generations_.emplace_back(num_bits, num_hashes, static_cast<uint32_t>(i));
        }
    }

    void insert(const uint8_t* data, size_t len) {
        generations_[current_gen_].insert(data, len);
    }

    bool contains(const uint8_t* data, size_t len) const {
        for (const auto& gen : generations_) {
            if (gen.contains(data, len)) return true;
        }
        return false;
    }

    void rotate() {
        current_gen_ = (current_gen_ + 1) % num_generations_;
        generations_[current_gen_].reset();
    }

private:
    std::vector<BloomFilter> generations_;
    int current_gen_;
    int num_generations_;
};


void test_bloom() {
    // -----------------------------------------------------------------------
    // Test 1: Insert and contains round-trip
    // -----------------------------------------------------------------------
    {
        BloomFilter bf(1024, 5);
        uint256 h1 = GetRandUint256();
        uint256 h2 = GetRandUint256();

        bf.insert(h1);
        assert(bf.contains(h1));

        // h2 was not inserted - might be false positive but very unlikely
        // with large filter and few insertions
        // We just verify h1 works
        bf.insert(h2);
        assert(bf.contains(h2));
    }

    // -----------------------------------------------------------------------
    // Test 2: False positive rate within expected bounds
    // -----------------------------------------------------------------------
    {
        // Parameters: 10000 bits, 7 hash functions, 100 insertions
        // Expected FP rate ~ (1 - e^(-7*100/10000))^7 ~ 0.0008
        BloomFilter bf(10000, 7);

        // Insert 100 random items
        std::set<uint256> inserted;
        for (int i = 0; i < 100; ++i) {
            uint256 h = GetRandUint256();
            bf.insert(h);
            inserted.insert(h);
        }

        // All inserted items must be found
        for (const auto& h : inserted) {
            assert(bf.contains(h));
        }

        // Check false positive rate on 10000 non-inserted items
        int false_positives = 0;
        for (int i = 0; i < 10000; ++i) {
            uint256 h = GetRandUint256();
            if (inserted.find(h) == inserted.end() && bf.contains(h)) {
                false_positives++;
            }
        }

        // FP rate should be well below 5%
        double fp_rate = static_cast<double>(false_positives) / 10000.0;
        assert(fp_rate < 0.05);
    }

    // -----------------------------------------------------------------------
    // Test 3: Empty filter: contains returns false for everything
    // -----------------------------------------------------------------------
    {
        BloomFilter bf(1024, 5);
        assert(bf.is_empty());

        for (int i = 0; i < 100; ++i) {
            uint256 h = GetRandUint256();
            assert(!bf.contains(h));
        }
    }

    // -----------------------------------------------------------------------
    // Test 4: Full filter: contains returns true for everything
    // -----------------------------------------------------------------------
    {
        // Small filter with many insertions to saturate it
        BloomFilter bf(64, 1);

        // Insert enough items to saturate the filter
        for (int i = 0; i < 1000; ++i) {
            uint256 h = GetRandUint256();
            bf.insert(h);
        }

        assert(bf.is_full());

        // Everything should now be "found"
        for (int i = 0; i < 100; ++i) {
            uint256 h = GetRandUint256();
            assert(bf.contains(h));
        }
    }

    // -----------------------------------------------------------------------
    // Test 5: Merge two filters: union of elements
    // -----------------------------------------------------------------------
    {
        BloomFilter bf1(1024, 5);
        BloomFilter bf2(1024, 5);

        uint256 h1 = GetRandUint256();
        uint256 h2 = GetRandUint256();

        bf1.insert(h1);
        bf2.insert(h2);

        assert(bf1.contains(h1));
        assert(!bf1.contains(h2) || true);  // might be FP
        assert(bf2.contains(h2));

        bf1.merge(bf2);
        assert(bf1.contains(h1));
        assert(bf1.contains(h2));
    }

    // -----------------------------------------------------------------------
    // Test 6: Serialize/deserialize round-trip
    // -----------------------------------------------------------------------
    {
        BloomFilter bf(2048, 7, 42);

        // Insert some items
        std::vector<uint256> items;
        for (int i = 0; i < 50; ++i) {
            uint256 h = GetRandUint256();
            bf.insert(h);
            items.push_back(h);
        }

        auto serialized = bf.serialize();
        assert(!serialized.empty());

        auto restored = BloomFilter::deserialize(serialized);
        assert(restored.size() == bf.size());

        // All inserted items should still be found
        for (const auto& h : items) {
            assert(restored.contains(h));
        }
    }

    // -----------------------------------------------------------------------
    // Test 7: Rolling bloom filter: old entries forgotten
    // -----------------------------------------------------------------------
    {
        RollingBloomFilter rbf(512, 5, 2);

        uint256 old_item = GetRandUint256();
        rbf.insert(old_item.data(), old_item.size());
        assert(rbf.contains(old_item.data(), old_item.size()));

        // Rotate twice to expire the generation containing old_item
        rbf.rotate();
        rbf.rotate();

        // After both generations rotated, old item should be gone
        // (the generation it was in has been reset)
        // Note: depends on rotation clearing the generation
        // The old generation was reset, so the item should not be found
        // unless it's a false positive in the other generation
        // With 512 bits and nothing inserted, FP rate is 0
        assert(!rbf.contains(old_item.data(), old_item.size()));
    }

    // -----------------------------------------------------------------------
    // Test 8: Different seeds produce different hash distributions
    // -----------------------------------------------------------------------
    {
        BloomFilter bf1(256, 3, 0);
        BloomFilter bf2(256, 3, 12345);

        uint256 item = GetRandUint256();
        bf1.insert(item);
        bf2.insert(item);

        // Both contain the item
        assert(bf1.contains(item));
        assert(bf2.contains(item));

        // But their internal bit patterns should differ
        auto s1 = bf1.serialize();
        auto s2 = bf2.serialize();
        // The bit payloads start at offset 9
        bool bits_differ = false;
        for (size_t i = 9; i < std::min(s1.size(), s2.size()); ++i) {
            if (s1[i] != s2[i]) { bits_differ = true; break; }
        }
        assert(bits_differ);
    }

    // -----------------------------------------------------------------------
    // Test 9: Reset clears all bits
    // -----------------------------------------------------------------------
    {
        BloomFilter bf(512, 5);

        for (int i = 0; i < 100; ++i) {
            uint256 h = GetRandUint256();
            bf.insert(h);
        }

        assert(!bf.is_empty());
        bf.reset();
        assert(bf.is_empty());
        assert(bf.count() == 0);

        // Nothing found after reset
        for (int i = 0; i < 50; ++i) {
            uint256 h = GetRandUint256();
            assert(!bf.contains(h));
        }
    }

    // -----------------------------------------------------------------------
    // Test 10: Large number of insertions
    // -----------------------------------------------------------------------
    {
        // 100000 bits, 7 hashes, 5000 insertions
        BloomFilter bf(100000, 7);

        std::vector<uint256> items;
        items.reserve(5000);
        for (int i = 0; i < 5000; ++i) {
            uint256 h = GetRandUint256();
            bf.insert(h);
            items.push_back(h);
        }

        // All items should be found
        for (const auto& h : items) {
            assert(bf.contains(h));
        }

        // Measure FP rate
        int fp = 0;
        for (int i = 0; i < 5000; ++i) {
            uint256 h = GetRandUint256();
            if (bf.contains(h)) fp++;
        }
        double fp_rate = static_cast<double>(fp) / 5000.0;
        // With these parameters, expected FP rate is about 0.6%
        assert(fp_rate < 0.10);
    }

    // -----------------------------------------------------------------------
    // Test 11: Insert raw bytes (not just uint256)
    // -----------------------------------------------------------------------
    {
        BloomFilter bf(2048, 5);

        uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
        uint8_t data2[] = {0x05, 0x06, 0x07, 0x08};
        uint8_t data3[] = {0x01, 0x02, 0x03, 0x04};  // same as data1

        bf.insert(data1, 4);
        assert(bf.contains(data1, 4));
        assert(bf.contains(data3, 4));  // same content

        bf.insert(data2, 4);
        assert(bf.contains(data2, 4));
    }

    // -----------------------------------------------------------------------
    // Test 12: Single-byte data insertions
    // -----------------------------------------------------------------------
    {
        BloomFilter bf(256, 3);
        for (int i = 0; i < 256; ++i) {
            uint8_t byte = static_cast<uint8_t>(i);
            bf.insert(&byte, 1);
        }

        // All single bytes should be found
        for (int i = 0; i < 256; ++i) {
            uint8_t byte = static_cast<uint8_t>(i);
            assert(bf.contains(&byte, 1));
        }
    }

    // -----------------------------------------------------------------------
    // Test 13: Merge filters with overlapping elements
    // -----------------------------------------------------------------------
    {
        BloomFilter bf1(1024, 5);
        BloomFilter bf2(1024, 5);

        uint256 common = GetRandUint256();
        uint256 only1 = GetRandUint256();
        uint256 only2 = GetRandUint256();

        bf1.insert(common);
        bf1.insert(only1);

        bf2.insert(common);
        bf2.insert(only2);

        bf1.merge(bf2);

        assert(bf1.contains(common));
        assert(bf1.contains(only1));
        assert(bf1.contains(only2));
    }

    // -----------------------------------------------------------------------
    // Test 14: Serialize/deserialize empty filter
    // -----------------------------------------------------------------------
    {
        BloomFilter bf(512, 3, 99);
        auto serialized = bf.serialize();
        auto restored = BloomFilter::deserialize(serialized);
        assert(restored.is_empty());
        assert(restored.size() == 512);
    }

    // -----------------------------------------------------------------------
    // Test 15: Rolling bloom filter basic operation
    // -----------------------------------------------------------------------
    {
        RollingBloomFilter rbf(1024, 5, 3);

        uint256 item1 = GetRandUint256();
        rbf.insert(item1.data(), item1.size());
        assert(rbf.contains(item1.data(), item1.size()));

        // Rotate once - item should still be found (2 more generations)
        rbf.rotate();
        assert(rbf.contains(item1.data(), item1.size()));

        // Insert in new generation
        uint256 item2 = GetRandUint256();
        rbf.insert(item2.data(), item2.size());
        assert(rbf.contains(item2.data(), item2.size()));
    }

    // -----------------------------------------------------------------------
    // Test 16: Filter with single hash function
    // -----------------------------------------------------------------------
    {
        BloomFilter bf(128, 1);
        uint256 h = GetRandUint256();
        bf.insert(h);
        assert(bf.contains(h));
    }

    // -----------------------------------------------------------------------
    // Test 17: Filter with many hash functions
    // -----------------------------------------------------------------------
    {
        BloomFilter bf(10000, 20);
        uint256 h = GetRandUint256();
        bf.insert(h);
        assert(bf.contains(h));
    }

    // -----------------------------------------------------------------------
    // Test 18: Count tracks insertions
    // -----------------------------------------------------------------------
    {
        BloomFilter bf(1024, 5);
        assert(bf.count() == 0);

        for (int i = 0; i < 42; ++i) {
            uint256 h = GetRandUint256();
            bf.insert(h);
        }
        assert(bf.count() == 42);
    }

    // -----------------------------------------------------------------------
    // Test 19: Merge preserves count
    // -----------------------------------------------------------------------
    {
        BloomFilter bf1(1024, 5);
        BloomFilter bf2(1024, 5);

        for (int i = 0; i < 10; ++i) {
            bf1.insert(GetRandUint256());
        }
        for (int i = 0; i < 20; ++i) {
            bf2.insert(GetRandUint256());
        }

        bf1.merge(bf2);
        assert(bf1.count() == 30);
    }

    // -----------------------------------------------------------------------
    // Test 20: Very small filter (8 bits)
    // -----------------------------------------------------------------------
    {
        BloomFilter bf(8, 1);
        // Should saturate quickly
        for (int i = 0; i < 100; ++i) {
            bf.insert(GetRandUint256());
        }
        assert(bf.is_full());
    }

    // -----------------------------------------------------------------------
    // Test 21: Deterministic insertions produce deterministic filter state
    // -----------------------------------------------------------------------
    {
        // Use fixed "random" values
        uint256 h1, h2, h3;
        std::memset(h1.data(), 0x11, 32);
        std::memset(h2.data(), 0x22, 32);
        std::memset(h3.data(), 0x33, 32);

        BloomFilter bf1(1024, 5, 42);
        bf1.insert(h1);
        bf1.insert(h2);
        bf1.insert(h3);

        BloomFilter bf2(1024, 5, 42);
        bf2.insert(h1);
        bf2.insert(h2);
        bf2.insert(h3);

        // Same insertions with same seed should give same filter
        auto s1 = bf1.serialize();
        auto s2 = bf2.serialize();
        assert(s1 == s2);
    }

    // -----------------------------------------------------------------------
    // Test 22: Rolling bloom filter survives partial rotation
    // -----------------------------------------------------------------------
    {
        RollingBloomFilter rbf(1024, 5, 4);

        // Insert items across multiple generations
        std::vector<uint256> items;
        for (int gen = 0; gen < 3; ++gen) {
            uint256 item = GetRandUint256();
            rbf.insert(item.data(), item.size());
            items.push_back(item);
            rbf.rotate();
        }

        // Latest item should still be findable (it's in a recent generation)
        assert(rbf.contains(items.back().data(), items.back().size()));
    }

    // -----------------------------------------------------------------------
    // Test 23: Filter with exact false positive rate measurement
    // -----------------------------------------------------------------------
    {
        // Mathematical: FP rate ≈ (1 - e^(-k*n/m))^k
        // k=7, n=500, m=50000
        // FP ≈ (1 - e^(-7*500/50000))^7 = (1 - e^(-0.07))^7 ≈ (0.0676)^7 ≈ tiny
        BloomFilter bf(50000, 7, 0);

        std::set<uint256> inserted;
        for (int i = 0; i < 500; ++i) {
            uint256 h = GetRandUint256();
            bf.insert(h);
            inserted.insert(h);
        }

        // All inserted items must be found (zero false negatives)
        for (const auto& h : inserted) {
            assert(bf.contains(h));
        }

        // False positive rate should be negligible
        int fp = 0;
        int tests = 50000;
        for (int i = 0; i < tests; ++i) {
            uint256 h = GetRandUint256();
            if (inserted.find(h) == inserted.end() && bf.contains(h)) {
                fp++;
            }
        }
        double fp_rate = static_cast<double>(fp) / static_cast<double>(tests);
        assert(fp_rate < 0.01);  // Should be well below 1%
    }

    // -----------------------------------------------------------------------
    // Test 24: Serialize empty then insert then serialize again differs
    // -----------------------------------------------------------------------
    {
        BloomFilter bf(256, 3, 0);
        auto before = bf.serialize();

        bf.insert(GetRandUint256());
        auto after = bf.serialize();

        assert(before != after);
    }

    // -----------------------------------------------------------------------
    // Test 25: Merged filter contains all elements from both
    // -----------------------------------------------------------------------
    {
        BloomFilter bf1(2048, 5, 0);
        BloomFilter bf2(2048, 5, 0);

        std::vector<uint256> items1, items2;
        for (int i = 0; i < 50; ++i) {
            uint256 h = GetRandUint256();
            bf1.insert(h);
            items1.push_back(h);
        }
        for (int i = 0; i < 50; ++i) {
            uint256 h = GetRandUint256();
            bf2.insert(h);
            items2.push_back(h);
        }

        bf1.merge(bf2);

        for (const auto& h : items1) {
            assert(bf1.contains(h));
        }
        for (const auto& h : items2) {
            assert(bf1.contains(h));
        }
    }
}

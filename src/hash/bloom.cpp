// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "bloom.h"
#include "keccak.h"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace flow {

// ===========================================================================
// Bloom filter parameter computation
// ===========================================================================

uint32_t bloom_optimal_bits(uint32_t n, double p) {
    if (n == 0 || p <= 0.0 || p >= 1.0) return 8;
    double m = -static_cast<double>(n) * std::log(p) / (std::log(2.0) * std::log(2.0));
    uint32_t result = static_cast<uint32_t>(m);
    if (result < 8) result = 8;
    // Round up to nearest byte
    result = (result + 7) & ~7u;
    return result;
}

uint32_t bloom_optimal_hashes(uint32_t m, uint32_t n) {
    if (n == 0) return 1;
    double k = (static_cast<double>(m) / static_cast<double>(n)) * std::log(2.0);
    uint32_t result = static_cast<uint32_t>(k + 0.5);
    if (result < 1) result = 1;
    if (result > CBloomFilter::MAX_HASH_FUNCS) result = CBloomFilter::MAX_HASH_FUNCS;
    return result;
}

// ===========================================================================
// CBloomFilter -- MurmurHash3-like hash function
// ===========================================================================

/** MurmurHash3 32-bit finalizer.
 *  Used to generate independent hash functions from a single hash.
 */
static uint32_t murmur3_mix(uint32_t h) {
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

/** MurmurHash3 32-bit hash of a byte array with a given seed. */
static uint32_t murmur3_32(const uint8_t* data, size_t len, uint32_t seed) {
    uint32_t h1 = seed;
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    // Process 4-byte blocks
    size_t nblocks = len / 4;
    for (size_t i = 0; i < nblocks; ++i) {
        uint32_t k1;
        std::memcpy(&k1, data + i * 4, 4);

        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> 17);
        k1 *= c2;

        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> 19);
        h1 = h1 * 5 + 0xe6546b64;
    }

    // Process remaining bytes
    const uint8_t* tail = data + nblocks * 4;
    uint32_t k1 = 0;
    switch (len & 3) {
        case 3: k1 ^= static_cast<uint32_t>(tail[2]) << 16; [[fallthrough]];
        case 2: k1 ^= static_cast<uint32_t>(tail[1]) << 8;  [[fallthrough]];
        case 1: k1 ^= static_cast<uint32_t>(tail[0]);
                k1 *= c1;
                k1 = (k1 << 15) | (k1 >> 17);
                k1 *= c2;
                h1 ^= k1;
    }

    // Finalization
    h1 ^= static_cast<uint32_t>(len);
    h1 = murmur3_mix(h1);
    return h1;
}

// ===========================================================================
// CBloomFilter implementation
// ===========================================================================

CBloomFilter::CBloomFilter()
    : n_bits_(0), n_hashes_(0), seed_(0)
{
}

CBloomFilter::CBloomFilter(uint32_t n_elements, double false_positive_rate, uint32_t seed) {
    n_bits_ = bloom_optimal_bits(n_elements, false_positive_rate);
    if (n_bits_ > MAX_BLOOM_FILTER_SIZE * 8) {
        n_bits_ = MAX_BLOOM_FILTER_SIZE * 8;
    }
    n_hashes_ = bloom_optimal_hashes(n_bits_, n_elements);
    seed_ = seed;
    bits_.resize((n_bits_ + 7) / 8, 0);
}

CBloomFilter::CBloomFilter(uint32_t n_bits, uint32_t n_hashes, uint32_t seed)
    : n_bits_(n_bits), n_hashes_(n_hashes), seed_(seed)
{
    if (n_bits_ > MAX_BLOOM_FILTER_SIZE * 8) {
        n_bits_ = MAX_BLOOM_FILTER_SIZE * 8;
    }
    if (n_hashes_ > MAX_HASH_FUNCS) {
        n_hashes_ = MAX_HASH_FUNCS;
    }
    bits_.resize((n_bits_ + 7) / 8, 0);
}

uint32_t CBloomFilter::hash_n(const uint8_t* data, size_t len, uint32_t n) const {
    // Generate independent hashes using MurmurHash3 with different seeds
    // The effective seed is: base_seed * MAX_HASH_FUNCS + n
    uint32_t effective_seed = seed_ * MAX_HASH_FUNCS + n;
    return murmur3_32(data, len, effective_seed) % n_bits_;
}

void CBloomFilter::set_bit(uint32_t index) {
    bits_[index >> 3] |= (1 << (index & 7));
}

bool CBloomFilter::get_bit(uint32_t index) const {
    return (bits_[index >> 3] >> (index & 7)) & 1;
}

void CBloomFilter::insert(const uint8_t* data, size_t len) {
    if (n_bits_ == 0) return;
    for (uint32_t i = 0; i < n_hashes_; ++i) {
        uint32_t bit_index = hash_n(data, len, i);
        set_bit(bit_index);
    }
}

void CBloomFilter::insert(const std::vector<uint8_t>& data) {
    insert(data.data(), data.size());
}

void CBloomFilter::insert_hash(const uint256& hash) {
    insert(hash.data(), hash.size());
}

bool CBloomFilter::contains(const uint8_t* data, size_t len) const {
    if (n_bits_ == 0) return false;
    for (uint32_t i = 0; i < n_hashes_; ++i) {
        uint32_t bit_index = hash_n(data, len, i);
        if (!get_bit(bit_index)) return false;
    }
    return true;
}

bool CBloomFilter::contains(const std::vector<uint8_t>& data) const {
    return contains(data.data(), data.size());
}

bool CBloomFilter::contains_hash(const uint256& hash) const {
    return contains(hash.data(), hash.size());
}

bool CBloomFilter::is_full() const {
    if (bits_.empty()) return true;
    for (size_t i = 0; i < bits_.size(); ++i) {
        // For the last byte, check only the valid bits
        if (i == bits_.size() - 1) {
            uint32_t valid_bits = n_bits_ % 8;
            if (valid_bits == 0) valid_bits = 8;
            uint8_t mask = (1 << valid_bits) - 1;
            if ((bits_[i] & mask) != mask) return false;
        } else {
            if (bits_[i] != 0xFF) return false;
        }
    }
    return true;
}

bool CBloomFilter::is_empty() const {
    for (uint8_t b : bits_) {
        if (b != 0) return false;
    }
    return true;
}

void CBloomFilter::reset() {
    std::fill(bits_.begin(), bits_.end(), 0);
}

bool CBloomFilter::merge(const CBloomFilter& other) {
    if (n_bits_ != other.n_bits_ || n_hashes_ != other.n_hashes_) {
        return false;
    }
    for (size_t i = 0; i < bits_.size(); ++i) {
        bits_[i] |= other.bits_[i];
    }
    return true;
}

uint32_t CBloomFilter::popcount() const {
    uint32_t count = 0;
    for (uint8_t b : bits_) {
        // Count bits in each byte
        uint8_t v = b;
        v = (v & 0x55) + ((v >> 1) & 0x55);
        v = (v & 0x33) + ((v >> 2) & 0x33);
        v = (v & 0x0F) + ((v >> 4) & 0x0F);
        count += v;
    }
    return count;
}

double CBloomFilter::estimated_element_count() const {
    if (n_bits_ == 0 || n_hashes_ == 0) return 0.0;
    uint32_t set_bits = popcount();
    if (set_bits == 0) return 0.0;
    if (set_bits >= n_bits_) return static_cast<double>(n_bits_); // saturated

    double m = static_cast<double>(n_bits_);
    double k = static_cast<double>(n_hashes_);
    double x = static_cast<double>(set_bits);

    // n_est = -(m/k) * ln(1 - x/m)
    return -(m / k) * std::log(1.0 - x / m);
}

double CBloomFilter::current_fpp() const {
    if (n_bits_ == 0 || n_hashes_ == 0) return 1.0;
    uint32_t set_bits = popcount();
    double ratio = static_cast<double>(set_bits) / static_cast<double>(n_bits_);
    return std::pow(ratio, static_cast<double>(n_hashes_));
}

std::vector<uint8_t> CBloomFilter::serialize() const {
    std::vector<uint8_t> result;
    result.reserve(12 + bits_.size());

    // n_bits (4 bytes, little-endian)
    result.push_back(static_cast<uint8_t>(n_bits_));
    result.push_back(static_cast<uint8_t>(n_bits_ >> 8));
    result.push_back(static_cast<uint8_t>(n_bits_ >> 16));
    result.push_back(static_cast<uint8_t>(n_bits_ >> 24));

    // n_hashes (4 bytes, little-endian)
    result.push_back(static_cast<uint8_t>(n_hashes_));
    result.push_back(static_cast<uint8_t>(n_hashes_ >> 8));
    result.push_back(static_cast<uint8_t>(n_hashes_ >> 16));
    result.push_back(static_cast<uint8_t>(n_hashes_ >> 24));

    // seed (4 bytes, little-endian)
    result.push_back(static_cast<uint8_t>(seed_));
    result.push_back(static_cast<uint8_t>(seed_ >> 8));
    result.push_back(static_cast<uint8_t>(seed_ >> 16));
    result.push_back(static_cast<uint8_t>(seed_ >> 24));

    // bits
    result.insert(result.end(), bits_.begin(), bits_.end());

    return result;
}

bool CBloomFilter::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 12) return false;

    n_bits_ = static_cast<uint32_t>(data[0]) |
              (static_cast<uint32_t>(data[1]) << 8) |
              (static_cast<uint32_t>(data[2]) << 16) |
              (static_cast<uint32_t>(data[3]) << 24);

    n_hashes_ = static_cast<uint32_t>(data[4]) |
                (static_cast<uint32_t>(data[5]) << 8) |
                (static_cast<uint32_t>(data[6]) << 16) |
                (static_cast<uint32_t>(data[7]) << 24);

    seed_ = static_cast<uint32_t>(data[8]) |
            (static_cast<uint32_t>(data[9]) << 8) |
            (static_cast<uint32_t>(data[10]) << 16) |
            (static_cast<uint32_t>(data[11]) << 24);

    // Validate
    if (n_bits_ > MAX_BLOOM_FILTER_SIZE * 8) return false;
    if (n_hashes_ > MAX_HASH_FUNCS) return false;

    size_t expected_bytes = (n_bits_ + 7) / 8;
    if (data.size() != 12 + expected_bytes) return false;

    bits_.assign(data.begin() + 12, data.end());
    return true;
}

// ===========================================================================
// CRollingBloomFilter implementation
// ===========================================================================

CRollingBloomFilter::CRollingBloomFilter(uint32_t n_elements,
                                           double false_positive_rate,
                                           uint32_t n_generations)
    : current_gen_(0),
      max_elements_(n_elements),
      current_count_(0),
      fpp_(false_positive_rate),
      seed_counter_(0)
{
    if (n_generations < 2) n_generations = 2;

    generations_.reserve(n_generations);
    for (uint32_t i = 0; i < n_generations; ++i) {
        generations_.emplace_back(n_elements, false_positive_rate, seed_counter_++);
    }
}

void CRollingBloomFilter::roll() {
    // Move to the next generation
    current_gen_ = (current_gen_ + 1) % static_cast<uint32_t>(generations_.size());
    generations_[current_gen_] = CBloomFilter(max_elements_, fpp_, seed_counter_++);
    current_count_ = 0;
}

void CRollingBloomFilter::insert(const uint8_t* data, size_t len) {
    // Insert into current generation
    generations_[current_gen_].insert(data, len);
    current_count_++;

    // Roll if current generation is full
    if (current_count_ >= max_elements_) {
        roll();
    }
}

void CRollingBloomFilter::insert(const std::vector<uint8_t>& data) {
    insert(data.data(), data.size());
}

void CRollingBloomFilter::insert_hash(const uint256& hash) {
    insert(hash.data(), hash.size());
}

bool CRollingBloomFilter::contains(const uint8_t* data, size_t len) const {
    // Check all generations
    for (const auto& gen : generations_) {
        if (gen.contains(data, len)) return true;
    }
    return false;
}

bool CRollingBloomFilter::contains(const std::vector<uint8_t>& data) const {
    return contains(data.data(), data.size());
}

bool CRollingBloomFilter::contains_hash(const uint256& hash) const {
    return contains(hash.data(), hash.size());
}

void CRollingBloomFilter::reset() {
    for (auto& gen : generations_) {
        gen.reset();
    }
    current_count_ = 0;
    current_gen_ = 0;
}

double CRollingBloomFilter::estimated_total_elements() const {
    double total = 0.0;
    for (const auto& gen : generations_) {
        total += gen.estimated_element_count();
    }
    return total;
}

} // namespace flow

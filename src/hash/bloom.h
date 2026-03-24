// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Bloom filter for transaction relay and deduplication.
// Uses Keccak-based hash functions for independence.

#pragma once

#include "../util/types.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace flow {

// ===========================================================================
// CBloomFilter: standard Bloom filter
// ===========================================================================

/** A Bloom filter probabilistic set data structure.
 *
 *  Insert and membership testing in O(k) where k is the number of hash
 *  functions. False positives are possible; false negatives are not.
 *
 *  Used for:
 *  - Transaction relay filtering (BIP-37 style)
 *  - UTXO deduplication
 *  - Peer address caching
 */
class CBloomFilter {
public:
    /** Construct a Bloom filter with optimal parameters.
     *  @param n_elements           Expected number of elements to insert.
     *  @param false_positive_rate  Desired false positive probability (e.g., 0.001).
     *  @param seed                 Random seed for hash functions.
     */
    CBloomFilter(uint32_t n_elements, double false_positive_rate, uint32_t seed);

    /** Construct a Bloom filter with explicit parameters.
     *  @param n_bits      Number of bits in the filter.
     *  @param n_hashes    Number of hash functions.
     *  @param seed        Random seed for hash functions.
     */
    CBloomFilter(uint32_t n_bits, uint32_t n_hashes, uint32_t seed);

    /** Default constructor (empty filter). */
    CBloomFilter();

    /** Insert raw data into the filter. */
    void insert(const uint8_t* data, size_t len);

    /** Insert a byte vector. */
    void insert(const std::vector<uint8_t>& data);

    /** Insert a uint256 hash. */
    void insert_hash(const uint256& hash);

    /** Test if data might be in the filter.
     *  @return true if possibly present, false if definitely not present.
     */
    bool contains(const uint8_t* data, size_t len) const;

    /** Test if a byte vector might be in the filter. */
    bool contains(const std::vector<uint8_t>& data) const;

    /** Test if a hash might be in the filter. */
    bool contains_hash(const uint256& hash) const;

    /** Check if the filter is full (all bits set).
     *  A full filter has a 100% false positive rate and is useless.
     */
    bool is_full() const;

    /** Check if the filter is empty (no bits set). */
    bool is_empty() const;

    /** Reset the filter (clear all bits). */
    void reset();

    /** Merge another filter into this one (bitwise OR).
     *  Both filters must have the same size and number of hash functions.
     *  @return true on success, false if filters are incompatible.
     */
    bool merge(const CBloomFilter& other);

    /** Get the number of bits in the filter. */
    uint32_t bit_count() const { return n_bits_; }

    /** Get the number of hash functions. */
    uint32_t hash_count() const { return n_hashes_; }

    /** Get the seed used for hash functions. */
    uint32_t seed() const { return seed_; }

    /** Get the raw bit array. */
    const std::vector<uint8_t>& data() const { return bits_; }

    /** Serialize the filter to a byte vector.
     *  Format: [4B n_bits][4B n_hashes][4B seed][bits...]
     */
    std::vector<uint8_t> serialize() const;

    /** Deserialize a filter from a byte vector.
     *  @return true on success.
     */
    bool deserialize(const std::vector<uint8_t>& data);

    /** Estimate the number of elements currently in the filter.
     *  Uses the formula: n_est = -(m/k) * ln(1 - X/m)
     *  where m = bit count, k = hash count, X = set bits count.
     */
    double estimated_element_count() const;

    /** Get the current false positive rate based on elements inserted. */
    double current_fpp() const;

    // Maximum allowed filter size (to prevent DoS)
    static constexpr uint32_t MAX_BLOOM_FILTER_SIZE = 36000;  // 36KB
    static constexpr uint32_t MAX_HASH_FUNCS = 50;

private:
    std::vector<uint8_t> bits_;   /**< Bit array (packed into bytes) */
    uint32_t n_bits_;             /**< Number of bits */
    uint32_t n_hashes_;           /**< Number of hash functions */
    uint32_t seed_;               /**< Seed for hash generation */

    /** Compute the i-th hash of data.
     *  Uses a keyed hash: MurmurHash3-like with different seeds.
     */
    uint32_t hash_n(const uint8_t* data, size_t len, uint32_t n) const;

    /** Set a bit in the filter. */
    void set_bit(uint32_t index);

    /** Test a bit in the filter. */
    bool get_bit(uint32_t index) const;

    /** Count the number of set bits. */
    uint32_t popcount() const;
};

// ===========================================================================
// CRollingBloomFilter: time-based expiring Bloom filter
// ===========================================================================

/** A rolling Bloom filter that automatically forgets old entries.
 *
 *  Internally uses multiple generations of bloom filters. Entries are
 *  inserted into the current generation. When the current generation
 *  is full, the oldest generation is discarded and a new one is created.
 *
 *  This provides approximate LRU behavior for set membership testing
 *  with bounded memory usage.
 *
 *  Used for:
 *  - Filtering recently-seen transactions (to avoid re-relaying)
 *  - Tracking recently-seen addresses
 */
class CRollingBloomFilter {
public:
    /** Construct a rolling Bloom filter.
     *  @param n_elements           Expected elements per generation.
     *  @param false_positive_rate  Desired false positive rate.
     *  @param n_generations        Number of generations to maintain (default 3).
     */
    CRollingBloomFilter(uint32_t n_elements, double false_positive_rate,
                         uint32_t n_generations = 3);

    /** Insert data into the current generation. */
    void insert(const uint8_t* data, size_t len);

    /** Insert a byte vector. */
    void insert(const std::vector<uint8_t>& data);

    /** Insert a hash. */
    void insert_hash(const uint256& hash);

    /** Test if data is in any generation.
     *  @return true if possibly present in any generation.
     */
    bool contains(const uint8_t* data, size_t len) const;

    /** Test if a byte vector is present. */
    bool contains(const std::vector<uint8_t>& data) const;

    /** Test if a hash is present. */
    bool contains_hash(const uint256& hash) const;

    /** Reset all generations. */
    void reset();

    /** Get the total number of elements across all generations (estimate). */
    double estimated_total_elements() const;

    /** Get the number of generations. */
    uint32_t generation_count() const { return static_cast<uint32_t>(generations_.size()); }

private:
    std::vector<CBloomFilter> generations_;
    uint32_t current_gen_;        /**< Index of the current generation */
    uint32_t max_elements_;       /**< Max elements per generation */
    uint32_t current_count_;      /**< Elements in current generation */
    double fpp_;                  /**< False positive rate per generation */
    uint32_t seed_counter_;       /**< Counter for generating unique seeds */

    /** Roll to the next generation (discard oldest). */
    void roll();
};

// ===========================================================================
// Bloom filter parameter computation
// ===========================================================================

/** Compute optimal number of hash functions.
 *  k = (m/n) * ln(2)
 *  @param m  Number of bits in the filter.
 *  @param n  Expected number of elements.
 *  @return   Optimal number of hash functions (minimum 1).
 */
uint32_t bloom_optimal_hashes(uint32_t m, uint32_t n);

/** Compute optimal bit array size.
 *  m = -n * ln(p) / (ln(2)^2)
 *  @param n  Expected number of elements.
 *  @param p  Desired false positive probability.
 *  @return   Required number of bits (minimum 8).
 */
uint32_t bloom_optimal_bits(uint32_t n, double p);

} // namespace flow

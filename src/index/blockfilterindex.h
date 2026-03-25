// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// BIP-157/158 compact block filters for light client support.
// Implements Golomb-coded sets (GCS) for space-efficient probabilistic
// membership testing. Light clients can download filters to determine
// whether a block contains relevant transactions without downloading
// the full block.
//
// Filter types:
//   BASIC (0): matches scriptPubKey patterns and outpoints spent
//
// Filter header chain:
//   filter_header_i = keccak256d(filter_hash_i || filter_header_{i-1})

#ifndef FLOWCOIN_INDEX_BLOCKFILTERINDEX_H
#define FLOWCOIN_INDEX_BLOCKFILTERINDEX_H

#include "index/base.h"
#include "primitives/block.h"
#include "util/types.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

struct sqlite3_stmt;

namespace flow {

// ============================================================================
// GCS (Golomb-Coded Set) filter
// ============================================================================

namespace gcs {

/// Golomb-Rice parameter P: false positive rate = 2^{-P}.
constexpr int P = 19;

/// Golomb-Rice parameter M: derived from P for optimal encoding.
/// M = floor(2^P * ln(2) * (1 + epsilon)) ~ 784931
constexpr uint64_t M = 784931;

/// Maximum number of elements in a single filter.
constexpr size_t MAX_FILTER_ELEMENTS = 1'000'000;

/// SipHash key derivation: first 16 bytes of block hash.
struct SipHashKey {
    uint64_t k0 = 0;
    uint64_t k1 = 0;
};

/// Derive a SipHash key from a block hash.
SipHashKey derive_key(const uint256& block_hash);

/// SipHash-2-4 implementation for element hashing.
uint64_t siphash(uint64_t k0, uint64_t k1,
                 const uint8_t* data, size_t len);

/// A Golomb-coded set filter.
class GCSFilter {
public:
    GCSFilter();

    // ---- Construction ------------------------------------------------------

    /// Build a filter from a set of raw elements and a block hash.
    /// Elements are hashed with SipHash, sorted, delta-encoded, and
    /// Golomb-Rice compressed.
    void build(const std::vector<std::vector<uint8_t>>& elements,
               const uint256& block_hash);

    // ---- Matching ----------------------------------------------------------

    /// Test if an element might be in the set (probabilistic).
    /// False positives are possible at rate 2^{-P}.
    /// False negatives never occur.
    bool match(const std::vector<uint8_t>& element) const;

    /// Test if any element from a set matches the filter.
    /// More efficient than calling match() in a loop because it
    /// merges the test set and does a single pass.
    bool match_any(const std::vector<std::vector<uint8_t>>& elements) const;

    // ---- Serialization -----------------------------------------------------

    /// Encode the filter to bytes for storage/transmission.
    std::vector<uint8_t> encode() const;

    /// Decode a filter from stored bytes. Returns false on corruption.
    bool decode(const std::vector<uint8_t>& data, const uint256& block_hash);

    // ---- Statistics --------------------------------------------------------

    /// Serialized size in bytes.
    size_t serialized_size() const;

    /// Number of elements in the filter.
    size_t element_count() const { return n_; }

    /// Check if the filter is empty (no elements).
    bool empty() const { return n_ == 0; }

private:
    std::vector<uint64_t> sorted_hashed_;  // sorted hashed elements (for matching)
    std::vector<uint8_t> encoded_;         // Golomb-Rice encoded data
    uint64_t n_ = 0;                       // element count
    SipHashKey key_;                        // SipHash key from block hash

    /// Hash an element to a uint64 in [0, n*M).
    uint64_t hash_element(const std::vector<uint8_t>& element) const;

    /// Hash raw bytes to a uint64 in [0, n*M).
    uint64_t hash_raw(const uint8_t* data, size_t len) const;

    // ---- Golomb-Rice coding ------------------------------------------------

    /// Encode a single value using Golomb-Rice coding.
    static void golomb_encode(std::vector<uint8_t>& out,
                              size_t& bit_pos, uint64_t value);

    /// Decode a single Golomb-Rice coded value.
    static uint64_t golomb_decode(const uint8_t* data,
                                  size_t& bit_pos, size_t data_len);

    /// Encode all deltas from sorted hashed elements.
    void encode_deltas();

    /// Decode deltas back to sorted hashed elements.
    bool decode_deltas(const uint8_t* data, size_t len);

    // ---- Bit I/O helpers ---------------------------------------------------

    /// Write a single bit to a byte buffer at a given bit position.
    static void write_bit(std::vector<uint8_t>& out,
                          size_t& bit_pos, bool bit);

    /// Write N low bits of a value to a byte buffer.
    static void write_bits(std::vector<uint8_t>& out,
                           size_t& bit_pos, uint64_t value, int n_bits);

    /// Read a single bit from a byte buffer.
    static bool read_bit(const uint8_t* data,
                         size_t& bit_pos, size_t data_len);

    /// Read N bits from a byte buffer as a uint64.
    static uint64_t read_bits(const uint8_t* data,
                              size_t& bit_pos, int n_bits, size_t data_len);
};

} // namespace gcs

// ============================================================================
// Block filter types (BIP-158)
// ============================================================================

enum class BlockFilterType : uint8_t {
    BASIC = 0,   // scriptPubKeys + spent outpoints
};

/// Convert filter type to string.
const char* block_filter_type_name(BlockFilterType type);

// ============================================================================
// BlockFilter: a computed filter for a single block
// ============================================================================

struct BlockFilter {
    BlockFilterType type = BlockFilterType::BASIC;
    uint256 block_hash;
    gcs::GCSFilter filter;
    uint256 filter_hash;   // keccak256d of the encoded filter

    /// Build a basic filter for a block.
    /// Extracts scriptPubKey data and spent outpoints as filter elements.
    static BlockFilter compute_basic(const CBlock& block);

    /// Compute the filter hash: keccak256d(encoded_filter).
    void compute_hash();

    /// Get the serialized filter data.
    std::vector<uint8_t> serialize() const;

    /// Deserialize a filter.
    bool deserialize(const std::vector<uint8_t>& data,
                     const uint256& block_hash_in,
                     BlockFilterType type_in = BlockFilterType::BASIC);
};

// ============================================================================
// BlockFilterIndex: chain index that stores block filters
// ============================================================================

class BlockFilterIndex : public BaseIndex {
public:
    /// Create a block filter index.
    /// @param db_path  Path to the SQLite database file.
    /// @param type     Filter type to build (default: BASIC).
    explicit BlockFilterIndex(const std::string& db_path,
                              BlockFilterType type = BlockFilterType::BASIC);

    ~BlockFilterIndex() override;

    // ---- Lookup ------------------------------------------------------------

    /// Get the filter for a block by its hash.
    bool get_filter(const uint256& block_hash, BlockFilter& filter_out) const;

    /// Get the filter for a block at a specific height.
    bool get_filter_at_height(uint64_t height, BlockFilter& filter_out) const;

    /// Get the filter header for a block.
    /// filter_header = keccak256d(filter_hash || prev_filter_header)
    bool get_filter_header(const uint256& block_hash, uint256& header_out) const;

    /// Get a range of filter headers starting at start_height.
    std::vector<uint256> get_filter_headers(uint64_t start_height,
                                             uint64_t count) const;

    /// Get the filter type this index builds.
    BlockFilterType filter_type() const { return type_; }

    /// Count total stored filters.
    uint64_t count() const;

    /// Check if a filter exists for a given block hash.
    bool has_filter(const uint256& block_hash) const;

protected:
    bool write_block(const CBlock& block, uint64_t height) override;
    bool undo_block(const CBlock& block, uint64_t height) override;
    bool init_db() override;

private:
    BlockFilterType type_;
    uint256 prev_filter_header_;  // running filter header chain

    // Prepared statements
    sqlite3_stmt* stmt_insert_ = nullptr;
    sqlite3_stmt* stmt_find_by_hash_ = nullptr;
    sqlite3_stmt* stmt_find_by_height_ = nullptr;
    sqlite3_stmt* stmt_header_by_hash_ = nullptr;
    sqlite3_stmt* stmt_headers_range_ = nullptr;
    sqlite3_stmt* stmt_delete_ = nullptr;
    sqlite3_stmt* stmt_count_ = nullptr;
    sqlite3_stmt* stmt_has_ = nullptr;
    sqlite3_stmt* stmt_prev_header_ = nullptr;

    void prepare_statements();
    void finalize_statements();

    /// Build filter elements for a basic filter.
    std::vector<std::vector<uint8_t>> get_basic_filter_elements(
        const CBlock& block) const;

    /// Compute the filter header from filter hash and previous header.
    uint256 compute_filter_header(const uint256& filter_hash,
                                  const uint256& prev_header) const;

    /// Load the previous filter header from the database for a given height.
    bool load_prev_filter_header(uint64_t height);
};

} // namespace flow

#endif // FLOWCOIN_INDEX_BLOCKFILTERINDEX_H

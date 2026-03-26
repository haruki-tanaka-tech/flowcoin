// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Delta payload compression, decompression, and manipulation for model
// weight updates in FlowCoin's Keccak-256d Proof-of-Work consensus.
//
// Each block contains a "delta" -- the difference between the model weights
// before and after training. These deltas are typically sparse (most weights
// change very little) and compress well with zstd.
//
// Two payload formats are supported:
//
// Sparse format:
//   [4 bytes: n_nonzero (LE)]
//   [n_nonzero x (4 bytes index LE, 4 bytes float32 value)]
//   Total uncompressed size: 4 + n_nonzero * 8
//
// Dense format:
//   [n x 4 bytes float32]
//   Total uncompressed size: n * 4
//
// Wire format in a block:
//   [zstd-compressed bytes of either sparse or dense payload]
//
// Consensus validates:
//   1. Compressed size is within [MIN_DELTA_SIZE, MAX_DELTA_SIZE]
//   2. Decompression succeeds
//   3. keccak256 of compressed delta matches uint256{} binding
//   4. No NaN or Inf values in the decompressed data
//   5. Sparse indices are in-range and sorted (no duplicates)

#ifndef FLOWCOIN_PRIMITIVES_DELTA_H
#define FLOWCOIN_PRIMITIVES_DELTA_H

#include "../util/types.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// Delta constants
// ---------------------------------------------------------------------------

/// Safety limit for decompressed delta size (2 GB).
static constexpr size_t MAX_DECOMPRESSED_SIZE = 2ULL * 1024 * 1024 * 1024;

/// Default zstd compression level.
static constexpr int DELTA_ZSTD_LEVEL = 3;

/// Minimum number of non-zero elements to justify sparse format.
/// Below this threshold, the overhead of sparse encoding is not worthwhile.
static constexpr size_t MIN_SPARSE_ELEMENTS = 1;

// ---------------------------------------------------------------------------
// Sparse delta entry
// ---------------------------------------------------------------------------

struct SparseEntry {
    uint32_t index;  //!< Weight index in the flattened parameter array
    float    value;  //!< Delta value (weight change)

    bool operator<(const SparseEntry& other) const { return index < other.index; }
    bool operator==(const SparseEntry& other) const {
        return index == other.index && value == other.value;
    }
};

// ---------------------------------------------------------------------------
// DeltaPayload -- full delta handling
// ---------------------------------------------------------------------------

class DeltaPayload {
public:
    DeltaPayload() = default;

    /// Construct from pre-compressed data.
    explicit DeltaPayload(std::vector<uint8_t> compressed_data)
        : compressed_(std::move(compressed_data)) {}

    // --- Compression / Decompression ---

    /// Compress a dense float32 vector into a zstd-compressed delta payload.
    /// If threshold > 0, values with |value| < threshold are zeroed before
    /// compression, and the payload is stored in sparse format.
    /// @param weights    Dense float32 array of weight deltas.
    /// @param n_weights  Number of elements in the weights array.
    /// @param threshold  Sparsification threshold (0 = no sparsification).
    /// @return true on success.
    bool compress(const float* weights, size_t n_weights, float threshold = 0.0f);

    /// Compress from a vector.
    bool compress(const std::vector<float>& weights, float threshold = 0.0f) {
        return compress(weights.data(), weights.size(), threshold);
    }

    /// Decompress into a dense float32 vector.
    /// For sparse payloads, missing indices are filled with zero.
    /// @param total_params  Total number of parameters (for sparse->dense expansion).
    /// @return Decompressed float32 values, or empty on error.
    std::vector<float> decompress(size_t total_params = 0) const;

    /// Decompress into raw bytes (no format interpretation).
    std::vector<uint8_t> decompress_raw() const;

    // --- Format queries ---

    /// Check if this delta uses sparse format.
    bool is_sparse() const;

    /// Get the compressed size in bytes.
    size_t get_compressed_size() const { return compressed_.size(); }

    /// Get the uncompressed size in bytes (from zstd frame header).
    size_t get_uncompressed_size() const;

    /// Compute the keccak256 hash of the compressed data.
    uint256 compute_hash() const;

    /// Check if this payload is empty.
    bool is_empty() const { return compressed_.empty(); }

    // --- Validation ---

    /// Validate the delta payload:
    ///   - Decompression succeeds
    ///   - No NaN or Inf values
    ///   - Sparse indices are sorted and in-range (if total_params > 0)
    ///   - Sizes are consistent
    /// @param total_params  Total number of model parameters (0 to skip range check).
    /// @return true if valid.
    bool validate(size_t total_params = 0) const;

    // --- Sparse analysis ---

    /// Count the number of non-zero elements after decompression.
    size_t count_nonzero() const;

    /// Compute the sparsity ratio (fraction of zero weights).
    /// Returns a value in [0.0, 1.0].
    /// @param total_params  Total number of model parameters.
    float sparsity_ratio(size_t total_params) const;

    /// Extract sparse entries from the compressed payload.
    /// @return Vector of (index, value) pairs, or empty on error.
    std::vector<SparseEntry> extract_sparse() const;

    // --- Merging ---

    /// Merge another delta into this one (element-wise addition).
    /// Both deltas must be decompressible. The result is stored as a
    /// new compressed payload with the given threshold.
    /// @param other          Delta to merge.
    /// @param total_params   Total number of model parameters.
    /// @param threshold      Sparsification threshold for the merged result.
    /// @return true on success.
    bool merge(const DeltaPayload& other, size_t total_params, float threshold = 0.0f);

    // --- Raw access ---

    /// Get a reference to the compressed data.
    const std::vector<uint8_t>& compressed_data() const { return compressed_; }

    /// Set the compressed data directly.
    void set_compressed_data(std::vector<uint8_t> data) {
        compressed_ = std::move(data);
    }

    /// Get a string representation for debugging.
    std::string to_string() const;

private:
    std::vector<uint8_t> compressed_;  //!< Zstd-compressed payload

    /// Encode float32 values in sparse format.
    static std::vector<uint8_t> encode_sparse(const float* weights, size_t n_weights,
                                               float threshold, uint32_t& sparse_count);

    /// Encode float32 values in dense format.
    static std::vector<uint8_t> encode_dense(const float* weights, size_t n_weights);

    /// Decode sparse format into dense float32 vector.
    static bool decode_sparse(const uint8_t* data, size_t len,
                              std::vector<float>& out, size_t total_params);

    /// Decode dense format into float32 vector.
    static bool decode_dense(const uint8_t* data, size_t len, std::vector<float>& out);
};

// ---------------------------------------------------------------------------
// Free functions (backward-compatible API)
// ---------------------------------------------------------------------------

/// Compress raw delta bytes using zstd at the default compression level (3).
std::vector<uint8_t> compress_delta(const uint8_t* data, size_t len);
std::vector<uint8_t> compress_delta(const std::vector<uint8_t>& data);

/// Decompress a zstd-compressed delta payload.
std::vector<uint8_t> decompress_delta(const uint8_t* data, size_t len);
std::vector<uint8_t> decompress_delta(const std::vector<uint8_t>& data);

/// Validate a decompressed delta buffer for NaN/Inf values.
/// Interprets the buffer as float32 values.
/// @return true if all values are finite.
bool validate_delta_values(const uint8_t* data, size_t len);
bool validate_delta_values(const std::vector<uint8_t>& data);

/// Compute the sparsity of a float32 delta buffer.
/// @return Fraction of zero values in [0.0, 1.0].
float compute_sparsity(const float* data, size_t n_floats);

/// Apply a sparsification threshold to a float32 buffer.
/// Values with |value| < threshold are set to zero.
/// @return Number of non-zero elements remaining.
size_t sparsify(float* data, size_t n_floats, float threshold);

} // namespace flow

#endif // FLOWCOIN_PRIMITIVES_DELTA_H

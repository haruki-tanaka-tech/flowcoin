// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "delta.h"
#include "../hash/keccak.h"

#include "zstd.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace flow {

// ===========================================================================
// Free functions (backward-compatible API)
// ===========================================================================

std::vector<uint8_t> compress_delta(const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) {
        return {};
    }

    size_t bound = ZSTD_compressBound(len);
    if (ZSTD_isError(bound)) {
        return {};
    }

    std::vector<uint8_t> out(bound);

    size_t compressed_size = ZSTD_compress(
        out.data(), out.size(),
        data, len,
        DELTA_ZSTD_LEVEL
    );

    if (ZSTD_isError(compressed_size)) {
        return {};
    }

    out.resize(compressed_size);
    return out;
}

std::vector<uint8_t> compress_delta(const std::vector<uint8_t>& data) {
    return compress_delta(data.data(), data.size());
}

std::vector<uint8_t> decompress_delta(const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) {
        return {};
    }

    unsigned long long decompressed_size = ZSTD_getFrameContentSize(data, len);

    if (decompressed_size == ZSTD_CONTENTSIZE_ERROR) {
        return {};
    }

    if (decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN) {
        return {};
    }

    if (decompressed_size > MAX_DECOMPRESSED_SIZE) {
        return {};
    }

    std::vector<uint8_t> out(static_cast<size_t>(decompressed_size));

    size_t actual_size = ZSTD_decompress(
        out.data(), out.size(),
        data, len
    );

    if (ZSTD_isError(actual_size)) {
        return {};
    }

    if (actual_size != static_cast<size_t>(decompressed_size)) {
        return {};
    }

    return out;
}

std::vector<uint8_t> decompress_delta(const std::vector<uint8_t>& data) {
    return decompress_delta(data.data(), data.size());
}

// ---------------------------------------------------------------------------
// validate_delta_values -- check for NaN/Inf in float32 buffer
// ---------------------------------------------------------------------------

bool validate_delta_values(const uint8_t* data, size_t len) {
    // Buffer must be a multiple of 4 bytes (float32)
    if (len % 4 != 0) return false;

    size_t n_floats = len / 4;
    for (size_t i = 0; i < n_floats; ++i) {
        float val;
        std::memcpy(&val, data + i * 4, 4);
        if (std::isnan(val) || std::isinf(val)) return false;
    }
    return true;
}

bool validate_delta_values(const std::vector<uint8_t>& data) {
    return validate_delta_values(data.data(), data.size());
}

// ---------------------------------------------------------------------------
// compute_sparsity
// ---------------------------------------------------------------------------

float compute_sparsity(const float* data, size_t n_floats) {
    if (n_floats == 0) return 1.0f;
    size_t zero_count = 0;
    for (size_t i = 0; i < n_floats; ++i) {
        if (data[i] == 0.0f) ++zero_count;
    }
    return static_cast<float>(zero_count) / static_cast<float>(n_floats);
}

// ---------------------------------------------------------------------------
// sparsify -- apply threshold
// ---------------------------------------------------------------------------

size_t sparsify(float* data, size_t n_floats, float threshold) {
    size_t nonzero = 0;
    float abs_threshold = std::fabs(threshold);
    for (size_t i = 0; i < n_floats; ++i) {
        if (std::fabs(data[i]) < abs_threshold) {
            data[i] = 0.0f;
        } else {
            ++nonzero;
        }
    }
    return nonzero;
}

// ===========================================================================
// DeltaPayload private helpers
// ===========================================================================

// ---------------------------------------------------------------------------
// encode_sparse -- float32 array to sparse format
// ---------------------------------------------------------------------------

std::vector<uint8_t> DeltaPayload::encode_sparse(const float* weights, size_t n_weights,
                                                   float threshold, uint32_t& sparse_count) {
    // First pass: count non-zero elements
    float abs_threshold = std::fabs(threshold);
    std::vector<SparseEntry> entries;
    entries.reserve(n_weights / 10);  // heuristic

    for (size_t i = 0; i < n_weights; ++i) {
        if (std::fabs(weights[i]) >= abs_threshold) {
            SparseEntry e;
            e.index = static_cast<uint32_t>(i);
            e.value = weights[i];
            entries.push_back(e);
        }
    }

    sparse_count = static_cast<uint32_t>(entries.size());

    // Encode: [4 bytes n_nonzero] [n_nonzero x (4 bytes index, 4 bytes value)]
    size_t total_size = 4 + entries.size() * 8;
    std::vector<uint8_t> buf(total_size);

    // Write count (LE)
    uint32_t count = static_cast<uint32_t>(entries.size());
    std::memcpy(buf.data(), &count, 4);

    // Write entries
    for (size_t i = 0; i < entries.size(); ++i) {
        size_t offset = 4 + i * 8;
        std::memcpy(buf.data() + offset, &entries[i].index, 4);
        std::memcpy(buf.data() + offset + 4, &entries[i].value, 4);
    }

    return buf;
}

// ---------------------------------------------------------------------------
// encode_dense -- float32 array to dense format
// ---------------------------------------------------------------------------

std::vector<uint8_t> DeltaPayload::encode_dense(const float* weights, size_t n_weights) {
    size_t total_size = n_weights * 4;
    std::vector<uint8_t> buf(total_size);
    std::memcpy(buf.data(), weights, total_size);
    return buf;
}

// ---------------------------------------------------------------------------
// decode_sparse -- sparse format to dense float32 vector
// ---------------------------------------------------------------------------

bool DeltaPayload::decode_sparse(const uint8_t* data, size_t len,
                                  std::vector<float>& out, size_t total_params) {
    if (len < 4) return false;

    uint32_t n_nonzero;
    std::memcpy(&n_nonzero, data, 4);

    // Validate size
    size_t expected = 4 + static_cast<size_t>(n_nonzero) * 8;
    if (len < expected) return false;

    // Initialize output to zeros
    if (total_params == 0) {
        // Without total_params, we can't expand to dense.
        // Find max index to determine required size.
        uint32_t max_idx = 0;
        for (uint32_t i = 0; i < n_nonzero; ++i) {
            uint32_t idx;
            std::memcpy(&idx, data + 4 + i * 8, 4);
            if (idx > max_idx) max_idx = idx;
        }
        total_params = max_idx + 1;
    }

    out.assign(total_params, 0.0f);

    uint32_t prev_idx = 0;
    for (uint32_t i = 0; i < n_nonzero; ++i) {
        uint32_t idx;
        float val;
        size_t offset = 4 + i * 8;
        std::memcpy(&idx, data + offset, 4);
        std::memcpy(&val, data + offset + 4, 4);

        // Validate index
        if (idx >= total_params) return false;

        // Validate sorting (indices must be strictly increasing)
        if (i > 0 && idx <= prev_idx) return false;

        // Validate value
        if (std::isnan(val) || std::isinf(val)) return false;

        out[idx] = val;
        prev_idx = idx;
    }

    return true;
}

// ---------------------------------------------------------------------------
// decode_dense -- dense format to float32 vector
// ---------------------------------------------------------------------------

bool DeltaPayload::decode_dense(const uint8_t* data, size_t len, std::vector<float>& out) {
    if (len % 4 != 0) return false;

    size_t n_floats = len / 4;
    out.resize(n_floats);
    std::memcpy(out.data(), data, len);

    // Validate values
    for (size_t i = 0; i < n_floats; ++i) {
        if (std::isnan(out[i]) || std::isinf(out[i])) return false;
    }

    return true;
}

// ===========================================================================
// DeltaPayload public methods
// ===========================================================================

// ---------------------------------------------------------------------------
// compress
// ---------------------------------------------------------------------------

bool DeltaPayload::compress(const float* weights, size_t n_weights, float threshold) {
    if (!weights || n_weights == 0) return false;

    std::vector<uint8_t> raw;

    if (threshold > 0.0f) {
        // Sparse encoding
        uint32_t sparse_count = 0;
        raw = encode_sparse(weights, n_weights, threshold, sparse_count);
    } else {
        // Dense encoding
        raw = encode_dense(weights, n_weights);
    }

    compressed_ = compress_delta(raw);
    return !compressed_.empty();
}

// ---------------------------------------------------------------------------
// decompress
// ---------------------------------------------------------------------------

std::vector<float> DeltaPayload::decompress(size_t total_params) const {
    if (compressed_.empty()) return {};

    auto raw = decompress_delta(compressed_);
    if (raw.empty()) return {};

    std::vector<float> result;

    if (is_sparse()) {
        if (!decode_sparse(raw.data(), raw.size(), result, total_params)) {
            return {};
        }
    } else {
        if (!decode_dense(raw.data(), raw.size(), result)) {
            return {};
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// decompress_raw
// ---------------------------------------------------------------------------

std::vector<uint8_t> DeltaPayload::decompress_raw() const {
    return decompress_delta(compressed_);
}

// ---------------------------------------------------------------------------
// is_sparse
// ---------------------------------------------------------------------------

bool DeltaPayload::is_sparse() const {
    if (compressed_.empty()) return false;

    auto raw = decompress_delta(compressed_);
    if (raw.empty()) return false;

    // A sparse payload starts with a 4-byte count, then count * 8 bytes.
    // A dense payload has size that's a multiple of 4.
    // Heuristic: if size == 4 + count * 8 where count is the first 4 bytes,
    // it's likely sparse.
    if (raw.size() < 4) return false;

    uint32_t n_nonzero;
    std::memcpy(&n_nonzero, raw.data(), 4);

    size_t expected_sparse = 4 + static_cast<size_t>(n_nonzero) * 8;
    return raw.size() == expected_sparse && n_nonzero > 0;
}

// ---------------------------------------------------------------------------
// get_uncompressed_size
// ---------------------------------------------------------------------------

size_t DeltaPayload::get_uncompressed_size() const {
    if (compressed_.empty()) return 0;

    unsigned long long size = ZSTD_getFrameContentSize(compressed_.data(), compressed_.size());
    if (size == ZSTD_CONTENTSIZE_ERROR || size == ZSTD_CONTENTSIZE_UNKNOWN) {
        return 0;
    }
    return static_cast<size_t>(size);
}

// ---------------------------------------------------------------------------
// compute_hash
// ---------------------------------------------------------------------------

uint256 DeltaPayload::compute_hash() const {
    if (compressed_.empty()) {
        uint256 null_hash;
        null_hash.set_null();
        return null_hash;
    }
    return keccak256(compressed_.data(), compressed_.size());
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

bool DeltaPayload::validate(size_t total_params) const {
    if (compressed_.empty()) return false;

    // Decompress
    auto raw = decompress_delta(compressed_);
    if (raw.empty()) return false;

    // Check for NaN/Inf
    if (is_sparse()) {
        // Validate sparse format
        if (raw.size() < 4) return false;

        uint32_t n_nonzero;
        std::memcpy(&n_nonzero, raw.data(), 4);

        size_t expected = 4 + static_cast<size_t>(n_nonzero) * 8;
        if (raw.size() != expected) return false;

        uint32_t prev_idx = 0;
        for (uint32_t i = 0; i < n_nonzero; ++i) {
            uint32_t idx;
            float val;
            size_t offset = 4 + i * 8;
            std::memcpy(&idx, raw.data() + offset, 4);
            std::memcpy(&val, raw.data() + offset + 4, 4);

            // Check for NaN/Inf
            if (std::isnan(val) || std::isinf(val)) return false;

            // Check index bounds
            if (total_params > 0 && idx >= total_params) return false;

            // Check sorted order
            if (i > 0 && idx <= prev_idx) return false;
            prev_idx = idx;
        }
    } else {
        // Validate dense format
        if (!validate_delta_values(raw)) return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// count_nonzero
// ---------------------------------------------------------------------------

size_t DeltaPayload::count_nonzero() const {
    if (compressed_.empty()) return 0;

    auto raw = decompress_delta(compressed_);
    if (raw.empty()) return 0;

    if (is_sparse()) {
        if (raw.size() < 4) return 0;
        uint32_t n_nonzero;
        std::memcpy(&n_nonzero, raw.data(), 4);
        return n_nonzero;
    }

    // Dense: count non-zero floats
    size_t n_floats = raw.size() / 4;
    size_t count = 0;
    for (size_t i = 0; i < n_floats; ++i) {
        float val;
        std::memcpy(&val, raw.data() + i * 4, 4);
        if (val != 0.0f) ++count;
    }
    return count;
}

// ---------------------------------------------------------------------------
// sparsity_ratio
// ---------------------------------------------------------------------------

float DeltaPayload::sparsity_ratio(size_t total_params) const {
    if (total_params == 0) return 0.0f;
    size_t nz = count_nonzero();
    return 1.0f - static_cast<float>(nz) / static_cast<float>(total_params);
}

// ---------------------------------------------------------------------------
// extract_sparse
// ---------------------------------------------------------------------------

std::vector<SparseEntry> DeltaPayload::extract_sparse() const {
    if (compressed_.empty()) return {};

    auto raw = decompress_delta(compressed_);
    if (raw.empty() || raw.size() < 4) return {};

    uint32_t n_nonzero;
    std::memcpy(&n_nonzero, raw.data(), 4);

    size_t expected = 4 + static_cast<size_t>(n_nonzero) * 8;
    if (raw.size() < expected) return {};

    std::vector<SparseEntry> entries(n_nonzero);
    for (uint32_t i = 0; i < n_nonzero; ++i) {
        size_t offset = 4 + i * 8;
        std::memcpy(&entries[i].index, raw.data() + offset, 4);
        std::memcpy(&entries[i].value, raw.data() + offset + 4, 4);
    }

    return entries;
}

// ---------------------------------------------------------------------------
// merge
// ---------------------------------------------------------------------------

bool DeltaPayload::merge(const DeltaPayload& other, size_t total_params, float threshold) {
    if (total_params == 0) return false;

    // Decompress both deltas
    auto weights_a = decompress(total_params);
    auto weights_b = other.decompress(total_params);

    if (weights_a.empty() || weights_b.empty()) return false;

    // Ensure same size
    if (weights_a.size() != weights_b.size()) {
        // Resize to the larger of the two
        size_t max_size = std::max(weights_a.size(), weights_b.size());
        weights_a.resize(max_size, 0.0f);
        weights_b.resize(max_size, 0.0f);
    }

    // Element-wise addition
    for (size_t i = 0; i < weights_a.size(); ++i) {
        weights_a[i] += weights_b[i];
    }

    // Recompress
    return compress(weights_a, threshold);
}

// ---------------------------------------------------------------------------
// to_string
// ---------------------------------------------------------------------------

std::string DeltaPayload::to_string() const {
    std::ostringstream ss;
    ss << "DeltaPayload(compressed=" << compressed_.size()
       << " uncompressed=" << get_uncompressed_size()
       << " sparse=" << (is_sparse() ? "yes" : "no")
       << " nonzero=" << count_nonzero()
       << ")";
    return ss.str();
}

} // namespace flow

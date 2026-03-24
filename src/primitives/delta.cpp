// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "delta.h"

#include "zstd.h"

#include <cstdlib>

namespace flow {

// ---------------------------------------------------------------------------
// Safety limit for decompressed delta size.
// ---------------------------------------------------------------------------
// A full model at max dimensions (d=1024, L=24) has roughly:
//   24 layers * (4*1024*1024 + 2*1024*2048 + misc) ~ 200M floats ~ 800 MB
// But sparse deltas should be much smaller. We cap at 2 GB to prevent
// memory exhaustion from malicious payloads while allowing headroom.
static constexpr size_t MAX_DECOMPRESSED_SIZE = 2ULL * 1024 * 1024 * 1024; // 2 GB

// ---------------------------------------------------------------------------
// Default zstd compression level.
// ---------------------------------------------------------------------------
// Level 3 is zstd's default: good balance of speed and ratio.
// Training deltas are written once and read many times during sync,
// so moderate compression is appropriate.
static constexpr int ZSTD_LEVEL = 3;

// ---------------------------------------------------------------------------
// compress_delta
// ---------------------------------------------------------------------------

std::vector<uint8_t> compress_delta(const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) {
        return {};
    }

    // ZSTD_compressBound returns the maximum compressed size for a given
    // input length. This is guaranteed to be sufficient for ZSTD_compress.
    size_t bound = ZSTD_compressBound(len);
    if (ZSTD_isError(bound)) {
        return {};
    }

    std::vector<uint8_t> out(bound);

    size_t compressed_size = ZSTD_compress(
        out.data(), out.size(),
        data, len,
        ZSTD_LEVEL
    );

    if (ZSTD_isError(compressed_size)) {
        return {};
    }

    // Shrink to actual compressed size
    out.resize(compressed_size);
    return out;
}

std::vector<uint8_t> compress_delta(const std::vector<uint8_t>& data) {
    return compress_delta(data.data(), data.size());
}

// ---------------------------------------------------------------------------
// decompress_delta
// ---------------------------------------------------------------------------

std::vector<uint8_t> decompress_delta(const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) {
        return {};
    }

    // Determine the decompressed size from the zstd frame header.
    // This returns ZSTD_CONTENTSIZE_UNKNOWN if the frame doesn't encode the
    // original siblockstoreze, or ZSTD_CONTENTSIZE_ERROR if the header is invalid.
    unsigned long long decompressed_size = ZSTD_getFrameContentSize(data, len);

    if (decompressed_size == ZSTD_CONTENTSIZE_ERROR) {
        // Corrupt or invalid zstd frame header.
        return {};
    }

    if (decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN) {
        // The frame doesn't encode the original size. This shouldn't happen
        // with data produced by compress_delta (zstd encodes size by default),
        // but could occur with hand-crafted malicious payloads.
        // We could use streaming decompression here, but for safety we reject.
        return {};
    }

    // Guard against decompression bombs: reject if the claimed output size
    // exceeds our safety limit.
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

    // Verify thatblockstore the actual decompressed size matches the frame header.
    // ZSTD_decompress should guarantee this, but belt-and-suspenders.
    if (actual_size != static_cast<size_t>(decompressed_size)) {
        return {};
    }

    return out;
}

std::vector<uint8_t> decompress_delta(const std::vector<uint8_t>& data) {
    return decompress_delta(data.data(), data.size());
}

} // namespace flow

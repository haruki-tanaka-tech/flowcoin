// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Delta payload compression and decompression for model weight updates.
//
// Each block contains a "delta" — the difference between the model weights
// before and after training. These deltas are typically sparse (most weights
// change very little) and compress well with zstd.
//
// Wire format of the delta payload in a block:
//   [zstd-compressed bytes]
//
// The uncompressed payload is an opaque byte stream interpreted by the
// training engine. Consensus only validates:
//   1. Compressed size is within [MIN_DELTA_SIZE, MAX_DELTA_SIZE]
//   2. Decompression succeeds
//   3. keccak256 of compressed delta matches header.delta_hash (if present)
//      or header.training_hash binding

#ifndef FLOWCOIN_PRIMITIVES_DELTA_H
#define FLOWCOIN_PRIMITIVES_DELTA_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace flow {

/// Compress raw delta bytes using zstd at the default compression level (3).
///
/// @param data  Pointer to uncompressed delta bytes.
/// @param len   Length of uncompressed data.
/// @return      Zstd-compressed bytes. Empty vector on compression failure.
std::vector<uint8_t> compress_delta(const uint8_t* data, size_t len);

/// Compress raw delta bytes using zstd (convenience overload).
std::vector<uint8_t> compress_delta(const std::vector<uint8_t>& data);

/// Decompress a zstd-compressed delta payload.
///
/// Uses ZSTD_getFrameContentSize to determine the output size, then
/// decompresses in a single pass. Returns an empty vector on any error
/// (corrupt data, truncated frame, size exceeds safety limit).
///
/// @param data  Pointer to compressed delta bytes.
/// @param len   Length of compressed data.
/// @return      Decompressed bytes. Empty vector on error.
std::vector<uint8_t> decompress_delta(const uint8_t* data, size_t len);

/// Decompress a zstd-compressed delta payload (convenience overload).
std::vector<uint8_t> decompress_delta(const std::vector<uint8_t>& data);

} // namespace flow

#endif // FLOWCOIN_PRIMITIVES_DELTA_H

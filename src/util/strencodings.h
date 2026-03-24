// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Hex encoding and decoding utilities for FlowCoin.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace flow {

/** Encode raw bytes as a lowercase hex string (2 characters per byte). */
std::string hex_encode(const uint8_t* data, size_t len);

/** Encode a byte vector as a lowercase hex string. */
std::string hex_encode(const std::vector<uint8_t>& data);

/** Decode a hex string into raw bytes.
 *  Returns an empty vector if the input is invalid (odd length or
 *  non-hex characters).
 */
std::vector<uint8_t> hex_decode(const std::string& hex);

/** Encode N bytes in reverse order as a hex string (big-endian display).
 *  Used for block hash display: hashes are stored as little-endian bytes
 *  but conventionally displayed with the most significant byte first.
 *
 *  Example: for a 32-byte hash stored as [a0, b1, c2, ...], this returns
 *  the hex of [..., c2, b1, a0] — the big-endian representation.
 */
template <size_t N>
std::string hex_encode_reverse(const uint8_t* data) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(N * 2);
    for (size_t i = N; i > 0; --i) {
        uint8_t b = data[i - 1];
        result.push_back(hex_chars[b >> 4]);
        result.push_back(hex_chars[b & 0x0f]);
    }
    return result;
}

} // namespace flow

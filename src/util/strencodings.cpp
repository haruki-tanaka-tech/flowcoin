// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Hex encoding and decoding implementation.

#include "strencodings.h"

namespace flow {

// ---------------------------------------------------------------------------
// Internal helper: convert a single hex character to its 4-bit value.
// Returns -1 for invalid characters.
// ---------------------------------------------------------------------------

static int hex_digit_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// ---------------------------------------------------------------------------
// hex_encode
// ---------------------------------------------------------------------------

std::string hex_encode(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(hex_chars[data[i] >> 4]);
        result.push_back(hex_chars[data[i] & 0x0f]);
    }
    return result;
}

std::string hex_encode(const std::vector<uint8_t>& data) {
    return hex_encode(data.data(), data.size());
}

// ---------------------------------------------------------------------------
// hex_decode
// ---------------------------------------------------------------------------

std::vector<uint8_t> hex_decode(const std::string& hex) {
    // Must be even length.
    if (hex.size() % 2 != 0)
        return {};

    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hex_digit_value(hex[i]);
        int lo = hex_digit_value(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return {};  // invalid hex character
        result.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return result;
}

} // namespace flow

// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// 256-bit unsigned integer arithmetic implementation.
// Modeled after Bitcoin Core's arith_uint256.cpp.

#include "arith_uint256.h"

#include <algorithm>
#include <cstring>

namespace flow {

// ===========================================================================
// SetCompact / GetCompact — Bitcoin's compact target encoding
// ===========================================================================

arith_uint256& arith_uint256::SetCompact(uint32_t nCompact, bool* pfNegative,
                                         bool* pfOverflow) {
    int nSize = nCompact >> 24;
    uint32_t nWord = nCompact & 0x007fffff;
    if (nSize <= 3) {
        nWord >>= 8 * (3 - nSize);
        *this = arith_uint256();
        pn[0] = nWord;
    } else {
        *this = arith_uint256();
        pn[0] = nWord;
        *this <<= 8 * (nSize - 3);
    }
    if (pfNegative)
        *pfNegative = (nWord != 0) && (nCompact & 0x00800000) != 0;
    if (pfOverflow)
        *pfOverflow = (nWord != 0) && ((nSize > 34) ||
                      (nWord > 0xff && nSize > 33) ||
                      (nWord > 0xffff && nSize > 32));
    return *this;
}

uint32_t arith_uint256::GetCompact(bool fNegative) const {
    int nSize = (bits() + 7) / 8;
    uint32_t nCompact = 0;
    if (nSize <= 3) {
        nCompact = GetLow64() << 8 * (3 - nSize);
    } else {
        arith_uint256 bn = *this >> 8 * (nSize - 3);
        nCompact = bn.GetLow64();
    }
    // The 0x00800000 bit denotes the sign.
    // Thus, if it is already set, divide the mantissa by 256 and increase
    // the exponent.
    if (nCompact & 0x00800000) {
        nCompact >>= 8;
        nSize++;
    }
    nCompact |= static_cast<uint32_t>(nSize) << 24;
    nCompact |= (fNegative && (nCompact & 0x007fffff) ? 0x00800000 : 0);
    return nCompact;
}

// ===========================================================================
// Arithmetic operators
// ===========================================================================

arith_uint256& arith_uint256::operator+=(const arith_uint256& b) {
    uint64_t carry = 0;
    for (int i = 0; i < WIDTH; ++i) {
        uint64_t sum = static_cast<uint64_t>(pn[i]) + b.pn[i] + carry;
        pn[i] = static_cast<uint32_t>(sum);
        carry = sum >> 32;
    }
    return *this;
}

arith_uint256& arith_uint256::operator-=(const arith_uint256& b) {
    uint64_t borrow = 0;
    for (int i = 0; i < WIDTH; ++i) {
        uint64_t diff = static_cast<uint64_t>(pn[i]) - b.pn[i] - borrow;
        pn[i] = static_cast<uint32_t>(diff);
        borrow = (diff >> 63) & 1;  // borrow if result wrapped
    }
    return *this;
}

arith_uint256& arith_uint256::operator*=(const arith_uint256& b) {
    // Schoolbook multiplication with uint64_t intermediates.
    uint32_t result[WIDTH]{};
    for (int j = 0; j < WIDTH; ++j) {
        uint64_t carry = 0;
        for (int i = 0; i + j < WIDTH; ++i) {
            uint64_t product = static_cast<uint64_t>(pn[i]) * b.pn[j]
                             + result[i + j] + carry;
            result[i + j] = static_cast<uint32_t>(product);
            carry = product >> 32;
        }
    }
    std::memcpy(pn, result, sizeof(pn));
    return *this;
}

arith_uint256& arith_uint256::operator*=(uint32_t b32) {
    uint64_t carry = 0;
    for (int i = 0; i < WIDTH; ++i) {
        uint64_t product = static_cast<uint64_t>(pn[i]) * b32 + carry;
        pn[i] = static_cast<uint32_t>(product);
        carry = product >> 32;
    }
    return *this;
}

arith_uint256& arith_uint256::operator/=(const arith_uint256& b) {
    // Long division: 256-bit by 256-bit.
    // We use the bit-by-bit shift-subtract algorithm.
    arith_uint256 num = *this;    // dividend (will become remainder)
    arith_uint256 div = b;        // divisor
    arith_uint256 quotient;

    if (div.IsNull()) {
        // Division by zero: return zero.
        *this = arith_uint256();
        return *this;
    }

    int num_bits = num.bits();
    int div_bits = div.bits();

    if (div_bits > num_bits) {
        // Divisor is larger than dividend: result is zero.
        *this = arith_uint256();
        return *this;
    }

    // Align divisor to the same bit position as the highest bit of the dividend.
    int shift = num_bits - div_bits;
    div <<= shift;

    for (int i = shift; i >= 0; --i) {
        if (num >= div) {
            num -= div;
            quotient.pn[i / 32] |= (1U << (i % 32));
        }
        div >>= 1;
    }
    *this = quotient;
    return *this;
}

arith_uint256& arith_uint256::operator%=(const arith_uint256& b) {
    arith_uint256 quotient = *this / b;
    *this -= quotient * b;
    return *this;
}

arith_uint256& arith_uint256::operator/=(uint32_t b32) {
    uint64_t rem = 0;
    for (int i = WIDTH - 1; i >= 0; --i) {
        uint64_t dividend = (rem << 32) | pn[i];
        pn[i] = static_cast<uint32_t>(dividend / b32);
        rem = dividend % b32;
    }
    return *this;
}

// ===========================================================================
// Increment / Decrement
// ===========================================================================

arith_uint256& arith_uint256::operator++() {
    for (int i = 0; i < WIDTH; ++i) {
        if (++pn[i] != 0)
            break;
    }
    return *this;
}

arith_uint256& arith_uint256::operator--() {
    for (int i = 0; i < WIDTH; ++i) {
        if (pn[i]-- != 0)
            break;
    }
    return *this;
}

arith_uint256 arith_uint256::operator-() const {
    arith_uint256 r;
    for (int i = 0; i < WIDTH; ++i)
        r.pn[i] = ~pn[i];
    ++r;
    return r;
}

// ===========================================================================
// Bit operations
// ===========================================================================

arith_uint256& arith_uint256::operator<<=(unsigned int shift) {
    if (shift == 0) return *this;
    if (shift >= 256) {
        std::memset(pn, 0, sizeof(pn));
        return *this;
    }

    unsigned int word_shift = shift / 32;
    unsigned int bit_shift = shift % 32;

    // Move words, processing from high to low to avoid overwriting source data.
    for (int i = WIDTH - 1; i >= 0; --i) {
        int src = i - static_cast<int>(word_shift);
        if (src >= 0) {
            pn[i] = pn[src] << bit_shift;
            if (bit_shift > 0 && src > 0)
                pn[i] |= pn[src - 1] >> (32 - bit_shift);
        } else {
            pn[i] = 0;
        }
    }
    return *this;
}

arith_uint256& arith_uint256::operator>>=(unsigned int shift) {
    if (shift == 0) return *this;
    if (shift >= 256) {
        std::memset(pn, 0, sizeof(pn));
        return *this;
    }

    unsigned int word_shift = shift / 32;
    unsigned int bit_shift = shift % 32;

    // Move words, processing from low to high to avoid overwriting source data.
    for (int i = 0; i < WIDTH; ++i) {
        unsigned int src = i + word_shift;
        if (src < static_cast<unsigned int>(WIDTH)) {
            pn[i] = pn[src] >> bit_shift;
            if (bit_shift > 0 && src + 1 < static_cast<unsigned int>(WIDTH))
                pn[i] |= pn[src + 1] << (32 - bit_shift);
        } else {
            pn[i] = 0;
        }
    }
    return *this;
}

arith_uint256& arith_uint256::operator&=(const arith_uint256& b) {
    for (int i = 0; i < WIDTH; ++i) pn[i] &= b.pn[i];
    return *this;
}

arith_uint256& arith_uint256::operator|=(const arith_uint256& b) {
    for (int i = 0; i < WIDTH; ++i) pn[i] |= b.pn[i];
    return *this;
}

arith_uint256& arith_uint256::operator^=(const arith_uint256& b) {
    for (int i = 0; i < WIDTH; ++i) pn[i] ^= b.pn[i];
    return *this;
}

arith_uint256 arith_uint256::operator~() const {
    arith_uint256 r;
    for (int i = 0; i < WIDTH; ++i) r.pn[i] = ~pn[i];
    return r;
}

// ===========================================================================
// Comparison operators
// ===========================================================================

bool arith_uint256::operator==(const arith_uint256& b) const {
    for (int i = 0; i < WIDTH; ++i)
        if (pn[i] != b.pn[i]) return false;
    return true;
}

bool arith_uint256::operator!=(const arith_uint256& b) const {
    return !(*this == b);
}

bool arith_uint256::operator<(const arith_uint256& b) const {
    for (int i = WIDTH - 1; i >= 0; --i) {
        if (pn[i] < b.pn[i]) return true;
        if (pn[i] > b.pn[i]) return false;
    }
    return false;
}

bool arith_uint256::operator<=(const arith_uint256& b) const {
    for (int i = WIDTH - 1; i >= 0; --i) {
        if (pn[i] < b.pn[i]) return true;
        if (pn[i] > b.pn[i]) return false;
    }
    return true;
}

bool arith_uint256::operator>(const arith_uint256& b) const {
    return b < *this;
}

bool arith_uint256::operator>=(const arith_uint256& b) const {
    return b <= *this;
}

// ===========================================================================
// Utility
// ===========================================================================

bool arith_uint256::IsNull() const {
    for (int i = 0; i < WIDTH; ++i)
        if (pn[i] != 0) return false;
    return true;
}

int arith_uint256::bits() const {
    for (int pos = WIDTH - 1; pos >= 0; --pos) {
        if (pn[pos] != 0) {
            // Find highest set bit in this limb.
            uint32_t word = pn[pos];
            int b = 0;
            // Use binary search for the highest set bit.
            if (word & 0xffff0000) { b += 16; word >>= 16; }
            if (word & 0x0000ff00) { b +=  8; word >>=  8; }
            if (word & 0x000000f0) { b +=  4; word >>=  4; }
            if (word & 0x0000000c) { b +=  2; word >>=  2; }
            if (word & 0x00000002) { b +=  1; }
            return pos * 32 + b + 1;
        }
    }
    return 0;
}

uint64_t arith_uint256::GetLow64() const {
    return static_cast<uint64_t>(pn[0]) | (static_cast<uint64_t>(pn[1]) << 32);
}

// ===========================================================================
// Hex encoding / decoding (big-endian display)
// ===========================================================================

void arith_uint256::SetHex(const std::string& str) {
    std::memset(pn, 0, sizeof(pn));

    // Skip optional "0x" prefix.
    size_t start = 0;
    if (str.size() >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
        start = 2;

    // Skip leading zeros in the string (but we still parse them).
    // Parse hex digits from left (most significant) to right (least significant).
    // The hex string is big-endian: leftmost character is most significant nibble.

    // First, collect all valid hex characters.
    std::string hex;
    hex.reserve(str.size() - start);
    for (size_t i = start; i < str.size(); ++i) {
        char c = str[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            hex.push_back(c);
        else
            break;
    }

    // Parse from the right (least significant) end, filling pn[] from index 0 up.
    size_t hex_len = hex.size();
    for (size_t i = 0; i < hex_len && i < 64; ++i) {
        char c = hex[hex_len - 1 - i];
        uint32_t nibble;
        if (c >= '0' && c <= '9') nibble = c - '0';
        else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
        else nibble = c - 'A' + 10;  // c >= 'A' && c <= 'F'

        pn[i / 8] |= nibble << ((i % 8) * 4);
    }
}

std::string arith_uint256::GetHex() const {
    static const char hex_chars[] = "0123456789abcdef";
    // Output 64 hex characters, big-endian (most significant limb first).
    std::string result;
    result.reserve(64);
    for (int i = WIDTH - 1; i >= 0; --i) {
        for (int j = 28; j >= 0; j -= 4) {
            result.push_back(hex_chars[(pn[i] >> j) & 0xf]);
        }
    }
    return result;
}

// ===========================================================================
// Conversion: uint256 <-> arith_uint256
// ===========================================================================

arith_uint256 UintToArith256(const uint256& hash) {
    arith_uint256 r;
    // uint256 byte layout is little-endian: byte 0 is least significant.
    // Pack groups of 4 bytes into each 32-bit limb.
    for (int i = 0; i < arith_uint256::WIDTH; ++i) {
        r.pn[i] = static_cast<uint32_t>(hash[i * 4 + 0])
                 | (static_cast<uint32_t>(hash[i * 4 + 1]) << 8)
                 | (static_cast<uint32_t>(hash[i * 4 + 2]) << 16)
                 | (static_cast<uint32_t>(hash[i * 4 + 3]) << 24);
    }
    return r;
}

uint256 ArithToUint256(const arith_uint256& a) {
    uint256 r;
    for (int i = 0; i < arith_uint256::WIDTH; ++i) {
        r[i * 4 + 0] = static_cast<uint8_t>(a.pn[i]);
        r[i * 4 + 1] = static_cast<uint8_t>(a.pn[i] >> 8);
        r[i * 4 + 2] = static_cast<uint8_t>(a.pn[i] >> 16);
        r[i * 4 + 3] = static_cast<uint8_t>(a.pn[i] >> 24);
    }
    return r;
}

} // namespace flow

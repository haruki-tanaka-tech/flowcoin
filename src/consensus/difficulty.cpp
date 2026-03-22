// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Difficulty adjustment identical to Bitcoin Core.
// Uses proper 256-bit arithmetic for precision.
//
// Reference: Bitcoin Core src/arith_uint256.cpp, src/pow.cpp

#include "difficulty.h"
#include "params.h"

#include <algorithm>
#include <cstring>

namespace flow::consensus {

// ─── arith_uint256 implementation ─────────────────────────────

arith_uint256 arith_uint256::from_uint256(const uint256& v) {
    arith_uint256 r;
    // uint256 is little-endian bytes. Pack into 4 x uint64 (also little-endian).
    for (int i = 0; i < 4; ++i) {
        r.d[i] = 0;
        for (int j = 0; j < 8; ++j) {
            r.d[i] |= static_cast<uint64_t>(v[i * 8 + j]) << (j * 8);
        }
    }
    return r;
}

uint256 arith_uint256::to_uint256() const {
    uint256 r;
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 8; ++j) {
            r[i * 8 + j] = static_cast<uint8_t>(d[i] >> (j * 8));
        }
    }
    return r;
}

arith_uint256& arith_uint256::operator*=(uint64_t rhs) {
    // 256-bit * 64-bit = 320-bit, but we truncate to 256
    __uint128_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        __uint128_t prod = static_cast<__uint128_t>(d[i]) * rhs + carry;
        d[i] = static_cast<uint64_t>(prod);
        carry = prod >> 64;
    }
    // carry overflow is lost (target should never be that large)
    return *this;
}

arith_uint256& arith_uint256::operator/=(uint64_t rhs) {
    // 256-bit / 64-bit using long division
    __uint128_t rem = 0;
    for (int i = 3; i >= 0; --i) {
        __uint128_t dividend = (rem << 64) | d[i];
        d[i] = static_cast<uint64_t>(dividend / rhs);
        rem = dividend % rhs;
    }
    return *this;
}

bool arith_uint256::operator<=(const arith_uint256& rhs) const {
    for (int i = 3; i >= 0; --i) {
        if (d[i] < rhs.d[i]) return true;
        if (d[i] > rhs.d[i]) return false;
    }
    return true; // equal
}

bool arith_uint256::operator>(const arith_uint256& rhs) const {
    return !(*this <= rhs);
}

bool arith_uint256::is_zero() const {
    return d[0] == 0 && d[1] == 0 && d[2] == 0 && d[3] == 0;
}

int arith_uint256::bits() const {
    for (int i = 3; i >= 0; --i) {
        if (d[i] != 0) {
            // Find highest bit in this word
            int b = 63;
            while (b > 0 && ((d[i] >> b) & 1) == 0) --b;
            return i * 64 + b + 1;
        }
    }
    return 0;
}

// ─── Compact target (nbits) encoding ──────────────────────────
//
// Matches Bitcoin Core's SetCompact / GetCompact exactly.

uint256 nbits_to_target(uint32_t nbits) {
    arith_uint256 target;

    int exponent = (nbits >> 24) & 0xFF;
    uint32_t mantissa = nbits & 0x7FFFFF;
    bool negative = (nbits & 0x800000) != 0;

    if (exponent <= 3) {
        mantissa >>= 8 * (3 - exponent);
        target.d[0] = mantissa;
    } else {
        target.d[0] = mantissa;
        // Shift left by 8 * (exponent - 3) bits
        int shift_bits = 8 * (exponent - 3);
        // Perform the shift across the 256-bit number
        int word_shift = shift_bits / 64;
        int bit_shift = shift_bits % 64;

        // Move words
        arith_uint256 shifted;
        for (int i = 3; i >= 0; --i) {
            int src = i - word_shift;
            if (src >= 0) {
                shifted.d[i] = target.d[src] << bit_shift;
                if (bit_shift > 0 && src > 0) {
                    shifted.d[i] |= target.d[src - 1] >> (64 - bit_shift);
                }
            }
        }
        target = shifted;
    }

    if (negative || mantissa == 0) {
        arith_uint256 zero;
        return zero.to_uint256();
    }

    return target.to_uint256();
}

uint32_t target_to_nbits(const uint256& target) {
    arith_uint256 a = arith_uint256::from_uint256(target);

    if (a.is_zero()) return 0;

    // Find the number of significant bytes
    int num_bits = a.bits();
    int size = (num_bits + 7) / 8; // number of bytes

    // Extract the top 3 bytes as mantissa
    uint32_t mantissa;
    if (size <= 3) {
        mantissa = static_cast<uint32_t>(a.d[0]) << (8 * (3 - size));
    } else {
        // Shift right to get top 3 bytes
        int shift_bits = 8 * (size - 3);
        int word_shift = shift_bits / 64;
        int bit_shift = shift_bits % 64;

        // Extract the value at the shifted position
        uint64_t val = 0;
        if (word_shift < 4) {
            val = a.d[word_shift] >> bit_shift;
            if (bit_shift > 0 && word_shift + 1 < 4) {
                val |= a.d[word_shift + 1] << (64 - bit_shift);
            }
        }
        mantissa = static_cast<uint32_t>(val) & 0xFFFFFF;
    }

    // If the sign bit (bit 23) is set, shift right one more byte
    if (mantissa & 0x800000) {
        mantissa >>= 8;
        size++;
    }

    return (static_cast<uint32_t>(size) << 24) | (mantissa & 0x7FFFFF);
}

// ─── Difficulty retarget ──────────────────────────────────────
//
// Identical to Bitcoin Core's CalculateNextWorkRequired.
// new_target = old_target * actual_timespan / target_timespan
//
// Clamped: actual_timespan ∈ [target/4, target*4]
// This ensures 10-minute blocks regardless of network training power.

uint32_t calculate_next_work(uint32_t parent_nbits, int64_t actual_timespan) {
    const int64_t target_timespan = RETARGET_TIMESPAN; // 1,209,600 seconds (2 weeks)

    // Clamp to [timespan/4, timespan*4]
    if (actual_timespan < target_timespan / MAX_RETARGET_FACTOR) {
        actual_timespan = target_timespan / MAX_RETARGET_FACTOR;
    }
    if (actual_timespan > target_timespan * MAX_RETARGET_FACTOR) {
        actual_timespan = target_timespan * MAX_RETARGET_FACTOR;
    }

    // new_target = old_target * actual_timespan / target_timespan
    arith_uint256 target = arith_uint256::from_uint256(nbits_to_target(parent_nbits));
    target *= static_cast<uint64_t>(actual_timespan);
    target /= static_cast<uint64_t>(target_timespan);

    return target_to_nbits(target.to_uint256());
}

// ─── Target comparison ────────────────────────────────────────
//
// Block is valid iff hash <= target.
// Both are 256-bit unsigned integers in little-endian byte order.

bool meets_target(const Hash256& hash, uint32_t nbits) {
    arith_uint256 h = arith_uint256::from_uint256(hash);
    arith_uint256 t = arith_uint256::from_uint256(nbits_to_target(nbits));
    return h <= t;
}

} // namespace flow::consensus

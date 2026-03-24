// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// 256-bit unsigned integer arithmetic for difficulty target calculations.
// Modeled after Bitcoin Core's arith_uint256.
//
// Internal storage: array of uint32_t[8], little-endian (limb 0 is least
// significant). All arithmetic, bitwise, and comparison operations are
// implemented for full 256-bit by 256-bit computation.

#pragma once

#include "types.h"

#include <cstdint>
#include <string>

namespace flow {

class arith_uint256 {
public:
    static constexpr int WIDTH = 8;  //!< Number of 32-bit limbs

    uint32_t pn[WIDTH]{};  //!< Little-endian limbs: pn[0] = least significant

    // --- Constructors ---

    arith_uint256() = default;

    explicit arith_uint256(uint64_t v) {
        pn[0] = static_cast<uint32_t>(v);
        pn[1] = static_cast<uint32_t>(v >> 32);
    }

    // --- Compact target encoding (Bitcoin nBits format) ---

    /** Decode compact "nBits" representation into this 256-bit value.
     *  @param nCompact  The compact encoding.
     *  @param pfNegative  If non-null, set to true if the sign bit was set.
     *  @param pfOverflow  If non-null, set to true if the value overflows 256 bits.
     *  @return Reference to this object.
     */
    arith_uint256& SetCompact(uint32_t nCompact, bool* pfNegative = nullptr,
                              bool* pfOverflow = nullptr);

    /** Encode this 256-bit value into the compact nBits representation.
     *  @param fNegative  If true, sets the sign bit.
     *  @return The compact encoding.
     */
    uint32_t GetCompact(bool fNegative = false) const;

    // --- Arithmetic operators ---

    arith_uint256& operator+=(const arith_uint256& b);
    arith_uint256& operator-=(const arith_uint256& b);
    arith_uint256& operator*=(const arith_uint256& b);
    arith_uint256& operator/=(const arith_uint256& b);
    arith_uint256& operator%=(const arith_uint256& b);

    arith_uint256& operator*=(uint32_t b32);
    arith_uint256& operator/=(uint32_t b32);

    arith_uint256 operator+(const arith_uint256& b) const { arith_uint256 r(*this); return r += b; }
    arith_uint256 operator-(const arith_uint256& b) const { arith_uint256 r(*this); return r -= b; }
    arith_uint256 operator*(const arith_uint256& b) const { arith_uint256 r(*this); return r *= b; }
    arith_uint256 operator/(const arith_uint256& b) const { arith_uint256 r(*this); return r /= b; }
    arith_uint256 operator%(const arith_uint256& b) const { arith_uint256 r(*this); return r %= b; }

    // --- Increment / Decrement ---

    arith_uint256& operator++();
    arith_uint256 operator++(int) { arith_uint256 r(*this); ++(*this); return r; }
    arith_uint256& operator--();
    arith_uint256 operator--(int) { arith_uint256 r(*this); --(*this); return r; }

    // --- Unary negation (two's complement) ---

    arith_uint256 operator-() const;

    // --- Bit operations ---

    arith_uint256& operator<<=(unsigned int shift);
    arith_uint256& operator>>=(unsigned int shift);

    arith_uint256 operator<<(unsigned int shift) const { arith_uint256 r(*this); return r <<= shift; }
    arith_uint256 operator>>(unsigned int shift) const { arith_uint256 r(*this); return r >>= shift; }

    arith_uint256& operator&=(const arith_uint256& b);
    arith_uint256& operator|=(const arith_uint256& b);
    arith_uint256& operator^=(const arith_uint256& b);

    arith_uint256 operator&(const arith_uint256& b) const { arith_uint256 r(*this); return r &= b; }
    arith_uint256 operator|(const arith_uint256& b) const { arith_uint256 r(*this); return r |= b; }
    arith_uint256 operator^(const arith_uint256& b) const { arith_uint256 r(*this); return r ^= b; }

    arith_uint256 operator~() const;

    // --- Comparison operators ---

    bool operator==(const arith_uint256& b) const;
    bool operator!=(const arith_uint256& b) const;
    bool operator<(const arith_uint256& b) const;
    bool operator<=(const arith_uint256& b) const;
    bool operator>(const arith_uint256& b) const;
    bool operator>=(const arith_uint256& b) const;

    // --- Utility ---

    bool IsNull() const;
    bool IsZero() const { return IsNull(); }
    bool IsNonZero() const { return !IsNull(); }

    /** Return the position of the highest set bit (1-indexed).
     *  Returns 0 if the value is zero. */
    int bits() const;

    /** Return the lowest 64 bits as a uint64_t. */
    uint64_t GetLow64() const;

    /** Set from a big-endian hex string. Leading zeros are significant. */
    void SetHex(const std::string& str);

    /** Return a big-endian hex string (64 characters with leading zeros). */
    std::string GetHex() const;

    std::string ToString() const { return GetHex(); }
};

// ---------------------------------------------------------------------------
// Free-standing conversion functions (matching Bitcoin Core API)
// ---------------------------------------------------------------------------

/** Interpret uint256 hash bytes as a little-endian 256-bit number.
 *  Byte 0 of the hash becomes the least significant byte of the integer.
 */
arith_uint256 UintToArith256(const uint256& hash);

/** Convert arith_uint256 back to a uint256 (little-endian byte layout). */
uint256 ArithToUint256(const arith_uint256& a);

} // namespace flow

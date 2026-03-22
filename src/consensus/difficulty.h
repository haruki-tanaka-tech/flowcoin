// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Difficulty adjustment — identical to Bitcoin.
// Retargets every 2016 blocks: compares actual time vs expected 20160 minutes.
// Bounded by factor of 4 in either direction.
//
// Formula: new_target = old_target * actual_timespan / target_timespan
// Where: target_timespan = 2016 * 600 = 1,209,600 seconds (2 weeks)
//
// This guarantees ~10 minute blocks regardless of total network training power.

#pragma once

#include "core/types.h"
#include <cstdint>

namespace flow::consensus {

// ─── 256-bit unsigned arithmetic for difficulty calculations ─

struct arith_uint256 {
    uint64_t d[4]{}; // little-endian: d[0] = least significant 64 bits

    arith_uint256() = default;

    // Convert from byte array (little-endian Blob)
    static arith_uint256 from_uint256(const uint256& v);

    // Convert back to byte array
    uint256 to_uint256() const;

    // Multiply by 64-bit scalar
    arith_uint256& operator*=(uint64_t rhs);

    // Divide by 64-bit scalar
    arith_uint256& operator/=(uint64_t rhs);

    // Comparison
    bool operator<=(const arith_uint256& rhs) const;
    bool operator>(const arith_uint256& rhs) const;
    bool is_zero() const;

    // Bit count (position of highest set bit + 1)
    int bits() const;
};

// ─── Compact target encoding (nbits) ─────────────────────────
//
// Bitcoin's "compact" format: 0xEEMMMMMM
//   EE = number of bytes in the full target value
//   MMMMMM = top 3 bytes of target (sign bit in bit 23 is always 0 for positive)
//   target = mantissa * 256^(exponent - 3)
//
// Examples:
//   0x1d00ffff → target with 29 significant bytes, top bytes 00ffff
//   0x1b0404cb → Bitcoin block 32256

uint256 nbits_to_target(uint32_t nbits);
uint32_t target_to_nbits(const uint256& target);

// Calculate the next required difficulty.
// Called every RETARGET_INTERVAL (2016) blocks.
//
// actual_timespan = timestamp of block N - timestamp of block (N - 2016)
// Clamped to [target_timespan/4, target_timespan*4]
//
// new_target = old_target * actual_timespan / target_timespan
uint32_t calculate_next_work(uint32_t parent_nbits, int64_t actual_timespan);

// Check if a hash meets the difficulty target: hash <= target
bool meets_target(const Hash256& hash, uint32_t nbits);

} // namespace flow::consensus

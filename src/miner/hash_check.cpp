// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "miner/hash_check.h"
#include "hash/keccak.h"

#include <cstring>

namespace flow::miner {

// =========================================================================
// derive_target: convert compact nBits to a full 256-bit target
// =========================================================================

uint256 derive_target(uint32_t nbits) {
    uint256 target;
    target.set_null();

    uint32_t exponent = nbits >> 24;
    uint32_t mantissa = nbits & 0x007FFFFFu;

    // Negative bit (bit 23 of mantissa) -- if set, target is zero (invalid)
    if (nbits & 0x00800000u) {
        return target;
    }

    if (exponent == 0) {
        return target;
    }

    if (exponent <= 3) {
        mantissa >>= 8 * (3 - exponent);
        target[31] = static_cast<uint8_t>(mantissa & 0xFF);
        if (exponent >= 2) target[30] = static_cast<uint8_t>((mantissa >> 8) & 0xFF);
        if (exponent >= 3) target[29] = static_cast<uint8_t>((mantissa >> 16) & 0xFF);
    } else {
        int byte_offset = 32 - exponent;

        if (byte_offset >= 0 && byte_offset < 32) {
            target[byte_offset] = static_cast<uint8_t>((mantissa >> 16) & 0xFF);
        }
        if (byte_offset + 1 >= 0 && byte_offset + 1 < 32) {
            target[byte_offset + 1] = static_cast<uint8_t>((mantissa >> 8) & 0xFF);
        }
        if (byte_offset + 2 >= 0 && byte_offset + 2 < 32) {
            target[byte_offset + 2] = static_cast<uint8_t>(mantissa & 0xFF);
        }
    }

    return target;
}

// =========================================================================
// meets_target: compare hash against target
// =========================================================================

bool meets_target(const uint256& hash, const uint256& target) {
    return hash <= target;
}

} // namespace flow::miner

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "miner/hash_check.h"
#include "hash/keccak.h"

#include <cstring>
#include <cmath>
#include <vector>

namespace flow::miner {

// =========================================================================
// derive_target: convert compact nBits to a full 256-bit target
// =========================================================================
//
// Compact format (same as Bitcoin):
//   byte 3:   exponent (number of bytes in the target)
//   bytes 0-2: mantissa (3 most significant bytes)
//   target = mantissa * 2^(8 * (exponent - 3))

uint256 derive_target(uint32_t nbits) {
    uint256 target;
    target.set_null();

    uint32_t exponent = nbits >> 24;
    uint32_t mantissa = nbits & 0x007FFFFFu;

    // Negative bit (bit 23 of mantissa) — if set, target is zero (invalid)
    if (nbits & 0x00800000u) {
        return target;
    }

    if (exponent == 0) {
        // Target is zero
        return target;
    }

    if (exponent <= 3) {
        // Mantissa fits within 3 bytes, shift right
        mantissa >>= 8 * (3 - exponent);
        // Store in big-endian format (byte 0 is most significant)
        target[31] = static_cast<uint8_t>(mantissa & 0xFF);
        if (exponent >= 2) target[30] = static_cast<uint8_t>((mantissa >> 8) & 0xFF);
        if (exponent >= 3) target[29] = static_cast<uint8_t>((mantissa >> 16) & 0xFF);
    } else {
        // Place mantissa bytes at the correct position
        // In our uint256, byte 0 is the most significant (big-endian)
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
// meets_target: compare hash against target (big-endian, byte 0 = MSB)
// =========================================================================

bool meets_target(const uint256& hash, const uint256& target) {
    // Compare big-endian: byte 0 is most significant
    return hash <= target;
}

// =========================================================================
// compute_mining_hash: derive a hash from training metrics
// =========================================================================
//
// Each training step changes loss, step count, and gradient norm,
// producing a unique hash. No extra GPU work required.
//
// Hash = Keccak256(loss_bytes || step_bytes || grad_norm_bytes || dataset_hash)

uint256 compute_mining_hash(float loss, uint64_t step,
                            float grad_norm, const uint256& dataset_hash) {
    // Build preimage: 4 + 8 + 4 + 32 = 48 bytes
    uint8_t preimage[48];

    uint32_t loss_bits;
    std::memcpy(&loss_bits, &loss, sizeof(loss_bits));
    preimage[0] = static_cast<uint8_t>((loss_bits >> 24) & 0xFF);
    preimage[1] = static_cast<uint8_t>((loss_bits >> 16) & 0xFF);
    preimage[2] = static_cast<uint8_t>((loss_bits >> 8) & 0xFF);
    preimage[3] = static_cast<uint8_t>(loss_bits & 0xFF);

    preimage[4]  = static_cast<uint8_t>((step >> 56) & 0xFF);
    preimage[5]  = static_cast<uint8_t>((step >> 48) & 0xFF);
    preimage[6]  = static_cast<uint8_t>((step >> 40) & 0xFF);
    preimage[7]  = static_cast<uint8_t>((step >> 32) & 0xFF);
    preimage[8]  = static_cast<uint8_t>((step >> 24) & 0xFF);
    preimage[9]  = static_cast<uint8_t>((step >> 16) & 0xFF);
    preimage[10] = static_cast<uint8_t>((step >> 8) & 0xFF);
    preimage[11] = static_cast<uint8_t>(step & 0xFF);

    uint32_t gnorm_bits;
    std::memcpy(&gnorm_bits, &grad_norm, sizeof(gnorm_bits));
    preimage[12] = static_cast<uint8_t>((gnorm_bits >> 24) & 0xFF);
    preimage[13] = static_cast<uint8_t>((gnorm_bits >> 16) & 0xFF);
    preimage[14] = static_cast<uint8_t>((gnorm_bits >> 8) & 0xFF);
    preimage[15] = static_cast<uint8_t>(gnorm_bits & 0xFF);

    std::memcpy(preimage + 16, dataset_hash.data(), 32);

    return flow::keccak256(preimage, sizeof(preimage));
}

// =========================================================================
// compute_delta_hash: hash the weight delta for block submission
// =========================================================================

uint256 compute_delta_hash(const float* delta, size_t count) {
    if (count == 0 || delta == nullptr) {
        return flow::keccak256(nullptr, 0);
    }
    return flow::keccak256(reinterpret_cast<const uint8_t*>(delta),
                           count * sizeof(float));
}

} // namespace flow::miner

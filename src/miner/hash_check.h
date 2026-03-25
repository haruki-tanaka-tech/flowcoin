// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Hash computation and target checking for the standalone miner.
// Converts nBits to 256-bit target and checks mining hashes.

#pragma once

#include "util/types.h"
#include <cstdint>
#include <cstddef>

namespace flow::miner {

// Derive 256-bit target from compact nBits encoding.
// Uses Bitcoin-compatible compact format.
uint256 derive_target(uint32_t nbits);

// Check if hash meets target (hash <= target, big-endian comparison).
bool meets_target(const uint256& hash, const uint256& target);

// Compute mining hash from training metrics.
// This is the "nonce" equivalent — each training step produces a unique
// hash with zero extra GPU overhead.
uint256 compute_mining_hash(float loss, uint64_t step,
                            float grad_norm, const uint256& dataset_hash);

// Compute full delta hash for block submission.
// Only called when a mining hash passes the target check.
uint256 compute_delta_hash(const float* delta, size_t count);

} // namespace flow::miner

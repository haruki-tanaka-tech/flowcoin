// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Hash computation and target checking for the standalone miner.
// Converts nBits to 256-bit target and checks PoW hashes.

#pragma once

#include "util/types.h"
#include <cstdint>
#include <cstddef>

namespace flow::miner {

// Derive 256-bit target from compact nBits encoding.
uint256 derive_target(uint32_t nbits);

// Check if hash meets target (hash <= target).
bool meets_target(const uint256& hash, const uint256& target);

} // namespace flow::miner

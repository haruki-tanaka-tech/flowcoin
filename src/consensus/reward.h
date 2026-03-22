// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#pragma once

#include "core/types.h"
#include <cstdint>

namespace flow::consensus {

// Get block subsidy (reward) at a given height.
// Starts at 50 FLOW, halves every 210,000 blocks.
// Returns 0 when all rewards are exhausted.
Amount get_block_subsidy(uint64_t height);

} // namespace flow::consensus

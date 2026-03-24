// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Cryptographically secure random number generation for FlowCoin.
// Uses /dev/urandom on Linux for entropy.

#pragma once

#include "types.h"

#include <cstddef>
#include <cstdint>

namespace flow {

/** Fill a buffer with cryptographically secure random bytes.
 *  Reads from /dev/urandom. Aborts the process if /dev/urandom
 *  is unavailable or a read fails.
 */
void GetRandBytes(uint8_t* buf, size_t len);

/** Return a cryptographically secure random 64-bit unsigned integer. */
uint64_t GetRandUint64();

/** Return a cryptographically secure random uint256. */
uint256 GetRandUint256();

} // namespace flow

// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>

namespace flow {

// Returns current unix timestamp in seconds.
// Uses a mockable offset for testing.
int64_t get_time();

// Returns current time in microseconds.
int64_t get_time_micros();

// Offset for testing: get_time() returns real_time + offset
void set_time_offset(int64_t offset_seconds);
int64_t get_time_offset();

} // namespace flow

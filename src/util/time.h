// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// System time utilities for FlowCoin.
// Provides wall-clock and monotonic time access with an adjustable
// offset for deterministic testing.

#pragma once

#include <cstdint>
#include <string>

namespace flow {

// ---------------------------------------------------------------------------
// Wall-clock time (system clock, includes mockable offset)
// ---------------------------------------------------------------------------

/** Return the current Unix timestamp in seconds. */
int64_t GetTime();

/** Return the current time in milliseconds since epoch. */
int64_t GetTimeMillis();

/** Return the current time in microseconds since epoch. */
int64_t GetTimeMicros();

// ---------------------------------------------------------------------------
// Monotonic clock (for measuring intervals, not affected by NTP adjustments)
// ---------------------------------------------------------------------------

/** Return monotonic time in microseconds (suitable for measuring durations).
 *  The epoch is arbitrary; only differences between values are meaningful.
 */
int64_t GetMonotonicMicros();

// ---------------------------------------------------------------------------
// Time formatting
// ---------------------------------------------------------------------------

/** Format a Unix timestamp as "YYYY-MM-DD HH:MM:SS" in UTC. */
std::string DateTimeStrFormat(int64_t timestamp);

// ---------------------------------------------------------------------------
// Time offset for testing
// ---------------------------------------------------------------------------

/** Set a global time offset in seconds.
 *  All subsequent calls to GetTime(), GetTimeMillis(), and GetTimeMicros()
 *  will return (real_time + offset). Set to 0 to disable.
 */
void SetTimeOffset(int64_t offset_seconds);

/** Get the current time offset in seconds. */
int64_t GetTimeOffset();

} // namespace flow

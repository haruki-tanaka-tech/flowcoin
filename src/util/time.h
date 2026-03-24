// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// System time utilities for FlowCoin.
// Provides wall-clock and monotonic time access with an adjustable
// offset for deterministic testing, plus network-adjusted time tracking.

#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace flow {

// ===========================================================================
// Wall-clock time (system clock, includes mockable offset)
// ===========================================================================

/** Return the current Unix timestamp in seconds. */
int64_t GetTime();

/** Return the current time in milliseconds since epoch. */
int64_t GetTimeMillis();

/** Return the current time in microseconds since epoch. */
int64_t GetTimeMicros();

// ===========================================================================
// Monotonic clock (for measuring intervals, not affected by NTP adjustments)
// ===========================================================================

/** Return monotonic time in microseconds (suitable for measuring durations).
 *  The epoch is arbitrary; only differences between values are meaningful.
 */
int64_t GetMonotonicMicros();

// ===========================================================================
// Time formatting and parsing
// ===========================================================================

/** Format a Unix timestamp as "YYYY-MM-DD HH:MM:SS" in UTC. */
std::string DateTimeStrFormat(int64_t timestamp);

/** Format a Unix timestamp as ISO 8601: "YYYY-MM-DDTHH:MM:SSZ". */
std::string FormatISO8601DateTime(int64_t timestamp);

/** Parse an ISO 8601 datetime string into a Unix timestamp.
 *  Accepts "YYYY-MM-DDTHH:MM:SSZ" format.
 *  @return Parsed timestamp, or 0 on parse failure.
 */
int64_t ParseISO8601DateTime(const std::string& str);

/** Format a duration in seconds as human-readable "Xd Yh Zm Ws". */
std::string FormatDuration(int64_t seconds);

/** Format a timestamp as "YYYY-MM-DD" (date only). */
std::string FormatDate(int64_t timestamp);

// ===========================================================================
// Time offset for testing
// ===========================================================================

/** Set a global time offset in seconds.
 *  All subsequent calls to GetTime(), GetTimeMillis(), and GetTimeMicros()
 *  will return (real_time + offset). Set to 0 to disable.
 */
void SetTimeOffset(int64_t offset_seconds);

/** Get the current time offset in seconds. */
int64_t GetTimeOffset();

// ===========================================================================
// Mock time (for deterministic testing)
// ===========================================================================

/** Set a mock time. When set to a non-zero value, GetTime() and related
 *  functions return this value instead of the real system time.
 *  Set to 0 to resume using real system time.
 */
void SetMockTime(int64_t mock_time);

/** Get the current mock time. Returns 0 if mock time is not active. */
int64_t GetMockTime();

// ===========================================================================
// Median Time Past (MTP) -- consensus time for block validation
// ===========================================================================
// Bitcoin uses the Median Time Past (median of the last 11 blocks'
// timestamps) for time-based validation checks. This prevents miners
// from manipulating the effective time by setting their timestamp too
// far in the future.

/// Number of previous blocks used for median time past calculation.
static constexpr int MEDIAN_TIME_SPAN = 11;

/** Compute the Median Time Past from a list of the most recent block timestamps.
 *  @param timestamps  Vector of timestamps (most recent first). Should have
 *                     at most MEDIAN_TIME_SPAN entries.
 *  @return The median timestamp. Returns 0 if the vector is empty.
 */
int64_t ComputeMedianTimePast(const std::vector<int64_t>& timestamps);

// ===========================================================================
// Network-Adjusted Time
// ===========================================================================
// Tracks time offsets reported by peers and computes a network-adjusted time.
// This prevents a node with an inaccurate local clock from rejecting valid
// blocks or accepting invalid ones.

class TimeData {
public:
    /** Get the singleton instance. */
    static TimeData& instance();

    /** Add a time offset sample from a peer.
     *  @param offset  Difference between peer's reported time and our local time
     *                 (peer_time - local_time), in seconds.
     */
    void add_time_sample(int64_t offset);

    /** Get the network-adjusted time offset.
     *  Returns the median of all collected peer offsets, clamped to a
     *  reasonable range (-70 minutes to +70 minutes).
     *  Returns 0 if fewer than 5 samples have been collected.
     */
    int64_t get_adjusted_offset() const;

    /** Get the network-adjusted current time.
     *  Returns GetTime() + get_adjusted_offset().
     */
    int64_t get_adjusted_time() const;

    /** Get the number of peer time samples collected. */
    size_t get_sample_count() const;

    /** Clear all time samples (for testing). */
    void clear();

    /// Maximum offset we'll accept from the network median (70 minutes).
    static constexpr int64_t MAX_ADJUSTED_OFFSET = 70 * 60;

    /// Minimum number of samples before we use the adjusted offset.
    static constexpr size_t MIN_SAMPLES = 5;

    /// Maximum number of samples to store.
    static constexpr size_t MAX_SAMPLES = 200;

private:
    TimeData() = default;

    mutable std::mutex mutex_;
    std::vector<int64_t> offsets_;  //!< Collected peer time offsets
    int64_t cached_offset_ = 0;    //!< Cached median offset
    bool offset_valid_ = false;    //!< Whether cached_offset_ is valid

    /** Recompute the median offset from all samples. */
    void recompute_offset();
};

/** Get the network-adjusted current time (convenience function). */
int64_t GetAdjustedTime();

// ===========================================================================
// Timer -- simple RAII stopwatch for benchmarking
// ===========================================================================

class Timer {
public:
    /// Start the timer.
    Timer();

    /// Get elapsed time in microseconds since construction or last reset.
    int64_t elapsed_micros() const;

    /// Get elapsed time in milliseconds.
    int64_t elapsed_millis() const;

    /// Get elapsed time in seconds (as double for sub-second precision).
    double elapsed_seconds() const;

    /// Reset the timer to zero.
    void reset();

private:
    int64_t start_;  //!< Monotonic start time in microseconds
};

} // namespace flow

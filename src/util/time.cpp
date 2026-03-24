// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// System time implementation.

#include "time.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <ctime>

namespace flow {

/** Global time offset for testing. Atomic for thread safety. */
static std::atomic<int64_t> g_time_offset{0};

// ---------------------------------------------------------------------------
// Wall-clock time
// ---------------------------------------------------------------------------

int64_t GetTime() {
    auto now = std::chrono::system_clock::now();
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    return secs + g_time_offset.load(std::memory_order_relaxed);
}

int64_t GetTimeMillis() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    return ms + g_time_offset.load(std::memory_order_relaxed) * 1'000;
}

int64_t GetTimeMicros() {
    auto now = std::chrono::system_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
    return us + g_time_offset.load(std::memory_order_relaxed) * 1'000'000;
}

// ---------------------------------------------------------------------------
// Monotonic clock
// ---------------------------------------------------------------------------

int64_t GetMonotonicMicros() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
}

// ---------------------------------------------------------------------------
// Time formatting
// ---------------------------------------------------------------------------

std::string DateTimeStrFormat(int64_t timestamp) {
    std::time_t t = static_cast<std::time_t>(timestamp);
    std::tm utc{};
    gmtime_r(&t, &utc);

    char buf[64];  // "YYYY-MM-DD HH:MM:SS" = 19 chars + null (extra space for safety)
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
                  utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
                  utc.tm_hour, utc.tm_min, utc.tm_sec);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// Time offset
// ---------------------------------------------------------------------------

void SetTimeOffset(int64_t offset_seconds) {
    g_time_offset.store(offset_seconds, std::memory_order_relaxed);
}

int64_t GetTimeOffset() {
    return g_time_offset.load(std::memory_order_relaxed);
}

} // namespace flow

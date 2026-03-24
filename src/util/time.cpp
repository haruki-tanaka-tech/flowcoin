// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "time.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <sstream>

namespace flow {

// ===========================================================================
// Global state
// ===========================================================================

/** Global time offset for testing. Atomic for thread safety. */
static std::atomic<int64_t> g_time_offset{0};

/** Mock time: when non-zero, GetTime() returns this fixed value. */
static std::atomic<int64_t> g_mock_time{0};

// ===========================================================================
// Wall-clock time
// ===========================================================================

int64_t GetTime() {
    int64_t mock = g_mock_time.load(std::memory_order_relaxed);
    if (mock != 0) return mock;

    auto now = std::chrono::system_clock::now();
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    return secs + g_time_offset.load(std::memory_order_relaxed);
}

int64_t GetTimeMillis() {
    int64_t mock = g_mock_time.load(std::memory_order_relaxed);
    if (mock != 0) return mock * 1000;

    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    return ms + g_time_offset.load(std::memory_order_relaxed) * 1'000;
}

int64_t GetTimeMicros() {
    int64_t mock = g_mock_time.load(std::memory_order_relaxed);
    if (mock != 0) return mock * 1'000'000;

    auto now = std::chrono::system_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
    return us + g_time_offset.load(std::memory_order_relaxed) * 1'000'000;
}

// ===========================================================================
// Monotonic clock
// ===========================================================================

int64_t GetMonotonicMicros() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
}

// ===========================================================================
// Time formatting and parsing
// ===========================================================================

std::string DateTimeStrFormat(int64_t timestamp) {
    std::time_t t = static_cast<std::time_t>(timestamp);
    std::tm utc{};
    gmtime_r(&t, &utc);

    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
                  utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
                  utc.tm_hour, utc.tm_min, utc.tm_sec);
    return std::string(buf);
}

std::string FormatISO8601DateTime(int64_t timestamp) {
    std::time_t t = static_cast<std::time_t>(timestamp);
    std::tm utc{};
    gmtime_r(&t, &utc);

    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
                  utc.tm_hour, utc.tm_min, utc.tm_sec);
    return std::string(buf);
}

int64_t ParseISO8601DateTime(const std::string& str) {
    // Parse "YYYY-MM-DDTHH:MM:SSZ"
    if (str.size() < 19) return 0;

    int year, month, day, hour, minute, second;
    if (std::sscanf(str.c_str(), "%d-%d-%dT%d:%d:%d",
                    &year, &month, &day, &hour, &minute, &second) != 6) {
        return 0;
    }

    // Basic validation
    if (year < 1970 || year > 2100) return 0;
    if (month < 1 || month > 12) return 0;
    if (day < 1 || day > 31) return 0;
    if (hour < 0 || hour > 23) return 0;
    if (minute < 0 || minute > 59) return 0;
    if (second < 0 || second > 60) return 0;  // allow leap second

    std::tm utc{};
    utc.tm_year = year - 1900;
    utc.tm_mon = month - 1;
    utc.tm_mday = day;
    utc.tm_hour = hour;
    utc.tm_min = minute;
    utc.tm_sec = second;

    // timegm converts struct tm (UTC) to time_t
    return static_cast<int64_t>(timegm(&utc));
}

std::string FormatDuration(int64_t seconds) {
    bool negative = false;
    if (seconds < 0) {
        negative = true;
        seconds = -seconds;
    }

    int64_t days = seconds / 86400;
    seconds %= 86400;
    int64_t hours = seconds / 3600;
    seconds %= 3600;
    int64_t minutes = seconds / 60;
    seconds %= 60;

    std::ostringstream ss;
    if (negative) ss << "-";
    if (days > 0) ss << days << "d ";
    if (hours > 0 || days > 0) ss << hours << "h ";
    if (minutes > 0 || hours > 0 || days > 0) ss << minutes << "m ";
    ss << seconds << "s";
    return ss.str();
}

std::string FormatDate(int64_t timestamp) {
    std::time_t t = static_cast<std::time_t>(timestamp);
    std::tm utc{};
    gmtime_r(&t, &utc);

    char buf[16];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d",
                  utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday);
    return std::string(buf);
}

// ===========================================================================
// Time offset
// ===========================================================================

void SetTimeOffset(int64_t offset_seconds) {
    g_time_offset.store(offset_seconds, std::memory_order_relaxed);
}

int64_t GetTimeOffset() {
    return g_time_offset.load(std::memory_order_relaxed);
}

// ===========================================================================
// Mock time
// ===========================================================================

void SetMockTime(int64_t mock_time) {
    g_mock_time.store(mock_time, std::memory_order_relaxed);
}

int64_t GetMockTime() {
    return g_mock_time.load(std::memory_order_relaxed);
}

// ===========================================================================
// Median Time Past
// ===========================================================================

int64_t ComputeMedianTimePast(const std::vector<int64_t>& timestamps) {
    if (timestamps.empty()) return 0;

    // Take at most MEDIAN_TIME_SPAN entries
    size_t n = std::min(timestamps.size(), static_cast<size_t>(MEDIAN_TIME_SPAN));

    // Copy and sort
    std::vector<int64_t> sorted(timestamps.begin(), timestamps.begin() + n);
    std::sort(sorted.begin(), sorted.end());

    // Return the median
    return sorted[n / 2];
}

// ===========================================================================
// TimeData -- network-adjusted time
// ===========================================================================

TimeData& TimeData::instance() {
    static TimeData data;
    return data;
}

void TimeData::add_time_sample(int64_t offset) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Cap the stored samples
    if (offsets_.size() >= MAX_SAMPLES) {
        // Remove oldest sample
        offsets_.erase(offsets_.begin());
    }

    offsets_.push_back(offset);
    offset_valid_ = false;  // Invalidate cache
}

void TimeData::recompute_offset() {
    if (offsets_.size() < MIN_SAMPLES) {
        cached_offset_ = 0;
        offset_valid_ = true;
        return;
    }

    // Compute median of all offsets
    std::vector<int64_t> sorted = offsets_;
    std::sort(sorted.begin(), sorted.end());

    int64_t median = sorted[sorted.size() / 2];

    // Clamp to reasonable range
    if (median > MAX_ADJUSTED_OFFSET) {
        median = MAX_ADJUSTED_OFFSET;
    } else if (median < -MAX_ADJUSTED_OFFSET) {
        median = -MAX_ADJUSTED_OFFSET;
    }

    cached_offset_ = median;
    offset_valid_ = true;
}

int64_t TimeData::get_adjusted_offset() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!offset_valid_) {
        // const_cast is safe here: we're just caching a derived value
        const_cast<TimeData*>(this)->recompute_offset();
    }

    return cached_offset_;
}

int64_t TimeData::get_adjusted_time() const {
    return GetTime() + get_adjusted_offset();
}

size_t TimeData::get_sample_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return offsets_.size();
}

void TimeData::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    offsets_.clear();
    cached_offset_ = 0;
    offset_valid_ = false;
}

int64_t GetAdjustedTime() {
    return TimeData::instance().get_adjusted_time();
}

// ===========================================================================
// Timer
// ===========================================================================

Timer::Timer() {
    start_ = GetMonotonicMicros();
}

int64_t Timer::elapsed_micros() const {
    return GetMonotonicMicros() - start_;
}

int64_t Timer::elapsed_millis() const {
    return elapsed_micros() / 1000;
}

double Timer::elapsed_seconds() const {
    return static_cast<double>(elapsed_micros()) / 1'000'000.0;
}

void Timer::reset() {
    start_ = GetMonotonicMicros();
}

} // namespace flow

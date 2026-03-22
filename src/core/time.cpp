// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "time.h"

namespace flow {

static std::atomic<int64_t> g_time_offset{0};

int64_t get_time() {
    auto now = std::chrono::system_clock::now();
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    return secs + g_time_offset.load(std::memory_order_relaxed);
}

int64_t get_time_micros() {
    auto now = std::chrono::system_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
    return us + g_time_offset.load(std::memory_order_relaxed) * 1'000'000;
}

void set_time_offset(int64_t offset_seconds) {
    g_time_offset.store(offset_seconds, std::memory_order_relaxed);
}

int64_t get_time_offset() {
    return g_time_offset.load(std::memory_order_relaxed);
}

} // namespace flow

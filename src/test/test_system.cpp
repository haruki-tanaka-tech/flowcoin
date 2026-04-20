// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for system time utilities and related functions.

#include "util/time.h"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

void test_system() {
    // -----------------------------------------------------------------------
    // Test 1: GetTime returns reasonable value (after 2025-01-01)
    // -----------------------------------------------------------------------
    {
        int64_t now = flow::GetTime();
        // Unix timestamp for 2025-01-01: 1735689600
        assert(now > 1735689600);
        // And before some far-future date (2100-01-01): 4102444800
        assert(now < 4102444800LL);
    }

    // -----------------------------------------------------------------------
    // Test 2: GetTimeMillis returns reasonable value
    // -----------------------------------------------------------------------
    {
        int64_t ms = flow::GetTimeMillis();
        // Should be roughly GetTime() * 1000
        int64_t now = flow::GetTime();
        assert(ms >= now * 1000 - 2000);  // within 2 seconds
        assert(ms <= now * 1000 + 2000);
    }

    // -----------------------------------------------------------------------
    // Test 3: GetTimeMicros returns reasonable value
    // -----------------------------------------------------------------------
    {
        int64_t us = flow::GetTimeMicros();
        int64_t now = flow::GetTime();
        assert(us >= now * 1000000LL - 2000000LL);
        assert(us <= now * 1000000LL + 2000000LL);
    }

    // -----------------------------------------------------------------------
    // Test 4: GetMonotonicMicros is monotonically increasing
    // -----------------------------------------------------------------------
    {
        int64_t prev = flow::GetMonotonicMicros();
        for (int i = 0; i < 100; i++) {
            int64_t curr = flow::GetMonotonicMicros();
            assert(curr >= prev);
            prev = curr;
        }
    }

    // -----------------------------------------------------------------------
    // Test 5: GetMonotonicMicros advances over time
    // -----------------------------------------------------------------------
    {
        int64_t before = flow::GetMonotonicMicros();
        // Do some work to burn a microsecond or two
        volatile int x = 0;
        for (int i = 0; i < 100000; i++) {
            x += i;
        }
        int64_t after = flow::GetMonotonicMicros();
        assert(after >= before);
    }

    // -----------------------------------------------------------------------
    // Test 6: DateTimeStrFormat produces correct string for known timestamp
    // -----------------------------------------------------------------------
    {
        // Unix timestamp 0 = 1970-01-01 00:00:00 UTC
        std::string s = flow::DateTimeStrFormat(0);
        assert(s == "1970-01-01 00:00:00");
    }

    // -----------------------------------------------------------------------
    // Test 7: DateTimeStrFormat for a known date
    // -----------------------------------------------------------------------
    {
        // 2026-03-21 00:00:00 UTC = 1742515200
        std::string s = flow::DateTimeStrFormat(1742515200);
        assert(s == "2026-03-21 00:00:00");
    }

    // -----------------------------------------------------------------------
    // Test 8: DateTimeStrFormat format is YYYY-MM-DD HH:MM:SS
    // -----------------------------------------------------------------------
    {
        // 2000-06-15 12:30:45 UTC = 961068645
        std::string s = flow::DateTimeStrFormat(961068645);
        assert(s == "2000-06-15 12:30:45");
    }

    // -----------------------------------------------------------------------
    // Test 9: SetTimeOffset / GetTimeOffset round-trip
    // -----------------------------------------------------------------------
    {
        // Save and restore original offset
        int64_t original = flow::GetTimeOffset();

        flow::SetTimeOffset(3600);
        assert(flow::GetTimeOffset() == 3600);

        flow::SetTimeOffset(-3600);
        assert(flow::GetTimeOffset() == -3600);

        flow::SetTimeOffset(0);
        assert(flow::GetTimeOffset() == 0);

        // Restore
        flow::SetTimeOffset(original);
    }

    // -----------------------------------------------------------------------
    // Test 10: SetTimeOffset affects GetTime
    // -----------------------------------------------------------------------
    {
        int64_t original = flow::GetTimeOffset();
        int64_t before = flow::GetTime();

        flow::SetTimeOffset(100);
        int64_t after = flow::GetTime();

        // After should be approximately before + 100
        int64_t diff = after - before;
        assert(diff >= 98 && diff <= 102);

        // Restore
        flow::SetTimeOffset(original);
    }

    // -----------------------------------------------------------------------
    // Test 11: SetTimeOffset affects GetTimeMillis
    // -----------------------------------------------------------------------
    {
        int64_t original = flow::GetTimeOffset();
        int64_t before = flow::GetTimeMillis();

        flow::SetTimeOffset(10);
        int64_t after = flow::GetTimeMillis();

        int64_t diff_ms = after - before;
        // Should be approximately 10000 ms (10 seconds offset)
        assert(diff_ms >= 9900 && diff_ms <= 10100);

        flow::SetTimeOffset(original);
    }

    // -----------------------------------------------------------------------
    // Test 12: GetTime, GetTimeMillis, GetTimeMicros are consistent
    // -----------------------------------------------------------------------
    {
        int64_t original = flow::GetTimeOffset();
        flow::SetTimeOffset(0);

        int64_t t_sec = flow::GetTime();
        int64_t t_ms = flow::GetTimeMillis();
        int64_t t_us = flow::GetTimeMicros();

        // ms should be approximately sec * 1000
        assert(t_ms / 1000 >= t_sec - 1);
        assert(t_ms / 1000 <= t_sec + 1);

        // us should be approximately sec * 1000000
        assert(t_us / 1000000LL >= t_sec - 1);
        assert(t_us / 1000000LL <= t_sec + 1);

        flow::SetTimeOffset(original);
    }

    // -----------------------------------------------------------------------
    // Test 13: DateTimeStrFormat handles midnight correctly
    // -----------------------------------------------------------------------
    {
        // 2024-01-01 00:00:00 UTC = 1704067200
        std::string s = flow::DateTimeStrFormat(1704067200);
        assert(s == "2024-01-01 00:00:00");
    }

    // -----------------------------------------------------------------------
    // Test 14: DateTimeStrFormat handles end of day
    // -----------------------------------------------------------------------
    {
        // 2024-01-01 23:59:59 UTC = 1704067200 + 86399 = 1704153599
        std::string s = flow::DateTimeStrFormat(1704153599);
        assert(s == "2024-01-01 23:59:59");
    }

    // -----------------------------------------------------------------------
    // Test 15: DateTimeStrFormat output length is always 19 chars
    // -----------------------------------------------------------------------
    {
        // "YYYY-MM-DD HH:MM:SS" = 19 characters
        std::string s = flow::DateTimeStrFormat(0);
        assert(s.length() == 19);

        s = flow::DateTimeStrFormat(1742515200);
        assert(s.length() == 19);
    }

    // -----------------------------------------------------------------------
    // Test 16: SetTimeOffset with large values
    // -----------------------------------------------------------------------
    {
        int64_t original = flow::GetTimeOffset();

        // Set offset to 1 year in the future
        flow::SetTimeOffset(365 * 24 * 3600);
        int64_t offset = flow::GetTimeOffset();
        assert(offset == 365 * 24 * 3600);

        // Verify time shifted
        int64_t shifted = flow::GetTime();
        flow::SetTimeOffset(0);
        int64_t normal = flow::GetTime();

        int64_t diff = shifted - normal;
        // Should be approximately 365 days
        assert(diff > 360 * 24 * 3600);
        assert(diff < 370 * 24 * 3600);

        flow::SetTimeOffset(original);
    }

    // -----------------------------------------------------------------------
    // Test 17: Negative time offset
    // -----------------------------------------------------------------------
    {
        int64_t original = flow::GetTimeOffset();
        int64_t before = flow::GetTime();

        flow::SetTimeOffset(-3600);
        int64_t after = flow::GetTime();

        // After should be approximately before - 3600
        int64_t diff = before - after;
        assert(diff >= 3598 && diff <= 3602);

        flow::SetTimeOffset(original);
    }

    // -----------------------------------------------------------------------
    // Test 18: GetTimeMicros precision
    // -----------------------------------------------------------------------
    {
        // Two rapid calls should differ by a small amount
        int64_t t1 = flow::GetTimeMicros();
        int64_t t2 = flow::GetTimeMicros();
        int64_t diff = t2 - t1;

        // Should be within 1 second
        assert(diff >= 0);
        assert(diff < 1000000);
    }

    // -----------------------------------------------------------------------
    // Test 19: GetMonotonicMicros is not affected by time offset
    // -----------------------------------------------------------------------
    {
        int64_t original = flow::GetTimeOffset();
        int64_t mono1 = flow::GetMonotonicMicros();

        flow::SetTimeOffset(1000);
        int64_t mono2 = flow::GetMonotonicMicros();

        // Monotonic time should advance normally regardless of offset
        assert(mono2 >= mono1);
        // The difference should be small (no 1000-second jump)
        assert(mono2 - mono1 < 5000000);  // less than 5 seconds

        flow::SetTimeOffset(original);
    }

    // -----------------------------------------------------------------------
    // Test 20: DateTimeStrFormat with leap year dates
    // -----------------------------------------------------------------------
    {
        // 2024-02-29 00:00:00 UTC = 1709164800
        std::string s = flow::DateTimeStrFormat(1709164800);
        assert(s == "2024-02-29 00:00:00");
    }

    // -----------------------------------------------------------------------
    // Test 21: DateTimeStrFormat with epoch boundaries
    // -----------------------------------------------------------------------
    {
        // 1 second after epoch
        std::string s = flow::DateTimeStrFormat(1);
        assert(s == "1970-01-01 00:00:01");
    }

    // -----------------------------------------------------------------------
    // Test 22: Multiple SetTimeOffset calls are independent
    // -----------------------------------------------------------------------
    {
        int64_t original = flow::GetTimeOffset();

        flow::SetTimeOffset(100);
        assert(flow::GetTimeOffset() == 100);

        flow::SetTimeOffset(200);
        assert(flow::GetTimeOffset() == 200);

        flow::SetTimeOffset(0);
        assert(flow::GetTimeOffset() == 0);

        flow::SetTimeOffset(-50);
        assert(flow::GetTimeOffset() == -50);

        flow::SetTimeOffset(original);
    }

    // -----------------------------------------------------------------------
    // Test 23: GetTimeMillis and GetTimeMicros consistency
    // -----------------------------------------------------------------------
    {
        int64_t original = flow::GetTimeOffset();
        flow::SetTimeOffset(0);

        int64_t ms = flow::GetTimeMillis();
        int64_t us = flow::GetTimeMicros();

        // us should be approximately ms * 1000
        assert(us / 1000 >= ms - 2);
        assert(us / 1000 <= ms + 2);

        flow::SetTimeOffset(original);
    }

    // -----------------------------------------------------------------------
    // Test 24: Time values are reasonable for known epoch
    // -----------------------------------------------------------------------
    {
        int64_t original = flow::GetTimeOffset();
        flow::SetTimeOffset(0);

        int64_t now = flow::GetTime();
        // Should be between 2025 and 2100
        assert(now >= 1735689600LL);   // 2025-01-01
        assert(now <= 4102444800LL);   // 2100-01-01

        flow::SetTimeOffset(original);
    }
}

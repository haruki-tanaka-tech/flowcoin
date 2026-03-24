// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for the logging subsystem.

#include "logging.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

// Helper: read entire file contents as string
static std::string read_file(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) return "";
    return std::string(std::istreambuf_iterator<char>(ifs),
                       std::istreambuf_iterator<char>());
}

// Helper: count occurrences of substring in string
static int count_occurrences(const std::string& haystack, const std::string& needle) {
    int count = 0;
    size_t pos = 0;
    while ((pos = haystack.find(needle, pos)) != std::string::npos) {
        count++;
        pos += needle.size();
    }
    return count;
}

void test_logging() {
    // All tests use a temporary log file
    std::string log_path = "/tmp/flowcoin_test_logging.log";

    // Clean up any existing file
    std::remove(log_path.c_str());

    // -----------------------------------------------------------------------
    // Test 1: log_init creates/opens log file
    // -----------------------------------------------------------------------
    {
        flow::log_init(log_path);
        flow::log_write(flow::LOG_INFO, "test", "Hello %s", "world");
        flow::log_shutdown();

        std::string content = read_file(log_path);
        assert(!content.empty());
        assert(content.find("Hello world") != std::string::npos);
    }

    // Cleanup for next test
    std::remove(log_path.c_str());

    // -----------------------------------------------------------------------
    // Test 2: Log levels filter correctly
    // -----------------------------------------------------------------------
    {
        flow::log_init(log_path);

        // Set minimum level to WARN — DEBUG and INFO should be suppressed
        flow::log_set_level(flow::LOG_WARN);
        flow::log_write(flow::LOG_DEBUG, "test", "debug message");
        flow::log_write(flow::LOG_INFO, "test", "info message");
        flow::log_write(flow::LOG_WARN, "test", "warn message");
        flow::log_write(flow::LOG_ERROR, "test", "error message");
        flow::log_shutdown();

        std::string content = read_file(log_path);
        assert(content.find("debug message") == std::string::npos);
        assert(content.find("info message") == std::string::npos);
        assert(content.find("warn message") != std::string::npos);
        assert(content.find("error message") != std::string::npos);

        // Reset level for subsequent tests
        flow::log_set_level(flow::LOG_INFO);
    }

    std::remove(log_path.c_str());

    // -----------------------------------------------------------------------
    // Test 3: Categories appear in log output
    // -----------------------------------------------------------------------
    {
        flow::log_init(log_path);
        flow::log_set_level(flow::LOG_DEBUG);
        flow::log_write(flow::LOG_INFO, "mycat", "categorized message");
        flow::log_shutdown();

        std::string content = read_file(log_path);
        assert(content.find("[mycat]") != std::string::npos);
        assert(content.find("categorized message") != std::string::npos);
    }

    std::remove(log_path.c_str());

    // -----------------------------------------------------------------------
    // Test 4: Timestamps are present in log output
    // -----------------------------------------------------------------------
    {
        flow::log_init(log_path);
        flow::log_set_level(flow::LOG_DEBUG);
        flow::log_write(flow::LOG_INFO, "test", "timestamp check");
        flow::log_shutdown();

        std::string content = read_file(log_path);
        // Timestamp format: [YYYY-MM-DD HH:MM:SS]
        // Check for year 20xx pattern
        assert(content.find("[20") != std::string::npos);
    }

    std::remove(log_path.c_str());

    // -----------------------------------------------------------------------
    // Test 5: Level labels appear correctly
    // -----------------------------------------------------------------------
    {
        flow::log_init(log_path);
        flow::log_set_level(flow::LOG_DEBUG);
        flow::log_write(flow::LOG_DEBUG, "test", "d");
        flow::log_write(flow::LOG_INFO, "test", "i");
        flow::log_write(flow::LOG_WARN, "test", "w");
        flow::log_write(flow::LOG_ERROR, "test", "e");
        flow::log_shutdown();

        std::string content = read_file(log_path);
        assert(content.find("[DEBUG]") != std::string::npos);
        assert(content.find("[INFO]") != std::string::npos);
        assert(content.find("[WARN]") != std::string::npos);
        assert(content.find("[ERROR]") != std::string::npos);
    }

    std::remove(log_path.c_str());

    // -----------------------------------------------------------------------
    // Test 6: Format strings work correctly with various types
    // -----------------------------------------------------------------------
    {
        flow::log_init(log_path);
        flow::log_set_level(flow::LOG_DEBUG);
        flow::log_write(flow::LOG_INFO, "test", "int=%d float=%.2f str=%s hex=0x%x",
                        42, 3.14, "hello", 0xff);
        flow::log_shutdown();

        std::string content = read_file(log_path);
        assert(content.find("int=42") != std::string::npos);
        assert(content.find("float=3.14") != std::string::npos);
        assert(content.find("str=hello") != std::string::npos);
        assert(content.find("hex=0xff") != std::string::npos);
    }

    std::remove(log_path.c_str());

    // -----------------------------------------------------------------------
    // Test 7: Concurrent logging is thread-safe (no crash)
    // -----------------------------------------------------------------------
    {
        flow::log_init(log_path);
        flow::log_set_level(flow::LOG_DEBUG);

        constexpr int num_threads = 8;
        constexpr int msgs_per_thread = 100;

        std::vector<std::thread> threads;
        for (int t = 0; t < num_threads; t++) {
            threads.emplace_back([t]() {
                for (int i = 0; i < msgs_per_thread; i++) {
                    flow::log_write(flow::LOG_INFO, "thread",
                                    "thread=%d msg=%d", t, i);
                }
            });
        }

        for (auto& th : threads) {
            th.join();
        }

        flow::log_shutdown();

        // Verify all messages were written
        std::string content = read_file(log_path);
        int total_lines = count_occurrences(content, "[thread]");
        assert(total_lines == num_threads * msgs_per_thread);
    }

    std::remove(log_path.c_str());

    // -----------------------------------------------------------------------
    // Test 8: log_shutdown flushes and closes file
    // -----------------------------------------------------------------------
    {
        flow::log_init(log_path);
        flow::log_write(flow::LOG_INFO, "test", "before shutdown");
        flow::log_shutdown();

        // File should be readable and contain the message
        std::string content = read_file(log_path);
        assert(content.find("before shutdown") != std::string::npos);
    }

    std::remove(log_path.c_str());

    // -----------------------------------------------------------------------
    // Test 9: log_init with empty path logs only to stdout (no file)
    // -----------------------------------------------------------------------
    {
        flow::log_init("");
        flow::log_write(flow::LOG_INFO, "test", "no file logging");
        flow::log_shutdown();
        // No crash is the success criterion
    }

    // -----------------------------------------------------------------------
    // Test 10: Macro helpers (LogDebug, LogInfo, etc.) work
    // -----------------------------------------------------------------------
    {
        flow::log_init(log_path);
        flow::log_set_level(flow::LOG_DEBUG);
        LogDebug("macrotest", "debug via macro %d", 1);
        LogInfo("macrotest", "info via macro %d", 2);
        LogWarn("macrotest", "warn via macro %d", 3);
        LogError("macrotest", "error via macro %d", 4);
        flow::log_shutdown();

        std::string content = read_file(log_path);
        assert(content.find("debug via macro 1") != std::string::npos);
        assert(content.find("info via macro 2") != std::string::npos);
        assert(content.find("warn via macro 3") != std::string::npos);
        assert(content.find("error via macro 4") != std::string::npos);
    }

    std::remove(log_path.c_str());

    // -----------------------------------------------------------------------
    // Test 11: Reinitializing log switches file
    // -----------------------------------------------------------------------
    {
        std::string path2 = "/tmp/flowcoin_test_logging2.log";
        std::remove(path2.c_str());

        flow::log_init(log_path);
        flow::log_write(flow::LOG_INFO, "test", "to file 1");

        // Re-init to a different file
        flow::log_init(path2);
        flow::log_write(flow::LOG_INFO, "test", "to file 2");
        flow::log_shutdown();

        std::string content1 = read_file(log_path);
        std::string content2 = read_file(path2);
        assert(content1.find("to file 1") != std::string::npos);
        assert(content2.find("to file 2") != std::string::npos);
        // "to file 2" should NOT be in file 1
        assert(content1.find("to file 2") == std::string::npos);

        std::remove(path2.c_str());
    }

    std::remove(log_path.c_str());

    // Reset log level to default for other tests
    flow::log_set_level(flow::LOG_INFO);
}

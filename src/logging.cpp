// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "logging.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>

namespace flow {

static FILE*    g_log_file  = nullptr;
static LogLevel g_min_level = LOG_INFO;
static std::mutex g_log_mutex;

void log_init(const std::string& log_file) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_file) {
        std::fclose(g_log_file);
        g_log_file = nullptr;
    }
    if (!log_file.empty()) {
        g_log_file = std::fopen(log_file.c_str(), "a");
    }
}

void log_shutdown() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_file) {
        std::fclose(g_log_file);
        g_log_file = nullptr;
    }
}

void log_set_level(LogLevel level) {
    g_min_level = level;
}

static const char* level_str(LogLevel level) {
    switch (level) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO:  return "INFO";
        case LOG_WARN:  return "WARN";
        case LOG_ERROR: return "ERROR";
    }
    return "???";
}

static void format_timestamp(char* buf, size_t len) {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    struct tm tm_buf;
    gmtime_r(&time_t_now, &tm_buf);
    std::strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm_buf);
}

void log_writev(LogLevel level, const char* category, const char* fmt, va_list args) {
    if (level < g_min_level) return;

    char timestamp[32];
    format_timestamp(timestamp, sizeof(timestamp));

    // Format the user message
    char msg[4096];
    std::vsnprintf(msg, sizeof(msg), fmt, args);

    // Build the full line: [timestamp] [LEVEL] [category] message
    char line[4200];
    std::snprintf(line, sizeof(line), "[%s] [%s] [%s] %s\n",
                  timestamp, level_str(level), category, msg);

    std::lock_guard<std::mutex> lock(g_log_mutex);

    // Write to stdout
    std::fputs(line, stdout);
    std::fflush(stdout);

    // Write to log file
    if (g_log_file) {
        std::fputs(line, g_log_file);
        std::fflush(g_log_file);
    }
}

void log_write(LogLevel level, const char* category, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_writev(level, category, fmt, args);
    va_end(args);
}

} // namespace flow

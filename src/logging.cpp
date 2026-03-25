// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "logging.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <mutex>
#include <sstream>
#include <thread>

namespace flow {

// ============================================================================
// Global logger state
// ============================================================================

static FILE*         g_log_file         = nullptr;
static std::string   g_log_file_path;
static LogLevel      g_min_level        = LOG_INFO;
static uint32_t      g_enabled_cats     = LOGCAT_ALL;
static bool          g_print_console    = true;
static bool          g_print_timestamps = true;
static bool          g_print_thread_id  = false;
static int64_t       g_max_file_size    = 100 * 1024 * 1024;  // 100 MB
static int           g_max_rotated      = 5;
static std::mutex    g_log_mutex;

// ============================================================================
// Level/category name tables
// ============================================================================

const char* log_level_name(LogLevel level) {
    switch (level) {
        case LOG_TRACE: return "TRACE";
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO:  return "INFO";
        case LOG_WARN:  return "WARN";
        case LOG_ERROR: return "ERROR";
        case LOG_FATAL: return "FATAL";
        case LOG_NONE:  return "NONE";
    }
    return "???";
}

LogLevel parse_log_level(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower == "trace")   return LOG_TRACE;
    if (lower == "debug")   return LOG_DEBUG;
    if (lower == "info")    return LOG_INFO;
    if (lower == "warn" || lower == "warning") return LOG_WARN;
    if (lower == "error")   return LOG_ERROR;
    if (lower == "fatal")   return LOG_FATAL;
    if (lower == "none")    return LOG_NONE;
    return LOG_INFO;
}

struct CategoryEntry {
    const char* name;
    uint32_t mask;
};

static const CategoryEntry g_category_table[] = {
    {"all",        LOGCAT_ALL},
    {"net",        LOGCAT_NET},
    {"mempool",    LOGCAT_MEMPOOL},
    {"validation", LOGCAT_VALIDATION},
    {"rpc",        LOGCAT_RPC},
    {"wallet",     LOGCAT_WALLET},
    {"mining",     LOGCAT_MINING},
    {"sync",       LOGCAT_SYNC},
    {"db",         LOGCAT_DB},
    {"eval",       LOGCAT_EVAL},
    {"lock",       LOGCAT_LOCK},
    {"addrman",    LOGCAT_ADDRMAN},
    {"bench",      LOGCAT_BENCH},
    {"http",       LOGCAT_HTTP},
};

uint32_t parse_log_category(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const auto& entry : g_category_table) {
        if (lower == entry.name) return entry.mask;
    }
    return 0;
}

const char* log_category_name(uint32_t cat) {
    for (const auto& entry : g_category_table) {
        if (cat == entry.mask) return entry.name;
    }
    return "unknown";
}

// ============================================================================
// Timestamp formatting
// ============================================================================

static void format_timestamp(char* buf, size_t len) {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    struct tm tm_buf;
    gmtime_r(&time_t_now, &tm_buf);

    int written = static_cast<int>(std::strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm_buf));
    if (written > 0 && static_cast<size_t>(written) + 5 < len) {
        std::snprintf(buf + written, len - static_cast<size_t>(written),
                     ".%03d", static_cast<int>(ms.count()));
    }
}

static int64_t now_us() {
    auto tp = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        tp.time_since_epoch()).count();
}

// ============================================================================
// File size check
// ============================================================================

static int64_t get_file_size(FILE* f) {
    if (!f) return 0;
    long pos = std::ftell(f);
    if (pos < 0) return 0;
    std::fseek(f, 0, SEEK_END);
    long end = std::ftell(f);
    std::fseek(f, pos, SEEK_SET);
    return static_cast<int64_t>(end);
}

// ============================================================================
// Log rotation
// ============================================================================

static void do_rotate() {
    if (g_log_file_path.empty() || !g_log_file) return;

    std::fclose(g_log_file);
    g_log_file = nullptr;

    // Shift existing rotated files: .5 -> delete, .4 -> .5, .3 -> .4, etc.
    for (int i = g_max_rotated; i >= 1; --i) {
        std::string old_name = g_log_file_path + "." + std::to_string(i);
        if (i == g_max_rotated) {
            std::filesystem::remove(old_name);
        } else {
            std::string new_name = g_log_file_path + "." + std::to_string(i + 1);
            try {
                std::filesystem::rename(old_name, new_name);
            } catch (...) {
                // Ignore — file might not exist
            }
        }
    }

    // Rename current log file to .1
    std::string rotated = g_log_file_path + ".1";
    try {
        std::filesystem::rename(g_log_file_path, rotated);
    } catch (...) {
        // If rename fails, just truncate
    }

    // Reopen the log file
    g_log_file = std::fopen(g_log_file_path.c_str(), "a");
}

// ============================================================================
// Initialization / shutdown
// ============================================================================

void log_init(const std::string& log_file) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_file) {
        std::fclose(g_log_file);
        g_log_file = nullptr;
    }
    g_log_file_path = log_file;
    if (!log_file.empty()) {
        g_log_file = std::fopen(log_file.c_str(), "a");
    }
}

void log_init_config(const LogConfig& config) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_file) {
        std::fclose(g_log_file);
        g_log_file = nullptr;
    }

    g_log_file_path    = config.log_file;
    g_min_level        = config.min_level;
    g_enabled_cats     = config.enabled_categories;
    g_print_console    = config.print_to_console;
    g_print_timestamps = config.print_timestamps;
    g_print_thread_id  = config.print_thread_id;
    g_max_file_size    = config.max_file_size;
    g_max_rotated      = config.max_rotated_files;

    if (!config.log_file.empty()) {
        g_log_file = std::fopen(config.log_file.c_str(), "a");
    }
}

void log_shutdown() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_file) {
        std::fflush(g_log_file);
        std::fclose(g_log_file);
        g_log_file = nullptr;
    }
}

// ============================================================================
// Level/category control
// ============================================================================

void log_set_level(LogLevel level) {
    g_min_level = level;
}

LogLevel log_get_level() {
    return g_min_level;
}

void log_enable_category(uint32_t category) {
    g_enabled_cats |= category;
}

void log_disable_category(uint32_t category) {
    g_enabled_cats &= ~category;
}

void log_set_categories(uint32_t mask) {
    g_enabled_cats = mask;
}

bool log_category_enabled(uint32_t category) {
    return (g_enabled_cats & category) != 0;
}

void log_set_console(bool enable) {
    g_print_console = enable;
}

void log_set_timestamps(bool enable) {
    g_print_timestamps = enable;
}

// Forward declarations for helpers used below
static void ring_push(const std::string& formatted, const LogEntry& entry);
static void update_stats(LogLevel level);

// ============================================================================
// Core write functions
// ============================================================================

void log_writev(LogLevel level, const char* category, const char* fmt, va_list args) {
    if (level < g_min_level) return;

    // Build timestamp
    char timestamp[40];
    if (g_print_timestamps) {
        format_timestamp(timestamp, sizeof(timestamp));
    }

    // Format the user message
    char msg[8192];
    std::vsnprintf(msg, sizeof(msg), fmt, args);

    // Build the full line
    char line[8400];
    int offset = 0;

    if (g_print_timestamps) {
        offset += std::snprintf(line + offset, sizeof(line) - static_cast<size_t>(offset),
                               "[%s] ", timestamp);
    }

    offset += std::snprintf(line + offset, sizeof(line) - static_cast<size_t>(offset),
                           "[%-5s] ", log_level_name(level));

    if (g_print_thread_id) {
        std::ostringstream tid;
        tid << std::this_thread::get_id();
        offset += std::snprintf(line + offset, sizeof(line) - static_cast<size_t>(offset),
                               "[%s] ", tid.str().c_str());
    }

    offset += std::snprintf(line + offset, sizeof(line) - static_cast<size_t>(offset),
                           "[%s] %s\n", category, msg);

    // Push to ring buffer and update stats before taking the log mutex
    {
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        LogEntry entry;
        entry.timestamp_ms = now_ms;
        entry.level = level;
        entry.category = category;
        entry.message = msg;
        if (g_print_thread_id) {
            std::ostringstream tid;
            tid << std::this_thread::get_id();
            entry.thread_id = tid.str();
        }

        ring_push(std::string(line), entry);
        update_stats(level);
    }

    std::lock_guard<std::mutex> lock(g_log_mutex);

    // Write to console
    if (g_print_console) {
        // Use stderr for warnings and above, stdout for info and below
        FILE* out = (level >= LOG_WARN) ? stderr : stdout;
        std::fputs(line, out);
        std::fflush(out);
    }

    // Write to log file
    if (g_log_file) {
        std::fputs(line, g_log_file);
        std::fflush(g_log_file);

        // Check if rotation is needed
        if (g_max_file_size > 0) {
            int64_t sz = get_file_size(g_log_file);
            if (sz > g_max_file_size) {
                do_rotate();
            }
        }
    }
}

void log_write(LogLevel level, const char* category, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_writev(level, category, fmt, args);
    va_end(args);
}

void log_raw(const std::string& message) {
    std::lock_guard<std::mutex> lock(g_log_mutex);

    if (g_print_console) {
        std::fputs(message.c_str(), stdout);
        std::fflush(stdout);
    }

    if (g_log_file) {
        std::fputs(message.c_str(), g_log_file);
        std::fflush(g_log_file);
    }
}

void log_flush() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_file) {
        std::fflush(g_log_file);
    }
    std::fflush(stdout);
}

void log_rotate() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    do_rotate();
}

std::string log_get_file() {
    return g_log_file_path;
}

int64_t log_get_file_size() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    return get_file_size(g_log_file);
}

std::string log_format(const char* fmt, ...) {
    char buf[8192];
    va_list args;
    va_start(args, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    return std::string(buf);
}

// ============================================================================
// Ring buffer for recent log entries
// ============================================================================

static constexpr size_t RING_BUFFER_SIZE = 1000;

struct RingEntry {
    std::string formatted_line;
    LogEntry structured;
};

static RingEntry   g_ring_buffer[RING_BUFFER_SIZE];
static size_t      g_ring_head = 0;
static size_t      g_ring_count = 0;
static std::mutex  g_ring_mutex;

// Statistics
static std::atomic<uint64_t> g_total_entries{0};
static std::atomic<uint64_t> g_stat_trace{0};
static std::atomic<uint64_t> g_stat_debug{0};
static std::atomic<uint64_t> g_stat_info{0};
static std::atomic<uint64_t> g_stat_warn{0};
static std::atomic<uint64_t> g_stat_error{0};
static std::atomic<uint64_t> g_stat_fatal{0};

static void ring_push(const std::string& formatted, const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(g_ring_mutex);
    g_ring_buffer[g_ring_head].formatted_line = formatted;
    g_ring_buffer[g_ring_head].structured = entry;
    g_ring_head = (g_ring_head + 1) % RING_BUFFER_SIZE;
    if (g_ring_count < RING_BUFFER_SIZE) {
        ++g_ring_count;
    }
}

static void update_stats(LogLevel level) {
    g_total_entries.fetch_add(1, std::memory_order_relaxed);
    switch (level) {
        case LOG_TRACE: g_stat_trace.fetch_add(1, std::memory_order_relaxed); break;
        case LOG_DEBUG: g_stat_debug.fetch_add(1, std::memory_order_relaxed); break;
        case LOG_INFO:  g_stat_info.fetch_add(1, std::memory_order_relaxed); break;
        case LOG_WARN:  g_stat_warn.fetch_add(1, std::memory_order_relaxed); break;
        case LOG_ERROR: g_stat_error.fetch_add(1, std::memory_order_relaxed); break;
        case LOG_FATAL: g_stat_fatal.fetch_add(1, std::memory_order_relaxed); break;
        default: break;
    }
}

std::vector<std::string> log_get_recent(size_t count) {
    std::lock_guard<std::mutex> lock(g_ring_mutex);
    std::vector<std::string> result;

    size_t n = std::min(count, g_ring_count);
    result.reserve(n);

    // Start from the oldest entry we want
    size_t start;
    if (g_ring_count < RING_BUFFER_SIZE) {
        // Buffer not full yet
        start = (g_ring_count >= n) ? (g_ring_count - n) : 0;
        n = std::min(n, g_ring_count);
    } else {
        // Buffer is full — oldest is at g_ring_head
        start = (g_ring_head + RING_BUFFER_SIZE - n) % RING_BUFFER_SIZE;
    }

    for (size_t i = 0; i < n; ++i) {
        size_t idx = (start + i) % RING_BUFFER_SIZE;
        result.push_back(g_ring_buffer[idx].formatted_line);
    }

    return result;
}

uint64_t log_get_total_entries() {
    return g_total_entries.load(std::memory_order_relaxed);
}

LogStats log_get_stats() {
    LogStats stats;
    stats.trace_count = g_stat_trace.load(std::memory_order_relaxed);
    stats.debug_count = g_stat_debug.load(std::memory_order_relaxed);
    stats.info_count  = g_stat_info.load(std::memory_order_relaxed);
    stats.warn_count  = g_stat_warn.load(std::memory_order_relaxed);
    stats.error_count = g_stat_error.load(std::memory_order_relaxed);
    stats.fatal_count = g_stat_fatal.load(std::memory_order_relaxed);
    return stats;
}

void log_reset_stats() {
    g_total_entries.store(0, std::memory_order_relaxed);
    g_stat_trace.store(0, std::memory_order_relaxed);
    g_stat_debug.store(0, std::memory_order_relaxed);
    g_stat_info.store(0, std::memory_order_relaxed);
    g_stat_warn.store(0, std::memory_order_relaxed);
    g_stat_error.store(0, std::memory_order_relaxed);
    g_stat_fatal.store(0, std::memory_order_relaxed);
}

std::vector<LogEntry> log_get_entries(size_t count) {
    std::lock_guard<std::mutex> lock(g_ring_mutex);
    std::vector<LogEntry> result;

    size_t n = std::min(count, g_ring_count);
    result.reserve(n);

    size_t start;
    if (g_ring_count < RING_BUFFER_SIZE) {
        start = (g_ring_count >= n) ? (g_ring_count - n) : 0;
        n = std::min(n, g_ring_count);
    } else {
        start = (g_ring_head + RING_BUFFER_SIZE - n) % RING_BUFFER_SIZE;
    }

    for (size_t i = 0; i < n; ++i) {
        size_t idx = (start + i) % RING_BUFFER_SIZE;
        result.push_back(g_ring_buffer[idx].structured);
    }

    return result;
}

// ============================================================================
// LogTimer implementation
// ============================================================================

LogTimer::LogTimer(const char* category, const char* label)
    : category_(category)
    , label_(label)
    , start_us_(now_us()) {
    LogDebug(category_, ">>> %s", label_);
}

LogTimer::~LogTimer() {
    int64_t elapsed_us = now_us() - start_us_;
    double ms = static_cast<double>(elapsed_us) / 1000.0;
    LogDebug(category_, "<<< %s [%.2f ms]", label_, ms);
}

} // namespace flow

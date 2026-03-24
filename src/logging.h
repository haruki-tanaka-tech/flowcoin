// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Logging subsystem for FlowCoin.
// Thread-safe, timestamped output to both file and console with
// configurable level filtering, category filtering, log rotation,
// and structured formatting.

#ifndef FLOWCOIN_LOGGING_H
#define FLOWCOIN_LOGGING_H

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <string>
#include <vector>

namespace flow {

// ============================================================================
// Log levels
// ============================================================================

enum LogLevel : int {
    LOG_TRACE = 0,
    LOG_DEBUG = 1,
    LOG_INFO  = 2,
    LOG_WARN  = 3,
    LOG_ERROR = 4,
    LOG_FATAL = 5,
    LOG_NONE  = 6,
};

/// Convert a log level to its string name.
const char* log_level_name(LogLevel level);

/// Parse a log level name (case-insensitive). Returns LOG_INFO on unrecognized input.
LogLevel parse_log_level(const std::string& name);

// ============================================================================
// Log categories
// ============================================================================

enum LogCategory : uint32_t {
    LOGCAT_ALL        = 0xFFFFFFFF,
    LOGCAT_NONE       = 0x00000000,
    LOGCAT_NET        = 0x00000001,
    LOGCAT_MEMPOOL    = 0x00000002,
    LOGCAT_VALIDATION = 0x00000004,
    LOGCAT_RPC        = 0x00000008,
    LOGCAT_WALLET     = 0x00000010,
    LOGCAT_MINING     = 0x00000020,
    LOGCAT_SYNC       = 0x00000040,
    LOGCAT_DB         = 0x00000080,
    LOGCAT_EVAL       = 0x00000100,
    LOGCAT_LOCK       = 0x00000200,
    LOGCAT_ADDRMAN    = 0x00000400,
    LOGCAT_BENCH      = 0x00000800,
    LOGCAT_HTTP       = 0x00001000,
};

/// Parse a category name to its bitmask. Returns 0 on unrecognized input.
uint32_t parse_log_category(const std::string& name);

/// Get the category name from its bitmask (returns "unknown" for unrecognized).
const char* log_category_name(uint32_t cat);

// ============================================================================
// Logger configuration
// ============================================================================

struct LogConfig {
    std::string log_file;               // Path to log file ("" = no file)
    LogLevel min_level         = LOG_INFO;
    uint32_t enabled_categories = LOGCAT_ALL;
    bool print_to_console      = true;   // Write to stdout
    bool print_timestamps      = true;   // Include timestamps in output
    bool print_thread_id       = false;  // Include thread ID in output
    bool print_source_location = false;  // Include file:line in output (debug builds)
    int64_t max_file_size      = 100 * 1024 * 1024;  // 100 MB before rotation
    int max_rotated_files      = 5;      // Keep up to 5 rotated log files
};

// ============================================================================
// Logger interface
// ============================================================================

/// Initialize the logging subsystem. Opens the log file for appending.
/// If config.log_file is empty, logs only to stdout.
void log_init(const std::string& log_file);

/// Initialize with full configuration.
void log_init_config(const LogConfig& config);

/// Shut down the logging subsystem. Flushes and closes the log file.
void log_shutdown();

/// Set the minimum log level. Messages below this level are suppressed.
void log_set_level(LogLevel level);

/// Get the current minimum log level.
LogLevel log_get_level();

/// Enable a log category by bitmask.
void log_enable_category(uint32_t category);

/// Disable a log category by bitmask.
void log_disable_category(uint32_t category);

/// Set all enabled categories at once.
void log_set_categories(uint32_t mask);

/// Check if a category is enabled.
bool log_category_enabled(uint32_t category);

/// Set whether to print to console (stdout).
void log_set_console(bool enable);

/// Set whether to include timestamps.
void log_set_timestamps(bool enable);

/// Write a log message with printf-style formatting.
void log_write(LogLevel level, const char* category, const char* fmt, ...)
    __attribute__((format(printf, 3, 4)));

/// Write a log message with a pre-built va_list.
void log_writev(LogLevel level, const char* category, const char* fmt, va_list args);

/// Write a raw string to the log (no formatting, no level check).
void log_raw(const std::string& message);

/// Flush the log file to disk.
void log_flush();

/// Rotate the log file if it exceeds the maximum size.
void log_rotate();

/// Get the current log file path.
std::string log_get_file();

/// Get the current log file size in bytes.
int64_t log_get_file_size();

/// Printf-style wrapper that returns a formatted string (for building log messages).
std::string log_format(const char* fmt, ...)
    __attribute__((format(printf, 1, 2)));

// ============================================================================
// Convenience macros
// ============================================================================

#define LogTrace(cat, ...) ::flow::log_write(::flow::LOG_TRACE, cat, __VA_ARGS__)
#define LogDebug(cat, ...) ::flow::log_write(::flow::LOG_DEBUG, cat, __VA_ARGS__)
#define LogInfo(cat, ...)  ::flow::log_write(::flow::LOG_INFO,  cat, __VA_ARGS__)
#define LogWarn(cat, ...)  ::flow::log_write(::flow::LOG_WARN,  cat, __VA_ARGS__)
#define LogError(cat, ...) ::flow::log_write(::flow::LOG_ERROR, cat, __VA_ARGS__)
#define LogFatal(cat, ...) ::flow::log_write(::flow::LOG_FATAL, cat, __VA_ARGS__)

/// Conditional logging: only evaluate the format string if the level is enabled.
#define LogPrintf(...) ::flow::log_write(::flow::LOG_INFO, "default", __VA_ARGS__)

// ============================================================================
// Recent log ring buffer (for RPC getlog command)
// ============================================================================

/// Get the N most recent log lines from the in-memory ring buffer.
/// The ring buffer holds the last 1000 entries regardless of file rotation.
std::vector<std::string> log_get_recent(size_t count = 100);

/// Get the total number of log entries written since startup.
uint64_t log_get_total_entries();

/// Get the number of entries at each log level since startup.
struct LogStats {
    uint64_t trace_count  = 0;
    uint64_t debug_count  = 0;
    uint64_t info_count   = 0;
    uint64_t warn_count   = 0;
    uint64_t error_count  = 0;
    uint64_t fatal_count  = 0;
};

LogStats log_get_stats();

/// Reset log statistics counters.
void log_reset_stats();

// ============================================================================
// Structured log entry (for programmatic access)
// ============================================================================

struct LogEntry {
    int64_t timestamp_ms;     // milliseconds since epoch
    LogLevel level;
    std::string category;
    std::string message;
    std::string thread_id;
};

/// Get recent log entries as structured objects.
std::vector<LogEntry> log_get_entries(size_t count = 100);

// ============================================================================
// Scoped log utilities
// ============================================================================

/// Timed log scope: logs entry and duration on scope exit.
class LogTimer {
public:
    LogTimer(const char* category, const char* label);
    ~LogTimer();
private:
    const char* category_;
    const char* label_;
    int64_t start_us_;
};

#define LOG_TIME(cat, label) ::flow::LogTimer _log_timer_##__LINE__(cat, label)

} // namespace flow

#endif // FLOWCOIN_LOGGING_H

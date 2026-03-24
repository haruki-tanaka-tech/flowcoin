// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Production logging system for FlowCoin.
// Supports multiple log levels, categories, file output with auto-rotation,
// console output, and configurable formatting.
//
// This is the util/ version of the logger -- provides Logger class and
// category-based macros. The top-level src/logging.h provides simpler
// macros that wrap this module.

#pragma once

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <set>
#include <string>

namespace flow {

// ---------------------------------------------------------------------------
// Log levels
// ---------------------------------------------------------------------------

enum class LogLevel {
    TRACE   = 0,
    DEBUG   = 1,
    INFO    = 2,
    WARNING = 3,
    ERROR   = 4,
    FATAL   = 5,
    NONE    = 6    // Disables all logging
};

// ---------------------------------------------------------------------------
// Log categories
// ---------------------------------------------------------------------------

enum class LogCategory {
    ALL,           // Default category (always enabled)
    NET,           // Network / peer communication
    VALIDATION,    // Block and transaction validation
    MINING,        // Block template construction and submission
    RPC,           // RPC server and request handling
    WALLET,        // Wallet operations
    MEMPOOL,       // Memory pool management
    MODEL,         // Model training and inference
    CHAIN,         // Chain state and block index
    SYNC,          // Initial block download and sync
    ADDRMAN,       // Address manager
    HTTP,          // HTTP server
    SCRIPT,        // Script evaluation (future)
    LOCK,          // Lock contention debugging
    BENCH,         // Performance benchmarking
    DB,            // Database operations
    PRUNE,         // Block pruning
    DELTA,         // Delta payload processing
    CATEGORY_COUNT // Sentinel (number of categories)
};

// ---------------------------------------------------------------------------
// Logger -- singleton production logger
// ---------------------------------------------------------------------------

class Logger {
public:
    /// Get the singleton instance.
    static Logger& instance();

    // --- Configuration ---

    /// Set the minimum log level. Messages below this level are suppressed.
    void set_level(LogLevel level);

    /// Get the current log level.
    LogLevel get_level() const;

    /// Set the log file path. Opens the file for appending.
    /// Pass empty string to disable file logging.
    void set_file(const std::string& path);

    /// Enable a specific log category.
    void enable_category(LogCategory cat);

    /// Disable a specific log category.
    void disable_category(LogCategory cat);

    /// Enable all categories.
    void enable_all_categories();

    /// Disable all categories except ALL.
    void disable_all_categories();

    /// Check if a category is enabled.
    bool is_category_enabled(LogCategory cat) const;

    /// Set whether to print to console (stdout).
    void set_print_to_console(bool enabled);

    /// Set whether to include timestamps in log output.
    void set_print_timestamps(bool enabled);

    /// Set whether to include category names in log output.
    void set_print_categories(bool enabled);

    /// Set whether to include source file and line in log output.
    void set_print_source_location(bool enabled);

    /// Set the maximum log file size in bytes.
    /// When exceeded, the log file is rotated (old content discarded).
    void set_max_file_size(size_t bytes);

    // --- Logging ---

    /// Log a message with full context.
    void log(LogLevel level, LogCategory cat, const char* file, int line,
             const char* fmt, ...) __attribute__((format(printf, 6, 7)));

    /// Log a message with va_list.
    void logv(LogLevel level, LogCategory cat, const char* file, int line,
              const char* fmt, va_list args);

    /// Check if a message at the given level and category would be logged.
    /// Use this to skip expensive string formatting when the message
    /// would be suppressed.
    bool will_log(LogLevel level, LogCategory cat) const;

    // --- File management ---

    /// Flush the log file buffer to disk.
    void flush();

    /// Get the current log file path (empty if no file logging).
    std::string get_log_path() const;

    /// Shrink the log file to keep only the last keep_bytes bytes.
    /// Default: keep last 10 MB.
    void shrink_log(size_t keep_bytes = 10 * 1024 * 1024);

    /// Reopen the log file (for log rotation via SIGHUP).
    void reopen();

    /// Close the log file.
    void close();

    // --- Statistics ---

    /// Get the current log file size.
    size_t get_file_size() const;

    /// Get total number of messages logged since startup.
    uint64_t get_message_count() const;

private:
    Logger();
    ~Logger();

    // Non-copyable
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    LogLevel level_ = LogLevel::INFO;
    std::set<LogCategory> enabled_cats_;
    std::string log_path_;
    FILE* log_file_ = nullptr;
    bool console_ = true;
    bool timestamps_ = true;
    bool categories_ = true;
    bool source_location_ = false;
    size_t max_size_ = 100 * 1024 * 1024;  // 100 MB
    size_t current_size_ = 0;
    uint64_t message_count_ = 0;
    mutable std::mutex mutex_;

    /// Rotate the log file if it exceeds max_size_.
    void rotate_if_needed();

    /// Get a string representation of a log level.
    static const char* level_string(LogLevel l);

    /// Get a string representation of a log category.
    static const char* category_string(LogCategory c);

    /// Format the current timestamp into buf.
    static void format_timestamp(char* buf, size_t len);

    /// Write a formatted line to all enabled outputs.
    void write_line(const char* line, size_t len);
};

// ---------------------------------------------------------------------------
// Convenience macros
// ---------------------------------------------------------------------------

#define FlowLogPrint(cat, ...) \
    do { if (::flow::Logger::instance().will_log(::flow::LogLevel::INFO, ::flow::LogCategory::cat)) \
        ::flow::Logger::instance().log(::flow::LogLevel::INFO, ::flow::LogCategory::cat, \
            __FILE__, __LINE__, __VA_ARGS__); } while(0)

#define FlowLogPrintf(...) \
    ::flow::Logger::instance().log(::flow::LogLevel::INFO, ::flow::LogCategory::ALL, \
        __FILE__, __LINE__, __VA_ARGS__)

#define FlowLogDebug(cat, ...) \
    do { if (::flow::Logger::instance().will_log(::flow::LogLevel::DEBUG, ::flow::LogCategory::cat)) \
        ::flow::Logger::instance().log(::flow::LogLevel::DEBUG, ::flow::LogCategory::cat, \
            __FILE__, __LINE__, __VA_ARGS__); } while(0)

#define FlowLogError(...) \
    ::flow::Logger::instance().log(::flow::LogLevel::ERROR, ::flow::LogCategory::ALL, \
        __FILE__, __LINE__, __VA_ARGS__)

#define FlowLogWarning(...) \
    ::flow::Logger::instance().log(::flow::LogLevel::WARNING, ::flow::LogCategory::ALL, \
        __FILE__, __LINE__, __VA_ARGS__)

#define FlowLogTrace(cat, ...) \
    do { if (::flow::Logger::instance().will_log(::flow::LogLevel::TRACE, ::flow::LogCategory::cat)) \
        ::flow::Logger::instance().log(::flow::LogLevel::TRACE, ::flow::LogCategory::cat, \
            __FILE__, __LINE__, __VA_ARGS__); } while(0)

#define FlowLogFatal(...) \
    ::flow::Logger::instance().log(::flow::LogLevel::FATAL, ::flow::LogCategory::ALL, \
        __FILE__, __LINE__, __VA_ARGS__)

} // namespace flow

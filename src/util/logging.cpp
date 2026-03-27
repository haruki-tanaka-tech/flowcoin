// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "logging.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <vector>

namespace flow {

// ===========================================================================
// Logger private helpers
// ===========================================================================

const char* Logger::level_string(LogLevel l) {
    switch (l) {
        case LogLevel::TRACE:   return "TRACE";
        case LogLevel::DEBUG:   return "DEBUG";
        case LogLevel::INFO:    return "INFO ";
        case LogLevel::WARNING: return "WARN ";
        case LogLevel::ERROR:   return "ERROR";
        case LogLevel::FATAL:   return "FATAL";
        case LogLevel::NONE:    return "NONE ";
    }
    return "?????";
}

const char* Logger::category_string(LogCategory c) {
    switch (c) {
        case LogCategory::ALL:            return "all";
        case LogCategory::NET:            return "net";
        case LogCategory::VALIDATION:     return "validation";
        case LogCategory::MINING:         return "mining";
        case LogCategory::RPC:            return "rpc";
        case LogCategory::WALLET:         return "wallet";
        case LogCategory::MEMPOOL:        return "mempool";
        case LogCategory::MODEL:          return "model";
        case LogCategory::CHAIN:          return "chain";
        case LogCategory::SYNC:           return "sync";
        case LogCategory::ADDRMAN:        return "addrman";
        case LogCategory::HTTP:           return "http";
        case LogCategory::SCRIPT:         return "script";
        case LogCategory::LOCK:           return "lock";
        case LogCategory::BENCH:          return "bench";
        case LogCategory::DB:             return "db";
        case LogCategory::PRUNE:          return "prune";
        case LogCategory::DELTA:          return "delta";
        case LogCategory::CATEGORY_COUNT: return "???";
    }
    return "???";
}

void Logger::format_timestamp(char* buf, size_t len) {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count() % 1000;

    struct tm tm_buf;
#ifdef _WIN32
    gmtime_s(&tm_buf, &time_t_now);
#else
    gmtime_r(&time_t_now, &tm_buf);
#endif
    std::snprintf(buf, len, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                  tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                  tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
                  static_cast<int>(ms));
}

void Logger::rotate_if_needed() {
    if (!log_file_) return;
    if (max_size_ == 0) return;  // no limit
    if (current_size_ <= max_size_) return;

    // Simple rotation: shrink the log
    shrink_log(max_size_ / 2);
}

void Logger::write_line(const char* line, size_t len) {
    // Write to console
    if (console_) {
        std::fwrite(line, 1, len, stdout);
        std::fflush(stdout);
    }

    // Write to log file
    if (log_file_) {
        std::fwrite(line, 1, len, log_file_);
        std::fflush(log_file_);
        current_size_ += len;
        rotate_if_needed();
    }
}

// ===========================================================================
// Logger construction
// ===========================================================================

Logger::Logger() {
    // Enable ALL category by default
    enabled_cats_.insert(LogCategory::ALL);
}

Logger::~Logger() {
    close();
}

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

// ===========================================================================
// Configuration
// ===========================================================================

void Logger::set_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    level_ = level;
}

LogLevel Logger::get_level() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return level_;
}

void Logger::set_file(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Close existing file
    if (log_file_) {
        std::fclose(log_file_);
        log_file_ = nullptr;
    }

    log_path_ = path;
    current_size_ = 0;

    if (!path.empty()) {
        log_file_ = std::fopen(path.c_str(), "a");
        if (log_file_) {
            // Determine current file size
            std::fseek(log_file_, 0, SEEK_END);
            current_size_ = static_cast<size_t>(std::ftell(log_file_));
        }
    }
}

void Logger::enable_category(LogCategory cat) {
    std::lock_guard<std::mutex> lock(mutex_);
    enabled_cats_.insert(cat);
}

void Logger::disable_category(LogCategory cat) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (cat != LogCategory::ALL) {
        enabled_cats_.erase(cat);
    }
}

void Logger::enable_all_categories() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (int i = 0; i < static_cast<int>(LogCategory::CATEGORY_COUNT); ++i) {
        enabled_cats_.insert(static_cast<LogCategory>(i));
    }
}

void Logger::disable_all_categories() {
    std::lock_guard<std::mutex> lock(mutex_);
    enabled_cats_.clear();
    enabled_cats_.insert(LogCategory::ALL);  // ALL is always enabled
}

bool Logger::is_category_enabled(LogCategory cat) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return enabled_cats_.count(cat) > 0 || enabled_cats_.count(LogCategory::ALL) > 0;
}

void Logger::set_print_to_console(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    console_ = enabled;
}

void Logger::set_print_timestamps(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    timestamps_ = enabled;
}

void Logger::set_print_categories(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    categories_ = enabled;
}

void Logger::set_print_source_location(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    source_location_ = enabled;
}

void Logger::set_max_file_size(size_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    max_size_ = bytes;
}

// ===========================================================================
// Logging
// ===========================================================================

bool Logger::will_log(LogLevel level, LogCategory cat) const {
    if (level < level_) return false;
    if (cat != LogCategory::ALL) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (enabled_cats_.count(cat) == 0 && enabled_cats_.count(LogCategory::ALL) == 0) {
            return false;
        }
    }
    return true;
}

void Logger::log(LogLevel level, LogCategory cat, const char* file, int line,
                 const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    logv(level, cat, file, line, fmt, args);
    va_end(args);
}

void Logger::logv(LogLevel level, LogCategory cat, const char* file, int line,
                  const char* fmt, va_list args) {
    if (!will_log(level, cat)) return;

    // Format the user message
    char msg[4096];
    std::vsnprintf(msg, sizeof(msg), fmt, args);

    // Build the full line
    char full_line[4608];
    size_t pos = 0;

    // Timestamp
    if (timestamps_) {
        char ts[32];
        format_timestamp(ts, sizeof(ts));
        pos += std::snprintf(full_line + pos, sizeof(full_line) - pos, "[%s] ", ts);
    }

    // Level
    pos += std::snprintf(full_line + pos, sizeof(full_line) - pos, "[%s] ", level_string(level));

    // Category
    if (categories_ && cat != LogCategory::ALL) {
        pos += std::snprintf(full_line + pos, sizeof(full_line) - pos,
                             "[%s] ", category_string(cat));
    }

    // Source location
    if (source_location_ && file) {
        // Extract just the filename from the full path
        const char* basename = file;
        for (const char* p = file; *p; ++p) {
            if (*p == '/') basename = p + 1;
        }
        pos += std::snprintf(full_line + pos, sizeof(full_line) - pos,
                             "(%s:%d) ", basename, line);
    }

    // Message
    pos += std::snprintf(full_line + pos, sizeof(full_line) - pos, "%s\n", msg);

    // Write under lock
    std::lock_guard<std::mutex> lock(mutex_);
    write_line(full_line, pos);
    ++message_count_;
}

// ===========================================================================
// File management
// ===========================================================================

void Logger::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (log_file_) {
        std::fflush(log_file_);
    }
    std::fflush(stdout);
}

std::string Logger::get_log_path() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return log_path_;
}

void Logger::shrink_log(size_t keep_bytes) {
    // Must be called with mutex_ held or from a context where the
    // file is not being written by other threads.

    if (!log_file_ || log_path_.empty()) return;
    if (current_size_ <= keep_bytes) return;

    // Read the last keep_bytes of the file
    std::fflush(log_file_);
    std::fclose(log_file_);

    std::vector<char> tail;
    {
        std::FILE* f = std::fopen(log_path_.c_str(), "r");
        if (!f) {
            log_file_ = std::fopen(log_path_.c_str(), "a");
            return;
        }

        std::fseek(f, 0, SEEK_END);
        long file_size = std::ftell(f);

        long offset = file_size - static_cast<long>(keep_bytes);
        if (offset < 0) offset = 0;

        std::fseek(f, offset, SEEK_SET);

        // Skip to next newline to avoid partial lines
        if (offset > 0) {
            int c;
            while ((c = std::fgetc(f)) != EOF && c != '\n') {}
        }

        long start = std::ftell(f);
        long remaining = file_size - start;
        if (remaining > 0) {
            tail.resize(static_cast<size_t>(remaining));
            size_t read_count = std::fread(tail.data(), 1, tail.size(), f);
            tail.resize(read_count);
        }

        std::fclose(f);
    }

    // Rewrite the file with only the tail
    {
        std::FILE* f = std::fopen(log_path_.c_str(), "w");
        if (f) {
            if (!tail.empty()) {
                std::fwrite(tail.data(), 1, tail.size(), f);
            }
            std::fclose(f);
        }
    }

    // Reopen for appending
    log_file_ = std::fopen(log_path_.c_str(), "a");
    if (log_file_) {
        std::fseek(log_file_, 0, SEEK_END);
        current_size_ = static_cast<size_t>(std::ftell(log_file_));
    } else {
        current_size_ = 0;
    }
}

void Logger::reopen() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (log_path_.empty()) return;

    if (log_file_) {
        std::fflush(log_file_);
        std::fclose(log_file_);
    }

    log_file_ = std::fopen(log_path_.c_str(), "a");
    if (log_file_) {
        std::fseek(log_file_, 0, SEEK_END);
        current_size_ = static_cast<size_t>(std::ftell(log_file_));
    } else {
        current_size_ = 0;
    }
}

void Logger::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (log_file_) {
        std::fflush(log_file_);
        std::fclose(log_file_);
        log_file_ = nullptr;
    }
    current_size_ = 0;
}

// ===========================================================================
// Statistics
// ===========================================================================

size_t Logger::get_file_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_size_;
}

uint64_t Logger::get_message_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return message_count_;
}

} // namespace flow

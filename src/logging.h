// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Simple logging subsystem for FlowCoin.
// Outputs to both a log file and stdout with timestamped, categorized messages.

#ifndef FLOWCOIN_LOGGING_H
#define FLOWCOIN_LOGGING_H

#include <cstdarg>
#include <string>

namespace flow {

enum LogLevel {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3,
};

/// Initialize the logging subsystem. Opens the log file for appending.
/// If path is empty, logs only to stdout.
void log_init(const std::string& log_file);

/// Shut down the logging subsystem. Flushes and closes the log file.
void log_shutdown();

/// Set the minimum log level. Messages below this level are suppressed.
void log_set_level(LogLevel level);

/// Write a log message with printf-style formatting.
void log_write(LogLevel level, const char* category, const char* fmt, ...);

/// Write a log message with a pre-built va_list.
void log_writev(LogLevel level, const char* category, const char* fmt, va_list args);

#define LogDebug(cat, ...) ::flow::log_write(::flow::LOG_DEBUG, cat, __VA_ARGS__)
#define LogInfo(cat, ...)  ::flow::log_write(::flow::LOG_INFO,  cat, __VA_ARGS__)
#define LogWarn(cat, ...)  ::flow::log_write(::flow::LOG_WARN,  cat, __VA_ARGS__)
#define LogError(cat, ...) ::flow::log_write(::flow::LOG_ERROR, cat, __VA_ARGS__)

} // namespace flow

#endif // FLOWCOIN_LOGGING_H

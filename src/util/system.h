// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// System-level utilities for FlowCoin: signal handling, PID files,
// process info, daemonization, environment queries, and shutdown coordination.

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace flow {
namespace sys {

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------

/// Callback type for signal handlers.
using SignalHandler = std::function<void(int)>;

/// Set a custom handler for a specific signal.
/// The handler is called from a dedicated signal-processing thread.
void set_signal_handler(int signal, SignalHandler handler);

/// Install default signal handlers:
///   SIGTERM, SIGINT -> request graceful shutdown
///   SIGHUP -> reopen log file (for log rotation)
///   SIGPIPE -> ignore (broken pipe on network I/O)
void install_default_handlers();

/// Block all signals in the calling thread.
/// Used to ensure only the signal-handler thread receives signals.
void block_all_signals();

// ---------------------------------------------------------------------------
// PID file management
// ---------------------------------------------------------------------------

/// Write the current process PID to a file.
/// @return true on success.
bool write_pid_file(const std::string& path);

/// Remove a PID file.
/// @return true on success.
bool remove_pid_file(const std::string& path);

/// Check if another instance is already running by examining a PID file.
/// Reads the PID from the file and checks if a process with that PID exists.
/// @return true if another instance appears to be running.
bool check_pid_file(const std::string& path);

/// Read the PID from a PID file.
/// @return The PID, or -1 on error.
int read_pid_file(const std::string& path);

// ---------------------------------------------------------------------------
// Process info
// ---------------------------------------------------------------------------

/// Get current process RSS (Resident Set Size) in bytes.
size_t get_memory_usage();

/// Get peak RSS in bytes (high watermark).
size_t get_peak_memory();

/// Get the number of CPU cores available.
int get_num_cores();

/// Get a platform description string, e.g. "Linux x86_64".
std::string get_platform();

/// Get the hostname of the system.
std::string get_hostname();

/// Get the current process PID.
int get_pid();

// ---------------------------------------------------------------------------
// Daemonize (Unix)
// ---------------------------------------------------------------------------

/// Fork the process into a background daemon.
/// The parent exits; the child continues as a daemon with:
///   - New session (setsid)
///   - stdin/stdout/stderr redirected to /dev/null
///   - Working directory set to /
/// @return true in the child (daemon), false in the parent.
bool daemonize();

// ---------------------------------------------------------------------------
// Environment and data directories
// ---------------------------------------------------------------------------

/// Get an environment variable value, or a default if not set.
std::string get_env(const std::string& name, const std::string& default_val = "");

/// Get the FlowCoin data directory.
/// Checks $FLOWCOIN_DATADIR first, then uses platform defaults:
///   Linux:  ~/.flowcoin
///   macOS:  ~/Library/Application Support/FlowCoin
std::string get_data_dir();

/// Get the path to the FlowCoin configuration file.
/// Returns get_data_dir() + "/flowcoin.conf"
std::string get_config_path();

/// Get the user's home directory.
std::string get_home_dir();

/// Expand tilde (~) in a path to the user's home directory.
std::string expand_path(const std::string& path);

// ---------------------------------------------------------------------------
// Time utilities (system-level)
// ---------------------------------------------------------------------------

/// Get current Unix timestamp in seconds.
int64_t get_time();

/// Get current time in milliseconds since epoch.
int64_t get_time_millis();

/// Get current time in microseconds since epoch.
int64_t get_time_micros();

/// Get monotonic clock time in microseconds (for elapsed time measurement).
int64_t get_monotonic_micros();

/// Format a Unix timestamp as "YYYY-MM-DD HH:MM:SS" in UTC.
std::string format_time(int64_t timestamp);

/// Format a duration in seconds as human-readable, e.g. "2h 30m 15s".
std::string format_duration(int64_t seconds);

/// Format bytes as human-readable, e.g. "1.23 GB".
std::string format_bytes(size_t bytes);

// ---------------------------------------------------------------------------
// ShutdownManager -- coordinates graceful shutdown
// ---------------------------------------------------------------------------

class ShutdownManager {
public:
    /// Request a graceful shutdown. Thread-safe, can be called from signal handlers.
    void request_shutdown();

    /// Check if shutdown has been requested.
    bool shutdown_requested() const {
        return shutdown_.load(std::memory_order_acquire);
    }

    /// Block until shutdown is requested.
    void wait_for_shutdown();

    /// Block until shutdown is requested, with a timeout in milliseconds.
    /// @return true if shutdown was requested, false if timeout expired.
    bool wait_for_shutdown(int64_t timeout_ms);

    /// Register a cleanup callback. Callbacks are called in reverse order
    /// (LIFO) when run_shutdown_callbacks() is called.
    void on_shutdown(std::function<void()> callback);

    /// Execute all registered shutdown callbacks in reverse order.
    /// Safe to call multiple times (callbacks are cleared after execution).
    void run_shutdown_callbacks();

    /// Get the global ShutdownManager instance.
    static ShutdownManager& instance();

private:
    std::atomic<bool> shutdown_{false};
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<std::function<void()>> callbacks_;
};

/// Convenience function: get the global shutdown manager.
ShutdownManager& shutdown();

/// Convenience: check if shutdown has been requested.
bool shutdown_requested();

/// Convenience: request shutdown.
void request_shutdown();

} // namespace sys
} // namespace flow

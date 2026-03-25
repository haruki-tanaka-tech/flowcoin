// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// System-level utilities shared across all FlowCoin modules.
// Provides application lifecycle management, thread naming, error
// handling, platform info, file descriptor management, and RNG seeding.

#ifndef FLOWCOIN_COMMON_SYSTEM_H
#define FLOWCOIN_COMMON_SYSTEM_H

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>
#include <vector>

namespace flow::common {

// ============================================================================
// Application lifecycle
// ============================================================================

/// Record the startup timestamp (called once from main).
void set_startup_time(int64_t time);

/// Get the startup timestamp.
int64_t get_startup_time();

/// Get seconds since startup.
int64_t get_uptime();

// ============================================================================
// Error handling and warnings
// ============================================================================

/// Format exception info for logging (handles nested exceptions).
std::string format_exception(const std::exception& e);

/// Print exception info to stderr.
void print_exception_info(const std::exception& e);

/// Set a global warning message (displayed by RPC getinfo).
void set_misc_warning(const std::string& warning);

/// Get the current global warning message.
std::string get_misc_warning();

/// Enable/disable abort-on-error for debugging.
void set_debug_break_on_error(bool enable);

/// Check if debug-break-on-error is enabled.
bool get_debug_break_on_error();

// ============================================================================
// Thread management
// ============================================================================

/// Set the name of the current thread (for debugging and logging).
/// Truncated to 15 characters on Linux (pthread_setname_np limit).
void set_thread_name(const std::string& name);

/// Get the name of the current thread.
std::string get_thread_name();

/// Rename the current thread to a name that includes an index,
/// e.g., "net-proc-3".
void set_indexed_thread_name(const std::string& base, int index);

// ============================================================================
// File descriptor management
// ============================================================================

/// Attempt to raise the open file descriptor limit.
/// Returns the new limit, or -1 on failure.
int set_fd_limit(int new_limit);

/// Get the current open file descriptor limit.
int get_fd_limit();

// ============================================================================
// Stack trace
// ============================================================================

/// Capture a stack trace of the current thread (for crash reports).
/// Returns a human-readable string with addresses and symbols (if available).
/// Falls back to a simple message if backtrace() is not available.
std::string get_stack_trace();

/// Install signal handlers for SIGSEGV, SIGABRT, etc.
/// that print a stack trace before exiting.
void install_crash_handlers();

// ============================================================================
// RNG seeding
// ============================================================================

/// Seed the process-local RNG from system entropy sources
/// (/dev/urandom, CryptGenRandom, getentropy, etc.).
/// Called once at startup.
void seed_rng_from_system();

// ============================================================================
// Locale
// ============================================================================

/// Set the process locale to "C" to ensure deterministic
/// number formatting and string comparison across platforms.
void set_locale();

// ============================================================================
// Platform information
// ============================================================================

struct PlatformInfo {
    std::string os_name;         // "Linux", "macOS", "Windows"
    std::string os_version;      // "6.5.0-generic", "14.0", "10.0.19045"
    std::string arch;            // "x86_64", "aarch64"
    std::string compiler;        // "GCC 13.2.0", "Clang 17.0.0"
    std::string compiler_version;
    int pointer_size = 0;        // 4 or 8
    bool is_64bit = false;
    size_t total_memory = 0;     // bytes
    size_t available_memory = 0; // bytes
    int cpu_cores = 0;           // logical cores
    int physical_cores = 0;      // physical cores
    std::string cpu_brand;
    std::string hostname;
    int pid = 0;
};

/// Gather platform information.
PlatformInfo get_platform_info();

/// Format platform info as a single-line summary.
std::string format_platform_summary();

// ============================================================================
// Directory utilities
// ============================================================================

/// Create the default data directory if it doesn't exist.
/// Returns true if directory exists or was successfully created.
bool ensure_data_dir(const std::string& path);

/// Get the default data directory path for the current platform.
/// Linux:   ~/.flowcoin
/// macOS:   ~/Library/Application Support/FlowCoin
/// Windows: %APPDATA%\FlowCoin
std::string get_default_data_dir();

/// Lock the data directory (create .lock file with advisory lock).
/// Returns false if another instance holds the lock.
bool lock_data_dir(const std::string& path);

/// Unlock the data directory.
void unlock_data_dir(const std::string& path);

} // namespace flow::common

#endif // FLOWCOIN_COMMON_SYSTEM_H

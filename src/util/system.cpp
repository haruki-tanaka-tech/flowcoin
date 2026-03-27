// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "system.h"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <process.h>
#include <psapi.h>
#else
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#endif

namespace flow {
namespace sys {

// ===========================================================================
// Signal handling
// ===========================================================================

// Map of registered signal handlers.
static std::mutex g_signal_mutex;
static std::map<int, SignalHandler> g_signal_handlers;

// C-level signal handler that dispatches to registered callbacks.
static void signal_dispatch(int signum) {
    std::lock_guard<std::mutex> lock(g_signal_mutex);
    auto it = g_signal_handlers.find(signum);
    if (it != g_signal_handlers.end()) {
        it->second(signum);
    }
}

void set_signal_handler(int signum, SignalHandler handler) {
    {
        std::lock_guard<std::mutex> lock(g_signal_mutex);
        g_signal_handlers[signum] = std::move(handler);
    }

#ifdef _WIN32
    signal(signum, signal_dispatch);
#else
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_dispatch;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(signum, &sa, nullptr);
#endif
}

void install_default_handlers() {
    // SIGTERM and SIGINT trigger graceful shutdown
    auto shutdown_handler = [](int) {
        ShutdownManager::instance().request_shutdown();
    };

    set_signal_handler(SIGTERM, shutdown_handler);
    set_signal_handler(SIGINT, shutdown_handler);

#ifndef _WIN32
    // SIGPIPE is ignored (broken pipe on network I/O is handled per-socket)
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGPIPE, &sa, nullptr);
#endif
}

void block_all_signals() {
#ifndef _WIN32
    sigset_t set;
    sigfillset(&set);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);
#endif
}

// ===========================================================================
// PID file management
// ===========================================================================

bool write_pid_file(const std::string& path) {
    std::FILE* f = std::fopen(path.c_str(), "w");
    if (!f) return false;
#ifdef _WIN32
    std::fprintf(f, "%d\n", static_cast<int>(_getpid()));
#else
    std::fprintf(f, "%d\n", getpid());
#endif
    std::fclose(f);
    return true;
}

bool remove_pid_file(const std::string& path) {
    return std::remove(path.c_str()) == 0 || errno == ENOENT;
}

int read_pid_file(const std::string& path) {
    std::FILE* f = std::fopen(path.c_str(), "r");
    if (!f) return -1;
    int pid = -1;
    if (std::fscanf(f, "%d", &pid) != 1) {
        pid = -1;
    }
    std::fclose(f);
    return pid;
}

bool check_pid_file(const std::string& path) {
    int pid = read_pid_file(path);
    if (pid <= 0) return false;

#ifdef _WIN32
    // Check if process exists using OpenProcess
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (h != nullptr) {
        CloseHandle(h);
        return true;
    }
    return false;
#else
    // Check if process exists
    if (kill(static_cast<pid_t>(pid), 0) == 0) {
        return true;   // process exists
    }
    if (errno == EPERM) {
        return true;   // process exists but we lack permission to signal it
    }
    return false;      // process does not exist
#endif
}

// ===========================================================================
// Process info
// ===========================================================================

size_t get_memory_usage() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return static_cast<size_t>(pmc.WorkingSetSize);
    }
    return 0;
#else
    // Read /proc/self/statm for RSS on Linux
    std::FILE* f = std::fopen("/proc/self/statm", "r");
    if (!f) return 0;

    long pages = 0;
    long rss = 0;
    if (std::fscanf(f, "%ld %ld", &pages, &rss) < 2) {
        std::fclose(f);
        return 0;
    }
    std::fclose(f);

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;

    return static_cast<size_t>(rss) * static_cast<size_t>(page_size);
#endif
}

size_t get_peak_memory() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return static_cast<size_t>(pmc.PeakWorkingSetSize);
    }
    return 0;
#else
    // Read VmHWM from /proc/self/status
    std::FILE* f = std::fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    size_t peak = 0;
    while (std::fgets(line, sizeof(line), f)) {
        long val;
        if (std::sscanf(line, "VmHWM: %ld kB", &val) == 1) {
            peak = static_cast<size_t>(val) * 1024;
            break;
        }
    }
    std::fclose(f);
    return peak;
#endif
}

int get_num_cores() {
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return static_cast<int>(si.dwNumberOfProcessors);
#else
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores <= 0) return 1;
    return static_cast<int>(cores);
#endif
}

std::string get_platform() {
#ifdef _WIN32
    return "Windows x86_64";
#else
    struct utsname info;
    if (uname(&info) != 0) return "Unknown";
    return std::string(info.sysname) + " " + info.machine;
#endif
}

std::string get_hostname() {
    char buf[256];
    if (gethostname(buf, sizeof(buf)) != 0) return "unknown";
    buf[sizeof(buf) - 1] = '\0';
    return std::string(buf);
}

int get_pid() {
#ifdef _WIN32
    return static_cast<int>(_getpid());
#else
    return static_cast<int>(getpid());
#endif
}

// ===========================================================================
// Daemonize
// ===========================================================================

bool daemonize() {
#ifdef _WIN32
    // Daemonization is not supported on Windows
    return false;
#else
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid > 0) {
        // Parent: exit
        _exit(0);
    }

    // Child: new session
    if (setsid() < 0) return false;

    // Fork again to prevent acquiring a controlling terminal
    pid = fork();
    if (pid < 0) return false;
    if (pid > 0) _exit(0);

    // Redirect stdin/stdout/stderr to /dev/null
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) close(devnull);
    }

    // Change working directory to /
    (void)chdir("/");

    // Reset file creation mask
    umask(0);

    return true;
#endif
}

// ===========================================================================
// Environment and data directories
// ===========================================================================

std::string get_env(const std::string& name, const std::string& default_val) {
    const char* val = getenv(name.c_str());
    if (val && val[0]) return std::string(val);
    return default_val;
}

std::string get_home_dir() {
#ifdef _WIN32
    const char* userprofile = getenv("USERPROFILE");
    if (userprofile && userprofile[0]) return std::string(userprofile);
    const char* homedrive = getenv("HOMEDRIVE");
    const char* homepath = getenv("HOMEPATH");
    if (homedrive && homepath) return std::string(homedrive) + std::string(homepath);
    return "C:\\";
#else
    const char* home = getenv("HOME");
    if (home && home[0]) return std::string(home);
    return "/root";
#endif
}

std::string get_data_dir() {
    // Check environment variable first
    std::string env_dir = get_env("FLOWCOIN_DATADIR");
    if (!env_dir.empty()) return env_dir;

#ifdef _WIN32
    const char* appdata = getenv("APPDATA");
    if (appdata && appdata[0]) return std::string(appdata) + "\\FlowCoin";
    return get_home_dir() + "\\FlowCoin";
#else
    // Platform default: ~/.flowcoin
    return get_home_dir() + "/.flowcoin";
#endif
}

std::string get_config_path() {
    return get_data_dir() + "/flowcoin.conf";
}

std::string expand_path(const std::string& path) {
    if (path.empty()) return path;
    if (path[0] == '~') {
        if (path.size() == 1 || path[1] == '/') {
            return get_home_dir() + path.substr(1);
        }
    }
    return path;
}

// ===========================================================================
// Time utilities
// ===========================================================================

int64_t get_time() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
}

int64_t get_time_millis() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
}

int64_t get_time_micros() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
}

int64_t get_monotonic_micros() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
}

std::string format_time(int64_t timestamp) {
    std::time_t t = static_cast<std::time_t>(timestamp);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &t);
#else
    gmtime_r(&t, &utc);
#endif

    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
                  utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
                  utc.tm_hour, utc.tm_min, utc.tm_sec);
    return std::string(buf);
}

std::string format_duration(int64_t seconds) {
    if (seconds < 0) seconds = -seconds;

    int64_t days = seconds / 86400;
    seconds %= 86400;
    int64_t hours = seconds / 3600;
    seconds %= 3600;
    int64_t minutes = seconds / 60;
    seconds %= 60;

    std::ostringstream ss;
    if (days > 0) ss << days << "d ";
    if (hours > 0 || days > 0) ss << hours << "h ";
    if (minutes > 0 || hours > 0 || days > 0) ss << minutes << "m ";
    ss << seconds << "s";
    return ss.str();
}

std::string format_bytes(size_t bytes) {
    char buf[64];
    if (bytes >= 1024ULL * 1024 * 1024 * 1024) {
        std::snprintf(buf, sizeof(buf), "%.2f TB",
                      static_cast<double>(bytes) / (1024.0 * 1024 * 1024 * 1024));
    } else if (bytes >= 1024ULL * 1024 * 1024) {
        std::snprintf(buf, sizeof(buf), "%.2f GB",
                      static_cast<double>(bytes) / (1024.0 * 1024 * 1024));
    } else if (bytes >= 1024ULL * 1024) {
        std::snprintf(buf, sizeof(buf), "%.2f MB",
                      static_cast<double>(bytes) / (1024.0 * 1024));
    } else if (bytes >= 1024) {
        std::snprintf(buf, sizeof(buf), "%.2f KB",
                      static_cast<double>(bytes) / 1024.0);
    } else {
        std::snprintf(buf, sizeof(buf), "%zu B", bytes);
    }
    return std::string(buf);
}

// ===========================================================================
// ShutdownManager
// ===========================================================================

void ShutdownManager::request_shutdown() {
    shutdown_.store(true, std::memory_order_release);
    cv_.notify_all();
}

void ShutdownManager::wait_for_shutdown() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this]() { return shutdown_.load(std::memory_order_acquire); });
}

bool ShutdownManager::wait_for_shutdown(int64_t timeout_ms) {
    std::unique_lock<std::mutex> lock(mutex_);
    return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this]() {
        return shutdown_.load(std::memory_order_acquire);
    });
}

void ShutdownManager::on_shutdown(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_.push_back(std::move(callback));
}

void ShutdownManager::run_shutdown_callbacks() {
    std::vector<std::function<void()>> cbs;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cbs = std::move(callbacks_);
        callbacks_.clear();
    }
    // Execute in reverse order (LIFO)
    for (auto it = cbs.rbegin(); it != cbs.rend(); ++it) {
        (*it)();
    }
}

ShutdownManager& ShutdownManager::instance() {
    static ShutdownManager mgr;
    return mgr;
}

// Convenience functions
ShutdownManager& shutdown() { return ShutdownManager::instance(); }
bool shutdown_requested() { return ShutdownManager::instance().shutdown_requested(); }
void request_shutdown() { ShutdownManager::instance().request_shutdown(); }

} // namespace sys
} // namespace flow

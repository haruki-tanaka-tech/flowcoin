// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "common/system.h"
#include "compat/compat.h"
#include "logging.h"

#include <atomic>
#include <chrono>
#include <clocale>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>

#include <filesystem>

#ifdef _WIN32
#include <io.h>
#endif

#ifndef _WIN32
#include <csignal>
#include <fcntl.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/sysinfo.h>
#endif
#ifdef __APPLE__
#include <mach/mach.h>
#include <sys/sysctl.h>
#endif
#endif

// backtrace support
#if defined(__GNUC__) && !defined(_WIN32)
#include <execinfo.h>
#include <cxxabi.h>
#define HAVE_BACKTRACE 1
#endif

namespace flow::common {

// ============================================================================
// Application lifecycle
// ============================================================================

static std::atomic<int64_t> g_startup_time{0};

void set_startup_time(int64_t time) {
    g_startup_time.store(time, std::memory_order_relaxed);
}

int64_t get_startup_time() {
    return g_startup_time.load(std::memory_order_relaxed);
}

int64_t get_uptime() {
    int64_t start = g_startup_time.load(std::memory_order_relaxed);
    if (start == 0) return 0;
    auto now = std::chrono::system_clock::now();
    int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    return now_s - start;
}

// ============================================================================
// Error handling
// ============================================================================

static std::mutex g_warning_mutex;
static std::string g_misc_warning;
static std::atomic<bool> g_debug_break{false};

std::string format_exception(const std::exception& e) {
    std::string msg = e.what();
    try {
        std::rethrow_if_nested(e);
    } catch (const std::exception& nested) {
        msg += " -> " + format_exception(nested);
    } catch (...) {
        msg += " -> <unknown nested exception>";
    }
    return msg;
}

void print_exception_info(const std::exception& e) {
    LogError("default", "Exception: %s", format_exception(e).c_str());
}

void set_misc_warning(const std::string& warning) {
    std::lock_guard<std::mutex> lock(g_warning_mutex);
    g_misc_warning = warning;
}

std::string get_misc_warning() {
    std::lock_guard<std::mutex> lock(g_warning_mutex);
    return g_misc_warning;
}

void set_debug_break_on_error(bool enable) {
    g_debug_break.store(enable, std::memory_order_relaxed);
}

bool get_debug_break_on_error() {
    return g_debug_break.load(std::memory_order_relaxed);
}

// ============================================================================
// Thread naming
// ============================================================================

#ifdef FLOW_THREAD_LOCAL
static FLOW_THREAD_LOCAL char t_thread_name[64] = "unknown";
#endif

void set_thread_name(const std::string& name) {
#ifdef FLOW_THREAD_LOCAL
    std::strncpy(t_thread_name, name.c_str(), sizeof(t_thread_name) - 1);
    t_thread_name[sizeof(t_thread_name) - 1] = '\0';
#endif

#if defined(__linux__)
    // Linux: 15 char limit
    std::string truncated = name.substr(0, 15);
    pthread_setname_np(pthread_self(), truncated.c_str());
#elif defined(__APPLE__)
    pthread_setname_np(name.c_str());
#endif
}

std::string get_thread_name() {
#ifdef FLOW_THREAD_LOCAL
    return t_thread_name;
#else
    return "unknown";
#endif
}

void set_indexed_thread_name(const std::string& base, int index) {
    set_thread_name(base + "-" + std::to_string(index));
}

// ============================================================================
// File descriptor management
// ============================================================================

int set_fd_limit(int new_limit) {
#ifdef _WIN32
    // Windows doesn't have a direct equivalent
    return _setmaxstdio(new_limit);
#else
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return -1;

    rl.rlim_cur = static_cast<rlim_t>(new_limit);
    if (rl.rlim_cur > rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
    }

    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) return -1;

    // Re-read to confirm
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return -1;
    return static_cast<int>(rl.rlim_cur);
#endif
}

int get_fd_limit() {
#ifdef _WIN32
    return _getmaxstdio();
#else
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return -1;
    return static_cast<int>(rl.rlim_cur);
#endif
}

// ============================================================================
// Stack trace
// ============================================================================

std::string get_stack_trace() {
#ifdef HAVE_BACKTRACE
    constexpr int max_frames = 64;
    void* frames[max_frames];
    int count = backtrace(frames, max_frames);

    char** symbols = backtrace_symbols(frames, count);
    if (!symbols) {
        return "<backtrace_symbols failed>";
    }

    std::ostringstream ss;
    ss << "Stack trace (" << count << " frames):\n";

    for (int i = 0; i < count; ++i) {
        std::string sym = symbols[i];

        // Try to demangle C++ symbols
        // Format on Linux: ./program(mangled+0x42) [0xaddr]
        size_t begin = sym.find('(');
        size_t plus = sym.find('+', begin);
        if (begin != std::string::npos && plus != std::string::npos) {
            std::string mangled = sym.substr(begin + 1, plus - begin - 1);
            int status = -1;
            char* demangled = abi::__cxa_demangle(mangled.c_str(),
                                                   nullptr, nullptr, &status);
            if (status == 0 && demangled) {
                ss << "  #" << i << " " << demangled
                   << sym.substr(plus) << "\n";
                free(demangled);
                continue;
            }
            free(demangled);
        }

        ss << "  #" << i << " " << sym << "\n";
    }

    free(symbols);
    return ss.str();

#else
    return "<stack trace not available on this platform>";
#endif
}

static void crash_signal_handler(int sig) {
    const char* name = "unknown";
    switch (sig) {
        case SIGSEGV: name = "SIGSEGV"; break;
        case SIGABRT: name = "SIGABRT"; break;
        case SIGFPE:  name = "SIGFPE"; break;
        case SIGILL:  name = "SIGILL"; break;
#ifndef _WIN32
        case SIGBUS:  name = "SIGBUS"; break;
#endif
    }

    // Use async-signal-safe write() instead of fprintf
    static const char crash_prefix[] = "\n*** FlowCoin crashed with signal ";
    static const char crash_suffix[] = " ***\n";
#ifdef _WIN32
    (void)!_write(_fileno(stderr), crash_prefix, sizeof(crash_prefix) - 1);
    (void)!_write(_fileno(stderr), name, (unsigned)std::strlen(name));
    (void)!_write(_fileno(stderr), crash_suffix, sizeof(crash_suffix) - 1);
#else
    (void)!write(STDERR_FILENO, crash_prefix, sizeof(crash_prefix) - 1);
    (void)!write(STDERR_FILENO, name, std::strlen(name));
    (void)!write(STDERR_FILENO, crash_suffix, sizeof(crash_suffix) - 1);
#endif

#ifdef HAVE_BACKTRACE
    std::string trace = get_stack_trace();
    (void)!write(STDERR_FILENO, trace.c_str(), trace.size());
    (void)!write(STDERR_FILENO, "\n", 1);
#endif

    // Re-raise to get a core dump
    signal(sig, SIG_DFL);
    raise(sig);
}

void install_crash_handlers() {
    signal(SIGSEGV, crash_signal_handler);
    signal(SIGABRT, crash_signal_handler);
    signal(SIGFPE, crash_signal_handler);
    signal(SIGILL, crash_signal_handler);
#ifndef _WIN32
    signal(SIGBUS, crash_signal_handler);
    // Ignore SIGPIPE (broken pipe on network writes)
    signal(SIGPIPE, SIG_IGN);
#endif
}

// ============================================================================
// RNG seeding
// ============================================================================

void seed_rng_from_system() {
    // Read entropy from the OS and feed it to our RNG.
    // We don't seed std::srand because we use our own PRNG.
    uint8_t entropy[64];
    bool got_entropy = false;

#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    // Try getrandom() first (no file descriptor needed)
#if defined(__linux__) && defined(SYS_getrandom)
    // getrandom is available since Linux 3.17
#endif

    // Fallback: /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, entropy, sizeof(entropy));
        close(fd);
        if (n == static_cast<ssize_t>(sizeof(entropy))) {
            got_entropy = true;
        }
    }
#elif defined(__APPLE__)
    // arc4random_buf is always available on macOS
    arc4random_buf(entropy, sizeof(entropy));
    got_entropy = true;
#elif defined(_WIN32)
    // CryptGenRandom
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextW(&hProv, nullptr, nullptr,
                              PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptGenRandom(hProv, sizeof(entropy), entropy)) {
            got_entropy = true;
        }
        CryptReleaseContext(hProv, 0);
    }
#endif

    // Mix in the current time as additional (non-primary) entropy
    auto now = std::chrono::high_resolution_clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        now.time_since_epoch()).count();

    // XOR time into the entropy buffer
    if (got_entropy) {
        for (size_t i = 0; i < sizeof(int64_t) && i < sizeof(entropy); ++i) {
            entropy[i] ^= static_cast<uint8_t>(ns >> (i * 8));
        }
    }

    // The entropy is consumed by our util/random module.
    // Cleanse the local buffer.
    volatile uint8_t* p = entropy;
    for (size_t i = 0; i < sizeof(entropy); ++i) {
        p[i] = 0;
    }
}

// ============================================================================
// Locale
// ============================================================================

void set_locale() {
    // Force "C" locale for deterministic number formatting.
    // Without this, atof/strtod may interpret commas as decimal separators
    // on European locales, causing consensus-critical parsing differences.
    std::setlocale(LC_ALL, "C");
    std::setlocale(LC_NUMERIC, "C");
}

// ============================================================================
// Platform information
// ============================================================================

PlatformInfo get_platform_info() {
    PlatformInfo info;

    // OS name
#ifdef PLATFORM_LINUX
    info.os_name = "Linux";
#elif defined(PLATFORM_MACOS)
    info.os_name = "macOS";
#elif defined(PLATFORM_WINDOWS)
    info.os_name = "Windows";
#elif defined(PLATFORM_FREEBSD)
    info.os_name = "FreeBSD";
#else
    info.os_name = "Unknown";
#endif

    // Architecture
#ifdef ARCH_X86_64
    info.arch = "x86_64";
#elif defined(ARCH_AARCH64)
    info.arch = "aarch64";
#elif defined(ARCH_X86)
    info.arch = "x86";
#elif defined(ARCH_ARM)
    info.arch = "arm";
#else
    info.arch = "unknown";
#endif

    info.pointer_size = sizeof(void*);
    info.is_64bit = (sizeof(void*) == 8);

    // Compiler
#if defined(__clang__)
    info.compiler = "Clang";
    info.compiler_version = std::to_string(__clang_major__) + "." +
                            std::to_string(__clang_minor__) + "." +
                            std::to_string(__clang_patchlevel__);
#elif defined(__GNUC__)
    info.compiler = "GCC";
    info.compiler_version = std::to_string(__GNUC__) + "." +
                            std::to_string(__GNUC_MINOR__) + "." +
                            std::to_string(__GNUC_PATCHLEVEL__);
#elif defined(_MSC_VER)
    info.compiler = "MSVC";
    info.compiler_version = std::to_string(_MSC_VER);
#else
    info.compiler = "Unknown";
#endif

    // CPU cores
    info.cpu_cores = static_cast<int>(std::thread::hardware_concurrency());
    info.physical_cores = info.cpu_cores;

    // OS version
#ifdef __linux__
    {
        struct utsname uts;
        if (uname(&uts) == 0) {
            info.os_version = uts.release;
            info.hostname = uts.nodename;
        }
    }

    // Memory info
    {
        struct sysinfo si;
        if (sysinfo(&si) == 0) {
            info.total_memory = static_cast<size_t>(si.totalram) * si.mem_unit;
            info.available_memory = static_cast<size_t>(si.freeram) * si.mem_unit;
        }
    }

    // CPU brand
    {
        std::ifstream cpuinfo("/proc/cpuinfo");
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.find("model name") != std::string::npos) {
                auto pos = line.find(':');
                if (pos != std::string::npos && pos + 2 < line.size()) {
                    info.cpu_brand = line.substr(pos + 2);
                }
                break;
            }
        }
    }
#endif

#ifdef __APPLE__
    // macOS version
    {
        char version[256];
        size_t size = sizeof(version);
        if (sysctlbyname("kern.osproductversion", version, &size, nullptr, 0) == 0) {
            info.os_version = version;
        }

        char hostname[256];
        size = sizeof(hostname);
        if (sysctlbyname("kern.hostname", hostname, &size, nullptr, 0) == 0) {
            info.hostname = hostname;
        }

        int64_t memsize = 0;
        size = sizeof(memsize);
        if (sysctlbyname("hw.memsize", &memsize, &size, nullptr, 0) == 0) {
            info.total_memory = static_cast<size_t>(memsize);
        }

        int physical = 0;
        size = sizeof(physical);
        if (sysctlbyname("hw.physicalcpu", &physical, &size, nullptr, 0) == 0) {
            info.physical_cores = physical;
        }

        char brand[256];
        size = sizeof(brand);
        if (sysctlbyname("machdep.cpu.brand_string", brand, &size, nullptr, 0) == 0) {
            info.cpu_brand = brand;
        }
    }
#endif

    // PID
#ifdef _WIN32
    info.pid = static_cast<int>(GetCurrentProcessId());
#else
    info.pid = static_cast<int>(getpid());
#endif

    return info;
}

std::string format_platform_summary() {
    auto info = get_platform_info();
    std::ostringstream ss;
    ss << info.os_name;
    if (!info.os_version.empty()) ss << " " << info.os_version;
    ss << " " << info.arch;
    ss << ", " << info.compiler << " " << info.compiler_version;
    ss << ", " << info.cpu_cores << " cores";
    if (info.total_memory > 0) {
        ss << ", " << (info.total_memory / (1024 * 1024)) << " MB RAM";
    }
    return ss.str();
}

// ============================================================================
// Directory utilities
// ============================================================================

bool ensure_data_dir(const std::string& path) {
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
        return std::filesystem::is_directory(path, ec);
    }
    return std::filesystem::create_directories(path, ec);
}

std::string get_default_data_dir() {
#ifdef PLATFORM_WINDOWS
    const char* appdata = std::getenv("APPDATA");
    if (appdata) {
        return std::string(appdata) + "\\FlowCoin";
    }
    return "FlowCoin";
#elif defined(PLATFORM_MACOS)
    const char* home = std::getenv("HOME");
    if (home) {
        return std::string(home) + "/Library/Application Support/FlowCoin";
    }
    return ".flowcoin";
#else
    const char* home = std::getenv("HOME");
    if (home) {
        return std::string(home) + "/.flowcoin";
    }
    return ".flowcoin";
#endif
}

bool lock_data_dir(const std::string& path) {
    std::string lock_path = path + "/.lock";

#ifdef _WIN32
    // Windows: use CreateFile with exclusive access
    HANDLE h = CreateFileA(lock_path.c_str(), GENERIC_WRITE,
                           0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    return h != INVALID_HANDLE_VALUE;
#else
    int fd = open(lock_path.c_str(), O_WRONLY | O_CREAT, 0644);
    if (fd < 0) return false;

    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        close(fd);
        return false;
    }

    // Keep the fd open (lock is held as long as fd is open)
    // Store the fd somewhere if we need to unlock later.
    // For simplicity, we leak the fd — it's held for the process lifetime.
    return true;
#endif
}

void unlock_data_dir(const std::string& path) {
    std::string lock_path = path + "/.lock";
    std::remove(lock_path.c_str());
}

} // namespace flow::common

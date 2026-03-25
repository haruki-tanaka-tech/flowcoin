// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Platform compatibility layer.
// Provides unified macros for platform detection, endianness, byte swapping,
// compiler hints, and portability shims. All FlowCoin modules include this
// header (directly or transitively) to ensure consistent cross-platform
// behavior on Linux, macOS, and Windows.

#ifndef FLOWCOIN_COMPAT_H
#define FLOWCOIN_COMPAT_H

#include <cstdint>
#include <cstddef>

// ============================================================================
// Platform detection
// ============================================================================

#if defined(_WIN32) || defined(_WIN64)
#define PLATFORM_WINDOWS 1
#define PLATFORM_NAME "Windows"
#elif defined(__APPLE__) && defined(__MACH__)
#define PLATFORM_MACOS 1
#define PLATFORM_NAME "macOS"
#elif defined(__linux__)
#define PLATFORM_LINUX 1
#define PLATFORM_NAME "Linux"
#elif defined(__FreeBSD__)
#define PLATFORM_FREEBSD 1
#define PLATFORM_NAME "FreeBSD"
#elif defined(__OpenBSD__)
#define PLATFORM_OPENBSD 1
#define PLATFORM_NAME "OpenBSD"
#else
#define PLATFORM_UNKNOWN 1
#define PLATFORM_NAME "Unknown"
#endif

// Architecture detection
#if defined(__x86_64__) || defined(_M_X64)
#define ARCH_X86_64 1
#define ARCH_NAME "x86_64"
#elif defined(__aarch64__) || defined(_M_ARM64)
#define ARCH_AARCH64 1
#define ARCH_NAME "aarch64"
#elif defined(__i386__) || defined(_M_IX86)
#define ARCH_X86 1
#define ARCH_NAME "x86"
#elif defined(__arm__) || defined(_M_ARM)
#define ARCH_ARM 1
#define ARCH_NAME "arm"
#elif defined(__riscv)
#define ARCH_RISCV 1
#define ARCH_NAME "riscv"
#else
#define ARCH_UNKNOWN 1
#define ARCH_NAME "unknown"
#endif

// Pointer size
#if defined(__LP64__) || defined(_WIN64) || defined(__x86_64__) || defined(__aarch64__)
#define POINTER_SIZE 8
#define IS_64BIT 1
#else
#define POINTER_SIZE 4
#define IS_64BIT 0
#endif

// ============================================================================
// Endianness
// ============================================================================

#if defined(__BYTE_ORDER__)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define PLATFORM_BIG_ENDIAN 1
#else
#define PLATFORM_LITTLE_ENDIAN 1
#endif
#elif defined(_WIN32)
// Windows is always little-endian on supported architectures
#define PLATFORM_LITTLE_ENDIAN 1
#else
// Default assumption (x86, ARM in LE mode)
#define PLATFORM_LITTLE_ENDIAN 1
#endif

// ============================================================================
// Byte swap intrinsics
// ============================================================================

#if defined(__GNUC__) || defined(__clang__)

inline uint16_t flow_bswap16(uint16_t x) { return __builtin_bswap16(x); }
inline uint32_t flow_bswap32(uint32_t x) { return __builtin_bswap32(x); }
inline uint64_t flow_bswap64(uint64_t x) { return __builtin_bswap64(x); }

#elif defined(_MSC_VER)

#include <stdlib.h>
inline uint16_t flow_bswap16(uint16_t x) { return _byteswap_ushort(x); }
inline uint32_t flow_bswap32(uint32_t x) { return _byteswap_ulong(x); }
inline uint64_t flow_bswap64(uint64_t x) { return _byteswap_uint64(x); }

#else

inline uint16_t flow_bswap16(uint16_t x) {
    return static_cast<uint16_t>((x >> 8) | (x << 8));
}
inline uint32_t flow_bswap32(uint32_t x) {
    x = ((x & 0xFF00FF00u) >> 8) | ((x & 0x00FF00FFu) << 8);
    return (x >> 16) | (x << 16);
}
inline uint64_t flow_bswap64(uint64_t x) {
    x = ((x & 0xFF00FF00FF00FF00ULL) >> 8) | ((x & 0x00FF00FF00FF00FFULL) << 8);
    x = ((x & 0xFFFF0000FFFF0000ULL) >> 16) | ((x & 0x0000FFFF0000FFFFULL) << 16);
    return (x >> 32) | (x << 32);
}

#endif

// ============================================================================
// Host-to-little-endian / Host-to-big-endian conversions
// ============================================================================

#ifdef PLATFORM_LITTLE_ENDIAN

inline uint16_t flow_htole16(uint16_t x) { return x; }
inline uint32_t flow_htole32(uint32_t x) { return x; }
inline uint64_t flow_htole64(uint64_t x) { return x; }
inline uint16_t flow_le16toh(uint16_t x) { return x; }
inline uint32_t flow_le32toh(uint32_t x) { return x; }
inline uint64_t flow_le64toh(uint64_t x) { return x; }

inline uint16_t flow_htobe16(uint16_t x) { return flow_bswap16(x); }
inline uint32_t flow_htobe32(uint32_t x) { return flow_bswap32(x); }
inline uint64_t flow_htobe64(uint64_t x) { return flow_bswap64(x); }
inline uint16_t flow_be16toh(uint16_t x) { return flow_bswap16(x); }
inline uint32_t flow_be32toh(uint32_t x) { return flow_bswap32(x); }
inline uint64_t flow_be64toh(uint64_t x) { return flow_bswap64(x); }

#else // Big endian

inline uint16_t flow_htole16(uint16_t x) { return flow_bswap16(x); }
inline uint32_t flow_htole32(uint32_t x) { return flow_bswap32(x); }
inline uint64_t flow_htole64(uint64_t x) { return flow_bswap64(x); }
inline uint16_t flow_le16toh(uint16_t x) { return flow_bswap16(x); }
inline uint32_t flow_le32toh(uint32_t x) { return flow_bswap32(x); }
inline uint64_t flow_le64toh(uint64_t x) { return flow_bswap64(x); }

inline uint16_t flow_htobe16(uint16_t x) { return x; }
inline uint32_t flow_htobe32(uint32_t x) { return x; }
inline uint64_t flow_htobe64(uint64_t x) { return x; }
inline uint16_t flow_be16toh(uint16_t x) { return x; }
inline uint32_t flow_be32toh(uint32_t x) { return x; }
inline uint64_t flow_be64toh(uint64_t x) { return x; }

#endif

// ============================================================================
// Read/write unaligned little-endian values from byte buffers
// ============================================================================

inline uint16_t read_le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) |
           (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t read_le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t read_le64(const uint8_t* p) {
    return static_cast<uint64_t>(p[0]) |
           (static_cast<uint64_t>(p[1]) << 8) |
           (static_cast<uint64_t>(p[2]) << 16) |
           (static_cast<uint64_t>(p[3]) << 24) |
           (static_cast<uint64_t>(p[4]) << 32) |
           (static_cast<uint64_t>(p[5]) << 40) |
           (static_cast<uint64_t>(p[6]) << 48) |
           (static_cast<uint64_t>(p[7]) << 56);
}

inline void write_le16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
}

inline void write_le32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

inline void write_le64(uint8_t* p, uint64_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
    p[4] = static_cast<uint8_t>(v >> 32);
    p[5] = static_cast<uint8_t>(v >> 40);
    p[6] = static_cast<uint8_t>(v >> 48);
    p[7] = static_cast<uint8_t>(v >> 56);
}

// ============================================================================
// Compiler hints
// ============================================================================

#if defined(__GNUC__) || defined(__clang__)
#define FLOW_LIKELY(x)   __builtin_expect(!!(x), 1)
#define FLOW_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define FLOW_ALIGN(x)    __attribute__((aligned(x)))
#define FLOW_NORETURN     __attribute__((noreturn))
#define FLOW_UNUSED       __attribute__((unused))
#define FLOW_NOINLINE     __attribute__((noinline))
#define FLOW_ALWAYS_INLINE __attribute__((always_inline)) inline
#define FLOW_PACKED       __attribute__((packed))
#define FLOW_PRINTF_FMT(fmt_idx, first_arg) \
    __attribute__((format(printf, fmt_idx, first_arg)))
#elif defined(_MSC_VER)
#define FLOW_LIKELY(x)   (x)
#define FLOW_UNLIKELY(x) (x)
#define FLOW_ALIGN(x)    __declspec(align(x))
#define FLOW_NORETURN     __declspec(noreturn)
#define FLOW_UNUSED
#define FLOW_NOINLINE     __declspec(noinline)
#define FLOW_ALWAYS_INLINE __forceinline
#define FLOW_PACKED
#define FLOW_PRINTF_FMT(fmt_idx, first_arg)
#else
#define FLOW_LIKELY(x)   (x)
#define FLOW_UNLIKELY(x) (x)
#define FLOW_ALIGN(x)
#define FLOW_NORETURN
#define FLOW_UNUSED
#define FLOW_NOINLINE
#define FLOW_ALWAYS_INLINE inline
#define FLOW_PACKED
#define FLOW_PRINTF_FMT(fmt_idx, first_arg)
#endif

// Thread-local storage
#define FLOW_THREAD_LOCAL thread_local

// ============================================================================
// Socket compatibility
// ============================================================================

#ifdef PLATFORM_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
#define INVALID_SOCKET_VALUE INVALID_SOCKET
#define SOCKET_ERROR_VALUE SOCKET_ERROR
inline int flow_closesocket(socket_t s) { return closesocket(s); }
inline int flow_socket_error() { return WSAGetLastError(); }
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
using socket_t = int;
#define INVALID_SOCKET_VALUE (-1)
#define SOCKET_ERROR_VALUE (-1)
inline int flow_closesocket(socket_t s) { return close(s); }
inline int flow_socket_error() { return errno; }
#endif

// Set socket to non-blocking mode
inline bool flow_set_nonblocking(socket_t s) {
#ifdef PLATFORM_WINDOWS
    u_long mode = 1;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags == -1) return false;
    return fcntl(s, F_SETFL, flags | O_NONBLOCK) != -1;
#endif
}

// ============================================================================
// Path separator
// ============================================================================

#ifdef PLATFORM_WINDOWS
constexpr char PATH_SEPARATOR = '\\';
constexpr const char* PATH_SEPARATOR_STR = "\\";
#else
constexpr char PATH_SEPARATOR = '/';
constexpr const char* PATH_SEPARATOR_STR = "/";
#endif

// ============================================================================
// Dynamic library loading
// ============================================================================

#ifdef PLATFORM_WINDOWS
#include <windows.h>
using dl_handle_t = HMODULE;
inline dl_handle_t flow_dlopen(const char* path) { return LoadLibraryA(path); }
inline void* flow_dlsym(dl_handle_t h, const char* sym) {
    return reinterpret_cast<void*>(GetProcAddress(h, sym));
}
inline void flow_dlclose(dl_handle_t h) { FreeLibrary(h); }
#else
#include <dlfcn.h>
using dl_handle_t = void*;
inline dl_handle_t flow_dlopen(const char* path) {
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
}
inline void* flow_dlsym(dl_handle_t h, const char* sym) { return dlsym(h, sym); }
inline void flow_dlclose(dl_handle_t h) { dlclose(h); }
#endif

// ============================================================================
// Miscellaneous portability
// ============================================================================

// Guaranteed page size (conservative estimate)
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

// Maximum path length
#ifdef PLATFORM_WINDOWS
#define FLOW_MAX_PATH MAX_PATH
#else
#include <limits.h>
#define FLOW_MAX_PATH PATH_MAX
#endif

#endif // FLOWCOIN_COMPAT_H

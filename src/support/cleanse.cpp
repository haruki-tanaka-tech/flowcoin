// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "support/cleanse.h"

#include <cstring>

// Check for explicit_bzero availability
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
#define HAVE_EXPLICIT_BZERO 1
#elif defined(__OpenBSD__) || defined(__FreeBSD__)
#define HAVE_EXPLICIT_BZERO 1
#endif

// Check for memset_s availability (C11 Annex K)
#if defined(__STDC_LIB_EXT1__)
#define HAVE_MEMSET_S 1
#endif

namespace flow {

void memory_cleanse(void* ptr, size_t len) {
    if (ptr == nullptr || len == 0) return;

#if defined(HAVE_EXPLICIT_BZERO)
    // Best option: explicit_bzero is specifically designed for this purpose.
    // It is guaranteed by the standard not to be optimized away.
    explicit_bzero(ptr, len);

#elif defined(HAVE_MEMSET_S)
    // C11 Annex K: memset_s is also guaranteed not to be optimized away.
    memset_s(ptr, len, 0, len);

#elif defined(_MSC_VER)
    // MSVC: SecureZeroMemory is guaranteed not to be optimized away.
    SecureZeroMemory(ptr, len);

#else
    // Fallback: Use volatile pointer to prevent optimization.
    // The compiler cannot prove that nothing reads through a volatile pointer,
    // so it must perform the writes.
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }

    // Additional barrier: an opaque function call that the compiler
    // cannot analyze across translation units.
    // The asm volatile acts as a compiler barrier.
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif

#endif
}

void cleanse_string(std::string& s) {
    if (!s.empty()) {
        // String data may be in SSO buffer or on heap.
        // We access through data() which returns a non-const pointer in C++17.
        memory_cleanse(s.data(), s.size());
        s.clear();
        // After clear(), the string may still hold the old buffer.
        // Shrink to force deallocation of any heap buffer.
        s.shrink_to_fit();
    }
}

bool timing_safe_equal(const void* a, const void* b, size_t len) {
    const volatile uint8_t* pa = static_cast<const volatile uint8_t*>(a);
    const volatile uint8_t* pb = static_cast<const volatile uint8_t*>(b);

    // Accumulate XOR of all byte pairs. If result is 0, all bytes matched.
    // The loop always runs to completion regardless of mismatches,
    // ensuring constant execution time.
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= pa[i] ^ pb[i];
    }

    // Convert to bool without branching on the actual diff value
    // (compiler should emit: test + setz or equivalent)
    return diff == 0;
}

} // namespace flow

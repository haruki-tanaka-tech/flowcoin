// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// STL-compatible allocators for sensitive data.
// SecureAllocator uses locked memory and securely wipes on deallocation.
// ZeroedAllocator ensures memory is wiped on deallocation but does not
// lock pages (lower overhead, suitable for non-secret data that should
// still be cleaned up).

#ifndef FLOWCOIN_SUPPORT_ALLOCATORS_H
#define FLOWCOIN_SUPPORT_ALLOCATORS_H

#include "support/cleanse.h"
#include "support/lockedpool.h"

#include <cstddef>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace flow {

// ============================================================================
// SecureAllocator — locked pages + secure wipe on deallocation
// ============================================================================

template<typename T>
struct SecureAllocator {
    using value_type = T;
    using size_type = size_t;
    using difference_type = std::ptrdiff_t;
    using propagate_on_container_move_assignment = std::true_type;
    using is_always_equal = std::true_type;

    SecureAllocator() noexcept = default;

    template<typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(size_t n) {
        if (n > std::numeric_limits<size_t>::max() / sizeof(T)) {
            throw std::bad_alloc();
        }
        size_t bytes = n * sizeof(T);
        void* p = locked_pool().allocate(bytes);
        if (!p) {
            throw std::bad_alloc();
        }
        return static_cast<T*>(p);
    }

    void deallocate(T* p, size_t n) noexcept {
        if (p) {
            locked_pool().deallocate(p, n * sizeof(T));
        }
    }

    template<typename U>
    bool operator==(const SecureAllocator<U>&) const noexcept { return true; }

    template<typename U>
    bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};

// ============================================================================
// ZeroedAllocator — standard allocation + secure wipe on deallocation
// ============================================================================

template<typename T>
struct ZeroedAllocator {
    using value_type = T;
    using size_type = size_t;
    using difference_type = std::ptrdiff_t;
    using propagate_on_container_move_assignment = std::true_type;
    using is_always_equal = std::true_type;

    ZeroedAllocator() noexcept = default;

    template<typename U>
    ZeroedAllocator(const ZeroedAllocator<U>&) noexcept {}

    T* allocate(size_t n) {
        if (n > std::numeric_limits<size_t>::max() / sizeof(T)) {
            throw std::bad_alloc();
        }
        T* p = static_cast<T*>(std::malloc(n * sizeof(T)));
        if (!p) {
            throw std::bad_alloc();
        }
        std::memset(p, 0, n * sizeof(T));
        return p;
    }

    void deallocate(T* p, size_t n) noexcept {
        if (p) {
            memory_cleanse(p, n * sizeof(T));
            std::free(p);
        }
    }

    template<typename U>
    bool operator==(const ZeroedAllocator<U>&) const noexcept { return true; }

    template<typename U>
    bool operator!=(const ZeroedAllocator<U>&) const noexcept { return false; }
};

// ============================================================================
// Type aliases for common secure containers
// ============================================================================

/// String type backed by locked memory.
/// Use for: passphrases, mnemonics, WIF keys, anything typed by users.
using SecureString = std::basic_string<char, std::char_traits<char>,
                                        SecureAllocator<char>>;

/// Vector type backed by locked memory.
/// Use for: raw private key bytes, seed material, decrypted data.
template<typename T>
using SecureVector = std::vector<T, SecureAllocator<T>>;

/// String type that zeroes on deallocation but uses normal heap.
/// Use for: log messages that might contain addresses, RPC auth tokens.
using CleanString = std::basic_string<char, std::char_traits<char>,
                                       ZeroedAllocator<char>>;

/// Vector type that zeroes on deallocation but uses normal heap.
template<typename T>
using CleanVector = std::vector<T, ZeroedAllocator<T>>;

// ============================================================================
// Utility: convert between secure and standard string types
// ============================================================================

inline SecureString to_secure(const std::string& s) {
    return SecureString(s.begin(), s.end());
}

inline std::string from_secure(const SecureString& s) {
    return std::string(s.begin(), s.end());
}

} // namespace flow

#endif // FLOWCOIN_SUPPORT_ALLOCATORS_H

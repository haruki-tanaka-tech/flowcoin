// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Secure memory wiping utilities.
// Guarantees that sensitive data (private keys, seeds, passphrases)
// is actually cleared from memory and not optimized away by the compiler.
// Also provides constant-time comparison to prevent timing side-channels.

#ifndef FLOWCOIN_SUPPORT_CLEANSE_H
#define FLOWCOIN_SUPPORT_CLEANSE_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace flow {

/// Securely wipe memory. This function is guaranteed not to be optimized
/// away by the compiler, even if the memory is not subsequently read.
/// Uses explicit_bzero() where available, otherwise volatile writes.
void memory_cleanse(void* ptr, size_t len);

/// Securely wipe a std::string's internal buffer, then clear it.
void cleanse_string(std::string& s);

/// Securely wipe a vector's internal buffer, then clear it.
template<typename T>
void cleanse_vector(std::vector<T>& v) {
    if (!v.empty()) {
        memory_cleanse(v.data(), v.size() * sizeof(T));
        v.clear();
    }
}

/// Constant-time comparison of two byte buffers.
/// Returns true if all bytes are equal, false otherwise.
/// Execution time does not depend on which bytes differ,
/// preventing timing side-channel attacks.
bool timing_safe_equal(const void* a, const void* b, size_t len);

/// Constant-time comparison of two byte arrays (template for Blob types).
template<size_t N>
bool timing_safe_equal_fixed(const uint8_t (&a)[N], const uint8_t (&b)[N]) {
    return timing_safe_equal(a, b, N);
}

/// Secure zero-fill of a fixed-size array.
template<typename T, size_t N>
void cleanse_array(T (&arr)[N]) {
    memory_cleanse(arr, sizeof(arr));
}

} // namespace flow

#endif // FLOWCOIN_SUPPORT_CLEANSE_H

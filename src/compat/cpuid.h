// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// CPU feature detection for selecting optimized code paths at runtime.
// Detects SSE, AVX, AES-NI, POPCNT, BMI2, and other instruction set
// extensions. Used by the training engine and crypto routines to pick
// the fastest available implementation.

#ifndef FLOWCOIN_COMPAT_CPUID_H
#define FLOWCOIN_COMPAT_CPUID_H

#include <cstdint>
#include <string>

namespace flow::compat {

// ============================================================================
// CPU feature flags
// ============================================================================

struct CPUFeatures {
    // x86 SIMD extensions
    bool sse2 = false;
    bool sse3 = false;
    bool ssse3 = false;
    bool sse4_1 = false;
    bool sse4_2 = false;
    bool avx = false;
    bool avx2 = false;
    bool avx512f = false;
    bool avx512bw = false;
    bool avx512vl = false;
    bool avx512_vnni = false;
    bool f16c = false;
    bool fma = false;

    // Crypto acceleration
    bool aes_ni = false;
    bool sha_ext = false;    // SHA-1/SHA-256 hardware
    bool pclmulqdq = false;  // carry-less multiplication (for GCM)

    // Bit manipulation
    bool bmi1 = false;
    bool bmi2 = false;
    bool popcnt = false;
    bool lzcnt = false;

    // ARM extensions (populated on aarch64)
    bool neon = false;
    bool arm_crc32 = false;
    bool arm_aes = false;
    bool arm_sha2 = false;
    bool arm_sve = false;

    // Cache and topology
    int cache_line_size = 64;
    int l1_data_cache_kb = 0;
    int l2_cache_kb = 0;
    int l3_cache_kb = 0;
    int num_physical_cores = 1;
    int num_logical_cores = 1;

    // CPU identity
    std::string vendor;   // "GenuineIntel", "AuthenticAMD", etc.
    std::string brand;    // Human-readable CPU name
    int family = 0;
    int model = 0;
    int stepping = 0;

    /// Populate all fields by querying the CPU.
    void detect();

    /// Return a human-readable summary of detected features.
    std::string to_string() const;

    /// Check if the CPU meets minimum requirements for FlowCoin.
    /// Requires: SSE2 (x86) or NEON (ARM), plus 64-bit pointers.
    bool meets_minimum_requirements() const;

    /// Get the singleton instance (detected once on first access).
    static const CPUFeatures& get();
};

} // namespace flow::compat

#endif // FLOWCOIN_COMPAT_CPUID_H

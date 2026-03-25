// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "compat/cpuid.h"
#include "compat/compat.h"

#include <cstring>
#include <sstream>
#include <thread>

#if defined(ARCH_X86_64) || defined(ARCH_X86)
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

#ifdef PLATFORM_LINUX
#include <fstream>
#endif

#ifdef PLATFORM_MACOS
#include <sys/sysctl.h>
#endif

namespace flow::compat {

// ============================================================================
// x86/x86_64 CPUID helpers
// ============================================================================

#if defined(ARCH_X86_64) || defined(ARCH_X86)

struct CpuidResult {
    uint32_t eax, ebx, ecx, edx;
};

static CpuidResult cpuid(uint32_t leaf, uint32_t subleaf = 0) {
    CpuidResult r{};
#ifdef _MSC_VER
    int regs[4];
    __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
    r.eax = static_cast<uint32_t>(regs[0]);
    r.ebx = static_cast<uint32_t>(regs[1]);
    r.ecx = static_cast<uint32_t>(regs[2]);
    r.edx = static_cast<uint32_t>(regs[3]);
#else
    __cpuid_count(leaf, subleaf, r.eax, r.ebx, r.ecx, r.edx);
#endif
    return r;
}

static uint64_t xgetbv(uint32_t xcr) {
#ifdef _MSC_VER
    return _xgetbv(xcr);
#else
    uint32_t lo, hi;
    __asm__ __volatile__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(xcr));
    return (static_cast<uint64_t>(hi) << 32) | lo;
#endif
}

static void detect_x86(CPUFeatures& f) {
    // Get max standard leaf
    auto leaf0 = cpuid(0);
    uint32_t max_leaf = leaf0.eax;

    // Vendor string
    char vendor[13];
    std::memcpy(vendor + 0, &leaf0.ebx, 4);
    std::memcpy(vendor + 4, &leaf0.edx, 4);
    std::memcpy(vendor + 8, &leaf0.ecx, 4);
    vendor[12] = '\0';
    f.vendor = vendor;

    if (max_leaf < 1) return;

    // Leaf 1: basic feature bits
    auto leaf1 = cpuid(1);

    f.family = ((leaf1.eax >> 8) & 0xF) + ((leaf1.eax >> 20) & 0xFF);
    f.model = ((leaf1.eax >> 4) & 0xF) | (((leaf1.eax >> 16) & 0xF) << 4);
    f.stepping = leaf1.eax & 0xF;

    f.sse2    = (leaf1.edx >> 26) & 1;
    f.sse3    = (leaf1.ecx >> 0) & 1;
    f.ssse3   = (leaf1.ecx >> 9) & 1;
    f.sse4_1  = (leaf1.ecx >> 19) & 1;
    f.sse4_2  = (leaf1.ecx >> 20) & 1;
    f.popcnt  = (leaf1.ecx >> 23) & 1;
    f.aes_ni  = (leaf1.ecx >> 25) & 1;
    f.pclmulqdq = (leaf1.ecx >> 1) & 1;
    f.f16c    = (leaf1.ecx >> 29) & 1;
    f.fma     = (leaf1.ecx >> 12) & 1;

    // Check OS support for AVX (XSAVE + OSXSAVE)
    bool os_avx = false;
    if ((leaf1.ecx >> 27) & 1) {  // OSXSAVE
        uint64_t xcr0 = xgetbv(0);
        os_avx = (xcr0 & 0x6) == 0x6;  // XMM + YMM state
    }

    f.avx = os_avx && ((leaf1.ecx >> 28) & 1);

    // Leaf 7: extended feature bits
    if (max_leaf >= 7) {
        auto leaf7 = cpuid(7, 0);
        f.bmi1   = (leaf7.ebx >> 3) & 1;
        f.avx2   = os_avx && ((leaf7.ebx >> 5) & 1);
        f.bmi2   = (leaf7.ebx >> 8) & 1;
        f.sha_ext = (leaf7.ebx >> 29) & 1;

        // AVX-512 requires OS support for ZMM state (xcr0 bits 5,6,7)
        bool os_avx512 = false;
        if (os_avx) {
            uint64_t xcr0 = xgetbv(0);
            os_avx512 = (xcr0 & 0xE0) == 0xE0;
        }

        f.avx512f   = os_avx512 && ((leaf7.ebx >> 16) & 1);
        f.avx512bw  = os_avx512 && ((leaf7.ebx >> 30) & 1);
        f.avx512vl  = os_avx512 && ((leaf7.ebx >> 31) & 1);
        f.avx512_vnni = os_avx512 && ((leaf7.ecx >> 11) & 1);
    }

    // Extended leaves for brand string
    auto ext0 = cpuid(0x80000000);
    uint32_t max_ext = ext0.eax;
    if (max_ext >= 0x80000004) {
        char brand[49];
        auto b2 = cpuid(0x80000002);
        auto b3 = cpuid(0x80000003);
        auto b4 = cpuid(0x80000004);
        std::memcpy(brand + 0,  &b2.eax, 16);
        std::memcpy(brand + 16, &b3.eax, 16);
        std::memcpy(brand + 32, &b4.eax, 16);
        brand[48] = '\0';
        f.brand = brand;
        // Trim leading spaces
        size_t start = f.brand.find_first_not_of(' ');
        if (start != std::string::npos) {
            f.brand = f.brand.substr(start);
        }
    }

    // Leaf 0x80000001: extended features
    if (max_ext >= 0x80000001) {
        auto ext1 = cpuid(0x80000001);
        f.lzcnt = (ext1.ecx >> 5) & 1;
    }

    // Cache line size from leaf 1 (CLFLUSH line size * 8)
    uint32_t clflush = ((leaf1.ebx >> 8) & 0xFF) * 8;
    if (clflush > 0) {
        f.cache_line_size = static_cast<int>(clflush);
    }

    // Try leaf 4 for cache sizes
    if (max_leaf >= 4) {
        for (uint32_t idx = 0; idx < 32; ++idx) {
            auto c = cpuid(4, idx);
            uint32_t type = c.eax & 0x1F;
            if (type == 0) break;  // No more caches

            uint32_t ways = ((c.ebx >> 22) & 0x3FF) + 1;
            uint32_t partitions = ((c.ebx >> 12) & 0x3FF) + 1;
            uint32_t line_size = (c.ebx & 0xFFF) + 1;
            uint32_t sets = c.ecx + 1;
            uint32_t total_kb = (ways * partitions * line_size * sets) / 1024;

            uint32_t level = (c.eax >> 5) & 0x7;
            if (level == 1 && (type == 1 || type == 3)) {
                f.l1_data_cache_kb = static_cast<int>(total_kb);
            } else if (level == 2) {
                f.l2_cache_kb = static_cast<int>(total_kb);
            } else if (level == 3) {
                f.l3_cache_kb = static_cast<int>(total_kb);
            }
        }
    }
}

#endif // x86

// ============================================================================
// ARM feature detection (Linux via /proc/cpuinfo or HWCAP)
// ============================================================================

#if defined(ARCH_AARCH64) || defined(ARCH_ARM)

static void detect_arm(CPUFeatures& f) {
    f.vendor = "ARM";

#ifdef PLATFORM_LINUX
    // Read /proc/cpuinfo for feature flags
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo.is_open()) {
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.find("Features") != std::string::npos ||
                line.find("features") != std::string::npos) {
                f.neon = line.find("neon") != std::string::npos ||
                         line.find("asimd") != std::string::npos;
                f.arm_crc32 = line.find("crc32") != std::string::npos;
                f.arm_aes = line.find("aes") != std::string::npos;
                f.arm_sha2 = line.find("sha2") != std::string::npos;
                f.arm_sve = line.find("sve") != std::string::npos;
            }
            if (line.find("model name") != std::string::npos ||
                line.find("Hardware") != std::string::npos) {
                auto pos = line.find(':');
                if (pos != std::string::npos && pos + 2 < line.size()) {
                    f.brand = line.substr(pos + 2);
                }
            }
        }
    }
#endif

#ifdef ARCH_AARCH64
    // NEON is mandatory on aarch64
    f.neon = true;
#endif
}

#endif // ARM

// ============================================================================
// Core count detection
// ============================================================================

static void detect_core_count(CPUFeatures& f) {
    f.num_logical_cores = static_cast<int>(std::thread::hardware_concurrency());
    if (f.num_logical_cores < 1) f.num_logical_cores = 1;

    // Estimate physical cores (heuristic: assume 2 threads per core for HT/SMT)
    f.num_physical_cores = f.num_logical_cores;

#ifdef PLATFORM_LINUX
    // Try to read from /sys for accurate physical core count
    std::ifstream core_file("/sys/devices/system/cpu/cpu0/topology/core_siblings_list");
    if (core_file.is_open()) {
        std::string siblings;
        std::getline(core_file, siblings);
        // If siblings list contains a range (e.g., "0-1"), divide by 2
        if (siblings.find('-') != std::string::npos ||
            siblings.find(',') != std::string::npos) {
            // Count commas + 1 for number of siblings
            int sib_count = 1;
            for (char c : siblings) {
                if (c == ',') sib_count++;
            }
            if (siblings.find('-') != std::string::npos && sib_count == 1) {
                sib_count = 2;  // Range like "0-1"
            }
            if (sib_count > 1) {
                f.num_physical_cores = f.num_logical_cores / sib_count;
            }
        }
    }
#endif

#ifdef PLATFORM_MACOS
    int physical = 0;
    size_t size = sizeof(physical);
    if (sysctlbyname("hw.physicalcpu", &physical, &size, nullptr, 0) == 0 && physical > 0) {
        f.num_physical_cores = physical;
    }
#endif

    if (f.num_physical_cores < 1) f.num_physical_cores = 1;
}

// ============================================================================
// CPUFeatures::detect
// ============================================================================

void CPUFeatures::detect() {
#if defined(ARCH_X86_64) || defined(ARCH_X86)
    detect_x86(*this);
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
    detect_arm(*this);
#else
    vendor = "unknown";
    brand = "unknown";
#endif

    detect_core_count(*this);
}

// ============================================================================
// CPUFeatures::to_string
// ============================================================================

std::string CPUFeatures::to_string() const {
    std::ostringstream ss;
    ss << "CPU: " << brand << "\n";
    ss << "Vendor: " << vendor;
    if (family > 0) {
        ss << " (family " << family << " model " << model
           << " stepping " << stepping << ")";
    }
    ss << "\n";
    ss << "Cores: " << num_physical_cores << " physical, "
       << num_logical_cores << " logical\n";
    ss << "Cache line: " << cache_line_size << " bytes";
    if (l1_data_cache_kb > 0) ss << ", L1d=" << l1_data_cache_kb << "K";
    if (l2_cache_kb > 0)      ss << ", L2=" << l2_cache_kb << "K";
    if (l3_cache_kb > 0)      ss << ", L3=" << l3_cache_kb << "K";
    ss << "\n";

    ss << "Features:";
    // x86
    if (sse2)     ss << " SSE2";
    if (sse3)     ss << " SSE3";
    if (ssse3)    ss << " SSSE3";
    if (sse4_1)   ss << " SSE4.1";
    if (sse4_2)   ss << " SSE4.2";
    if (avx)      ss << " AVX";
    if (avx2)     ss << " AVX2";
    if (avx512f)  ss << " AVX-512F";
    if (avx512bw) ss << " AVX-512BW";
    if (avx512vl) ss << " AVX-512VL";
    if (avx512_vnni) ss << " AVX-512VNNI";
    if (f16c)     ss << " F16C";
    if (fma)      ss << " FMA";
    if (aes_ni)   ss << " AES-NI";
    if (sha_ext)  ss << " SHA";
    if (pclmulqdq) ss << " PCLMULQDQ";
    if (bmi1)     ss << " BMI1";
    if (bmi2)     ss << " BMI2";
    if (popcnt)   ss << " POPCNT";
    if (lzcnt)    ss << " LZCNT";
    // ARM
    if (neon)       ss << " NEON";
    if (arm_crc32)  ss << " CRC32";
    if (arm_aes)    ss << " ARM-AES";
    if (arm_sha2)   ss << " ARM-SHA2";
    if (arm_sve)    ss << " SVE";
    ss << "\n";

    return ss.str();
}

// ============================================================================
// CPUFeatures::meets_minimum_requirements
// ============================================================================

bool CPUFeatures::meets_minimum_requirements() const {
#if defined(ARCH_X86_64) || defined(ARCH_X86)
    // SSE2 is mandatory on x86_64 (part of the ABI)
    if (!sse2) return false;
#elif defined(ARCH_AARCH64)
    // NEON is mandatory on aarch64
    if (!neon) return false;
#endif

    // Require 64-bit
#if !IS_64BIT
    return false;
#endif

    return true;
}

// ============================================================================
// CPUFeatures::get (singleton)
// ============================================================================

const CPUFeatures& CPUFeatures::get() {
    static CPUFeatures instance = []() {
        CPUFeatures f;
        f.detect();
        return f;
    }();
    return instance;
}

} // namespace flow::compat

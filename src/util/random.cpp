// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "random.h"

#include "../hash/keccak.h"

#include "../logging.h"

#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>
// RtlGenRandom is exported from advapi32.dll as SystemFunction036.
// Not all MinGW versions declare it, so we declare it manually.
extern "C" BOOLEAN NTAPI SystemFunction036(PVOID, ULONG);
#define RtlGenRandom SystemFunction036
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

namespace flow {

// ===========================================================================
// Raw entropy functions
// ===========================================================================

#ifdef _WIN32

void GetRandBytes(uint8_t* buf, size_t len) {
    // Use RtlGenRandom (SystemFunction036) which is simpler and always available.
    // Defined in <ntsecapi.h> but we declare it directly to avoid header issues.
    if (!RtlGenRandom(buf, static_cast<ULONG>(len))) {
        LogFatal("default", "RtlGenRandom failed");
        std::abort();
    }
}

#else // !_WIN32

static int GetUrandomFD() {
    static int fd = -1;
    if (fd == -1) {
        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            LogFatal("default", "failed to open /dev/urandom: %s",
                     std::strerror(errno));
            std::abort();
        }
    }
    return fd;
}

void GetRandBytes(uint8_t* buf, size_t len) {
    int fd = GetUrandomFD();
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            LogFatal("default", "read from /dev/urandom failed: %s",
                     std::strerror(errno));
            std::abort();
        }
        if (n == 0) {
            LogFatal("default", "/dev/urandom returned EOF");
            std::abort();
        }
        total += static_cast<size_t>(n);
    }
}

#endif // _WIN32

uint64_t GetRandUint64() {
    uint64_t v;
    GetRandBytes(reinterpret_cast<uint8_t*>(&v), sizeof(v));
    return v;
}

uint32_t GetRandUint32() {
    uint32_t v;
    GetRandBytes(reinterpret_cast<uint8_t*>(&v), sizeof(v));
    return v;
}

uint256 GetRandUint256() {
    uint256 v;
    GetRandBytes(v.data(), uint256::size());
    return v;
}

uint64_t GetRand(uint64_t max) {
    if (max == 0) return 0;
    if (max == 1) return 0;

    // Rejection sampling to avoid modulo bias.
    // Find the largest multiple of max that fits in uint64_t.
    uint64_t limit = (UINT64_MAX / max) * max;
    uint64_t r;
    do {
        r = GetRandUint64();
    } while (r >= limit);
    return r % max;
}

uint64_t GetRandRange(uint64_t min, uint64_t max) {
    if (min >= max) return min;
    return min + GetRand(max - min + 1);
}

uint256 GetRandHash() {
    return GetRandUint256();
}

bool GetRandBool(double p) {
    if (p <= 0.0) return false;
    if (p >= 1.0) return true;
    // Convert uint64 to double in [0, 1)
    uint64_t r = GetRandUint64();
    double d = static_cast<double>(r) / static_cast<double>(UINT64_MAX);
    return d < p;
}

// ===========================================================================
// CSPRNG
// ===========================================================================

CSPRNG::CSPRNG() {
    seed_from_system();
}

CSPRNG::CSPRNG(const uint256& seed) {
    std::memcpy(state_, seed.data(), 32);
    buf_pos_ = 32;  // force refill on first use
}

CSPRNG::CSPRNG(const uint8_t* seed_data, size_t seed_len) {
    // Hash the seed to fill the state
    if (seed_len >= 32) {
        std::memcpy(state_, seed_data, 32);
    } else {
        std::memset(state_, 0, 32);
        std::memcpy(state_, seed_data, seed_len);
    }
    // Mix in with keccak to spread entropy
    uint256 mixed = keccak256(state_, 32);
    std::memcpy(state_, mixed.data(), 32);
    buf_pos_ = 32;
}

void CSPRNG::seed_from_system() {
    // Gather entropy from multiple sources
    uint8_t entropy[96];

    // Source 1: /dev/urandom (32 bytes)
    GetRandBytes(entropy, 32);

    // Source 2: high-resolution timestamps (16 bytes)
    auto now = std::chrono::high_resolution_clock::now();
    auto epoch = now.time_since_epoch();
    auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(epoch).count();
    std::memcpy(entropy + 32, &nanos, 8);

    auto steady = std::chrono::steady_clock::now().time_since_epoch();
    auto steady_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(steady).count();
    std::memcpy(entropy + 40, &steady_ns, 8);

    // Source 3: PID (16 bytes)
#ifdef _WIN32
    DWORD pid = GetCurrentProcessId();
    std::memcpy(entropy + 48, &pid, sizeof(pid));
    DWORD ppid = 0;  // No easy equivalent on Windows
    std::memcpy(entropy + 48 + sizeof(pid), &ppid, sizeof(ppid));
#else
    pid_t pid = getpid();
    std::memcpy(entropy + 48, &pid, sizeof(pid));
    pid_t ppid = getppid();
    std::memcpy(entropy + 48 + sizeof(pid), &ppid, sizeof(ppid));
#endif

    // Source 4: more urandom (32 bytes)
    GetRandBytes(entropy + 64, 32);

    // Mix all entropy with keccak256
    uint256 mixed = keccak256(entropy, sizeof(entropy));
    std::memcpy(state_, mixed.data(), 32);
    buf_pos_ = 32;
}

void CSPRNG::refill() {
    // state = keccak256(state)
    uint256 new_state = keccak256(state_, 32);
    std::memcpy(state_, new_state.data(), 32);

    // buffer = keccak256(state) -- second application
    uint256 new_buffer = keccak256(state_, 32);
    std::memcpy(buffer_, new_buffer.data(), 32);

    buf_pos_ = 0;
}

void CSPRNG::get_bytes(uint8_t* out, size_t len) {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t written = 0;
    while (written < len) {
        if (buf_pos_ >= 32) {
            refill();
        }
        size_t avail = 32 - buf_pos_;
        size_t to_copy = std::min(avail, len - written);
        std::memcpy(out + written, buffer_ + buf_pos_, to_copy);
        buf_pos_ += to_copy;
        written += to_copy;
    }
}

uint64_t CSPRNG::get_uint64() {
    uint64_t v;
    get_bytes(reinterpret_cast<uint8_t*>(&v), sizeof(v));
    return v;
}

uint32_t CSPRNG::get_uint32() {
    uint32_t v;
    get_bytes(reinterpret_cast<uint8_t*>(&v), sizeof(v));
    return v;
}

uint64_t CSPRNG::get_range(uint64_t max) {
    if (max == 0) return 0;
    if (max == 1) return 0;

    uint64_t limit = (UINT64_MAX / max) * max;
    uint64_t r;
    do {
        r = get_uint64();
    } while (r >= limit);
    return r % max;
}

uint64_t CSPRNG::get_range(uint64_t min, uint64_t max) {
    if (min >= max) return min;
    return min + get_range(max - min + 1);
}

uint256 CSPRNG::get_uint256() {
    uint256 v;
    get_bytes(v.data(), 32);
    return v;
}

double CSPRNG::get_double() {
    // Generate a double in [0.0, 1.0) using 53 bits of randomness
    uint64_t r = get_uint64();
    return static_cast<double>(r >> 11) * (1.0 / 9007199254740992.0);
}

bool CSPRNG::get_bool(double p) {
    if (p <= 0.0) return false;
    if (p >= 1.0) return true;
    return get_double() < p;
}

void CSPRNG::add_entropy(const uint8_t* data, size_t len) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Mix new entropy into state: state = keccak256(state || data)
    std::vector<uint8_t> combined(32 + len);
    std::memcpy(combined.data(), state_, 32);
    std::memcpy(combined.data() + 32, data, len);

    uint256 mixed = keccak256(combined.data(), combined.size());
    std::memcpy(state_, mixed.data(), 32);

    buf_pos_ = 32;  // force refill
}

void CSPRNG::reseed() {
    std::lock_guard<std::mutex> lock(mutex_);
    // Cannot call seed_from_system() while holding lock since it
    // doesn't acquire lock. Directly gather entropy.
    uint8_t entropy[64];
    GetRandBytes(entropy, 32);

    auto now = std::chrono::high_resolution_clock::now();
    auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(
        now.time_since_epoch()).count();
    std::memcpy(entropy + 32, &nanos, 8);
    GetRandBytes(entropy + 40, 24);

    // Mix with current state
    std::vector<uint8_t> combined(32 + 64);
    std::memcpy(combined.data(), state_, 32);
    std::memcpy(combined.data() + 32, entropy, 64);

    uint256 mixed = keccak256(combined.data(), combined.size());
    std::memcpy(state_, mixed.data(), 32);
    buf_pos_ = 32;
}

CSPRNG& CSPRNG::global() {
    static CSPRNG instance;
    return instance;
}

// ===========================================================================
// DeterministicRNG (xoshiro256**)
// ===========================================================================

DeterministicRNG::DeterministicRNG(uint64_t seed) {
    init_state(seed);
}

DeterministicRNG::DeterministicRNG(const uint256& seed) {
    // Use first 8 bytes as the base seed
    uint64_t s = 0;
    std::memcpy(&s, seed.data(), 8);
    init_state(s);
}

void DeterministicRNG::init_state(uint64_t seed) {
    // Use SplitMix64 to initialize the 4-word state from a single seed.
    // This is the standard way to seed xoshiro from a single value.
    auto splitmix = [](uint64_t& z) -> uint64_t {
        z += 0x9e3779b97f4a7c15ULL;
        uint64_t result = z;
        result = (result ^ (result >> 30)) * 0xbf58476d1ce4e5b9ULL;
        result = (result ^ (result >> 27)) * 0x94d049bb133111ebULL;
        return result ^ (result >> 31);
    };

    s_[0] = splitmix(seed);
    s_[1] = splitmix(seed);
    s_[2] = splitmix(seed);
    s_[3] = splitmix(seed);
}

uint64_t DeterministicRNG::next_uint64() {
    // xoshiro256** algorithm
    const uint64_t result = rotl(s_[1] * 5, 7) * 9;
    const uint64_t t = s_[1] << 17;

    s_[2] ^= s_[0];
    s_[3] ^= s_[1];
    s_[1] ^= s_[2];
    s_[0] ^= s_[3];
    s_[2] ^= t;
    s_[3] = rotl(s_[3], 45);

    return result;
}

uint32_t DeterministicRNG::next_uint32() {
    return static_cast<uint32_t>(next_uint64());
}

float DeterministicRNG::next_float() {
    // Generate a float in [0.0, 1.0) using 24 bits (float32 mantissa)
    return static_cast<float>(next_uint64() >> 40) * (1.0f / 16777216.0f);
}

double DeterministicRNG::next_double() {
    return static_cast<double>(next_uint64() >> 11) * (1.0 / 9007199254740992.0);
}

float DeterministicRNG::next_normal() {
    // Box-Muller transform
    double u1, u2;
    do {
        u1 = next_double();
    } while (u1 == 0.0);
    u2 = next_double();

    double z0 = std::sqrt(-2.0 * std::log(u1)) * std::cos(2.0 * M_PI * u2);
    return static_cast<float>(z0);
}

float DeterministicRNG::next_normal(float mean, float std) {
    return mean + std * next_normal();
}

void DeterministicRNG::fill_bytes(uint8_t* out, size_t len) {
    size_t pos = 0;
    while (pos + 8 <= len) {
        uint64_t v = next_uint64();
        std::memcpy(out + pos, &v, 8);
        pos += 8;
    }
    if (pos < len) {
        uint64_t v = next_uint64();
        std::memcpy(out + pos, &v, len - pos);
    }
}

uint64_t DeterministicRNG::next_range(uint64_t max) {
    if (max == 0) return 0;
    if (max == 1) return 0;

    uint64_t limit = (UINT64_MAX / max) * max;
    uint64_t r;
    do {
        r = next_uint64();
    } while (r >= limit);
    return r % max;
}

void DeterministicRNG::reset(uint64_t seed) {
    init_state(seed);
}

} // namespace flow

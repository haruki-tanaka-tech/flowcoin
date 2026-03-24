// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Cryptographically secure random number generation for FlowCoin.
// Provides both raw entropy access (/dev/urandom) and a CSPRNG
// based on Keccak-256 for deterministic and performance-critical use.

#pragma once

#include "types.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

namespace flow {

// ---------------------------------------------------------------------------
// Raw entropy functions (reads from /dev/urandom)
// ---------------------------------------------------------------------------

/** Fill a buffer with cryptographically secure random bytes.
 *  Reads from /dev/urandom. Aborts the process if /dev/urandom
 *  is unavailable or a read fails.
 */
void GetRandBytes(uint8_t* buf, size_t len);

/** Return a cryptographically secure random 64-bit unsigned integer. */
uint64_t GetRandUint64();

/** Return a cryptographically secure random uint256. */
uint256 GetRandUint256();

/** Return a cryptographically secure random 32-bit unsigned integer. */
uint32_t GetRandUint32();

/** Return a random uint64_t in [0, max). */
uint64_t GetRand(uint64_t max);

/** Return a random uint64_t in [min, max]. */
uint64_t GetRandRange(uint64_t min, uint64_t max);

/** Return a random 256-bit hash (convenience alias for GetRandUint256). */
uint256 GetRandHash();

/** Return a random boolean with probability p of being true. */
bool GetRandBool(double p = 0.5);

// ---------------------------------------------------------------------------
// CSPRNG -- Keccak-based cryptographically secure PRNG
// ---------------------------------------------------------------------------
// Internally maintains a 32-byte Keccak state. Each refill:
//   state = keccak256(state)
//   buffer = keccak256(state)
// The buffer is consumed byte-by-byte. This provides forward secrecy:
// even if the current state is compromised, past outputs cannot be
// recovered.

class CSPRNG {
public:
    /// Auto-seed from /dev/urandom + timestamps + PID.
    CSPRNG();

    /// Deterministic seed for testing/reproducibility.
    explicit CSPRNG(const uint256& seed);

    /// Seed from a raw byte array.
    CSPRNG(const uint8_t* seed_data, size_t seed_len);

    /// Generate random bytes.
    void get_bytes(uint8_t* out, size_t len);

    /// Generate a random uint64_t.
    uint64_t get_uint64();

    /// Generate a random uint32_t.
    uint32_t get_uint32();

    /// Generate a random integer in [0, max).
    uint64_t get_range(uint64_t max);

    /// Generate a random integer in [min, max].
    uint64_t get_range(uint64_t min, uint64_t max);

    /// Generate a random uint256.
    uint256 get_uint256();

    /// Generate a random float in [0.0, 1.0).
    double get_double();

    /// Generate a random boolean with probability p of being true.
    bool get_bool(double p = 0.5);

    /// Reseed with additional entropy (mixed into state).
    void add_entropy(const uint8_t* data, size_t len);

    /// Reseed from /dev/urandom.
    void reseed();

    /// Get the global thread-safe CSPRNG instance.
    static CSPRNG& global();

private:
    uint8_t state_[32];    //!< Keccak internal state
    uint8_t buffer_[32];   //!< Output buffer
    size_t buf_pos_ = 32;  //!< Position in buffer (32 = empty)
    std::mutex mutex_;     //!< Thread safety

    /// Refill the output buffer from the state.
    /// state = keccak256(state), buffer = keccak256(state)
    void refill();

    /// Seed the CSPRNG from system entropy sources.
    void seed_from_system();
};

// ---------------------------------------------------------------------------
// Deterministic RNG for consensus (reproducible weight initialization)
// ---------------------------------------------------------------------------
// Not cryptographically secure -- used only for deterministic model
// weight initialization where all nodes must produce identical values
// from the same seed.

class DeterministicRNG {
public:
    /// Construct with a seed value.
    explicit DeterministicRNG(uint64_t seed);

    /// Construct from a uint256 seed.
    explicit DeterministicRNG(const uint256& seed);

    /// Generate next uint64_t (xoshiro256** algorithm).
    uint64_t next_uint64();

    /// Generate next uint32_t.
    uint32_t next_uint32();

    /// Generate next float in [0.0, 1.0).
    float next_float();

    /// Generate next double in [0.0, 1.0).
    double next_double();

    /// Generate a normally distributed float (mean=0, std=1).
    float next_normal();

    /// Generate a normally distributed float with given mean and std.
    float next_normal(float mean, float std);

    /// Fill a buffer with random bytes.
    void fill_bytes(uint8_t* out, size_t len);

    /// Generate a random integer in [0, max).
    uint64_t next_range(uint64_t max);

    /// Reset with a new seed.
    void reset(uint64_t seed);

private:
    uint64_t s_[4];  //!< xoshiro256** state

    /// Initialize state from seed using SplitMix64.
    void init_state(uint64_t seed);

    /// Rotate left helper.
    static uint64_t rotl(uint64_t x, int k) {
        return (x << k) | (x >> (64 - k));
    }
};

} // namespace flow

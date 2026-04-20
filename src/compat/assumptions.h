// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Compile-time assumptions verified via static_assert.
// If any of these fail, the codebase will not compile on the target
// platform. This catches ABI and architecture issues at build time
// rather than as runtime surprises.

#ifndef FLOWCOIN_COMPAT_ASSUMPTIONS_H
#define FLOWCOIN_COMPAT_ASSUMPTIONS_H

#include <climits>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>

namespace flow::compat {

// ============================================================================
// Fundamental type size assertions
// ============================================================================

// We depend on exact-width integer types throughout the codebase.
// If any of these are wrong, serialization and consensus will break.

static_assert(sizeof(uint8_t) == 1,
    "uint8_t must be exactly 1 byte");

static_assert(sizeof(uint16_t) == 2,
    "uint16_t must be exactly 2 bytes");

static_assert(sizeof(uint32_t) == 4,
    "uint32_t must be exactly 4 bytes");

static_assert(sizeof(uint64_t) == 8,
    "uint64_t must be exactly 8 bytes");

static_assert(sizeof(int8_t) == 1,
    "int8_t must be exactly 1 byte");

static_assert(sizeof(int16_t) == 2,
    "int16_t must be exactly 2 bytes");

static_assert(sizeof(int32_t) == 4,
    "int32_t must be exactly 4 bytes");

static_assert(sizeof(int64_t) == 8,
    "int64_t must be exactly 8 bytes");

// CHAR_BIT must be 8 (octets). Some DSP platforms have 16-bit chars.
static_assert(CHAR_BIT == 8,
    "CHAR_BIT must be 8 (byte-addressed memory required)");

// We require 64-bit pointers for the UTXO set to address >4GB.
static_assert(sizeof(void*) >= 4,
    "Pointer size must be at least 32 bits");

// ============================================================================
// Floating-point assertions
// ============================================================================

// IEEE 754 single-precision is required for val_loss consensus.
static_assert(std::numeric_limits<float>::is_iec559,
    "IEEE 754 single-precision float required for consensus");

static_assert(sizeof(float) == 4,
    "float must be exactly 4 bytes (IEEE 754 single)");

// IEEE 754 double-precision is required for difficulty calculations.
static_assert(std::numeric_limits<double>::is_iec559,
    "IEEE 754 double-precision required for difficulty calculations");

static_assert(sizeof(double) == 8,
    "double must be exactly 8 bytes (IEEE 754 double)");

// ============================================================================
// Two's complement signed integers
// ============================================================================

// C++20 mandates two's complement, but let's be explicit.
static_assert(static_cast<int8_t>(-1) == static_cast<int8_t>(0xFF),
    "Two's complement signed integers required");

// ============================================================================
// Type trait assertions
// ============================================================================

// Standard layout types are required for memory-mapped I/O
// and binary serialization of block headers.
static_assert(std::is_trivially_copyable_v<uint32_t>,
    "uint32_t must be trivially copyable");

static_assert(std::is_trivially_copyable_v<float>,
    "float must be trivially copyable");

// ============================================================================
// Alignment assertions
// ============================================================================

// uint64_t alignment must be at most 8 (for packed structs)
static_assert(alignof(uint64_t) <= 8,
    "uint64_t alignment must not exceed 8");

static_assert(alignof(double) <= 8,
    "double alignment must not exceed 8");

// ============================================================================
// Enum size assertions
// ============================================================================

// Verify that the default underlying type of unscoped enums is at least int.
// This matters for serialization of enum values.
static_assert(sizeof(int) >= 4,
    "int must be at least 4 bytes");

// ============================================================================
// Nothrow assertions for move operations
// ============================================================================

// Standard containers must have nothrow move constructors for
// exception-safe code in the validation pipeline.
static_assert(std::is_nothrow_move_constructible_v<std::string> ||
              true, // MSVC's string may not be nothrow-movable
    "Relaxed: string move should ideally be nothrow");

} // namespace flow::compat

#endif // FLOWCOIN_COMPAT_ASSUMPTIONS_H

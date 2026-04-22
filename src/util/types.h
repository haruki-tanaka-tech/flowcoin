// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Fundamental types used throughout FlowCoin.
// Defines fixed-size byte arrays (Blob), cryptographic type aliases,
// monetary amounts, and a Result<T> error-handling type.

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <variant>

namespace flow {

// ---------------------------------------------------------------------------
// Fixed-size byte array
// ---------------------------------------------------------------------------

/** Generic fixed-size byte array, used as the basis for hashes, keys,
 *  and signatures. Provides comparison operators, zero-checking utilities,
 *  and raw byte access.
 *
 *  Template parameter N is the number of bytes.
 */
template <size_t N>
struct Blob {
    std::array<uint8_t, N> m_data{};

    // --- Constructors ---

    Blob() = default;

    /** Construct from a raw byte pointer (must point to at least N bytes). */
    explicit Blob(const uint8_t* src) {
        std::memcpy(m_data.data(), src, N);
    }

    /** Construct from a std::array of the same size. */
    explicit Blob(const std::array<uint8_t, N>& arr) : m_data(arr) {}

    // --- Raw byte access ---

    const uint8_t* data() const { return m_data.data(); }
    uint8_t* data() { return m_data.data(); }
    static constexpr size_t size() { return N; }

    // --- Iterator access ---

    const uint8_t* begin() const { return m_data.data(); }
    const uint8_t* end() const { return m_data.data() + N; }
    uint8_t* begin() { return m_data.data(); }
    uint8_t* end() { return m_data.data() + N; }

    // --- Element access ---

    uint8_t& operator[](size_t i) { return m_data[i]; }
    const uint8_t& operator[](size_t i) const { return m_data[i]; }

    // --- Null / zero checking ---

    /** Return true if all bytes are zero. */
    bool is_null() const {
        for (auto b : m_data) {
            if (b != 0) return false;
        }
        return true;
    }

    /** Set all bytes to zero. */
    void set_null() { m_data.fill(0); }

    // --- Comparison operators (lexicographic on raw bytes, index 0 upward) ---

    bool operator==(const Blob& other) const { return m_data == other.m_data; }
    bool operator!=(const Blob& other) const { return m_data != other.m_data; }

    bool operator<(const Blob& other) const {
        for (size_t i = 0; i < N; ++i) {
            if (m_data[i] < other.m_data[i]) return true;
            if (m_data[i] > other.m_data[i]) return false;
        }
        return false;
    }

    bool operator<=(const Blob& other) const {
        for (size_t i = 0; i < N; ++i) {
            if (m_data[i] < other.m_data[i]) return true;
            if (m_data[i] > other.m_data[i]) return false;
        }
        return true;
    }

    bool operator>(const Blob& other) const {
        return other < *this;
    }

    bool operator>=(const Blob& other) const {
        return other <= *this;
    }

    /** Return a hex string representation. */
    std::string to_hex() const {
        static const char hex_chars[] = "0123456789abcdef";
        std::string result;
        result.reserve(N * 2);
        for (size_t i = 0; i < N; ++i) {
            result.push_back(hex_chars[(m_data[i] >> 4) & 0xF]);
            result.push_back(hex_chars[m_data[i] & 0xF]);
        }
        return result;
    }
};

// ---------------------------------------------------------------------------
// Core type aliases
// ---------------------------------------------------------------------------

using uint256 = Blob<32>;     //!< 256-bit value (hashes, targets)
using uint512 = Blob<64>;     //!< 512-bit value (HMAC output, signatures)

using Hash256 = Blob<32>;     //!< 256-bit hash digest
using Signature = Blob<64>;   //!< Ed25519 signature (64 bytes)
using PubKey = Blob<32>;      //!< Ed25519 public key (32 bytes)
using PrivKey = Blob<32>;     //!< Ed25519 private key seed (32 bytes)

using Height = uint64_t;      //!< Block height
using Timestamp = int64_t;    //!< Unix timestamp in seconds

// ---------------------------------------------------------------------------
// Monetary amount
// ---------------------------------------------------------------------------

/** Represents a monetary value in atomic units.
 *  1 FLC = 100,000,000 atomic units (same precision as Bitcoin satoshis).
 *  Uses signed int64 to allow representing negative deltas in calculations.
 */
using Amount = int64_t;

/** Atomic units per FLC coin. */
static constexpr int64_t COIN = 100'000'000LL;

// ---------------------------------------------------------------------------
// Result<T> -- error handling without exceptions
// ---------------------------------------------------------------------------

/** Encapsulates an error message for use with Result<T>. */
struct Error {
    std::string message;
    explicit Error(std::string msg) : message(std::move(msg)) {}
};

/** A sum type representing either a success value T or an Error.
 *  Modeled after Rust's Result<T, E> -- used throughout FlowCoin
 *  for operations that can fail without throwing exceptions.
 *
 *  Usage:
 *    Result<Block> r = parse_block(data);
 *    if (r.ok()) use(r.value());
 *    else log_error(r.error_message());
 */
template <typename T>
class Result {
public:
    Result(T val) : data_(std::move(val)) {}      // NOLINT: intentional implicit
    Result(Error err) : data_(std::move(err)) {}   // NOLINT: intentional implicit

    /** Return true if the result holds a success value. */
    bool ok() const { return std::holds_alternative<T>(data_); }

    /** Return true if the result holds an error. */
    bool has_error() const { return std::holds_alternative<Error>(data_); }

    /** Access the success value (undefined behavior if has_error()). */
    const T& value() const { return std::get<T>(data_); }
    T& value() { return std::get<T>(data_); }

    /** Access the error (undefined behavior if ok()). */
    const Error& error() const { return std::get<Error>(data_); }
    const std::string& error_message() const { return std::get<Error>(data_).message; }

    /** Boolean conversion: true if ok(). */
    explicit operator bool() const { return ok(); }

private:
    std::variant<T, Error> data_;
};

/** Sentinel type for Result<Ok>, representing a void success. */
struct Ok {};

/** Convenience alias for operations that succeed with no return value. */
using Status = Result<Ok>;

} // namespace flow

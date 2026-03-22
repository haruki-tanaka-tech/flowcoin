// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <variant>

namespace flow {

// ─── Fixed-size byte array ────────────────────────────────────

template <size_t N>
struct Blob {
    std::array<uint8_t, N> data{};

    Blob() = default;

    explicit Blob(const uint8_t* src) {
        std::memcpy(data.data(), src, N);
    }

    explicit Blob(const std::array<uint8_t, N>& arr) : data(arr) {}

    const uint8_t* begin() const { return data.data(); }
    const uint8_t* end() const { return data.data() + N; }
    uint8_t* begin() { return data.data(); }
    uint8_t* end() { return data.data() + N; }
    const uint8_t* bytes() const { return data.data(); }
    uint8_t* bytes() { return data.data(); }
    static constexpr size_t size() { return N; }

    bool is_zero() const {
        for (auto b : data) {
            if (b != 0) return false;
        }
        return true;
    }

    void set_zero() { data.fill(0); }

    bool operator==(const Blob& other) const { return data == other.data; }
    bool operator!=(const Blob& other) const { return data != other.data; }
    bool operator<(const Blob& other) const { return data < other.data; }

    uint8_t& operator[](size_t i) { return data[i]; }
    const uint8_t& operator[](size_t i) const { return data[i]; }

    std::string to_hex() const {
        static const char hex_chars[] = "0123456789abcdef";
        std::string result;
        result.reserve(N * 2);
        for (auto b : data) {
            result.push_back(hex_chars[b >> 4]);
            result.push_back(hex_chars[b & 0x0f]);
        }
        return result;
    }

    static Blob from_hex(const std::string& hex) {
        Blob result;
        if (hex.size() != N * 2) return result;
        for (size_t i = 0; i < N; ++i) {
            auto hi = hex_digit(hex[i * 2]);
            auto lo = hex_digit(hex[i * 2 + 1]);
            if (hi < 0 || lo < 0) return Blob{};
            result.data[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return result;
    }

    static const Blob ZERO;

private:
    static int hex_digit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }
};

template <size_t N>
const Blob<N> Blob<N>::ZERO{};

// ─── Core types ───────────────────────────────────────────────

using uint256 = Blob<32>;
using Hash256 = Blob<32>;
using Signature = Blob<64>;
using PubKey = Blob<32>;
using PrivKey = Blob<32>;

using Height = uint64_t;
using Timestamp = int64_t;

// Amount in atomic units (1 FLOW = 100,000,000 atomic units)
struct Amount {
    int64_t value{0};

    Amount() = default;
    explicit Amount(int64_t v) : value(v) {}

    Amount operator+(Amount other) const { return Amount{value + other.value}; }
    Amount operator-(Amount other) const { return Amount{value - other.value}; }
    Amount& operator+=(Amount other) { value += other.value; return *this; }
    Amount& operator-=(Amount other) { value -= other.value; return *this; }
    bool operator==(Amount other) const { return value == other.value; }
    bool operator!=(Amount other) const { return value != other.value; }
    bool operator<(Amount other) const { return value < other.value; }
    bool operator<=(Amount other) const { return value <= other.value; }
    bool operator>(Amount other) const { return value > other.value; }
    bool operator>=(Amount other) const { return value >= other.value; }

    static constexpr int64_t COIN = 100'000'000LL;
};

// ─── Result<T> ────────────────────────────────────────────────

struct Error {
    std::string message;

    explicit Error(std::string msg) : message(std::move(msg)) {}
};

template <typename T>
class Result {
public:
    Result(T val) : data_(std::move(val)) {} // NOLINT: intentional implicit
    Result(Error err) : data_(std::move(err)) {} // NOLINT: intentional implicit

    bool ok() const { return std::holds_alternative<T>(data_); }
    bool has_error() const { return std::holds_alternative<Error>(data_); }

    const T& value() const { return std::get<T>(data_); }
    T& value() { return std::get<T>(data_); }

    const Error& error() const { return std::get<Error>(data_); }
    const std::string& error_message() const { return std::get<Error>(data_).message; }

    explicit operator bool() const { return ok(); }

private:
    std::variant<T, Error> data_;
};

// Specialization for void-like results
struct Ok {};

using Status = Result<Ok>;

} // namespace flow

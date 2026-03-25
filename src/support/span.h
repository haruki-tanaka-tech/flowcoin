// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Span<T>: a non-owning view over a contiguous range of T elements.
// Similar to std::span (C++20), but available without requiring C++20
// library support on all target platforms.
//
// Used throughout FlowCoin for zero-copy byte buffer passing between
// serialization, hashing, and network modules.

#ifndef FLOWCOIN_SUPPORT_SPAN_H
#define FLOWCOIN_SUPPORT_SPAN_H

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <array>
#include <type_traits>
#include <vector>

namespace flow {

// ============================================================================
// Span<T>
// ============================================================================

template<typename T>
class Span {
public:
    using element_type = T;
    using value_type = std::remove_cv_t<T>;
    using size_type = size_t;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using iterator = pointer;
    using const_iterator = const_pointer;

    // ---- Constructors -------------------------------------------------------

    /// Empty span.
    constexpr Span() noexcept : data_(nullptr), size_(0) {}

    /// From pointer and size.
    constexpr Span(T* data, size_t size) noexcept : data_(data), size_(size) {}

    /// From two pointers (begin, end).
    constexpr Span(T* begin, T* end) noexcept
        : data_(begin), size_(static_cast<size_t>(end - begin)) {
        assert(end >= begin);
    }

    /// From C-style array.
    template<size_t N>
    constexpr Span(T (&arr)[N]) noexcept : data_(arr), size_(N) {}

    /// From std::array.
    template<size_t N>
    constexpr Span(std::array<T, N>& arr) noexcept
        : data_(arr.data()), size_(N) {}

    /// From const std::array (only for Span<const T>).
    template<size_t N, typename = std::enable_if_t<std::is_const_v<T>>>
    constexpr Span(const std::array<std::remove_const_t<T>, N>& arr) noexcept
        : data_(arr.data()), size_(N) {}

    /// From std::vector.
    Span(std::vector<value_type>& vec) noexcept
        : data_(vec.data()), size_(vec.size()) {}

    /// From const std::vector (only for Span<const T>).
    template<typename = std::enable_if_t<std::is_const_v<T>>>
    Span(const std::vector<value_type>& vec) noexcept
        : data_(vec.data()), size_(vec.size()) {}

    /// Implicit conversion from Span<non-const> to Span<const>.
    template<typename U, typename = std::enable_if_t<
        std::is_const_v<T> && std::is_same_v<std::remove_const_t<T>, U>>>
    constexpr Span(const Span<U>& other) noexcept
        : data_(other.data()), size_(other.size()) {}

    // ---- Element access -----------------------------------------------------

    constexpr T& operator[](size_t idx) const {
        assert(idx < size_);
        return data_[idx];
    }

    constexpr T& front() const {
        assert(size_ > 0);
        return data_[0];
    }

    constexpr T& back() const {
        assert(size_ > 0);
        return data_[size_ - 1];
    }

    constexpr T* data() const noexcept { return data_; }

    // ---- Capacity -----------------------------------------------------------

    constexpr size_t size() const noexcept { return size_; }
    constexpr size_t size_bytes() const noexcept { return size_ * sizeof(T); }
    constexpr bool empty() const noexcept { return size_ == 0; }

    // ---- Iterators ----------------------------------------------------------

    constexpr iterator begin() const noexcept { return data_; }
    constexpr iterator end() const noexcept { return data_ + size_; }

    // ---- Subviews -----------------------------------------------------------

    /// First N elements.
    constexpr Span first(size_t count) const {
        assert(count <= size_);
        return Span(data_, count);
    }

    /// Last N elements.
    constexpr Span last(size_t count) const {
        assert(count <= size_);
        return Span(data_ + (size_ - count), count);
    }

    /// Subspan starting at offset with count elements.
    constexpr Span subspan(size_t offset, size_t count = static_cast<size_t>(-1)) const {
        assert(offset <= size_);
        size_t actual_count = count;
        if (actual_count > size_ - offset) {
            actual_count = size_ - offset;
        }
        return Span(data_ + offset, actual_count);
    }

private:
    T* data_;
    size_t size_;
};

// ============================================================================
// Deduction guides
// ============================================================================

template<typename T, size_t N>
Span(T (&)[N]) -> Span<T>;

template<typename T, size_t N>
Span(std::array<T, N>&) -> Span<T>;

template<typename T, size_t N>
Span(const std::array<T, N>&) -> Span<const T>;

template<typename T>
Span(std::vector<T>&) -> Span<T>;

template<typename T>
Span(const std::vector<T>&) -> Span<const T>;

// ============================================================================
// Common type aliases
// ============================================================================

using ByteSpan = Span<const uint8_t>;
using MutableByteSpan = Span<uint8_t>;

// ============================================================================
// Helper functions
// ============================================================================

/// Create a ByteSpan from a string.
inline ByteSpan as_bytes(const std::string& s) {
    return ByteSpan(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

/// Create a ByteSpan from a raw pointer and size.
inline ByteSpan as_bytes(const void* data, size_t size) {
    return ByteSpan(static_cast<const uint8_t*>(data), size);
}

/// Create a MutableByteSpan from a raw pointer and size.
inline MutableByteSpan as_writable_bytes(void* data, size_t size) {
    return MutableByteSpan(static_cast<uint8_t*>(data), size);
}

/// Convert a span to a vector (copies the data).
template<typename T>
std::vector<std::remove_const_t<T>> to_vector(Span<T> span) {
    return std::vector<std::remove_const_t<T>>(span.begin(), span.end());
}

/// Create a Span from any contiguous container.
template<typename Container>
auto make_span(Container& c) -> Span<typename Container::value_type> {
    return Span<typename Container::value_type>(c.data(), c.size());
}

template<typename Container>
auto make_span(const Container& c) -> Span<const typename Container::value_type> {
    return Span<const typename Container::value_type>(c.data(), c.size());
}

} // namespace flow

#endif // FLOWCOIN_SUPPORT_SPAN_H

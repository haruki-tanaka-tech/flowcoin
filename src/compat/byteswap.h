// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Portable byte-order serialization helpers.
// Provides type-safe serialization of integers and floats into
// byte buffers in little-endian wire format. Used throughout the
// serialization layer to ensure consistent byte ordering regardless
// of host architecture.
//
// All consensus-critical data is serialized in little-endian format
// (matching Bitcoin's wire protocol). These helpers ensure correctness
// on both little-endian (x86, ARM LE) and big-endian (POWER, s390x)
// architectures.

#ifndef FLOWCOIN_COMPAT_BYTESWAP_H
#define FLOWCOIN_COMPAT_BYTESWAP_H

#include "compat/compat.h"

#include <cstdint>
#include <cstring>
#include <type_traits>

namespace flow::compat {

// ============================================================================
// Serialization: write native types to little-endian byte buffer
// ============================================================================

/// Write a uint8_t to a byte buffer.
inline void ser_u8(uint8_t* buf, uint8_t val) {
    buf[0] = val;
}

/// Write a uint16_t in little-endian format.
inline void ser_u16(uint8_t* buf, uint16_t val) {
    write_le16(buf, val);
}

/// Write a uint32_t in little-endian format.
inline void ser_u32(uint8_t* buf, uint32_t val) {
    write_le32(buf, val);
}

/// Write a uint64_t in little-endian format.
inline void ser_u64(uint8_t* buf, uint64_t val) {
    write_le64(buf, val);
}

/// Write an int8_t to a byte buffer.
inline void ser_i8(uint8_t* buf, int8_t val) {
    buf[0] = static_cast<uint8_t>(val);
}

/// Write an int16_t in little-endian format.
inline void ser_i16(uint8_t* buf, int16_t val) {
    write_le16(buf, static_cast<uint16_t>(val));
}

/// Write an int32_t in little-endian format.
inline void ser_i32(uint8_t* buf, int32_t val) {
    write_le32(buf, static_cast<uint32_t>(val));
}

/// Write an int64_t in little-endian format.
inline void ser_i64(uint8_t* buf, int64_t val) {
    write_le64(buf, static_cast<uint64_t>(val));
}

/// Write a float (IEEE 754 single) in little-endian format.
/// Uses memcpy for type-punning safety (no aliasing violations).
inline void ser_f32(uint8_t* buf, float val) {
    uint32_t bits;
    std::memcpy(&bits, &val, 4);
    write_le32(buf, bits);
}

/// Write a double (IEEE 754 double) in little-endian format.
inline void ser_f64(uint8_t* buf, double val) {
    uint64_t bits;
    std::memcpy(&bits, &val, 8);
    write_le64(buf, bits);
}

// ============================================================================
// Deserialization: read little-endian byte buffer to native types
// ============================================================================

/// Read a uint8_t from a byte buffer.
inline uint8_t deser_u8(const uint8_t* buf) {
    return buf[0];
}

/// Read a uint16_t from little-endian buffer.
inline uint16_t deser_u16(const uint8_t* buf) {
    return read_le16(buf);
}

/// Read a uint32_t from little-endian buffer.
inline uint32_t deser_u32(const uint8_t* buf) {
    return read_le32(buf);
}

/// Read a uint64_t from little-endian buffer.
inline uint64_t deser_u64(const uint8_t* buf) {
    return read_le64(buf);
}

/// Read an int8_t from a byte buffer.
inline int8_t deser_i8(const uint8_t* buf) {
    return static_cast<int8_t>(buf[0]);
}

/// Read an int16_t from little-endian buffer.
inline int16_t deser_i16(const uint8_t* buf) {
    return static_cast<int16_t>(read_le16(buf));
}

/// Read an int32_t from little-endian buffer.
inline int32_t deser_i32(const uint8_t* buf) {
    return static_cast<int32_t>(read_le32(buf));
}

/// Read an int64_t from little-endian buffer.
inline int64_t deser_i64(const uint8_t* buf) {
    return static_cast<int64_t>(read_le64(buf));
}

/// Read a float from little-endian buffer.
inline float deser_f32(const uint8_t* buf) {
    uint32_t bits = read_le32(buf);
    float val;
    std::memcpy(&val, &bits, 4);
    return val;
}

/// Read a double from little-endian buffer.
inline double deser_f64(const uint8_t* buf) {
    uint64_t bits = read_le64(buf);
    double val;
    std::memcpy(&val, &bits, 8);
    return val;
}

// ============================================================================
// CompactSize encoding (Bitcoin's variable-length integer)
// ============================================================================

/// Compute the serialized size of a CompactSize value.
inline size_t compact_size_bytes(uint64_t val) {
    if (val < 253) return 1;
    if (val <= 0xFFFF) return 3;
    if (val <= 0xFFFFFFFF) return 5;
    return 9;
}

/// Write a CompactSize value. Returns number of bytes written.
inline size_t write_compact_size(uint8_t* buf, uint64_t val) {
    if (val < 253) {
        buf[0] = static_cast<uint8_t>(val);
        return 1;
    }
    if (val <= 0xFFFF) {
        buf[0] = 253;
        write_le16(buf + 1, static_cast<uint16_t>(val));
        return 3;
    }
    if (val <= 0xFFFFFFFF) {
        buf[0] = 254;
        write_le32(buf + 1, static_cast<uint32_t>(val));
        return 5;
    }
    buf[0] = 255;
    write_le64(buf + 1, val);
    return 9;
}

/// Read a CompactSize value. Returns {value, bytes_consumed}.
/// Returns {0, 0} on error (buffer too short).
struct CompactSizeResult {
    uint64_t value;
    size_t bytes_consumed;
};

inline CompactSizeResult read_compact_size(const uint8_t* buf, size_t buf_len) {
    if (buf_len < 1) return {0, 0};

    uint8_t first = buf[0];
    if (first < 253) {
        return {first, 1};
    }
    if (first == 253) {
        if (buf_len < 3) return {0, 0};
        return {read_le16(buf + 1), 3};
    }
    if (first == 254) {
        if (buf_len < 5) return {0, 0};
        return {read_le32(buf + 1), 5};
    }
    // first == 255
    if (buf_len < 9) return {0, 0};
    return {read_le64(buf + 1), 9};
}

// ============================================================================
// Generic endian conversion for arbitrary integer types
// ============================================================================

template<typename T>
inline T to_little_endian(T val) {
    static_assert(std::is_integral_v<T>, "to_little_endian requires integer type");
    if constexpr (sizeof(T) == 1) return val;
    else if constexpr (sizeof(T) == 2) return static_cast<T>(flow_htole16(static_cast<uint16_t>(val)));
    else if constexpr (sizeof(T) == 4) return static_cast<T>(flow_htole32(static_cast<uint32_t>(val)));
    else if constexpr (sizeof(T) == 8) return static_cast<T>(flow_htole64(static_cast<uint64_t>(val)));
    else static_assert(sizeof(T) <= 8, "Unsupported integer size");
}

template<typename T>
inline T from_little_endian(T val) {
    static_assert(std::is_integral_v<T>, "from_little_endian requires integer type");
    if constexpr (sizeof(T) == 1) return val;
    else if constexpr (sizeof(T) == 2) return static_cast<T>(flow_le16toh(static_cast<uint16_t>(val)));
    else if constexpr (sizeof(T) == 4) return static_cast<T>(flow_le32toh(static_cast<uint32_t>(val)));
    else if constexpr (sizeof(T) == 8) return static_cast<T>(flow_le64toh(static_cast<uint64_t>(val)));
    else static_assert(sizeof(T) <= 8, "Unsupported integer size");
}

template<typename T>
inline T to_big_endian(T val) {
    static_assert(std::is_integral_v<T>, "to_big_endian requires integer type");
    if constexpr (sizeof(T) == 1) return val;
    else if constexpr (sizeof(T) == 2) return static_cast<T>(flow_htobe16(static_cast<uint16_t>(val)));
    else if constexpr (sizeof(T) == 4) return static_cast<T>(flow_htobe32(static_cast<uint32_t>(val)));
    else if constexpr (sizeof(T) == 8) return static_cast<T>(flow_htobe64(static_cast<uint64_t>(val)));
    else static_assert(sizeof(T) <= 8, "Unsupported integer size");
}

template<typename T>
inline T from_big_endian(T val) {
    static_assert(std::is_integral_v<T>, "from_big_endian requires integer type");
    if constexpr (sizeof(T) == 1) return val;
    else if constexpr (sizeof(T) == 2) return static_cast<T>(flow_be16toh(static_cast<uint16_t>(val)));
    else if constexpr (sizeof(T) == 4) return static_cast<T>(flow_be32toh(static_cast<uint32_t>(val)));
    else if constexpr (sizeof(T) == 8) return static_cast<T>(flow_be64toh(static_cast<uint64_t>(val)));
    else static_assert(sizeof(T) <= 8, "Unsupported integer size");
}

} // namespace flow::compat

#endif // FLOWCOIN_COMPAT_BYTESWAP_H

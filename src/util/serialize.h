// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Binary serialization framework for the FlowCoin wire protocol (header-only).
// All multi-byte integers are stored in little-endian byte order,
// matching the Bitcoin wire format. Includes streaming writer/reader
// classes, Bitcoin-style CompactSize variable-length encoding,
// DataStream for in-memory serialization, and hash-writing adapters.
//
// DataWriter writes to a growable vector<uint8_t>.
// DataReader reads from a fixed-size byte span, with error checking
// (no exceptions -- sets an internal error flag on out-of-bounds reads).

#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace flow {

// ===========================================================================
// DataWriter -- streaming serializer into a growable byte buffer
// ===========================================================================

class DataWriter {
public:
    DataWriter() = default;
    explicit DataWriter(size_t reserve) { buf_.reserve(reserve); }

    // --- Primitive writes ---

    void write_u8(uint8_t v) { buf_.push_back(v); }

    void write_u16_le(uint16_t v) {
        buf_.push_back(static_cast<uint8_t>(v));
        buf_.push_back(static_cast<uint8_t>(v >> 8));
    }

    void write_u32_le(uint32_t v) {
        buf_.push_back(static_cast<uint8_t>(v));
        buf_.push_back(static_cast<uint8_t>(v >> 8));
        buf_.push_back(static_cast<uint8_t>(v >> 16));
        buf_.push_back(static_cast<uint8_t>(v >> 24));
    }

    void write_u64_le(uint64_t v) {
        for (int i = 0; i < 8; ++i)
            buf_.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }

    void write_i64_le(int64_t v) {
        write_u64_le(static_cast<uint64_t>(v));
    }

    void write_float_le(float v) {
        uint32_t bits;
        std::memcpy(&bits, &v, sizeof(bits));
        write_u32_le(bits);
    }

    void write_double_le(double v) {
        uint64_t bits;
        std::memcpy(&bits, &v, sizeof(bits));
        write_u64_le(bits);
    }

    void write_bytes(const uint8_t* data, size_t len) {
        buf_.insert(buf_.end(), data, data + len);
    }

    void write_compact_size(uint64_t v) {
        if (v < 0xfd) {
            write_u8(static_cast<uint8_t>(v));
        } else if (v <= 0xffff) {
            write_u8(0xfd);
            write_u16_le(static_cast<uint16_t>(v));
        } else if (v <= 0xffffffff) {
            write_u8(0xfe);
            write_u32_le(static_cast<uint32_t>(v));
        } else {
            write_u8(0xff);
            write_u64_le(v);
        }
    }

    // --- String serialization ---

    void write_string(const std::string& s) {
        write_compact_size(s.size());
        write_bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    // --- Vector serialization ---

    void write_byte_vector(const std::vector<uint8_t>& v) {
        write_compact_size(v.size());
        if (!v.empty()) {
            write_bytes(v.data(), v.size());
        }
    }

    // --- Boolean ---

    void write_bool(bool v) {
        write_u8(v ? 1 : 0);
    }

    // --- Access ---

    const std::vector<uint8_t>& data() const { return buf_; }
    std::vector<uint8_t> release() { return std::move(buf_); }
    size_t size() const { return buf_.size(); }
    void clear() { buf_.clear(); }

    // --- Seek ---

    /** Get current write position. */
    size_t position() const { return buf_.size(); }

    /** Overwrite data at a specific position (must be within existing buffer). */
    void write_at(size_t pos, const uint8_t* data, size_t len) {
        if (pos + len <= buf_.size()) {
            std::memcpy(buf_.data() + pos, data, len);
        }
    }

    void write_u32_at(size_t pos, uint32_t v) {
        uint8_t bytes[4];
        bytes[0] = static_cast<uint8_t>(v);
        bytes[1] = static_cast<uint8_t>(v >> 8);
        bytes[2] = static_cast<uint8_t>(v >> 16);
        bytes[3] = static_cast<uint8_t>(v >> 24);
        write_at(pos, bytes, 4);
    }

private:
    std::vector<uint8_t> buf_;
};

// ===========================================================================
// DataReader -- streaming deserializer over a fixed byte span
// ===========================================================================

class DataReader {
public:
    DataReader(const uint8_t* data, size_t len)
        : data_(data), len_(len), pos_(0), error_(false) {}

    explicit DataReader(const std::vector<uint8_t>& data)
        : data_(data.data()), len_(data.size()), pos_(0), error_(false) {}

    // --- Primitive reads ---

    uint8_t read_u8() {
        if (!check(1)) return 0;
        return data_[pos_++];
    }

    uint16_t read_u16_le() {
        if (!check(2)) return 0;
        uint16_t v = static_cast<uint16_t>(data_[pos_])
                   | (static_cast<uint16_t>(data_[pos_ + 1]) << 8);
        pos_ += 2;
        return v;
    }

    uint32_t read_u32_le() {
        if (!check(4)) return 0;
        uint32_t v = static_cast<uint32_t>(data_[pos_])
                   | (static_cast<uint32_t>(data_[pos_ + 1]) << 8)
                   | (static_cast<uint32_t>(data_[pos_ + 2]) << 16)
                   | (static_cast<uint32_t>(data_[pos_ + 3]) << 24);
        pos_ += 4;
        return v;
    }

    uint64_t read_u64_le() {
        if (!check(8)) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v |= static_cast<uint64_t>(data_[pos_ + i]) << (i * 8);
        pos_ += 8;
        return v;
    }

    int64_t read_i64_le() {
        return static_cast<int64_t>(read_u64_le());
    }

    float read_float_le() {
        uint32_t bits = read_u32_le();
        if (error_) return 0.0f;
        float f;
        std::memcpy(&f, &bits, sizeof(f));
        return f;
    }

    double read_double_le() {
        uint64_t bits = read_u64_le();
        if (error_) return 0.0;
        double d;
        std::memcpy(&d, &bits, sizeof(d));
        return d;
    }

    std::vector<uint8_t> read_bytes(size_t n) {
        if (!check(n)) return {};
        std::vector<uint8_t> result(data_ + pos_, data_ + pos_ + n);
        pos_ += n;
        return result;
    }

    /** Read bytes into an existing buffer. Returns true on success. */
    bool read_bytes_into(uint8_t* out, size_t n) {
        if (!check(n)) return false;
        std::memcpy(out, data_ + pos_, n);
        pos_ += n;
        return true;
    }

    uint64_t read_compact_size() {
        uint8_t first = read_u8();
        if (error_) return 0;
        if (first < 0xfd) return first;
        if (first == 0xfd) return read_u16_le();
        if (first == 0xfe) return read_u32_le();
        return read_u64_le();
    }

    /** Read a CompactSize with a maximum value check. */
    uint64_t read_compact_size_limited(uint64_t max_value) {
        uint64_t v = read_compact_size();
        if (!error_ && v > max_value) {
            error_ = true;
            return 0;
        }
        return v;
    }

    // --- String deserialization ---

    std::string read_string() {
        uint64_t len = read_compact_size();
        if (error_ || len > remaining()) {
            error_ = true;
            return {};
        }
        std::string s(reinterpret_cast<const char*>(data_ + pos_),
                      static_cast<size_t>(len));
        pos_ += static_cast<size_t>(len);
        return s;
    }

    // --- Vector deserialization ---

    std::vector<uint8_t> read_byte_vector() {
        uint64_t len = read_compact_size();
        if (error_ || len > remaining()) {
            error_ = true;
            return {};
        }
        return read_bytes(static_cast<size_t>(len));
    }

    // --- Boolean ---

    bool read_bool() {
        return read_u8() != 0;
    }

    // --- Status ---

    size_t remaining() const {
        return (pos_ <= len_) ? (len_ - pos_) : 0;
    }

    bool eof() const { return pos_ >= len_; }
    bool error() const { return error_; }
    size_t position() const { return pos_; }

    std::string error_msg() const {
        if (!error_) return {};
        return "DataReader: read past end of buffer at offset "
             + std::to_string(pos_) + " (buffer size " + std::to_string(len_) + ")";
    }

    /** Skip n bytes. */
    void skip(size_t n) {
        if (!check(n)) return;
        pos_ += n;
    }

    /** Reset read position to the beginning. */
    void reset() {
        pos_ = 0;
        error_ = false;
    }

    /** Seek to a specific position. */
    void seek(size_t pos) {
        if (pos > len_) {
            error_ = true;
            return;
        }
        pos_ = pos;
        error_ = false;
    }

private:
    const uint8_t* data_;
    size_t len_;
    size_t pos_;
    bool error_;

    bool check(size_t n) {
        if (error_) return false;
        if (pos_ + n > len_) {
            error_ = true;
            return false;
        }
        return true;
    }
};

// ===========================================================================
// DataStream -- growable buffer with both read and write cursors
// ===========================================================================

class DataStream {
public:
    DataStream() = default;
    explicit DataStream(size_t reserve) { buf_.reserve(reserve); }
    explicit DataStream(std::vector<uint8_t> data)
        : buf_(std::move(data)), read_pos_(0) {}

    // --- Write operations (append to end) ---

    void write_u8(uint8_t v) { buf_.push_back(v); }
    void write_u16_le(uint16_t v) {
        buf_.push_back(static_cast<uint8_t>(v));
        buf_.push_back(static_cast<uint8_t>(v >> 8));
    }
    void write_u32_le(uint32_t v) {
        buf_.push_back(static_cast<uint8_t>(v));
        buf_.push_back(static_cast<uint8_t>(v >> 8));
        buf_.push_back(static_cast<uint8_t>(v >> 16));
        buf_.push_back(static_cast<uint8_t>(v >> 24));
    }
    void write_u64_le(uint64_t v) {
        for (int i = 0; i < 8; ++i)
            buf_.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }
    void write_bytes(const uint8_t* data, size_t len) {
        buf_.insert(buf_.end(), data, data + len);
    }
    void write_compact_size(uint64_t v) {
        if (v < 0xfd) {
            write_u8(static_cast<uint8_t>(v));
        } else if (v <= 0xffff) {
            write_u8(0xfd);
            write_u16_le(static_cast<uint16_t>(v));
        } else if (v <= 0xffffffff) {
            write_u8(0xfe);
            write_u32_le(static_cast<uint32_t>(v));
        } else {
            write_u8(0xff);
            write_u64_le(v);
        }
    }

    // --- Read operations (from read cursor) ---

    uint8_t read_u8() {
        if (read_pos_ >= buf_.size()) { error_ = true; return 0; }
        return buf_[read_pos_++];
    }
    uint32_t read_u32_le() {
        if (read_pos_ + 4 > buf_.size()) { error_ = true; return 0; }
        uint32_t v = static_cast<uint32_t>(buf_[read_pos_])
                   | (static_cast<uint32_t>(buf_[read_pos_ + 1]) << 8)
                   | (static_cast<uint32_t>(buf_[read_pos_ + 2]) << 16)
                   | (static_cast<uint32_t>(buf_[read_pos_ + 3]) << 24);
        read_pos_ += 4;
        return v;
    }
    uint64_t read_u64_le() {
        if (read_pos_ + 8 > buf_.size()) { error_ = true; return 0; }
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v |= static_cast<uint64_t>(buf_[read_pos_ + i]) << (i * 8);
        read_pos_ += 8;
        return v;
    }

    // --- Buffer access ---

    const std::vector<uint8_t>& data() const { return buf_; }
    std::vector<uint8_t> release() { return std::move(buf_); }
    size_t size() const { return buf_.size(); }
    size_t read_remaining() const {
        return (read_pos_ <= buf_.size()) ? (buf_.size() - read_pos_) : 0;
    }
    bool error() const { return error_; }
    void clear() { buf_.clear(); read_pos_ = 0; error_ = false; }

    /// Construct from hex string (implemented in serialize.cpp).
    static DataStream from_hex(const std::string& hex);

    /// Convert to hex string (implemented in serialize.cpp).
    std::string to_hex() const;

private:
    std::vector<uint8_t> buf_;
    size_t read_pos_ = 0;
    bool error_ = false;
};

// ===========================================================================
// CSizeComputer -- computes serialized size without allocating
// ===========================================================================

class CSizeComputer {
public:
    CSizeComputer() = default;

    void write_u8(uint8_t) { size_ += 1; }
    void write_u16_le(uint16_t) { size_ += 2; }
    void write_u32_le(uint32_t) { size_ += 4; }
    void write_u64_le(uint64_t) { size_ += 8; }
    void write_i64_le(int64_t) { size_ += 8; }
    void write_float_le(float) { size_ += 4; }
    void write_double_le(double) { size_ += 8; }
    void write_bytes(const uint8_t*, size_t len) { size_ += len; }
    void write_bool(bool) { size_ += 1; }

    void write_compact_size(uint64_t v) {
        if (v < 0xfd) size_ += 1;
        else if (v <= 0xffff) size_ += 3;
        else if (v <= 0xffffffff) size_ += 5;
        else size_ += 9;
    }

    void write_string(const std::string& s) {
        write_compact_size(s.size());
        size_ += s.size();
    }

    void write_byte_vector(const std::vector<uint8_t>& v) {
        write_compact_size(v.size());
        size_ += v.size();
    }

    size_t size() const { return size_; }
    void reset() { size_ = 0; }

private:
    size_t size_ = 0;
};

// ===========================================================================
// Serialization free functions for common types
// ===========================================================================

/// Serialize a uint32_t to a byte vector (little-endian).
inline std::vector<uint8_t> SerializeU32(uint32_t v) {
    return {static_cast<uint8_t>(v),
            static_cast<uint8_t>(v >> 8),
            static_cast<uint8_t>(v >> 16),
            static_cast<uint8_t>(v >> 24)};
}

/// Serialize a uint64_t to a byte vector (little-endian).
inline std::vector<uint8_t> SerializeU64(uint64_t v) {
    std::vector<uint8_t> buf(8);
    for (int i = 0; i < 8; ++i)
        buf[i] = static_cast<uint8_t>(v >> (i * 8));
    return buf;
}

/// Deserialize a uint32_t from bytes (little-endian).
inline uint32_t DeserializeU32(const uint8_t* data) {
    return static_cast<uint32_t>(data[0])
         | (static_cast<uint32_t>(data[1]) << 8)
         | (static_cast<uint32_t>(data[2]) << 16)
         | (static_cast<uint32_t>(data[3]) << 24);
}

/// Deserialize a uint64_t from bytes (little-endian).
inline uint64_t DeserializeU64(const uint8_t* data) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<uint64_t>(data[i]) << (i * 8);
    return v;
}

// ===========================================================================
// CHashWriter -- serialize directly into a Keccak-256 hash
// ===========================================================================
// Implements the same write interface as DataWriter, but feeds data
// into a hash computation instead of a buffer. Useful for computing
// the hash of a serialized structure without materializing the full byte array.

// CHashWriter is declared in serialize.cpp with full keccak.h access.
// Use it via: #include "util/serialize.h" and #include "hash/keccak.h"
// See serialize.cpp for the CHashWriter implementation.

// ===========================================================================
// Hex serialization helpers (implemented in serialize.cpp)
// ===========================================================================

std::string SerializeToHex(const std::vector<uint8_t>& data);
std::vector<uint8_t> DeserializeFromHex(const std::string& hex);

// ===========================================================================
// Byte order conversion (implemented in serialize.cpp)
// ===========================================================================

uint16_t ReadLE16(const uint8_t* ptr);
uint32_t ReadLE32(const uint8_t* ptr);
uint64_t ReadLE64(const uint8_t* ptr);
void WriteLE16(uint8_t* ptr, uint16_t v);
void WriteLE32(uint8_t* ptr, uint32_t v);
void WriteLE64(uint8_t* ptr, uint64_t v);

uint16_t ReadBE16(const uint8_t* ptr);
uint32_t ReadBE32(const uint8_t* ptr);
uint64_t ReadBE64(const uint8_t* ptr);
void WriteBE16(uint8_t* ptr, uint16_t v);
void WriteBE32(uint8_t* ptr, uint32_t v);
void WriteBE64(uint8_t* ptr, uint64_t v);

} // namespace flow

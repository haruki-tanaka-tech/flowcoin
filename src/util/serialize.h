// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Binary serialization framework for the FlowCoin wire protocol (header-only).
// All multi-byte integers are stored in little-endian byte order,
// matching the Bitcoin wire format. Includes streaming writer/reader
// classes and Bitcoin-style CompactSize variable-length encoding.
//
// DataWriter writes to a growable vector<uint8_t>.
// DataReader reads from a fixed-size byte span, with error checking
// (no exceptions — sets an internal error flag on out-of-bounds reads).

#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace flow {

// ===========================================================================
// DataWriter — streaming serializer into a growable byte buffer
// ===========================================================================

/** Appends serialized data to an internal std::vector<uint8_t>.
 *  Supports all primitive types and Bitcoin-style CompactSize encoding.
 *
 *  Usage:
 *    DataWriter w;
 *    w.write_u32_le(version);
 *    w.write_compact_size(tx_count);
 *    const auto& bytes = w.data();
 */
class DataWriter {
public:
    DataWriter() = default;

    /** Pre-allocate buffer capacity for performance. */
    explicit DataWriter(size_t reserve) { buf_.reserve(reserve); }

    // --- Primitive writes ---

    /** Write a single byte. */
    void write_u8(uint8_t v) { buf_.push_back(v); }

    /** Write a 16-bit unsigned integer (little-endian). */
    void write_u16_le(uint16_t v) {
        buf_.push_back(static_cast<uint8_t>(v));
        buf_.push_back(static_cast<uint8_t>(v >> 8));
    }

    /** Write a 32-bit unsigned integer (little-endian). */
    void write_u32_le(uint32_t v) {
        buf_.push_back(static_cast<uint8_t>(v));
        buf_.push_back(static_cast<uint8_t>(v >> 8));
        buf_.push_back(static_cast<uint8_t>(v >> 16));
        buf_.push_back(static_cast<uint8_t>(v >> 24));
    }

    /** Write a 64-bit unsigned integer (little-endian). */
    void write_u64_le(uint64_t v) {
        for (int i = 0; i < 8; ++i)
            buf_.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }

    /** Write a 64-bit signed integer (little-endian, stored as uint64). */
    void write_i64_le(int64_t v) {
        write_u64_le(static_cast<uint64_t>(v));
    }

    /** Write a 32-bit IEEE 754 float (little-endian, raw bytes via memcpy). */
    void write_float_le(float v) {
        uint32_t bits;
        std::memcpy(&bits, &v, sizeof(bits));
        write_u32_le(bits);
    }

    /** Write raw bytes. */
    void write_bytes(const uint8_t* data, size_t len) {
        buf_.insert(buf_.end(), data, data + len);
    }

    /** Write a Bitcoin-style CompactSize variable-length integer.
     *
     *  Encoding:
     *    < 0xfd:         1 byte
     *    <= 0xffff:      0xfd + 2 bytes (LE)
     *    <= 0xffffffff:  0xfe + 4 bytes (LE)
     *    else:           0xff + 8 bytes (LE)
     */
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

    // --- Access ---

    /** Access the serialized buffer (read-only). */
    const std::vector<uint8_t>& data() const { return buf_; }

    /** Move the buffer out of the writer (consumes the writer). */
    std::vector<uint8_t> release() { return std::move(buf_); }

    /** Current size of the serialized data in bytes. */
    size_t size() const { return buf_.size(); }

private:
    std::vector<uint8_t> buf_;
};

// ===========================================================================
// DataReader — streaming deserializer over a fixed byte span
// ===========================================================================

/** Reads serialized data from a contiguous byte region.
 *  All reads check bounds and set an internal error flag on failure
 *  (no exceptions are thrown). Callers should check error() after
 *  a sequence of reads.
 *
 *  Usage:
 *    DataReader r(data_ptr, data_len);
 *    uint32_t version = r.read_u32_le();
 *    uint64_t count = r.read_compact_size();
 *    if (r.error()) { ... handle error ... }
 */
class DataReader {
public:
    DataReader(const uint8_t* data, size_t len)
        : data_(data), len_(len), pos_(0), error_(false) {}

    // --- Primitive reads ---

    /** Read a single byte. Returns 0 on error. */
    uint8_t read_u8() {
        if (!check(1)) return 0;
        return data_[pos_++];
    }

    /** Read a 16-bit unsigned integer (little-endian). Returns 0 on error. */
    uint16_t read_u16_le() {
        if (!check(2)) return 0;
        uint16_t v = static_cast<uint16_t>(data_[pos_])
                   | (static_cast<uint16_t>(data_[pos_ + 1]) << 8);
        pos_ += 2;
        return v;
    }

    /** Read a 32-bit unsigned integer (little-endian). Returns 0 on error. */
    uint32_t read_u32_le() {
        if (!check(4)) return 0;
        uint32_t v = static_cast<uint32_t>(data_[pos_])
                   | (static_cast<uint32_t>(data_[pos_ + 1]) << 8)
                   | (static_cast<uint32_t>(data_[pos_ + 2]) << 16)
                   | (static_cast<uint32_t>(data_[pos_ + 3]) << 24);
        pos_ += 4;
        return v;
    }

    /** Read a 64-bit unsigned integer (little-endian). Returns 0 on error. */
    uint64_t read_u64_le() {
        if (!check(8)) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v |= static_cast<uint64_t>(data_[pos_ + i]) << (i * 8);
        pos_ += 8;
        return v;
    }

    /** Read a 64-bit signed integer (little-endian). Returns 0 on error. */
    int64_t read_i64_le() {
        return static_cast<int64_t>(read_u64_le());
    }

    /** Read a 32-bit IEEE 754 float (little-endian). Returns 0.0f on error. */
    float read_float_le() {
        uint32_t bits = read_u32_le();
        if (error_) return 0.0f;
        float f;
        std::memcpy(&f, &bits, sizeof(f));
        return f;
    }

    /** Read n bytes into a new vector. Returns empty vector on error. */
    std::vector<uint8_t> read_bytes(size_t n) {
        if (!check(n)) return {};
        std::vector<uint8_t> result(data_ + pos_, data_ + pos_ + n);
        pos_ += n;
        return result;
    }

    /** Read a Bitcoin-style CompactSize variable-length integer.
     *  Returns 0 on error.
     */
    uint64_t read_compact_size() {
        uint8_t first = read_u8();
        if (error_) return 0;
        if (first < 0xfd) return first;
        if (first == 0xfd) return read_u16_le();
        if (first == 0xfe) return read_u32_le();
        return read_u64_le();  // first == 0xff
    }

    // --- Status ---

    /** Number of bytes remaining to be read. */
    size_t remaining() const {
        return (pos_ <= len_) ? (len_ - pos_) : 0;
    }

    /** Return true if all data has been consumed. */
    bool eof() const { return pos_ >= len_; }

    /** Return true if an out-of-bounds read was attempted. */
    bool error() const { return error_; }

    /** Return a human-readable error message, or empty string if no error. */
    std::string error_msg() const {
        if (!error_) return {};
        return "DataReader: read past end of buffer at offset "
             + std::to_string(pos_) + " (buffer size " + std::to_string(len_) + ")";
    }

private:
    const uint8_t* data_;
    size_t len_;
    size_t pos_;
    bool error_;

    /** Check that at least n bytes remain. Sets error flag on failure. */
    bool check(size_t n) {
        if (error_) return false;
        if (pos_ + n > len_) {
            error_ = true;
            return false;
        }
        return true;
    }
};

} // namespace flow

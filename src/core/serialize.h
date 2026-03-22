// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <vector>

namespace flow {

// ─── Little-endian write ──────────────────────────────────────

inline void write_le16(uint8_t* dst, uint16_t v) {
    dst[0] = static_cast<uint8_t>(v);
    dst[1] = static_cast<uint8_t>(v >> 8);
}

inline void write_le32(uint8_t* dst, uint32_t v) {
    dst[0] = static_cast<uint8_t>(v);
    dst[1] = static_cast<uint8_t>(v >> 8);
    dst[2] = static_cast<uint8_t>(v >> 16);
    dst[3] = static_cast<uint8_t>(v >> 24);
}

inline void write_le64(uint8_t* dst, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        dst[i] = static_cast<uint8_t>(v >> (i * 8));
    }
}

// ─── Little-endian read ───────────────────────────────────────

inline uint16_t read_le16(const uint8_t* src) {
    return static_cast<uint16_t>(src[0])
         | (static_cast<uint16_t>(src[1]) << 8);
}

inline uint32_t read_le32(const uint8_t* src) {
    return static_cast<uint32_t>(src[0])
         | (static_cast<uint32_t>(src[1]) << 8)
         | (static_cast<uint32_t>(src[2]) << 16)
         | (static_cast<uint32_t>(src[3]) << 24);
}

inline uint64_t read_le64(const uint8_t* src) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(src[i]) << (i * 8);
    }
    return v;
}

inline float read_le_float(const uint8_t* src) {
    uint32_t bits = read_le32(src);
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

inline void write_le_float(uint8_t* dst, float f) {
    uint32_t bits;
    std::memcpy(&bits, &f, sizeof(bits));
    write_le32(dst, bits);
}

// ─── Streaming serializer ─────────────────────────────────────

class VectorWriter {
public:
    VectorWriter() = default;
    explicit VectorWriter(size_t reserve) { buf_.reserve(reserve); }

    void write(const uint8_t* data, size_t len) {
        buf_.insert(buf_.end(), data, data + len);
    }

    void write_u8(uint8_t v) { buf_.push_back(v); }

    void write_u16(uint16_t v) {
        uint8_t tmp[2];
        write_le16(tmp, v);
        write(tmp, 2);
    }

    void write_u32(uint32_t v) {
        uint8_t tmp[4];
        write_le32(tmp, v);
        write(tmp, 4);
    }

    void write_u64(uint64_t v) {
        uint8_t tmp[8];
        write_le64(tmp, v);
        write(tmp, 8);
    }

    void write_i64(int64_t v) {
        write_u64(static_cast<uint64_t>(v));
    }

    void write_float(float v) {
        uint8_t tmp[4];
        write_le_float(tmp, v);
        write(tmp, 4);
    }

    void write_bytes(std::span<const uint8_t> data) {
        write(data.data(), data.size());
    }

    // CompactSize: Bitcoin-style variable-length integer encoding
    void write_compact_size(uint64_t v) {
        if (v < 253) {
            write_u8(static_cast<uint8_t>(v));
        } else if (v <= 0xFFFF) {
            write_u8(253);
            write_u16(static_cast<uint16_t>(v));
        } else if (v <= 0xFFFFFFFF) {
            write_u8(254);
            write_u32(static_cast<uint32_t>(v));
        } else {
            write_u8(255);
            write_u64(v);
        }
    }

    const std::vector<uint8_t>& data() const { return buf_; }
    std::vector<uint8_t> release() { return std::move(buf_); }
    size_t size() const { return buf_.size(); }

private:
    std::vector<uint8_t> buf_;
};

// ─── Streaming deserializer ───────────────────────────────────

class SpanReader {
public:
    explicit SpanReader(std::span<const uint8_t> data) : data_(data) {}

    void read(uint8_t* dst, size_t len) {
        if (pos_ + len > data_.size()) {
            throw std::runtime_error("SpanReader: read past end");
        }
        std::memcpy(dst, data_.data() + pos_, len);
        pos_ += len;
    }

    uint8_t read_u8() {
        if (pos_ >= data_.size()) {
            throw std::runtime_error("SpanReader: read past end");
        }
        return data_[pos_++];
    }

    uint16_t read_u16() {
        uint8_t tmp[2];
        read(tmp, 2);
        return read_le16(tmp);
    }

    uint32_t read_u32() {
        uint8_t tmp[4];
        read(tmp, 4);
        return read_le32(tmp);
    }

    uint64_t read_u64() {
        uint8_t tmp[8];
        read(tmp, 8);
        return read_le64(tmp);
    }

    int64_t read_i64() {
        return static_cast<int64_t>(read_u64());
    }

    float read_float() {
        uint8_t tmp[4];
        read(tmp, 4);
        return read_le_float(tmp);
    }

    void read_bytes(uint8_t* dst, size_t len) {
        read(dst, len);
    }

    uint64_t read_compact_size() {
        uint8_t first = read_u8();
        if (first < 253) return first;
        if (first == 253) return read_u16();
        if (first == 254) return read_u32();
        return read_u64();
    }

    size_t remaining() const { return data_.size() - pos_; }
    bool empty() const { return pos_ >= data_.size(); }
    size_t position() const { return pos_; }

private:
    std::span<const uint8_t> data_;
    size_t pos_{0};
};

} // namespace flow

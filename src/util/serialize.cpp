// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Serialization helper implementations.
// Most serialization is header-only (in serialize.h), but these functions
// provide utility operations that benefit from being in a compilation unit.

#include "serialize.h"
#include "../hash/keccak.h"
#include "types.h"

#include <algorithm>
#include <cstring>

namespace flow {

// ===========================================================================
// CHashWriter -- serialize directly into a hash computation
// ===========================================================================
// Writes data into a Keccak-256 hasher instead of a buffer.
// Useful for computing the hash of a serialized structure without
// materializing the full serialized form in memory.
//
// This class is defined entirely in this .cpp file because it requires
// the full CKeccak256 definition from hash/keccak.h.

class CHashWriter {
public:
    CKeccak256 hasher_;
    size_t size_ = 0;

    CHashWriter() { hasher_.reset(); }

    void write_u8(uint8_t v);
    void write_u16_le(uint16_t v);
    void write_u32_le(uint32_t v);
    void write_u64_le(uint64_t v);
    void write_i64_le(int64_t v);
    void write_float_le(float v);
    void write_double_le(double v);
    void write_bytes(const uint8_t* data, size_t len);
    void write_compact_size(uint64_t v);
    void write_string(const std::string& s);
    void write_byte_vector(const std::vector<uint8_t>& v);
    void write_bool(bool v);
    uint256 finalize();
    uint256 finalize_double();
    void reset();
    size_t size() const;
};

void CHashWriter::write_u8(uint8_t v) {
    hasher_.update(&v, 1);
    size_ += 1;
}

void CHashWriter::write_u16_le(uint16_t v) {
    uint8_t buf[2];
    buf[0] = static_cast<uint8_t>(v);
    buf[1] = static_cast<uint8_t>(v >> 8);
    hasher_.update(buf, 2);
    size_ += 2;
}

void CHashWriter::write_u32_le(uint32_t v) {
    uint8_t buf[4];
    buf[0] = static_cast<uint8_t>(v);
    buf[1] = static_cast<uint8_t>(v >> 8);
    buf[2] = static_cast<uint8_t>(v >> 16);
    buf[3] = static_cast<uint8_t>(v >> 24);
    hasher_.update(buf, 4);
    size_ += 4;
}

void CHashWriter::write_u64_le(uint64_t v) {
    uint8_t buf[8];
    for (int i = 0; i < 8; ++i)
        buf[i] = static_cast<uint8_t>(v >> (i * 8));
    hasher_.update(buf, 8);
    size_ += 8;
}

void CHashWriter::write_i64_le(int64_t v) {
    write_u64_le(static_cast<uint64_t>(v));
}

void CHashWriter::write_float_le(float v) {
    uint32_t bits;
    std::memcpy(&bits, &v, sizeof(bits));
    write_u32_le(bits);
}

void CHashWriter::write_double_le(double v) {
    uint64_t bits;
    std::memcpy(&bits, &v, sizeof(bits));
    write_u64_le(bits);
}

void CHashWriter::write_bytes(const uint8_t* data, size_t len) {
    hasher_.update(data, len);
    size_ += len;
}

void CHashWriter::write_compact_size(uint64_t v) {
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

void CHashWriter::write_string(const std::string& s) {
    write_compact_size(s.size());
    write_bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void CHashWriter::write_byte_vector(const std::vector<uint8_t>& v) {
    write_compact_size(v.size());
    if (!v.empty()) {
        write_bytes(v.data(), v.size());
    }
}

void CHashWriter::write_bool(bool v) {
    write_u8(v ? 1 : 0);
}

uint256 CHashWriter::finalize() {
    return hasher_.finalize();
}

uint256 CHashWriter::finalize_double() {
    uint256 first = hasher_.finalize();
    return keccak256(first.data(), 32);
}

void CHashWriter::reset() {
    hasher_.reset();
    size_ = 0;
}

size_t CHashWriter::size() const {
    return size_;
}

// ===========================================================================
// Hex serialization helpers
// ===========================================================================

std::string SerializeToHex(const std::vector<uint8_t>& data) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t b : data) {
        result.push_back(hex_chars[b >> 4]);
        result.push_back(hex_chars[b & 0x0f]);
    }
    return result;
}

std::vector<uint8_t> DeserializeFromHex(const std::string& hex) {
    if (hex.size() % 2 != 0) return {};

    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        auto hex_val = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };

        int hi = hex_val(hex[i]);
        int lo = hex_val(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        result.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return result;
}

// ===========================================================================
// DataStream utility methods
// ===========================================================================

DataStream DataStream::from_hex(const std::string& hex) {
    auto bytes = DeserializeFromHex(hex);
    return DataStream(std::move(bytes));
}

std::string DataStream::to_hex() const {
    return SerializeToHex(buf_);
}

// ===========================================================================
// Byte order conversion helpers
// ===========================================================================

uint16_t ReadLE16(const uint8_t* ptr) {
    return static_cast<uint16_t>(ptr[0])
         | (static_cast<uint16_t>(ptr[1]) << 8);
}

uint32_t ReadLE32(const uint8_t* ptr) {
    return static_cast<uint32_t>(ptr[0])
         | (static_cast<uint32_t>(ptr[1]) << 8)
         | (static_cast<uint32_t>(ptr[2]) << 16)
         | (static_cast<uint32_t>(ptr[3]) << 24);
}

uint64_t ReadLE64(const uint8_t* ptr) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<uint64_t>(ptr[i]) << (i * 8);
    return v;
}

void WriteLE16(uint8_t* ptr, uint16_t v) {
    ptr[0] = static_cast<uint8_t>(v);
    ptr[1] = static_cast<uint8_t>(v >> 8);
}

void WriteLE32(uint8_t* ptr, uint32_t v) {
    ptr[0] = static_cast<uint8_t>(v);
    ptr[1] = static_cast<uint8_t>(v >> 8);
    ptr[2] = static_cast<uint8_t>(v >> 16);
    ptr[3] = static_cast<uint8_t>(v >> 24);
}

void WriteLE64(uint8_t* ptr, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        ptr[i] = static_cast<uint8_t>(v >> (i * 8));
}

uint16_t ReadBE16(const uint8_t* ptr) {
    return static_cast<uint16_t>(ptr[1])
         | (static_cast<uint16_t>(ptr[0]) << 8);
}

uint32_t ReadBE32(const uint8_t* ptr) {
    return static_cast<uint32_t>(ptr[3])
         | (static_cast<uint32_t>(ptr[2]) << 8)
         | (static_cast<uint32_t>(ptr[1]) << 16)
         | (static_cast<uint32_t>(ptr[0]) << 24);
}

uint64_t ReadBE64(const uint8_t* ptr) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<uint64_t>(ptr[7 - i]) << (i * 8);
    return v;
}

void WriteBE16(uint8_t* ptr, uint16_t v) {
    ptr[0] = static_cast<uint8_t>(v >> 8);
    ptr[1] = static_cast<uint8_t>(v);
}

void WriteBE32(uint8_t* ptr, uint32_t v) {
    ptr[0] = static_cast<uint8_t>(v >> 24);
    ptr[1] = static_cast<uint8_t>(v >> 16);
    ptr[2] = static_cast<uint8_t>(v >> 8);
    ptr[3] = static_cast<uint8_t>(v);
}

void WriteBE64(uint8_t* ptr, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        ptr[i] = static_cast<uint8_t>(v >> ((7 - i) * 8));
}

} // namespace flow

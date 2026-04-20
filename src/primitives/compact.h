// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// CompactSize and VarInt encoding for FlowCoin wire protocol.
//
// CompactSize encoding (Bitcoin-compatible):
//   Value range          Wire format
//   0-252               1 byte
//   253-0xFFFF           0xFD + 2 bytes LE
//   0x10000-0xFFFFFFFF   0xFE + 4 bytes LE
//   > 0xFFFFFFFF         0xFF + 8 bytes LE
//
// VarInt encoding (7-bit chunks with continuation bit):
//   Used in block file indexes for compact storage.
//   Each byte uses bits 0-6 for data and bit 7 as continuation flag.
//   Final byte has bit 7 cleared. Encodes MSB first.

#ifndef FLOWCOIN_PRIMITIVES_COMPACT_H
#define FLOWCOIN_PRIMITIVES_COMPACT_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// CompactSize: Bitcoin-compatible variable-length integer encoding
// ---------------------------------------------------------------------------

class CompactSize {
public:
    /// Encode a value into the output buffer.
    /// @param value  The integer to encode.
    /// @param out    Output buffer (must have at least 9 bytes available).
    /// @return       Number of bytes written (1, 3, 5, or 9).
    static size_t encode(uint64_t value, uint8_t* out);

    /// Decode a CompactSize from a byte buffer.
    /// @param data   Input buffer.
    /// @param len    Length of input buffer in bytes.
    /// @param value  Output: decoded integer value.
    /// @return       Number of bytes consumed, or 0 on error (buffer too short).
    static size_t decode(const uint8_t* data, size_t len, uint64_t& value);

    /// Compute the encoded size without actually encoding.
    /// @param value  The integer to measure.
    /// @return       Number of bytes the encoding would occupy (1, 3, 5, or 9).
    static size_t encoded_size(uint64_t value);

    /// Encode into a vector, appending bytes.
    static void encode_to(uint64_t value, std::vector<uint8_t>& out);

    /// Decode from a vector starting at a given offset.
    /// @param data   Input vector.
    /// @param offset Starting offset (updated on success to point past the decoded value).
    /// @param value  Output: decoded integer value.
    /// @return       true on success, false if buffer is too short.
    static bool decode_from(const std::vector<uint8_t>& data, size_t& offset, uint64_t& value);

    /// Maximum value that can be encoded with a given number of bytes.
    static constexpr uint64_t max_for_size(size_t n_bytes) {
        switch (n_bytes) {
            case 1: return 252;
            case 3: return 0xFFFF;
            case 5: return 0xFFFFFFFF;
            case 9: return 0xFFFFFFFFFFFFFFFFULL;
            default: return 0;
        }
    }

    /// Check if a value is in canonical form.
    /// Non-canonical encodings use more bytes than necessary and are rejected
    /// by strict validation to prevent malleability.
    static bool is_canonical(uint64_t value, size_t wire_bytes);
};

// ---------------------------------------------------------------------------
// VarInt: 7-bit variable-length integer encoding (block file format)
// ---------------------------------------------------------------------------

class VarInt {
public:
    /// Encode a value into the output buffer using 7-bit chunks.
    /// @param value  The integer to encode.
    /// @param out    Output buffer (must have at least 10 bytes available).
    /// @return       Number of bytes written.
    static size_t encode(uint64_t value, uint8_t* out);

    /// Decode a VarInt from a byte buffer.
    /// @param data   Input buffer.
    /// @param len    Length of input buffer in bytes.
    /// @param value  Output: decoded integer value.
    /// @return       Number of bytes consumed, or 0 on error.
    static size_t decode(const uint8_t* data, size_t len, uint64_t& value);

    /// Compute the encoded size without actually encoding.
    static size_t encoded_size(uint64_t value);

    /// Encode into a vector, appending bytes.
    static void encode_to(uint64_t value, std::vector<uint8_t>& out);

    /// Decode from a vector starting at a given offset.
    static bool decode_from(const std::vector<uint8_t>& data, size_t& offset, uint64_t& value);

    /// Maximum number of bytes a VarInt can occupy (for uint64_t: 10).
    static constexpr size_t MAX_SIZE = 10;
};

// ---------------------------------------------------------------------------
// CompactSizeWriter: streaming CompactSize writer for serialization
// ---------------------------------------------------------------------------

class CompactSizeWriter {
public:
    explicit CompactSizeWriter(std::vector<uint8_t>& buf) : buf_(buf) {}

    /// Write a CompactSize-encoded integer.
    void write(uint64_t value) {
        CompactSize::encode_to(value, buf_);
    }

    /// Write a length-prefixed byte vector.
    void write_bytes(const uint8_t* data, size_t len) {
        write(len);
        buf_.insert(buf_.end(), data, data + len);
    }

    /// Write a length-prefixed byte vector.
    void write_bytes(const std::vector<uint8_t>& data) {
        write_bytes(data.data(), data.size());
    }

private:
    std::vector<uint8_t>& buf_;
};

// ---------------------------------------------------------------------------
// CompactSizeReader: streaming CompactSize reader for deserialization
// ---------------------------------------------------------------------------

class CompactSizeReader {
public:
    CompactSizeReader(const uint8_t* data, size_t len)
        : data_(data), len_(len), pos_(0), error_(false) {}

    /// Read a CompactSize-encoded integer. Returns 0 and sets error on failure.
    uint64_t read() {
        if (error_) return 0;
        uint64_t value = 0;
        size_t consumed = CompactSize::decode(data_ + pos_, len_ - pos_, value);
        if (consumed == 0) {
            error_ = true;
            return 0;
        }
        pos_ += consumed;
        return value;
    }

    /// Read a CompactSize-encoded integer with a maximum value check.
    uint64_t read_limited(uint64_t max_value) {
        uint64_t v = read();
        if (!error_ && v > max_value) {
            error_ = true;
            return 0;
        }
        return v;
    }

    /// Read a length-prefixed byte vector.
    std::vector<uint8_t> read_bytes() {
        uint64_t len = read();
        if (error_ || len > remaining()) {
            error_ = true;
            return {};
        }
        std::vector<uint8_t> result(data_ + pos_, data_ + pos_ + len);
        pos_ += static_cast<size_t>(len);
        return result;
    }

    /// Read raw bytes of a specified length (no length prefix).
    std::vector<uint8_t> read_raw(size_t n) {
        if (error_ || n > remaining()) {
            error_ = true;
            return {};
        }
        std::vector<uint8_t> result(data_ + pos_, data_ + pos_ + n);
        pos_ += n;
        return result;
    }

    size_t remaining() const {
        return (pos_ <= len_) ? (len_ - pos_) : 0;
    }
    size_t position() const { return pos_; }
    bool error() const { return error_; }
    bool eof() const { return pos_ >= len_; }

private:
    const uint8_t* data_;
    size_t len_;
    size_t pos_;
    bool error_;
};

} // namespace flow

#endif // FLOWCOIN_PRIMITIVES_COMPACT_H

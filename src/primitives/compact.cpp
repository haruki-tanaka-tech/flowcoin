// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "compact.h"

#include <cstring>

namespace flow {

// ===========================================================================
// CompactSize
// ===========================================================================

size_t CompactSize::encode(uint64_t value, uint8_t* out) {
    if (value < 253) {
        out[0] = static_cast<uint8_t>(value);
        return 1;
    }
    if (value <= 0xFFFF) {
        out[0] = 0xFD;
        out[1] = static_cast<uint8_t>(value);
        out[2] = static_cast<uint8_t>(value >> 8);
        return 3;
    }
    if (value <= 0xFFFFFFFF) {
        out[0] = 0xFE;
        out[1] = static_cast<uint8_t>(value);
        out[2] = static_cast<uint8_t>(value >> 8);
        out[3] = static_cast<uint8_t>(value >> 16);
        out[4] = static_cast<uint8_t>(value >> 24);
        return 5;
    }
    out[0] = 0xFF;
    for (int i = 0; i < 8; ++i) {
        out[1 + i] = static_cast<uint8_t>(value >> (i * 8));
    }
    return 9;
}

size_t CompactSize::decode(const uint8_t* data, size_t len, uint64_t& value) {
    if (len < 1) return 0;

    uint8_t first = data[0];

    if (first < 0xFD) {
        value = first;
        return 1;
    }
    if (first == 0xFD) {
        if (len < 3) return 0;
        value = static_cast<uint64_t>(data[1])
              | (static_cast<uint64_t>(data[2]) << 8);
        return 3;
    }
    if (first == 0xFE) {
        if (len < 5) return 0;
        value = static_cast<uint64_t>(data[1])
              | (static_cast<uint64_t>(data[2]) << 8)
              | (static_cast<uint64_t>(data[3]) << 16)
              | (static_cast<uint64_t>(data[4]) << 24);
        return 5;
    }
    // first == 0xFF
    if (len < 9) return 0;
    value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(data[1 + i]) << (i * 8);
    }
    return 9;
}

size_t CompactSize::encoded_size(uint64_t value) {
    if (value < 253) return 1;
    if (value <= 0xFFFF) return 3;
    if (value <= 0xFFFFFFFF) return 5;
    return 9;
}

void CompactSize::encode_to(uint64_t value, std::vector<uint8_t>& out) {
    uint8_t buf[9];
    size_t n = encode(value, buf);
    out.insert(out.end(), buf, buf + n);
}

bool CompactSize::decode_from(const std::vector<uint8_t>& data, size_t& offset, uint64_t& value) {
    if (offset >= data.size()) return false;
    size_t consumed = decode(data.data() + offset, data.size() - offset, value);
    if (consumed == 0) return false;
    offset += consumed;
    return true;
}

bool CompactSize::is_canonical(uint64_t value, size_t wire_bytes) {
    // A canonical encoding uses the minimum number of bytes.
    return wire_bytes == encoded_size(value);
}

// ===========================================================================
// VarInt (7-bit continuation encoding)
// ===========================================================================
//
// Encoding uses Bitcoin Core's VarInt format for block file indexes:
//   - Each byte encodes 7 bits of data (bits 0-6).
//   - Bit 7 is set on all bytes except the last.
//   - To avoid ambiguity, each continuation byte adds 1 to its value
//     before shifting. This means the encoding is unique.
//
// Encoding algorithm:
//   tmp[0] = value & 0x7F
//   value >>= 7
//   while (value > 0):
//     value -= 1  (ensures unique representation)
//     tmp[n] = (value & 0x7F) | 0x80
//     value >>= 7
//   Write tmp[] in reverse order.
//
// Decoding:
//   value = 0
//   loop:
//     byte = read()
//     value = (value << 7) | (byte & 0x7F)
//     if (byte & 0x80) == 0: break
//     value += 1  (undo the -1 from encoding)

size_t VarInt::encode(uint64_t value, uint8_t* out) {
    // Build in a temporary buffer (reversed output).
    uint8_t tmp[MAX_SIZE];
    size_t n = 0;

    tmp[n] = static_cast<uint8_t>(value & 0x7F);
    ++n;
    value >>= 7;

    while (value > 0) {
        value -= 1;
        tmp[n] = static_cast<uint8_t>((value & 0x7F) | 0x80);
        ++n;
        value >>= 7;
    }

    // Reverse into output buffer.
    for (size_t i = 0; i < n; ++i) {
        out[i] = tmp[n - 1 - i];
    }
    return n;
}

size_t VarInt::decode(const uint8_t* data, size_t len, uint64_t& value) {
    value = 0;
    size_t i = 0;

    for (;;) {
        if (i >= len) return 0;  // buffer exhausted
        if (i >= MAX_SIZE) return 0;  // too many bytes, corrupt data

        uint8_t byte = data[i];
        value = (value << 7) | (byte & 0x7F);
        ++i;

        if ((byte & 0x80) == 0) {
            return i;
        }
        value += 1;
    }
}

size_t VarInt::encoded_size(uint64_t value) {
    uint8_t tmp[MAX_SIZE];
    return encode(value, tmp);
}

void VarInt::encode_to(uint64_t value, std::vector<uint8_t>& out) {
    uint8_t buf[MAX_SIZE];
    size_t n = encode(value, buf);
    out.insert(out.end(), buf, buf + n);
}

bool VarInt::decode_from(const std::vector<uint8_t>& data, size_t& offset, uint64_t& value) {
    if (offset >= data.size()) return false;
    size_t consumed = decode(data.data() + offset, data.size() - offset, value);
    if (consumed == 0) return false;
    offset += consumed;
    return true;
}

} // namespace flow

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "keccak.h"

#include <cstring>
#include <stdexcept>

namespace flow {

// ===========================================================================
// Internal helper -- single-shot Keccak-256 into a raw 32-byte buffer
// ===========================================================================

static void keccak256_raw(const uint8_t* data, size_t len, uint8_t* out32) {
    Keccak_HashInstance ctx;
    /* rate=1088, capacity=512, output=256 bits, delimitedSuffix=0x01 (original Keccak) */
    if (Keccak_HashInitialize(&ctx, 1088, 512, 256, 0x01) != KECCAK_SUCCESS) {
        throw std::runtime_error("Keccak_HashInitialize failed");
    }
    if (Keccak_HashUpdate(&ctx, data, len * 8) != KECCAK_SUCCESS) {
        throw std::runtime_error("Keccak_HashUpdate failed");
    }
    if (Keccak_HashFinal(&ctx, out32) != KECCAK_SUCCESS) {
        throw std::runtime_error("Keccak_HashFinal failed");
    }
}

// Internal: Keccak-512 single-shot
static void keccak512_raw(const uint8_t* data, size_t len, uint8_t* out64) {
    Keccak_HashInstance ctx;
    if (Keccak_HashInitialize(&ctx, 576, 1024, 512, 0x01) != KECCAK_SUCCESS) {
        throw std::runtime_error("keccak512 init failed");
    }
    if (Keccak_HashUpdate(&ctx, data, len * 8) != KECCAK_SUCCESS) {
        throw std::runtime_error("keccak512 update failed");
    }
    if (Keccak_HashFinal(&ctx, out64) != KECCAK_SUCCESS) {
        throw std::runtime_error("keccak512 finalize failed");
    }
}

// ===========================================================================
// Single-shot Keccak-256
// ===========================================================================

uint256 keccak256(const uint8_t* data, size_t len) {
    uint256 result;
    keccak256_raw(data, len, result.data());
    return result;
}

uint256 keccak256(const std::vector<uint8_t>& data) {
    return keccak256(data.data(), data.size());
}

uint256 keccak256(const std::string& data) {
    return keccak256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// ===========================================================================
// Double hash
// ===========================================================================

uint256 keccak256d(const uint8_t* data, size_t len) {
    uint256 inner;
    keccak256_raw(data, len, inner.data());
    uint256 result;
    keccak256_raw(inner.data(), 32, result.data());
    return result;
}

uint256 keccak256d(const std::vector<uint8_t>& data) {
    return keccak256d(data.data(), data.size());
}

uint256 keccak256d(const std::string& data) {
    return keccak256d(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// ===========================================================================
// Incremental hasher: CKeccak256
// ===========================================================================

CKeccak256::CKeccak256() {
    reset();
}

void CKeccak256::update(const uint8_t* data, size_t len) {
    if (Keccak_HashUpdate(&state_, data, len * 8) != KECCAK_SUCCESS) {
        throw std::runtime_error("CKeccak256::update failed");
    }
}

void CKeccak256::update(const std::vector<uint8_t>& data) {
    update(data.data(), data.size());
}

void CKeccak256::update(const std::string& data) {
    update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

uint256 CKeccak256::finalize() {
    uint256 result;
    if (Keccak_HashFinal(&state_, result.data()) != KECCAK_SUCCESS) {
        throw std::runtime_error("CKeccak256::finalize failed");
    }
    return result;
}

void CKeccak256::reset() {
    if (Keccak_HashInitialize(&state_, 1088, 512, 256, 0x01) != KECCAK_SUCCESS) {
        throw std::runtime_error("CKeccak256::reset failed");
    }
}

// ===========================================================================
// Incremental hasher: CKeccak256D (double hash)
// ===========================================================================

CKeccak256D::CKeccak256D() = default;

void CKeccak256D::update(const uint8_t* data, size_t len) {
    inner_.update(data, len);
}

void CKeccak256D::update(const std::vector<uint8_t>& data) {
    inner_.update(data);
}

uint256 CKeccak256D::finalize() {
    // First hash
    uint256 inner_hash = inner_.finalize();
    // Second hash
    uint256 result;
    keccak256_raw(inner_hash.data(), 32, result.data());
    return result;
}

void CKeccak256D::reset() {
    inner_.reset();
}

// ===========================================================================
// Keccak-512
// ===========================================================================

uint512 keccak512(const uint8_t* data, size_t len) {
    uint512 result;
    keccak512_raw(data, len, result.data());
    return result;
}

uint512 keccak512(const std::vector<uint8_t>& data) {
    return keccak512(data.data(), data.size());
}

// ===========================================================================
// HashWriter
// ===========================================================================

HashWriter::HashWriter() = default;

void HashWriter::write(const uint8_t* data, size_t len) {
    hasher_.update(data, len);
}

void HashWriter::write(const std::vector<uint8_t>& data) {
    hasher_.update(data);
}

uint256 HashWriter::GetHash() {
    uint256 result = hasher_.finalize();
    hasher_.reset();
    return result;
}

uint256 HashWriter::GetDoubleHash() {
    uint256 inner = hasher_.finalize();
    hasher_.reset();
    uint256 result;
    keccak256_raw(inner.data(), 32, result.data());
    return result;
}

void HashWriter::reset() {
    hasher_.reset();
}

// Little-endian serialization helpers
static void write_le16(uint8_t* out, uint16_t val) {
    out[0] = static_cast<uint8_t>(val);
    out[1] = static_cast<uint8_t>(val >> 8);
}

static void write_le32(uint8_t* out, uint32_t val) {
    out[0] = static_cast<uint8_t>(val);
    out[1] = static_cast<uint8_t>(val >> 8);
    out[2] = static_cast<uint8_t>(val >> 16);
    out[3] = static_cast<uint8_t>(val >> 24);
}

static void write_le64(uint8_t* out, uint64_t val) {
    for (int i = 0; i < 8; ++i) {
        out[i] = static_cast<uint8_t>(val >> (i * 8));
    }
}

HashWriter& HashWriter::operator<<(uint8_t val) {
    write(&val, 1);
    return *this;
}

HashWriter& HashWriter::operator<<(uint16_t val) {
    uint8_t buf[2];
    write_le16(buf, val);
    write(buf, 2);
    return *this;
}

HashWriter& HashWriter::operator<<(uint32_t val) {
    uint8_t buf[4];
    write_le32(buf, val);
    write(buf, 4);
    return *this;
}

HashWriter& HashWriter::operator<<(uint64_t val) {
    uint8_t buf[8];
    write_le64(buf, val);
    write(buf, 8);
    return *this;
}

HashWriter& HashWriter::operator<<(int32_t val) {
    return *this << static_cast<uint32_t>(val);
}

HashWriter& HashWriter::operator<<(int64_t val) {
    return *this << static_cast<uint64_t>(val);
}

HashWriter& HashWriter::operator<<(const uint256& val) {
    write(val.data(), val.size());
    return *this;
}

HashWriter& HashWriter::operator<<(const uint512& val) {
    write(val.data(), val.size());
    return *this;
}

HashWriter& HashWriter::operator<<(const std::vector<uint8_t>& val) {
    // Write length as compact size (simplified: up to 32-bit length)
    uint64_t sz = val.size();
    if (sz < 253) {
        uint8_t b = static_cast<uint8_t>(sz);
        write(&b, 1);
    } else if (sz <= 0xffff) {
        uint8_t b = 253;
        write(&b, 1);
        uint8_t buf[2];
        write_le16(buf, static_cast<uint16_t>(sz));
        write(buf, 2);
    } else if (sz <= 0xffffffff) {
        uint8_t b = 254;
        write(&b, 1);
        uint8_t buf[4];
        write_le32(buf, static_cast<uint32_t>(sz));
        write(buf, 4);
    } else {
        uint8_t b = 255;
        write(&b, 1);
        uint8_t buf[8];
        write_le64(buf, sz);
        write(buf, 8);
    }
    if (!val.empty()) {
        write(val.data(), val.size());
    }
    return *this;
}

HashWriter& HashWriter::operator<<(const std::string& val) {
    std::vector<uint8_t> bytes(val.begin(), val.end());
    return *this << bytes;
}

// ===========================================================================
// Hash comparison utilities
// ===========================================================================

bool hash_meets_target(const uint256& hash, const uint256& target) {
    return hash <= target;
}

bool hash_has_leading_zeros(const uint256& hash, int n_bits) {
    if (n_bits <= 0) return true;
    if (n_bits > 256) return false;

    int full_bytes = n_bits / 8;
    int remaining_bits = n_bits % 8;

    // Check full zero bytes
    for (int i = 0; i < full_bytes && i < 32; ++i) {
        if (hash[i] != 0) return false;
    }

    // Check remaining bits in the next byte
    if (remaining_bits > 0 && full_bytes < 32) {
        uint8_t mask = static_cast<uint8_t>(0xFF << (8 - remaining_bits));
        if ((hash[full_bytes] & mask) != 0) return false;
    }

    return true;
}

int count_leading_zeros(const uint256& hash) {
    int count = 0;
    for (int i = 0; i < 32; ++i) {
        if (hash[i] == 0) {
            count += 8;
        } else {
            // Count leading zeros in this byte
            uint8_t b = hash[i];
            for (int bit = 7; bit >= 0; --bit) {
                if (b & (1 << bit)) return count;
                count++;
            }
            return count;
        }
    }
    return 256;  // all zeros
}

} // namespace flow

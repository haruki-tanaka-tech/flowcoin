// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "keccak.h"

#include <cstring>
#include <stdexcept>

namespace flow {

// ---------------------------------------------------------------------------
// Internal helper — single-shot Keccak-256 into a raw 32-byte buffer
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Single-shot
// ---------------------------------------------------------------------------

uint256 keccak256(const uint8_t* data, size_t len) {
    uint256 result;
    keccak256_raw(data, len, result.data());
    return result;
}

uint256 keccak256(const std::vector<uint8_t>& data) {
    return keccak256(data.data(), data.size());
}

// ---------------------------------------------------------------------------
// Double hash
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Incremental hasher
// ---------------------------------------------------------------------------

CKeccak256::CKeccak256() {
    reset();
}

void CKeccak256::update(const uint8_t* data, size_t len) {
    if (Keccak_HashUpdate(&state_, data, len * 8) != KECCAK_SUCCESS) {
        throw std::runtime_error("CKeccak256::update failed");
    }
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

} // namespace flow

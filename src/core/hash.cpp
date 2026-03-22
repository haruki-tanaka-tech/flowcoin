// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "hash.h"

extern "C" {
#include <KeccakHash.h>
}

#include <cassert>
#include <cstring>

namespace flow {

static_assert(sizeof(Keccak_HashInstance) <= 256,
    "Keccak_HashInstance exceeds state_ buffer size");

Hash256 keccak256(const uint8_t* data, size_t len) {
    Hash256 result;
    Keccak_HashInstance ctx;
    // Keccak-256: rate=1088, capacity=512, suffix=0x01 (NOT 0x06 which is SHA-3)
    Keccak_HashInitialize(&ctx, 1088, 512, 256, 0x01);
    Keccak_HashUpdate(&ctx, data, len * 8); // length in bits
    Keccak_HashFinal(&ctx, result.bytes());
    return result;
}

Hash256 keccak256(std::span<const uint8_t> data) {
    return keccak256(data.data(), data.size());
}

Hash256 keccak256d(const uint8_t* data, size_t len) {
    Hash256 first = keccak256(data, len);
    return keccak256(first.bytes(), 32);
}

Hash256 keccak256d(std::span<const uint8_t> data) {
    return keccak256d(data.data(), data.size());
}

Keccak256Hasher::Keccak256Hasher() {
    auto* ctx = reinterpret_cast<Keccak_HashInstance*>(state_);
    Keccak_HashInitialize(ctx, 1088, 512, 256, 0x01);
}

void Keccak256Hasher::update(const uint8_t* data, size_t len) {
    auto* ctx = reinterpret_cast<Keccak_HashInstance*>(state_);
    Keccak_HashUpdate(ctx, data, len * 8);
}

void Keccak256Hasher::update(std::span<const uint8_t> data) {
    update(data.data(), data.size());
}

Hash256 Keccak256Hasher::finalize() {
    Hash256 result;
    auto* ctx = reinterpret_cast<Keccak_HashInstance*>(state_);
    Keccak_HashFinal(ctx, result.bytes());
    return result;
}

} // namespace flow

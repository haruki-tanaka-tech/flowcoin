// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#pragma once

#include "types.h"
#include <cstddef>
#include <cstdint>

namespace flow {

// Keccak-256 (pad=0x01, NOT SHA-3 pad=0x06)
// keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
Hash256 keccak256(const uint8_t* data, size_t len);
Hash256 keccak256(std::span<const uint8_t> data);

// Double Keccak-256: keccak256(keccak256(data))
Hash256 keccak256d(const uint8_t* data, size_t len);
Hash256 keccak256d(std::span<const uint8_t> data);

// Incremental hasher
class Keccak256Hasher {
public:
    Keccak256Hasher();
    void update(const uint8_t* data, size_t len);
    void update(std::span<const uint8_t> data);
    Hash256 finalize();

private:
    // KeccakHash context is 212 bytes. We over-allocate to be safe.
    alignas(8) uint8_t state_[256];
};

} // namespace flow

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Keccak-256 hashing wrappers over XKCP.
// Uses original Keccak padding (0x01), NOT SHA-3 (0x06).

#pragma once

#include "../util/types.h"
#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" {
#include "KeccakHash.h"
}

namespace flow {

// ---------------------------------------------------------------------------
// Single-shot Keccak-256
// ---------------------------------------------------------------------------

/** Hash arbitrary data with Keccak-256 (Ethereum-compatible, pad byte 0x01). */
uint256 keccak256(const uint8_t* data, size_t len);

/** Hash a byte vector with Keccak-256. */
uint256 keccak256(const std::vector<uint8_t>& data);

// ---------------------------------------------------------------------------
// Double Keccak-256 (analogous to Bitcoin's SHA256d)
// ---------------------------------------------------------------------------

/** Compute keccak256(keccak256(data)). */
uint256 keccak256d(const uint8_t* data, size_t len);

/** Compute keccak256(keccak256(data)). */
uint256 keccak256d(const std::vector<uint8_t>& data);

// ---------------------------------------------------------------------------
// Incremental hasher
// ---------------------------------------------------------------------------

/** Incremental Keccak-256 hasher for streaming data. */
class CKeccak256 {
public:
    CKeccak256();

    /** Feed data into the hash. Can be called multiple times. */
    void update(const uint8_t* data, size_t len);

    /** Finalize and return the 32-byte digest. The hasher is consumed;
     *  call reset() before reusing. */
    uint256 finalize();

    /** Reset to initial state for reuse. */
    void reset();

private:
    Keccak_HashInstance state_;
};

} // namespace flow

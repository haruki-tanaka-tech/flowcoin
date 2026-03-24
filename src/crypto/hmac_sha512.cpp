// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "hmac_sha512.h"

#include <cstring>
#include <stdexcept>
#include <vector>

extern "C" {
#include "../hash/KeccakHash.h"
}

namespace flow {

// Keccak-512 parameters
// rate = 576 bits = 72 bytes (this is the block size for HMAC)
static constexpr size_t KECCAK512_BLOCK_SIZE = 72;
static constexpr size_t KECCAK512_OUTPUT_SIZE = 64;

// ---------------------------------------------------------------------------
// Internal: raw Keccak-512 single-shot
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Internal: Keccak-512 incremental
// ---------------------------------------------------------------------------

struct Keccak512Ctx {
    Keccak_HashInstance state;

    Keccak512Ctx() {
        if (Keccak_HashInitialize(&state, 576, 1024, 512, 0x01) != KECCAK_SUCCESS) {
            throw std::runtime_error("keccak512 ctx init failed");
        }
    }

    void update(const uint8_t* data, size_t len) {
        if (Keccak_HashUpdate(&state, data, len * 8) != KECCAK_SUCCESS) {
            throw std::runtime_error("keccak512 ctx update failed");
        }
    }

    void finalize(uint8_t* out64) {
        if (Keccak_HashFinal(&state, out64) != KECCAK_SUCCESS) {
            throw std::runtime_error("keccak512 ctx finalize failed");
        }
    }
};

// ---------------------------------------------------------------------------
// HMAC-Keccak-512 (RFC 2104)
// ---------------------------------------------------------------------------

uint512 hmac_keccak512(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len)
{
    uint8_t key_block[KECCAK512_BLOCK_SIZE];
    std::memset(key_block, 0, KECCAK512_BLOCK_SIZE);

    // Step 1: If key is longer than block size, hash it
    if (key_len > KECCAK512_BLOCK_SIZE) {
        keccak512_raw(key, key_len, key_block);
        // key_block now contains the 64-byte hash, zero-padded to 72
    } else {
        std::memcpy(key_block, key, key_len);
        // Remaining bytes are already zero from memset
    }

    // Step 2: Compute ipad and opad
    uint8_t ipad[KECCAK512_BLOCK_SIZE];
    uint8_t opad[KECCAK512_BLOCK_SIZE];
    for (size_t i = 0; i < KECCAK512_BLOCK_SIZE; ++i) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    // Step 3: Inner hash = Keccak-512(ipad || data)
    uint8_t inner_hash[KECCAK512_OUTPUT_SIZE];
    {
        Keccak512Ctx ctx;
        ctx.update(ipad, KECCAK512_BLOCK_SIZE);
        ctx.update(data, data_len);
        ctx.finalize(inner_hash);
    }

    // Step 4: Outer hash = Keccak-512(opad || inner_hash)
    uint512 result;
    {
        Keccak512Ctx ctx;
        ctx.update(opad, KECCAK512_BLOCK_SIZE);
        ctx.update(inner_hash, KECCAK512_OUTPUT_SIZE);
        ctx.finalize(result.data());
    }

    // Wipe sensitive intermediates
    std::memset(key_block, 0, sizeof(key_block));
    std::memset(ipad, 0, sizeof(ipad));
    std::memset(opad, 0, sizeof(opad));
    std::memset(inner_hash, 0, sizeof(inner_hash));

    return result;
}

} // namespace flow

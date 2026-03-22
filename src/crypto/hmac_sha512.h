// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// HMAC-SHA512 implementation for SLIP-0010 HD derivation.
// SHA-512 is implemented inline (same as RFC 6234).

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace flow::crypto {

// SHA-512 state
struct Sha512State {
    uint64_t h[8];
    uint64_t total[2];
    uint8_t buffer[128];
    size_t buflen;
};

void sha512_init(Sha512State& s);
void sha512_update(Sha512State& s, const uint8_t* data, size_t len);
void sha512_final(Sha512State& s, uint8_t out[64]);

// SHA-512 one-shot
void sha512(const uint8_t* data, size_t len, uint8_t out[64]);

// HMAC-SHA512
void hmac_sha512(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t out[64]);

} // namespace flow::crypto

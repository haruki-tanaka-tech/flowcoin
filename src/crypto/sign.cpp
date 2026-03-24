// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "sign.h"

#include <cstring>

extern "C" {
#include "ed25519.h"
}

namespace flow {

std::array<uint8_t, 64> ed25519_sign(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* privkey,
    const uint8_t* pubkey)
{
    std::array<uint8_t, 64> sig;
    ::ed25519_sign(msg, msg_len, privkey, pubkey, sig.data());
    return sig;
}

bool ed25519_verify(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* pubkey,
    const uint8_t* signature)
{
    // ed25519_sign_open returns 0 on success, -1 on failure
    return ::ed25519_sign_open(msg, msg_len, pubkey, signature) == 0;
}

} // namespace flow

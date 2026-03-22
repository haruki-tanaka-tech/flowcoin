// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "sign.h"

extern "C" {
#include <ed25519.h>
}

namespace flow::crypto {

Signature sign(const PrivKey& privkey, const PubKey& pubkey,
               const uint8_t* msg, size_t msg_len) {
    Signature sig;
    ed25519_sign(msg, msg_len, privkey.bytes(), pubkey.bytes(), sig.bytes());
    return sig;
}

Signature sign(const PrivKey& privkey, const PubKey& pubkey,
               std::span<const uint8_t> msg) {
    return sign(privkey, pubkey, msg.data(), msg.size());
}

bool verify(const PubKey& pubkey, const uint8_t* msg, size_t msg_len,
            const Signature& sig) {
    // ed25519_sign_open returns 0 on success, non-zero on failure
    return ed25519_sign_open(msg, msg_len, pubkey.bytes(), sig.bytes()) == 0;
}

bool verify(const PubKey& pubkey, std::span<const uint8_t> msg,
            const Signature& sig) {
    return verify(pubkey, msg.data(), msg.size(), sig);
}

} // namespace flow::crypto

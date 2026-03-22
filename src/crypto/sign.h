// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#pragma once

#include "core/types.h"
#include <cstddef>
#include <cstdint>
#include <span>

namespace flow::crypto {

// Sign a message with Ed25519. Returns 64-byte signature.
Signature sign(const PrivKey& privkey, const PubKey& pubkey,
               const uint8_t* msg, size_t msg_len);

Signature sign(const PrivKey& privkey, const PubKey& pubkey,
               std::span<const uint8_t> msg);

// Verify an Ed25519 signature. Returns true if valid.
bool verify(const PubKey& pubkey, const uint8_t* msg, size_t msg_len,
            const Signature& sig);

bool verify(const PubKey& pubkey, std::span<const uint8_t> msg,
            const Signature& sig);

} // namespace flow::crypto

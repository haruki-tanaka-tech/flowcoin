// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Ed25519 signing and verification (Keccak-512 internals).

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace flow {

/** Sign a message with an Ed25519 private key.
 *  @param msg      Pointer to message bytes.
 *  @param msg_len  Length of the message.
 *  @param privkey  32-byte Ed25519 secret key seed.
 *  @param pubkey   32-byte Ed25519 public key.
 *  @return         64-byte Ed25519 signature.
 */
std::array<uint8_t, 64> ed25519_sign(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* privkey,
    const uint8_t* pubkey);

/** Verify an Ed25519 signature.
 *  @param msg       Pointer to message bytes.
 *  @param msg_len   Length of the message.
 *  @param pubkey    32-byte Ed25519 public key.
 *  @param signature 64-byte Ed25519 signature.
 *  @return          true if the signature is valid.
 */
bool ed25519_verify(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* pubkey,
    const uint8_t* signature);

} // namespace flow

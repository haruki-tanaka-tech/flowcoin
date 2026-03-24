// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Ed25519 signing and verification (Keccak-512 internals).
// Full signing API including batch verification and convenience wrappers.

#pragma once

#include "../util/types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// Core Ed25519 signing / verification
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Hash-based signing (sign a pre-computed 32-byte hash)
// ---------------------------------------------------------------------------

/** Sign a pre-computed 32-byte hash with Ed25519.
 *  This is used for signing block headers and transaction hashes
 *  where the hash has already been computed.
 *  @param hash32   32-byte hash to sign.
 *  @param privkey  32-byte private key seed.
 *  @param pubkey   32-byte public key.
 *  @return         64-byte signature.
 */
std::array<uint8_t, 64> ed25519_sign_hash(
    const uint8_t* hash32,
    const uint8_t* privkey,
    const uint8_t* pubkey);

/** Verify a signature over a pre-computed 32-byte hash.
 *  @param hash32    32-byte hash that was signed.
 *  @param pubkey    32-byte public key.
 *  @param signature 64-byte signature.
 *  @return          true if the signature is valid.
 */
bool ed25519_verify_hash(
    const uint8_t* hash32,
    const uint8_t* pubkey,
    const uint8_t* signature);

// ---------------------------------------------------------------------------
// Batch verification
// ---------------------------------------------------------------------------

/** Verify multiple Ed25519 signatures in a batch.
 *  Uses ed25519-donna's batch verification which is faster than
 *  verifying each signature individually.
 *
 *  @param messages   Array of message pointers.
 *  @param msg_lens   Array of message lengths.
 *  @param pubkeys    Array of 32-byte public key pointers.
 *  @param signatures Array of 64-byte signature pointers.
 *  @param count      Number of signatures to verify.
 *  @return           true if ALL signatures are valid.
 */
bool ed25519_verify_batch(
    const uint8_t* const* messages,
    const size_t* msg_lens,
    const uint8_t* const* pubkeys,
    const uint8_t* const* signatures,
    size_t count);

/** Verify multiple Ed25519 signatures, reporting individual results.
 *  @param messages   Array of message pointers.
 *  @param msg_lens   Array of message lengths.
 *  @param pubkeys    Array of 32-byte public key pointers.
 *  @param signatures Array of 64-byte signature pointers.
 *  @param count      Number of signatures to verify.
 *  @param valid_out  Array of bools, set to true/false for each signature.
 *  @return           true if ALL signatures are valid.
 */
bool ed25519_verify_batch_individual(
    const uint8_t* const* messages,
    const size_t* msg_lens,
    const uint8_t* const* pubkeys,
    const uint8_t* const* signatures,
    size_t count,
    bool* valid_out);

// ---------------------------------------------------------------------------
// Convenience wrappers (vector-based)
// ---------------------------------------------------------------------------

/** Sign a message using std::vector and std::array types.
 *  @param message  Message bytes.
 *  @param privkey  32-byte private key.
 *  @param pubkey   32-byte public key.
 *  @return         64-byte signature.
 */
std::array<uint8_t, 64> sign_message(
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, 32>& privkey,
    const std::array<uint8_t, 32>& pubkey);

/** Verify a message signature using std::vector and std::array types.
 *  @param message    Message bytes.
 *  @param pubkey     32-byte public key.
 *  @param signature  64-byte signature.
 *  @return           true if the signature is valid.
 */
bool verify_message(
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, 32>& pubkey,
    const std::array<uint8_t, 64>& signature);

/** Sign a uint256 hash.
 *  @param hash     Hash value to sign.
 *  @param privkey  32-byte private key.
 *  @param pubkey   32-byte public key.
 *  @return         64-byte signature.
 */
std::array<uint8_t, 64> sign_hash(
    const uint256& hash,
    const std::array<uint8_t, 32>& privkey,
    const std::array<uint8_t, 32>& pubkey);

/** Verify a signature over a uint256 hash.
 *  @param hash      Hash value that was signed.
 *  @param pubkey    32-byte public key.
 *  @param signature 64-byte signature.
 *  @return          true if the signature is valid.
 */
bool verify_hash(
    const uint256& hash,
    const std::array<uint8_t, 32>& pubkey,
    const std::array<uint8_t, 64>& signature);

// ---------------------------------------------------------------------------
// Signature validation
// ---------------------------------------------------------------------------

/** Check if a 64-byte signature has valid encoding.
 *  Checks that the S component is within the valid range for Ed25519.
 *  @param signature  64-byte Ed25519 signature.
 *  @return           true if the encoding is valid.
 */
bool is_valid_signature(const uint8_t* signature);

/** Check if a 64-byte signature has valid encoding (array version). */
bool is_valid_signature(const std::array<uint8_t, 64>& signature);

} // namespace flow

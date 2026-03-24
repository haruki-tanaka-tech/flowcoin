// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "sign.h"

#include <cstring>

extern "C" {
#include "ed25519.h"
}

namespace flow {

// ---------------------------------------------------------------------------
// Core Ed25519 signing
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Hash-based signing (pre-computed 32-byte hash)
// ---------------------------------------------------------------------------

std::array<uint8_t, 64> ed25519_sign_hash(
    const uint8_t* hash32,
    const uint8_t* privkey,
    const uint8_t* pubkey)
{
    // Sign the 32-byte hash as a message
    return ed25519_sign(hash32, 32, privkey, pubkey);
}

bool ed25519_verify_hash(
    const uint8_t* hash32,
    const uint8_t* pubkey,
    const uint8_t* signature)
{
    return ed25519_verify(hash32, 32, pubkey, signature);
}

// ---------------------------------------------------------------------------
// Batch verification
// ---------------------------------------------------------------------------

bool ed25519_verify_batch(
    const uint8_t* const* messages,
    const size_t* msg_lens,
    const uint8_t* const* pubkeys,
    const uint8_t* const* signatures,
    size_t count)
{
    if (count == 0) return true;

    // For single signature, just verify directly
    if (count == 1) {
        return ed25519_verify(messages[0], msg_lens[0], pubkeys[0], signatures[0]);
    }

    // Use ed25519-donna's batch verification
    // The C API takes non-const pointers, so we need to cast away const.
    // ed25519_sign_open_batch does not modify the data.
    std::vector<int> valid(count);
    std::vector<size_t> lens(msg_lens, msg_lens + count);
    int result = ::ed25519_sign_open_batch(
        const_cast<const unsigned char**>(messages),
        lens.data(),
        const_cast<const unsigned char**>(pubkeys),
        const_cast<const unsigned char**>(signatures),
        count,
        valid.data()
    );

    // result == 0 means all signatures are valid
    if (result == 0) return true;

    // If batch verification failed, check individual results
    for (size_t i = 0; i < count; ++i) {
        if (valid[i] != 0) return false;
    }

    return true;
}

bool ed25519_verify_batch_individual(
    const uint8_t* const* messages,
    const size_t* msg_lens,
    const uint8_t* const* pubkeys,
    const uint8_t* const* signatures,
    size_t count,
    bool* valid_out)
{
    if (count == 0) return true;

    bool all_valid = true;

    // Try batch verification first
    std::vector<int> valid_raw(count);
    std::vector<size_t> lens(msg_lens, msg_lens + count);
    int batch_result = ::ed25519_sign_open_batch(
        const_cast<const unsigned char**>(messages),
        lens.data(),
        const_cast<const unsigned char**>(pubkeys),
        const_cast<const unsigned char**>(signatures),
        count,
        valid_raw.data()
    );

    if (batch_result == 0) {
        // All valid
        for (size_t i = 0; i < count; ++i) {
            valid_out[i] = true;
        }
        return true;
    }

    // Batch failed — verify individually to find which ones are invalid
    for (size_t i = 0; i < count; ++i) {
        valid_out[i] = ed25519_verify(messages[i], msg_lens[i], pubkeys[i], signatures[i]);
        if (!valid_out[i]) all_valid = false;
    }

    return all_valid;
}

// ---------------------------------------------------------------------------
// Convenience wrappers (vector/array based)
// ---------------------------------------------------------------------------

std::array<uint8_t, 64> sign_message(
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, 32>& privkey,
    const std::array<uint8_t, 32>& pubkey)
{
    return ed25519_sign(message.data(), message.size(),
                        privkey.data(), pubkey.data());
}

bool verify_message(
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, 32>& pubkey,
    const std::array<uint8_t, 64>& signature)
{
    return ed25519_verify(message.data(), message.size(),
                          pubkey.data(), signature.data());
}

std::array<uint8_t, 64> sign_hash(
    const uint256& hash,
    const std::array<uint8_t, 32>& privkey,
    const std::array<uint8_t, 32>& pubkey)
{
    return ed25519_sign_hash(hash.data(), privkey.data(), pubkey.data());
}

bool verify_hash(
    const uint256& hash,
    const std::array<uint8_t, 32>& pubkey,
    const std::array<uint8_t, 64>& signature)
{
    return ed25519_verify_hash(hash.data(), pubkey.data(), signature.data());
}

// ---------------------------------------------------------------------------
// Signature validation
// ---------------------------------------------------------------------------

/** Check if a signature has valid Ed25519 encoding.
 *
 *  An Ed25519 signature is (R, S) where:
 *  - R is an encoded curve point (32 bytes) — first half
 *  - S is a scalar < L (32 bytes) — second half
 *
 *  L = 2^252 + 27742317777372353535851937790883648493
 *
 *  We check that S < L to reject malleable signatures.
 */
bool is_valid_signature(const uint8_t* signature) {
    // Ed25519 group order L in little-endian
    static const uint8_t L[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    };

    const uint8_t* S = signature + 32;

    // Check S < L (little-endian comparison, MSB first)
    for (int i = 31; i >= 0; --i) {
        if (S[i] < L[i]) return true;
        if (S[i] > L[i]) return false;
    }

    // S == L is invalid (S must be strictly less)
    return false;
}

bool is_valid_signature(const std::array<uint8_t, 64>& signature) {
    return is_valid_signature(signature.data());
}

} // namespace flow

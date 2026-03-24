// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Bech32m encoding/decoding for FlowCoin addresses (BIP-350).
// HRP = "fl", witness version 0, 20-byte program from keccak256d(pubkey).

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace flow {

/** Encode witness data as a Bech32m string.
 *  @param hrp              Human-readable part (e.g., "fl").
 *  @param witness_version  Witness version (0..16).
 *  @param program          Witness program bytes (e.g., 20-byte pubkey hash).
 *  @return                 Bech32m-encoded address string, or empty on error.
 */
std::string bech32m_encode(const std::string& hrp, uint8_t witness_version,
                           const std::vector<uint8_t>& program);

/** Decoded Bech32m address. */
struct Bech32mDecoded {
    std::string hrp;
    uint8_t witness_version;
    std::vector<uint8_t> program;
    bool valid;
};

/** Decode a Bech32m address string.
 *  @param addr  The Bech32m-encoded address.
 *  @return      Decoded components with valid=true on success.
 */
Bech32mDecoded bech32m_decode(const std::string& addr);

/** Generate a FlowCoin address from a 32-byte Ed25519 public key.
 *  1. pubkey_hash = keccak256d(pubkey)[0..19]  (first 20 bytes)
 *  2. address = bech32m_encode("fl", 0, pubkey_hash)
 */
std::string pubkey_to_address(const uint8_t* pubkey32);

} // namespace flow

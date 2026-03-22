// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Bech32m address encoding for FlowCoin.
// Format: fl1q<hash><checksum> (mainnet) or tfl1q<hash><checksum> (testnet)

#pragma once

#include "core/types.h"
#include <string>
#include <vector>

namespace flow::crypto {

// Encode a 20-byte pubkey hash to a Bech32m address.
// HRP is "fl" for mainnet, "tfl" for testnet.
// Witness version is 0.
std::string encode_address(const std::string& hrp, uint8_t witness_version,
                           const uint8_t* pubkey_hash, size_t hash_len);

// Decode a Bech32m address back to HRP, witness version, and pubkey hash.
struct DecodedAddress {
    std::string hrp;
    uint8_t witness_version;
    std::vector<uint8_t> pubkey_hash;
};

Result<DecodedAddress> decode_address(const std::string& addr);

// Convenience: create address from Ed25519 pubkey.
// pubkey_hash = keccak256d(pubkey)[0..19] (20 bytes)
std::string pubkey_to_address(const PubKey& pubkey, const std::string& hrp = "fl");

} // namespace flow::crypto

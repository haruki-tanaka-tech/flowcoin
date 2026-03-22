// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Bech32m encoding based on BIP-350.
// Reference: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

#include "address.h"
#include "core/hash.h"

#include <algorithm>
#include <cctype>
#include <vector>

namespace flow::crypto {

static const char* BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Bech32m constant (different from Bech32's 1)
static constexpr uint32_t BECH32M_CONST = 0x2bc830a3;

static uint32_t bech32_polymod(const std::vector<uint8_t>& values) {
    static const uint32_t GEN[5] = {
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
    };
    uint32_t chk = 1;
    for (auto v : values) {
        uint8_t b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (int i = 0; i < 5; ++i) {
            if ((b >> i) & 1) chk ^= GEN[i];
        }
    }
    return chk;
}

static std::vector<uint8_t> hrp_expand(const std::string& hrp) {
    std::vector<uint8_t> ret;
    ret.reserve(hrp.size() * 2 + 1);
    for (char c : hrp) {
        ret.push_back(static_cast<uint8_t>(c) >> 5);
    }
    ret.push_back(0);
    for (char c : hrp) {
        ret.push_back(static_cast<uint8_t>(c) & 31);
    }
    return ret;
}

static std::vector<uint8_t> create_checksum(const std::string& hrp,
                                             const std::vector<uint8_t>& data) {
    auto values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.resize(values.size() + 6, 0);
    uint32_t polymod = bech32_polymod(values) ^ BECH32M_CONST;
    std::vector<uint8_t> ret(6);
    for (int i = 0; i < 6; ++i) {
        ret[i] = (polymod >> (5 * (5 - i))) & 31;
    }
    return ret;
}

static bool verify_checksum(const std::string& hrp,
                             const std::vector<uint8_t>& data) {
    auto values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    return bech32_polymod(values) == BECH32M_CONST;
}

// Convert between 8-bit groups and 5-bit groups
static bool convert_bits(std::vector<uint8_t>& out, int to_bits,
                         const uint8_t* in, size_t in_len, int from_bits,
                         bool pad) {
    uint32_t acc = 0;
    int bits = 0;
    uint32_t max_v = (1 << to_bits) - 1;
    for (size_t i = 0; i < in_len; ++i) {
        uint32_t value = in[i];
        if (value >> from_bits) return false;
        acc = (acc << from_bits) | value;
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            out.push_back((acc >> bits) & max_v);
        }
    }
    if (pad) {
        if (bits > 0) {
            out.push_back((acc << (to_bits - bits)) & max_v);
        }
    } else if (bits >= from_bits || ((acc << (to_bits - bits)) & max_v)) {
        return false;
    }
    return true;
}

std::string encode_address(const std::string& hrp, uint8_t witness_version,
                           const uint8_t* pubkey_hash, size_t hash_len) {
    std::vector<uint8_t> data;
    data.push_back(witness_version);
    if (!convert_bits(data, 5, pubkey_hash, hash_len, 8, true)) {
        return "";
    }

    auto checksum = create_checksum(hrp, data);

    std::string result = hrp + '1';
    for (auto d : data) {
        result.push_back(BECH32_CHARSET[d]);
    }
    for (auto c : checksum) {
        result.push_back(BECH32_CHARSET[c]);
    }
    return result;
}

Result<DecodedAddress> decode_address(const std::string& addr) {
    // Find separator '1'
    auto sep = addr.rfind('1');
    if (sep == std::string::npos || sep < 1 || sep + 7 > addr.size()) {
        return Error{"invalid bech32m: no separator"};
    }

    std::string hrp = addr.substr(0, sep);
    // Verify all lowercase or all uppercase
    bool has_lower = false, has_upper = false;
    for (char c : addr) {
        if (c >= 'a' && c <= 'z') has_lower = true;
        if (c >= 'A' && c <= 'Z') has_upper = true;
    }
    if (has_lower && has_upper) {
        return Error{"invalid bech32m: mixed case"};
    }

    // Convert hrp to lowercase
    std::string hrp_lower;
    for (char c : hrp) {
        hrp_lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }

    // Decode data part
    std::vector<uint8_t> data;
    for (size_t i = sep + 1; i < addr.size(); ++i) {
        char c = std::tolower(static_cast<unsigned char>(addr[i]));
        auto pos = std::string(BECH32_CHARSET).find(c);
        if (pos == std::string::npos) {
            return Error{"invalid bech32m: invalid character"};
        }
        data.push_back(static_cast<uint8_t>(pos));
    }

    if (!verify_checksum(hrp_lower, data)) {
        return Error{"invalid bech32m: checksum failed"};
    }

    // Remove checksum (last 6)
    data.resize(data.size() - 6);

    if (data.empty()) {
        return Error{"invalid bech32m: empty data"};
    }

    uint8_t witness_version = data[0];
    std::vector<uint8_t> pubkey_hash;
    if (!convert_bits(pubkey_hash, 8, data.data() + 1, data.size() - 1, 5, false)) {
        return Error{"invalid bech32m: bit conversion failed"};
    }

    if (pubkey_hash.size() < 2 || pubkey_hash.size() > 40) {
        return Error{"invalid bech32m: invalid program length"};
    }

    DecodedAddress result;
    result.hrp = hrp_lower;
    result.witness_version = witness_version;
    result.pubkey_hash = std::move(pubkey_hash);
    return result;
}

std::string pubkey_to_address(const PubKey& pubkey, const std::string& hrp) {
    // pubkey_hash = keccak256d(pubkey)[0..19] (20 bytes)
    Hash256 full_hash = keccak256d(pubkey.bytes(), 32);
    return encode_address(hrp, 0, full_hash.bytes(), 20);
}

} // namespace flow::crypto

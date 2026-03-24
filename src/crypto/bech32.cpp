// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "bech32.h"
#include "../hash/keccak.h"

#include <algorithm>
#include <cstring>

namespace flow {

// ---------------------------------------------------------------------------
// Bech32m constants (BIP-350)
// ---------------------------------------------------------------------------

static const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,  // 0-9
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,  // A-O
    1,   0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,  // P-Z
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,  // a-o
    1,   0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,  // p-z
};

// Bech32m checksum constant (BIP-350)
static constexpr uint32_t BECH32M_CONST = 0x2bc830a3;

// ---------------------------------------------------------------------------
// GF(32) polynomial operations for checksum
// ---------------------------------------------------------------------------

static uint32_t bech32_polymod(const std::vector<uint8_t>& values) {
    static constexpr uint32_t GEN[5] = {
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
    };
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint32_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (int i = 0; i < 5; ++i) {
            if ((top >> i) & 1) {
                chk ^= GEN[i];
            }
        }
    }
    return chk;
}

/** Expand HRP for checksum computation. */
static std::vector<uint8_t> hrp_expand(const std::string& hrp) {
    std::vector<uint8_t> ret;
    ret.reserve(hrp.size() * 2 + 1);
    for (char c : hrp) {
        ret.push_back(static_cast<uint8_t>(c) >> 5);
    }
    ret.push_back(0);
    for (char c : hrp) {
        ret.push_back(static_cast<uint8_t>(c) & 0x1f);
    }
    return ret;
}

/** Verify or create the checksum. */
static bool verify_checksum(const std::string& hrp, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    return bech32_polymod(values) == BECH32M_CONST;
}

static std::vector<uint8_t> create_checksum(const std::string& hrp, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.resize(values.size() + 6, 0);  // append 6 zero bytes
    uint32_t polymod = bech32_polymod(values) ^ BECH32M_CONST;

    std::vector<uint8_t> ret(6);
    for (int i = 0; i < 6; ++i) {
        ret[i] = static_cast<uint8_t>((polymod >> (5 * (5 - i))) & 0x1f);
    }
    return ret;
}

// ---------------------------------------------------------------------------
// Bit conversion: 8-bit groups <-> 5-bit groups
// ---------------------------------------------------------------------------

/** Convert between bit groups. frombits/tobits are the group sizes.
 *  pad=true adds zero padding for encoding, pad=false rejects extra bits for decoding.
 */
static bool convert_bits(std::vector<uint8_t>& out,
                         const std::vector<uint8_t>& in,
                         int frombits, int tobits, bool pad) {
    int acc = 0;
    int bits = 0;
    int maxv = (1 << tobits) - 1;

    for (uint8_t value : in) {
        if ((value >> frombits)) {
            return false;
        }
        acc = (acc << frombits) | value;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            out.push_back(static_cast<uint8_t>((acc >> bits) & maxv));
        }
    }

    if (pad) {
        if (bits > 0) {
            out.push_back(static_cast<uint8_t>((acc << (tobits - bits)) & maxv));
        }
    } else {
        if (bits >= frombits) return false;
        if ((acc << (tobits - bits)) & maxv) return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::string bech32m_encode(const std::string& hrp, uint8_t witness_version,
                           const std::vector<uint8_t>& program) {
    // Convert 8-bit program bytes to 5-bit groups
    std::vector<uint8_t> data5;
    data5.push_back(witness_version);  // witness version is already a 5-bit value
    if (!convert_bits(data5, program, 8, 5, true)) {
        return "";
    }

    // Create checksum
    std::vector<uint8_t> checksum = create_checksum(hrp, data5);

    // Build result string
    std::string result = hrp + "1";
    result.reserve(result.size() + data5.size() + checksum.size());
    for (uint8_t d : data5) {
        result += CHARSET[d];
    }
    for (uint8_t c : checksum) {
        result += CHARSET[c];
    }

    return result;
}

Bech32mDecoded bech32m_decode(const std::string& addr) {
    Bech32mDecoded result;
    result.valid = false;

    // Must have at least HRP + '1' + 6 checksum chars
    if (addr.size() < 8) return result;

    // Check for mixed case
    bool has_lower = false, has_upper = false;
    for (char c : addr) {
        if (c >= 'a' && c <= 'z') has_lower = true;
        if (c >= 'A' && c <= 'Z') has_upper = true;
    }
    if (has_lower && has_upper) return result;

    // Convert to lowercase for processing
    std::string lower = addr;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Find the separator '1' (last occurrence)
    size_t sep = lower.rfind('1');
    if (sep == std::string::npos || sep == 0 || sep + 7 > lower.size()) {
        return result;
    }

    // Extract HRP
    std::string hrp = lower.substr(0, sep);
    for (char c : hrp) {
        if (c < 33 || c > 126) return result;
    }

    // Decode data part (everything after separator)
    std::vector<uint8_t> data;
    for (size_t i = sep + 1; i < lower.size(); ++i) {
        uint8_t c = static_cast<uint8_t>(lower[i]);
        if (c >= 128) return result;
        int8_t val = CHARSET_REV[c];
        if (val < 0) return result;
        data.push_back(static_cast<uint8_t>(val));
    }

    // Verify checksum
    if (!verify_checksum(hrp, data)) return result;

    // Remove checksum (last 6 values)
    data.resize(data.size() - 6);

    // First value is witness version
    if (data.empty()) return result;
    uint8_t witness_version = data[0];
    if (witness_version > 16) return result;

    // Convert remaining 5-bit groups to 8-bit program
    std::vector<uint8_t> data_no_ver(data.begin() + 1, data.end());
    std::vector<uint8_t> program;
    if (!convert_bits(program, data_no_ver, 5, 8, false)) {
        return result;
    }

    // Witness program length validation (BIP-141)
    if (program.size() < 2 || program.size() > 40) return result;
    if (witness_version == 0 && program.size() != 20 && program.size() != 32) return result;

    result.hrp = hrp;
    result.witness_version = witness_version;
    result.program = std::move(program);
    result.valid = true;

    return result;
}

std::string pubkey_to_address(const uint8_t* pubkey32) {
    // 1. Hash the public key: keccak256d(pubkey)
    uint256 hash = keccak256d(pubkey32, 32);

    // 2. Take the first 20 bytes as the pubkey hash
    std::vector<uint8_t> program(hash.data(), hash.data() + 20);

    // 3. Encode as Bech32m with HRP "fl" and witness version 0
    return bech32m_encode("fl", 0, program);
}

} // namespace flow

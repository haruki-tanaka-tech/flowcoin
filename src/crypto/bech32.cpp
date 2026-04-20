// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "bech32.h"
#include "../hash/keccak.h"

#include <algorithm>
#include <cstring>

namespace flow {

// ---------------------------------------------------------------------------
// Bech32/Bech32m constants
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

// ---------------------------------------------------------------------------
// GF(32) polynomial operations for checksum
// ---------------------------------------------------------------------------

/** Generator polynomial coefficients for the BCH code used in Bech32.
 *  These define the error-detecting properties of the checksum.
 */
static constexpr uint32_t GEN[5] = {
    0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
};

/** Compute the Bech32/Bech32m polymod checksum.
 *  This is the core checksum algorithm that operates over GF(32).
 *  The polynomial used detects up to 4 errors in addresses up to
 *  length 89 characters.
 */
static uint32_t bech32_polymod(const std::vector<uint8_t>& values) {
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

/** Expand HRP for checksum computation.
 *  The HRP is expanded by splitting each character into its high and
 *  low 5-bit parts, separated by a zero byte. This ensures the HRP
 *  contributes to the checksum.
 */
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

/** Verify the checksum of a Bech32/Bech32m string.
 *  @return The encoding variant detected, or INVALID.
 */
static Bech32Encoding verify_checksum(const std::string& hrp,
                                       const std::vector<uint8_t>& data) {
    std::vector<uint8_t> values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    uint32_t pm = bech32_polymod(values);
    if (pm == BECH32_CONST) return Bech32Encoding::BECH32;
    if (pm == BECH32M_CONST) return Bech32Encoding::BECH32M;
    return Bech32Encoding::INVALID;
}

/** Create a 6-value checksum for the given HRP and data.
 *  @param encoding  Which constant to use (Bech32 or Bech32m).
 */
static std::vector<uint8_t> create_checksum(const std::string& hrp,
                                             const std::vector<uint8_t>& data,
                                             Bech32Encoding encoding) {
    uint32_t target = (encoding == Bech32Encoding::BECH32M) ? BECH32M_CONST : BECH32_CONST;

    std::vector<uint8_t> values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.resize(values.size() + 6, 0);  // append 6 zero bytes
    uint32_t polymod = bech32_polymod(values) ^ target;

    std::vector<uint8_t> ret(6);
    for (int i = 0; i < 6; ++i) {
        ret[i] = static_cast<uint8_t>((polymod >> (5 * (5 - i))) & 0x1f);
    }
    return ret;
}

// ---------------------------------------------------------------------------
// Bit conversion: 8-bit groups <-> 5-bit groups
// ---------------------------------------------------------------------------

bool convertbits(std::vector<uint8_t>& out,
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
// Low-level Bech32 encode/decode
// ---------------------------------------------------------------------------

std::string bech32_encode(const std::string& hrp,
                          const std::vector<uint8_t>& data5,
                          Bech32Encoding encoding) {
    if (encoding == Bech32Encoding::INVALID) return "";

    // Validate HRP: must be 1-83 characters, ASCII 33-126
    if (hrp.empty() || hrp.size() > 83) return "";
    for (char c : hrp) {
        if (c < 33 || c > 126) return "";
    }

    // Validate data values: each must be 0..31
    for (uint8_t d : data5) {
        if (d > 31) return "";
    }

    // Total length check: hrp + 1 (separator) + data + 6 (checksum) <= 90
    if (hrp.size() + 1 + data5.size() + 6 > 90) return "";

    // Create checksum
    std::vector<uint8_t> checksum = create_checksum(hrp, data5, encoding);

    // Build result string — always lowercase
    std::string result;
    result.reserve(hrp.size() + 1 + data5.size() + 6);

    for (char c : hrp) {
        result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    result += '1';

    for (uint8_t d : data5) {
        result += CHARSET[d];
    }
    for (uint8_t c : checksum) {
        result += CHARSET[c];
    }

    return result;
}

Bech32Decoded bech32_decode(const std::string& str) {
    Bech32Decoded result;
    result.encoding = Bech32Encoding::INVALID;

    // Length check: minimum is HRP(1) + separator(1) + checksum(6) = 8
    if (str.size() < 8 || str.size() > 90) return result;

    // Check for mixed case
    bool has_lower = false, has_upper = false;
    for (char c : str) {
        if (c >= 'a' && c <= 'z') has_lower = true;
        if (c >= 'A' && c <= 'Z') has_upper = true;
    }
    if (has_lower && has_upper) return result;

    // Convert to lowercase for processing
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Find the separator '1' (last occurrence)
    size_t sep = lower.rfind('1');
    if (sep == std::string::npos || sep == 0 || sep + 7 > lower.size()) {
        return result;
    }

    // Extract HRP and validate characters
    std::string hrp = lower.substr(0, sep);
    for (char c : hrp) {
        if (c < 33 || c > 126) return result;
    }

    // Decode data part (everything after separator)
    std::vector<uint8_t> data;
    data.reserve(lower.size() - sep - 1);
    for (size_t i = sep + 1; i < lower.size(); ++i) {
        uint8_t c = static_cast<uint8_t>(lower[i]);
        if (c >= 128) return result;
        int8_t val = CHARSET_REV[c];
        if (val < 0) return result;
        data.push_back(static_cast<uint8_t>(val));
    }

    // Must have at least 6 values for the checksum
    if (data.size() < 6) return result;

    // Verify checksum and detect encoding variant
    Bech32Encoding enc = verify_checksum(hrp, data);
    if (enc == Bech32Encoding::INVALID) return result;

    // Remove checksum (last 6 values)
    data.resize(data.size() - 6);

    result.hrp = std::move(hrp);
    result.data5 = std::move(data);
    result.encoding = enc;

    return result;
}

// ---------------------------------------------------------------------------
// Bech32m witness address encoding
// ---------------------------------------------------------------------------

std::string bech32m_encode(const std::string& hrp, uint8_t witness_version,
                           const std::vector<uint8_t>& program) {
    // Witness version must be 0..16
    if (witness_version > 16) return "";

    // Witness program length must be 2..40 bytes
    if (program.size() < 2 || program.size() > 40) return "";

    // v0 requires exactly 20 or 32 bytes
    if (witness_version == 0 && program.size() != 20 && program.size() != 32) {
        return "";
    }

    // Choose encoding: v0 uses Bech32, v1+ uses Bech32m per BIP-350.
    // (Earlier code mistakenly picked BECH32M for both branches, producing
    // non-standard v0 addresses. Real Bitcoin P2WPKH 'bc1q...' is bech32.)
    Bech32Encoding enc = (witness_version == 0) ? Bech32Encoding::BECH32
                                                : Bech32Encoding::BECH32M;

    // Convert 8-bit program bytes to 5-bit groups
    std::vector<uint8_t> data5;
    data5.push_back(witness_version);  // witness version is already a 5-bit value
    if (!convertbits(data5, program, 8, 5, true)) {
        return "";
    }

    return bech32_encode(hrp, data5, enc);
}

Bech32mDecoded bech32m_decode(const std::string& addr) {
    Bech32mDecoded result;
    result.valid = false;
    result.witness_version = 0;
    result.encoding = Bech32Encoding::INVALID;

    // Decode the raw Bech32 string
    Bech32Decoded decoded = bech32_decode(addr);
    if (decoded.encoding == Bech32Encoding::INVALID) return result;

    // Must have at least one data value (witness version)
    if (decoded.data5.empty()) return result;

    // Extract witness version
    uint8_t witness_version = decoded.data5[0];
    if (witness_version > 16) return result;

    // BIP350: v0 must be bech32, v1+ must be bech32m. Reject mismatches so
    // we don't accept malformed addresses that the encoder would never
    // produce (and that Bitcoin wallets would also refuse).
    if (witness_version == 0 && decoded.encoding != Bech32Encoding::BECH32) {
        return result;
    }
    if (witness_version >= 1 && decoded.encoding != Bech32Encoding::BECH32M) {
        return result;
    }

    // Convert remaining 5-bit groups to 8-bit program bytes
    std::vector<uint8_t> data_no_ver(decoded.data5.begin() + 1, decoded.data5.end());
    std::vector<uint8_t> program;
    if (!convertbits(program, data_no_ver, 5, 8, false)) {
        return result;
    }

    // Witness program length validation (BIP-141)
    if (program.size() < 2 || program.size() > 40) return result;
    if (witness_version == 0 && program.size() != 20 && program.size() != 32) {
        return result;
    }

    result.hrp = std::move(decoded.hrp);
    result.witness_version = witness_version;
    result.program = std::move(program);
    result.encoding = decoded.encoding;
    result.valid = true;

    return result;
}

// ---------------------------------------------------------------------------
// FlowCoin address utilities
// ---------------------------------------------------------------------------

std::string pubkey_to_address(const uint8_t* pubkey32) {
    return pubkey_to_address(pubkey32, "fl");
}

std::string pubkey_to_address(const uint8_t* pubkey32, const std::string& hrp) {
    // 1. Hash the public key: keccak256d(pubkey)
    uint256 hash = keccak256d(pubkey32, 32);

    // 2. Take the first 20 bytes as the pubkey hash
    std::vector<uint8_t> program(hash.data(), hash.data() + 20);

    // 3. Encode as Bech32m with the given HRP and witness version 0
    return bech32m_encode(hrp, 0, program);
}

bool address_to_pubkey_hash(const std::string& address,
                            std::vector<uint8_t>& hash_out) {
    return address_to_pubkey_hash(address, "fl", hash_out);
}

bool address_to_pubkey_hash(const std::string& address,
                            const std::string& expected_hrp,
                            std::vector<uint8_t>& hash_out) {
    Bech32mDecoded decoded = bech32m_decode(address);
    if (!decoded.valid) return false;

    // Check HRP matches
    if (decoded.hrp != expected_hrp) return false;

    // Check witness version 0
    if (decoded.witness_version != 0) return false;

    // Check 20-byte program
    if (decoded.program.size() != 20) return false;

    hash_out = decoded.program;
    return true;
}

bool validate_address(const std::string& address, const std::string& hrp) {
    std::string error;
    return validate_address(address, hrp, error);
}

bool validate_address(const std::string& address, const std::string& hrp,
                      std::string& error) {
    // Check for empty address
    if (address.empty()) {
        error = "empty address";
        return false;
    }

    // Length check: Bech32 addresses must be 8..90 characters
    if (address.size() < 8) {
        error = "address too short";
        return false;
    }
    if (address.size() > 90) {
        error = "address too long";
        return false;
    }

    // Check for mixed case
    bool has_lower = false, has_upper = false;
    for (char c : address) {
        if (c >= 'a' && c <= 'z') has_lower = true;
        if (c >= 'A' && c <= 'Z') has_upper = true;
    }
    if (has_lower && has_upper) {
        error = "mixed case in address";
        return false;
    }

    // Check for invalid characters
    std::string lower = address;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Check that it starts with the expected HRP
    if (lower.substr(0, hrp.size()) != hrp) {
        error = "wrong HRP (expected '" + hrp + "')";
        return false;
    }

    // Check separator
    if (lower.size() <= hrp.size() || lower[hrp.size()] != '1') {
        error = "missing separator '1' after HRP";
        return false;
    }

    // Check all characters after separator are in the Bech32 charset
    for (size_t i = hrp.size() + 1; i < lower.size(); ++i) {
        uint8_t c = static_cast<uint8_t>(lower[i]);
        if (c >= 128 || CHARSET_REV[c] < 0) {
            error = "invalid character '" + std::string(1, lower[i]) + "' at position " +
                    std::to_string(i);
            return false;
        }
    }

    // Full decode to check checksum and structure
    Bech32mDecoded decoded = bech32m_decode(address);
    if (!decoded.valid) {
        error = "checksum verification failed";
        return false;
    }

    // Verify HRP
    if (decoded.hrp != hrp) {
        error = "HRP mismatch (got '" + decoded.hrp + "', expected '" + hrp + "')";
        return false;
    }

    // Verify witness version
    if (decoded.witness_version > 16) {
        error = "invalid witness version " + std::to_string(decoded.witness_version);
        return false;
    }

    // Verify program length for v0
    if (decoded.witness_version == 0) {
        if (decoded.program.size() != 20 && decoded.program.size() != 32) {
            error = "invalid witness v0 program length " +
                    std::to_string(decoded.program.size()) +
                    " (expected 20 or 32)";
            return false;
        }
    }

    error.clear();
    return true;
}

} // namespace flow

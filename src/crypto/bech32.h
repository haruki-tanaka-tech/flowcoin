// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Bech32 (BIP-173) and Bech32m (BIP-350) encoding/decoding for FlowCoin.
// HRP = "fl", witness version 0, 20-byte program from keccak256d(pubkey).

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// Encoding types
// ---------------------------------------------------------------------------

/** Which Bech32 variant to use. */
enum class Bech32Encoding {
    BECH32,     /**< Original BIP-173 encoding (witness v0) */
    BECH32M,    /**< BIP-350 encoding (witness v1+) */
    INVALID,    /**< Not a valid Bech32 string */
};

// ---------------------------------------------------------------------------
// Low-level encode/decode (raw 5-bit data)
// ---------------------------------------------------------------------------

/** Encode a Bech32 or Bech32m string from HRP and 5-bit data values.
 *  @param hrp       Human-readable part (e.g., "fl").
 *  @param data5     Data values (each 0..31, 5-bit groups).
 *  @param encoding  Bech32 or Bech32m.
 *  @return          Encoded string, or empty on error.
 */
std::string bech32_encode(const std::string& hrp,
                          const std::vector<uint8_t>& data5,
                          Bech32Encoding encoding);

/** Decoded Bech32/Bech32m result (raw 5-bit data). */
struct Bech32Decoded {
    std::string hrp;
    std::vector<uint8_t> data5;  /**< 5-bit data values (no checksum) */
    Bech32Encoding encoding;     /**< Which encoding was detected */
};

/** Decode a Bech32 or Bech32m string.
 *  Automatically detects whether the checksum is Bech32 or Bech32m.
 *  @param str  The encoded string.
 *  @return     Decoded components. encoding=INVALID on failure.
 */
Bech32Decoded bech32_decode(const std::string& str);

// ---------------------------------------------------------------------------
// Bit conversion
// ---------------------------------------------------------------------------

/** Convert between bit groups (e.g., 8-bit to 5-bit and vice versa).
 *  @param out       Output vector (appended to).
 *  @param in        Input data bytes.
 *  @param frombits  Number of bits per input group (e.g., 8).
 *  @param tobits    Number of bits per output group (e.g., 5).
 *  @param pad       If true, add zero padding for encoding. If false,
 *                   reject non-zero extra bits (for decoding).
 *  @return          true on success, false if input contains invalid values
 *                   or if padding check fails.
 */
bool convertbits(std::vector<uint8_t>& out,
                 const std::vector<uint8_t>& in,
                 int frombits, int tobits, bool pad);

// ---------------------------------------------------------------------------
// Bech32m witness address encoding (BIP-350)
// ---------------------------------------------------------------------------

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
    Bech32Encoding encoding;  /**< Which encoding variant was detected */
};

/** Decode a Bech32m address string.
 *  @param addr  The Bech32m-encoded address.
 *  @return      Decoded components with valid=true on success.
 */
Bech32mDecoded bech32m_decode(const std::string& addr);

// ---------------------------------------------------------------------------
// FlowCoin address utilities
// ---------------------------------------------------------------------------

/** Generate a FlowCoin address from a 32-byte Ed25519 public key.
 *  1. pubkey_hash = keccak256d(pubkey)[0..19]  (first 20 bytes)
 *  2. address = bech32m_encode("fl", 0, pubkey_hash)
 */
std::string pubkey_to_address(const uint8_t* pubkey32);

/** Generate a FlowCoin address from a 32-byte Ed25519 public key
 *  with a custom HRP (for testnet, etc.).
 */
std::string pubkey_to_address(const uint8_t* pubkey32, const std::string& hrp);

/** Decode a FlowCoin address and extract the 20-byte pubkey hash.
 *  @param address  Bech32m-encoded address.
 *  @param hash_out Receives the 20-byte pubkey hash on success.
 *  @return         true on success.
 */
bool address_to_pubkey_hash(const std::string& address,
                            std::vector<uint8_t>& hash_out);

/** Decode a FlowCoin address and extract the 20-byte pubkey hash
 *  with expected HRP validation.
 */
bool address_to_pubkey_hash(const std::string& address,
                            const std::string& expected_hrp,
                            std::vector<uint8_t>& hash_out);

/** Validate a FlowCoin address.
 *  Checks format, checksum, length, and HRP.
 *  @param address  The address to validate.
 *  @param hrp      Expected HRP (default "fl").
 *  @return         true if the address is valid.
 */
bool validate_address(const std::string& address, const std::string& hrp = "fl");

/** Validate address and return a detailed error string on failure.
 *  @param address  The address to validate.
 *  @param hrp      Expected HRP.
 *  @param error    Receives error description on failure.
 *  @return         true if the address is valid.
 */
bool validate_address(const std::string& address, const std::string& hrp,
                      std::string& error);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** The FlowCoin mainnet HRP. */
static constexpr const char* FLOWCOIN_HRP_MAINNET = "fl";

/** The FlowCoin testnet HRP. */
static constexpr const char* FLOWCOIN_HRP_TESTNET = "tfl";

/** The FlowCoin regtest HRP. */
static constexpr const char* FLOWCOIN_HRP_REGTEST = "flrt";

/** Bech32m checksum constant (BIP-350). */
static constexpr uint32_t BECH32M_CONST = 0x2bc830a3;

/** Original Bech32 checksum constant (BIP-173). */
static constexpr uint32_t BECH32_CONST = 1;

/** The Bech32 character set. */
static constexpr const char* BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

} // namespace flow

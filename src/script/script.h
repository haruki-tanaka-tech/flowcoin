// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Script system for FlowCoin.
//
// Implements a stack-based script interpreter similar to Bitcoin Script,
// adapted for Ed25519 + Keccak. Provides standard transaction types (P2PKH,
// P2SH, multisig) and a full interpreter for future extensibility.

#ifndef FLOWCOIN_SCRIPT_H
#define FLOWCOIN_SCRIPT_H

#include "util/types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace flow {
namespace script {

// ===========================================================================
// Opcodes
// ===========================================================================

enum Opcode : uint8_t {
    // --- Constants ---
    OP_0            = 0x00,
    OP_FALSE        = OP_0,
    OP_PUSHDATA1    = 0x4c,  // next byte = length, then data
    OP_PUSHDATA2    = 0x4d,  // next 2 bytes = length, then data
    OP_1NEGATE      = 0x4f,
    OP_TRUE         = 0x51,
    OP_1            = OP_TRUE,
    OP_2            = 0x52,
    OP_3            = 0x53,
    OP_4            = 0x54,
    OP_5            = 0x55,
    OP_6            = 0x56,
    OP_7            = 0x57,
    OP_8            = 0x58,
    OP_9            = 0x59,
    OP_10           = 0x5a,
    OP_11           = 0x5b,
    OP_12           = 0x5c,
    OP_13           = 0x5d,
    OP_14           = 0x5e,
    OP_15           = 0x5f,
    OP_16           = 0x60,

    // --- Flow control ---
    OP_NOP          = 0x61,
    OP_IF           = 0x63,
    OP_NOTIF        = 0x64,
    OP_ELSE         = 0x67,
    OP_ENDIF        = 0x68,
    OP_VERIFY       = 0x69,
    OP_RETURN       = 0x6a,

    // --- Stack ---
    OP_2DROP        = 0x6d,
    OP_2DUP         = 0x6e,
    OP_DROP         = 0x75,
    OP_DUP          = 0x76,
    OP_OVER         = 0x78,
    OP_PICK         = 0x79,
    OP_ROLL         = 0x7a,
    OP_ROT          = 0x7b,
    OP_SWAP         = 0x7c,

    // --- Bitwise / comparison ---
    OP_EQUAL        = 0x87,
    OP_EQUALVERIFY  = 0x88,

    // --- Arithmetic ---
    OP_ADD          = 0x93,
    OP_SUB          = 0x94,

    // --- Crypto (FlowCoin-specific) ---
    OP_KECCAK256            = 0xa8,   // Keccak-256 hash
    OP_KECCAK256D           = 0xa9,   // Double Keccak-256
    OP_CHECKSIG             = 0xac,   // Ed25519 verify
    OP_CHECKSIGVERIFY       = 0xad,
    OP_CHECKMULTISIG        = 0xae,   // m-of-n Ed25519
    OP_CHECKMULTISIGVERIFY  = 0xaf,

    // --- Locktime ---
    OP_NOP1                 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY  = 0xb1,   // CLTV (BIP-65 equivalent)
    OP_CHECKSEQUENCEVERIFY  = 0xb2,   // CSV (BIP-112 equivalent)

    // --- NOPs (reserved for soft forks) ---
    OP_NOP4         = 0xb3,
    OP_NOP5         = 0xb4,
    OP_NOP6         = 0xb5,
    OP_NOP7         = 0xb6,
    OP_NOP8         = 0xb7,
    OP_NOP9         = 0xb8,
    OP_NOP10        = 0xb9,

    OP_INVALIDOPCODE = 0xff,
};

/** Get the human-readable name of an opcode. */
std::string opcode_name(Opcode op);

/** Parse an opcode name to its value. Returns OP_INVALIDOPCODE on failure. */
Opcode opcode_from_name(const std::string& name);

// ===========================================================================
// Script types
// ===========================================================================

enum class ScriptType {
    UNKNOWN,
    P2PKH,        // Pay to pubkey hash
    P2SH,         // Pay to script hash
    MULTISIG,     // m-of-n multisig
    NULL_DATA,    // OP_RETURN data carrier
    COINBASE,     // Coinbase script
    EMPTY,        // Empty script
};

/** Convert ScriptType to a human-readable string. */
std::string script_type_name(ScriptType type);

// ===========================================================================
// Size constants
// ===========================================================================

constexpr size_t PUBKEY_HASH_SIZE = 32;   // keccak256d output
constexpr size_t SCRIPT_HASH_SIZE = 32;   // keccak256d of script
constexpr size_t SIGNATURE_SIZE   = 64;   // Ed25519 signature
constexpr size_t PUBKEY_SIZE      = 32;   // Ed25519 public key
constexpr size_t SCRIPT_SIG_SIZE  = SIGNATURE_SIZE + PUBKEY_SIZE;  // 96 bytes

// Maximum sizes
constexpr size_t MAX_SCRIPT_SIZE        = 10000;  // bytes
constexpr size_t MAX_STACK_SIZE         = 1000;   // elements
constexpr size_t MAX_STACK_ELEMENT_SIZE = 520;    // bytes per element
constexpr size_t MAX_OPS_PER_SCRIPT     = 201;
constexpr size_t MAX_PUBKEYS_PER_MULTISIG = 20;

// ===========================================================================
// CScript: script bytecode container
// ===========================================================================

class CScript : public std::vector<uint8_t> {
public:
    using std::vector<uint8_t>::vector;

    // --- Script builders ---

    /** Push raw data onto the script. Uses minimal encoding:
     *  - 1..75 bytes: direct push (length byte + data)
     *  - 76..255 bytes: OP_PUSHDATA1 + 1-byte length + data
     *  - 256..65535 bytes: OP_PUSHDATA2 + 2-byte length + data
     */
    CScript& push_data(const uint8_t* data, size_t len);

    /** Push a byte vector. */
    CScript& push_data(const std::vector<uint8_t>& data);

    /** Push an integer value (-1, 0, 1..16 use opcodes, others use data push). */
    CScript& push_int(int64_t value);

    /** Push an opcode. */
    CScript& push_op(Opcode op);

    // --- Standard script constructors ---

    /** Create a P2PKH scriptPubKey.
     *  OP_DUP OP_KECCAK256D <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
     */
    static CScript p2pkh(const std::vector<uint8_t>& pubkey_hash);

    /** Create a P2PKH scriptPubKey from a 32-byte array. */
    static CScript p2pkh(const std::array<uint8_t, 32>& pubkey_hash);

    /** Create a P2SH scriptPubKey.
     *  OP_KECCAK256D <script_hash> OP_EQUAL
     */
    static CScript p2sh(const std::vector<uint8_t>& script_hash);

    /** Create a multisig scriptPubKey.
     *  OP_m <pubkey1> <pubkey2> ... <pubkeyN> OP_n OP_CHECKMULTISIG
     */
    static CScript multisig(int m, const std::vector<std::vector<uint8_t>>& pubkeys);

    /** Create an OP_RETURN data carrier script.
     *  OP_RETURN <data>
     */
    static CScript op_return(const std::vector<uint8_t>& data);

    // --- Script analysis ---

    /** Classify the script type. */
    ScriptType classify() const;

    /** Check if this is a P2PKH script. */
    bool is_p2pkh() const;

    /** Check if this is a P2SH script. */
    bool is_p2sh() const;

    /** Check if this is a multisig script.
     *  @param m  Receives the required signature count.
     *  @param n  Receives the total pubkey count.
     *  @return   true if this is a valid multisig script.
     */
    bool is_multisig(int& m, int& n) const;

    /** Check if this is an OP_RETURN script. */
    bool is_op_return() const;

    /** Check if this script is provably unspendable.
     *  An unspendable script starts with OP_RETURN or is too large.
     */
    bool is_unspendable() const;

    // --- Data extraction ---

    /** Extract the pubkey hash from a P2PKH script.
     *  @param hash  Receives the 32-byte pubkey hash.
     *  @return      true if this is a valid P2PKH script.
     */
    bool get_p2pkh_hash(std::vector<uint8_t>& hash) const;

    /** Extract the script hash from a P2SH script.
     *  @param hash  Receives the 32-byte script hash.
     *  @return      true if this is a valid P2SH script.
     */
    bool get_p2sh_hash(std::vector<uint8_t>& hash) const;

    /** Extract OP_RETURN data.
     *  @param data  Receives the data bytes.
     *  @return      true if this is an OP_RETURN script with valid data.
     */
    bool get_op_return_data(std::vector<uint8_t>& data) const;

    // --- Signature operations count ---

    /** Count the number of signature operations in this script.
     *  @param accurate  If true, count OP_CHECKMULTISIG accurately;
     *                   if false, count it as MAX_PUBKEYS_PER_MULTISIG.
     */
    int count_sigops(bool accurate = false) const;

    // --- Serialization ---

    /** Convert to human-readable assembly format. */
    std::string to_asm() const;

    /** Convert to hex string. */
    std::string to_hex() const;

    /** Parse from hex string. */
    static CScript from_hex(const std::string& hex);
};

// ===========================================================================
// Legacy compatibility functions (flat functions from original API)
// ===========================================================================

/** Identify the script type from a script_pubkey (legacy format). */
ScriptType classify(const std::vector<uint8_t>& script_pubkey);

/** Create a P2PKH script_pubkey from a pubkey hash (32 bytes). */
std::vector<uint8_t> make_p2pkh(const std::array<uint8_t, 32>& pubkey_hash);
std::vector<uint8_t> make_p2pkh(const std::vector<uint8_t>& pubkey_hash);

/** Create a P2PKH script_pubkey from a raw pubkey (32 bytes). */
std::vector<uint8_t> make_p2pkh_from_pubkey(const uint8_t* pubkey32);

/** Extract the pubkey hash from a P2PKH script_pubkey. */
std::vector<uint8_t> extract_pubkey_hash(const std::vector<uint8_t>& script_pubkey);
bool extract_pubkey_hash(const std::vector<uint8_t>& script_pubkey,
                         std::array<uint8_t, 32>& out);

/** Build a scriptSig from a signature and pubkey. */
std::vector<uint8_t> make_script_sig(const uint8_t* signature64,
                                     const uint8_t* pubkey32);

/** Extract signature and pubkey from a scriptSig. */
bool parse_script_sig(const std::vector<uint8_t>& script_sig,
                      const uint8_t*& sig_out,
                      const uint8_t*& pubkey_out);

/** Verify a script: check that scriptSig satisfies script_pubkey. */
bool verify_script(const std::vector<uint8_t>& script_sig,
                   const std::vector<uint8_t>& script_pubkey,
                   const uint256& tx_hash);

/** Count signature operations in a script. */
int count_sigops(const std::vector<uint8_t>& script);

// ===========================================================================
// Script interpreter
// ===========================================================================

/** Verification flags for the script interpreter. */
static constexpr uint32_t SCRIPT_VERIFY_NONE                  = 0;
static constexpr uint32_t SCRIPT_VERIFY_P2SH                  = (1 << 0);
static constexpr uint32_t SCRIPT_VERIFY_STRICTENC              = (1 << 1);
static constexpr uint32_t SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY    = (1 << 2);
static constexpr uint32_t SCRIPT_VERIFY_CHECKSEQUENCEVERIFY    = (1 << 3);
static constexpr uint32_t SCRIPT_VERIFY_NULLDUMMY              = (1 << 4);

/** Standard verification flags (used for relay policy). */
static constexpr uint32_t STANDARD_SCRIPT_VERIFY_FLAGS =
    SCRIPT_VERIFY_P2SH |
    SCRIPT_VERIFY_STRICTENC |
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
    SCRIPT_VERIFY_NULLDUMMY;

class ScriptInterpreter {
public:
    /** Verify a script pair: run scriptSig, then scriptPubKey on the result.
     *  @param script_sig     The unlocking script (input).
     *  @param script_pubkey  The locking script (output being spent).
     *  @param tx_hash        The transaction hash being signed.
     *  @param flags          Verification flags.
     *  @return               true if the scripts evaluate successfully.
     */
    static bool verify(const CScript& script_sig,
                       const CScript& script_pubkey,
                       const uint256& tx_hash,
                       uint32_t flags = STANDARD_SCRIPT_VERIFY_FLAGS);

    /** Execute a single script on a stack.
     *  @param script   The script to execute.
     *  @param stack    The stack (modified in place).
     *  @param tx_hash  The transaction hash (for OP_CHECKSIG).
     *  @param flags    Verification flags.
     *  @param error    Receives error description on failure.
     *  @return         true if the script executed without errors.
     */
    static bool eval(const CScript& script,
                     std::vector<std::vector<uint8_t>>& stack,
                     const uint256& tx_hash,
                     uint32_t flags,
                     std::string& error);
};

} // namespace script
} // namespace flow

#endif // FLOWCOIN_SCRIPT_H

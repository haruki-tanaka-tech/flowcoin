// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Simplified script system for FlowCoin.
//
// Unlike Bitcoin's full stack-based Script, FlowCoin uses Ed25519 signatures
// directly. The "script" is a thin wrapper around pubkey hash verification.
//
// ScriptPubKey format (locking script):
//   [32 bytes: pubkey_hash]  (keccak256d(pubkey))
//
// ScriptSig format (unlocking script):
//   [64 bytes: Ed25519 signature] [32 bytes: Ed25519 pubkey]
//
// Verification:
//   1. Hash the pubkey: keccak256d(pubkey)
//   2. Compare with script_pubkey (the 32-byte hash)
//   3. Verify Ed25519 signature over the transaction hash

#ifndef FLOWCOIN_SCRIPT_H
#define FLOWCOIN_SCRIPT_H

#include "util/types.h"

#include <cstdint>
#include <vector>

namespace flow {
namespace script {

// Standard script types
enum class ScriptType {
    UNKNOWN,
    P2PKH,        // Pay to pubkey hash (32 bytes)
    COINBASE,     // Coinbase script (arbitrary data, not 32 bytes)
    EMPTY,        // Empty script (genesis, etc.)
};

// Size constants
constexpr size_t PUBKEY_HASH_SIZE = 32;   // keccak256d output
constexpr size_t SIGNATURE_SIZE   = 64;   // Ed25519 signature
constexpr size_t PUBKEY_SIZE      = 32;   // Ed25519 public key
constexpr size_t SCRIPT_SIG_SIZE  = SIGNATURE_SIZE + PUBKEY_SIZE;  // 96 bytes

// Identify the script type from a script_pubkey
ScriptType classify(const std::vector<uint8_t>& script_pubkey);

// Create a P2PKH script_pubkey from a pubkey hash (32 bytes)
std::vector<uint8_t> make_p2pkh(const std::array<uint8_t, 32>& pubkey_hash);

// Create a P2PKH script_pubkey from a pubkey hash vector
std::vector<uint8_t> make_p2pkh(const std::vector<uint8_t>& pubkey_hash);

// Create a P2PKH script_pubkey from a raw pubkey (32 bytes).
// Hashes the pubkey with keccak256d to produce the 32-byte hash.
std::vector<uint8_t> make_p2pkh_from_pubkey(const uint8_t* pubkey32);

// Extract the pubkey hash from a P2PKH script_pubkey.
// Returns empty vector if not a valid P2PKH script.
std::vector<uint8_t> extract_pubkey_hash(const std::vector<uint8_t>& script_pubkey);

// Extract the pubkey hash into a fixed-size array.
// Returns false if not a valid P2PKH script.
bool extract_pubkey_hash(const std::vector<uint8_t>& script_pubkey,
                         std::array<uint8_t, 32>& out);

// Build a scriptSig from a signature and pubkey.
// Returns a 96-byte vector: [64 sig][32 pubkey].
std::vector<uint8_t> make_script_sig(const uint8_t* signature64,
                                     const uint8_t* pubkey32);

// Extract signature and pubkey from a scriptSig.
// Returns false if the scriptSig is not exactly 96 bytes.
bool parse_script_sig(const std::vector<uint8_t>& script_sig,
                      const uint8_t*& sig_out,
                      const uint8_t*& pubkey_out);

// Verify a script: check that scriptSig satisfies script_pubkey.
//   script_sig:    [64 sig + 32 pubkey]
//   script_pubkey: [32 pubkey_hash]
//   tx_hash:       the hash being signed (transaction hash without signatures)
bool verify_script(const std::vector<uint8_t>& script_sig,
                   const std::vector<uint8_t>& script_pubkey,
                   const uint256& tx_hash);

// Count signature operations in a script.
// Each P2PKH script counts as 1 sigop.
int count_sigops(const std::vector<uint8_t>& script);

} // namespace script
} // namespace flow

#endif // FLOWCOIN_SCRIPT_H

// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Standard transaction types and script construction for FlowCoin.
// Provides utility functions for creating and analyzing standard scripts.

#ifndef FLOWCOIN_SCRIPT_STANDARD_H
#define FLOWCOIN_SCRIPT_STANDARD_H

#include "script/script.h"
#include "util/types.h"

#include <string>
#include <vector>

namespace flow {
namespace script {

// ===========================================================================
// Transaction output type identification
// ===========================================================================

/** Determine the standard type of a scriptPubKey.
 *  Also extracts relevant data (pubkey hashes, script hash, etc.).
 *
 *  @param script_pubkey   The output script to classify.
 *  @param solutions_out   Receives extracted data:
 *                         - P2PKH: 1 element, the 32-byte pubkey hash
 *                         - P2SH: 1 element, the 32-byte script hash
 *                         - MULTISIG: m element(s) followed by n pubkeys
 *                         - NULL_DATA: 1 element, the OP_RETURN data
 *  @return                The script type.
 */
ScriptType Solver(const CScript& script_pubkey,
                   std::vector<std::vector<uint8_t>>& solutions_out);

/** Simplified Solver that only returns the type. */
ScriptType Solver(const CScript& script_pubkey);

// ===========================================================================
// Standard transaction checks
// ===========================================================================

/** Check if a script is standard (acceptable for relay).
 *  Non-standard scripts are valid but may not be relayed by default.
 *
 *  @param script    The script to check.
 *  @param reason    Receives the reason for rejection (if non-standard).
 *  @return          true if the script is standard.
 */
bool IsStandard(const CScript& script, std::string& reason);

/** Check if a script is standard (no reason output). */
bool IsStandard(const CScript& script);

/** Check if a scriptSig is standard (pushes only).
 *  A standard scriptSig contains only data pushes.
 */
bool IsStandardScriptSig(const CScript& script_sig);

/** Maximum data size in an OP_RETURN output. */
static constexpr size_t MAX_OP_RETURN_DATA = 80;

// ===========================================================================
// Address / destination extraction
// ===========================================================================

/** A transaction destination: an address string or raw script.
 *  For P2PKH: the Bech32m address.
 *  For P2SH: the Bech32m address with witness version 0.
 *  For others: empty string.
 */
struct TxDestination {
    ScriptType type;
    std::string address;             /**< Human-readable address (if applicable) */
    std::vector<uint8_t> hash;       /**< Pubkey hash or script hash */
    int multisig_m = 0;              /**< Required sigs (multisig only) */
    int multisig_n = 0;              /**< Total keys (multisig only) */
    std::vector<std::vector<uint8_t>> pubkeys;  /**< Public keys (multisig only) */
};

/** Extract the destination from a scriptPubKey.
 *  @param script_pubkey  The output script.
 *  @param hrp            Network HRP for address encoding (default "fl").
 *  @return               The destination with type and address filled in.
 */
TxDestination ExtractDestination(const CScript& script_pubkey,
                                  const std::string& hrp = "fl");

/** Extract just the address string from a scriptPubKey.
 *  @param script_pubkey  The output script.
 *  @param hrp            Network HRP (default "fl").
 *  @return               The address string, or empty if not addressable.
 */
std::string ExtractAddress(const CScript& script_pubkey,
                            const std::string& hrp = "fl");

// ===========================================================================
// Script construction from destinations
// ===========================================================================

/** Create a scriptPubKey for a given address.
 *  Decodes the Bech32m address and creates the appropriate script.
 *
 *  @param address  The FlowCoin address.
 *  @return         The scriptPubKey. Empty script on invalid address.
 */
CScript GetScriptForDestination(const std::string& address);

/** Create a scriptPubKey for a pubkey hash.
 *  @param pubkey_hash  The 32-byte keccak256d hash of the public key.
 *  @return             P2PKH scriptPubKey.
 */
CScript GetScriptForPubKeyHash(const std::vector<uint8_t>& pubkey_hash);

/** Create a scriptPubKey for a public key.
 *  Hashes the pubkey and creates a P2PKH script.
 *  @param pubkey  The 32-byte Ed25519 public key.
 *  @return        P2PKH scriptPubKey.
 */
CScript GetScriptForPubKey(const std::vector<uint8_t>& pubkey);

/** Create a multisig scriptPubKey.
 *  @param m        Required number of signatures.
 *  @param pubkeys  The public keys (32 bytes each).
 *  @return         Multisig scriptPubKey. Empty on invalid parameters.
 */
CScript MakeMultisigScript(int m, const std::vector<std::vector<uint8_t>>& pubkeys);

/** Create a P2SH scriptPubKey that wraps a given redeem script.
 *  @param redeem_script  The script to wrap.
 *  @return               P2SH scriptPubKey.
 */
CScript GetScriptForP2SH(const CScript& redeem_script);

/** Create an OP_RETURN script with the given data.
 *  @param data  The data to embed (max 80 bytes).
 *  @return      OP_RETURN scriptPubKey. Empty if data is too large.
 */
CScript GetScriptForNullData(const std::vector<uint8_t>& data);

// ===========================================================================
// Script utility functions
// ===========================================================================

/** Compute the script hash for P2SH: keccak256d(script). */
uint256 ComputeScriptHash(const CScript& script);

/** Check if a script requires exactly one signature. */
bool IsSingleSigScript(const CScript& script);

/** Get the minimum number of signatures required by a script.
 *  @param script  The scriptPubKey.
 *  @return        Number of required signatures (0 for unknown scripts).
 */
int GetMinRequiredSigs(const CScript& script);

} // namespace script
} // namespace flow

#endif // FLOWCOIN_SCRIPT_STANDARD_H

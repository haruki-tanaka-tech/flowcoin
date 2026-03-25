// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Extended relay and mempool policy (non-consensus rules).
// Supplements the basic policy checks in mempool/policy.h with
// transaction standardness, package relay, weight accounting,
// and script policy enforcement.

#ifndef FLOWCOIN_POLICY_POLICY_H
#define FLOWCOIN_POLICY_POLICY_H

#include "primitives/transaction.h"
#include "script/script.h"
#include "util/types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace flow {
namespace policy {

// ============================================================================
// Policy constants
// ============================================================================

/// Maximum standard transaction weight (100K vbytes * 4 = 400K weight units).
constexpr size_t MAX_STANDARD_TX_WEIGHT = 400000;

/// Maximum P2SH redeemScript size.
constexpr size_t MAX_P2SH_SCRIPT_SIZE = 520;

/// Maximum standard scriptSig size (for non-P2SH inputs).
/// Ed25519: 64-byte sig + 32-byte pubkey + push overhead = ~99 bytes.
/// Allow generous margin for future script types.
constexpr size_t MAX_STANDARD_SCRIPTSIG_SIZE = 1650;

/// Maximum keys in a standard bare multisig output.
constexpr int MAX_STD_MULTISIG_KEYS = 3;

/// Maximum OP_RETURN relay size: 80 bytes of data + 3 bytes overhead.
constexpr size_t MAX_OP_RETURN_RELAY = 83;

/// Dust relay fee rate: 3000 satoshis per kB.
constexpr Amount DUST_RELAY_FEE_RATE = 3000;

/// Default minimum relay transaction fee: 1000 sat/kB.
constexpr Amount DEFAULT_MIN_RELAY_TX_FEE = 1000;

/// Default incremental relay fee for RBF: 1000 sat/kB.
constexpr Amount DEFAULT_INCREMENTAL_RELAY_FEE = 1000;

/// Default minimum block template fee: 1000 sat/kB.
constexpr Amount DEFAULT_BLOCK_MIN_TX_FEE = 1000;

/// Maximum ancestor chain count for package relay.
constexpr size_t MAX_ANCESTOR_COUNT = 25;

/// Maximum ancestor chain size in bytes.
constexpr size_t MAX_ANCESTOR_SIZE = 101000;

/// Maximum descendant chain count.
constexpr size_t MAX_DESCENDANT_COUNT = 25;

/// Maximum descendant chain size in bytes.
constexpr size_t MAX_DESCENDANT_SIZE = 101000;

// ============================================================================
// Transaction standardness check
// ============================================================================

/// Result of a policy standardness check.
struct PolicyCheckResult {
    bool is_standard = false;
    std::string reason;
    int score = 0;  // misbehavior score for non-standard (0-100)
};

/// Check if a transaction is standard for relay.
/// Applies non-consensus rules:
///   1. Transaction weight within MAX_STANDARD_TX_WEIGHT
///   2. Version in [1, 2]
///   3. All outputs have standard scripts (P2PKH, P2SH, multisig, OP_RETURN)
///   4. No dust outputs (below dust threshold)
///   5. OP_RETURN data within MAX_OP_RETURN_RELAY bytes
///   6. At most one OP_RETURN output
///   7. Input scripts within size limits
///   8. No non-push-only scriptSig data
///   9. Total sigops within limits
PolicyCheckResult check_transaction_standard(const CTransaction& tx);

/// Check if a single output is a standard type.
bool is_standard_output(const CTxOut& txout);

/// Check if a script is a standard type for output scripts.
bool is_standard_script_pubkey(const script::CScript& script);

/// Check if all input scripts are standard.
bool are_inputs_standard(const CTransaction& tx);

// ============================================================================
// Dust policy
// ============================================================================

/// Check if an output is dust at the given relay fee rate.
/// An output is dust if the fee to spend it exceeds its value.
/// Spending requires at least one input: 36 outpoint + 32 pubkey + 64 sig = 132 bytes.
bool is_dust_output(const CTxOut& txout, Amount relay_fee_rate);

/// Calculate the dust threshold at a given relay fee rate.
/// Returns the minimum non-dust output value.
Amount get_dust_threshold_at_rate(const CTxOut& txout, Amount relay_fee_rate);

/// Calculate the minimum output value to avoid being dust at the default rate.
Amount get_default_dust_threshold();

// ============================================================================
// Script policy
// ============================================================================

/// Count the number of signature operations in a transaction.
/// Used for mempool acceptance limits (max 4000 sigops per block).
int count_tx_sigops(const CTransaction& tx);

/// Maximum sigops per transaction for standardness.
constexpr int MAX_STANDARD_TX_SIGOPS = 4000;

// ============================================================================
// Package policy
// ============================================================================

/// Maximum number of transactions in a package.
constexpr size_t MAX_PACKAGE_COUNT = 25;

/// Maximum total weight of a package.
constexpr size_t MAX_PACKAGE_WEIGHT = 404000;

/// Result of package policy checks.
struct PackageCheckResult {
    bool accepted = false;
    std::string reason;
    std::vector<uint256> accepted_txids;
    std::vector<uint256> rejected_txids;
};

/// Check a package of transactions for relay policy compliance.
/// A package is a set of transactions where each transaction's parents
/// appear earlier in the vector (topologically sorted).
PackageCheckResult check_package(const std::vector<CTransaction>& txs);

/// Validate package topology: each tx's parents must appear earlier.
bool check_package_topology(const std::vector<CTransaction>& txs);

/// Check aggregate package weight and count limits.
bool check_package_limits(const std::vector<CTransaction>& txs);

// ============================================================================
// RBF policy constants
// ============================================================================

/// Maximum number of transactions that can be evicted by a single replacement.
constexpr int MAX_BIP125_REPLACEMENT_CANDIDATES = 100;

/// Result of an RBF policy check.
struct RBFCheckResult {
    bool replaceable = false;
    Amount required_fee = 0;
    std::string reason;
};

/// Check if a replacement transaction meets RBF policy requirements.
/// Rules:
///   1. All conflicting transactions must signal replaceability
///   2. Replacement must not introduce new unconfirmed inputs
///   3. Replacement must pay strictly higher absolute fee
///   4. Replacement fee increase must cover incremental relay fee
///   5. At most MAX_BIP125_REPLACEMENT_CANDIDATES evicted
RBFCheckResult check_rbf_policy(const CTransaction& replacement,
                                 const std::vector<CTransaction>& conflicts,
                                 Amount incremental_relay_fee);

// ============================================================================
// Fee rate utilities
// ============================================================================

/// Calculate fee rate in satoshis per kB from total fee and tx size.
Amount calculate_fee_rate(Amount fee, size_t tx_size);

/// Calculate total fee from fee rate (sat/kB) and tx size.
Amount calculate_fee_from_rate(Amount fee_rate, size_t tx_size);

/// Check if a fee meets the minimum relay fee.
bool meets_minimum_relay_fee(Amount fee, size_t tx_size,
                              Amount min_relay_fee = DEFAULT_MIN_RELAY_TX_FEE);

// ============================================================================
// Weight calculations
// ============================================================================

/// Calculate the weight of a transaction.
/// For FlowCoin: weight = serialized_size * 4 (no witness discount).
size_t get_transaction_weight(const CTransaction& tx);

/// Calculate the virtual size from weight.
/// vsize = ceil(weight / 4)
size_t get_virtual_size_from_weight(size_t weight);

// ============================================================================
// Extended standardness check
// ============================================================================

/// Extended standardness check with configurable relay fee rate
/// and optional strict mode that applies additional DoS protections.
PolicyCheckResult check_transaction_standard_extended(
    const CTransaction& tx,
    Amount relay_fee_rate = DUST_RELAY_FEE_RATE,
    bool strict_mode = false);

} // namespace policy
} // namespace flow

#endif // FLOWCOIN_POLICY_POLICY_H

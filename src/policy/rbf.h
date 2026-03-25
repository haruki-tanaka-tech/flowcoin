// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Replace-by-fee (RBF) policy implementation.
// Implements BIP-125-style opt-in RBF with five rules governing
// when a mempool transaction can be replaced by a higher-fee version.
//
// Rules:
//   1. All conflicting transactions must signal opt-in replaceability
//      (any input with nSequence < 0xFFFFFFFE, or in FlowCoin,
//       we use a version-based signal: version >= 2)
//   2. Replacement must not introduce new unconfirmed inputs
//   3. Replacement must pay strictly higher absolute fee
//   4. Replacement fee increase must cover at least the incremental
//      relay fee for the replacement transaction's size
//   5. At most MAX_REPLACEMENTS (100) transactions can be evicted

#ifndef FLOWCOIN_POLICY_RBF_H
#define FLOWCOIN_POLICY_RBF_H

#include "mempool/mempool.h"
#include "primitives/transaction.h"
#include "util/types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace flow {
namespace rbf {

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of transactions that can be evicted by a single replacement.
constexpr int MAX_REPLACEMENTS = 100;

/// Sequence number threshold: inputs with nSequence < this signal RBF.
/// In Bitcoin: 0xFFFFFFFE. In FlowCoin we use version-based signaling
/// but also check this for compatibility.
constexpr uint32_t SEQUENCE_FINAL = 0xFFFFFFFE;

// ============================================================================
// Signal detection
// ============================================================================

/// Check if a transaction signals opt-in replace-by-fee.
/// A transaction signals RBF if:
///   - version >= 2, OR
///   - any input's sequence number < SEQUENCE_FINAL
/// In FlowCoin's Ed25519 model, sequence numbers are not stored
/// in the input, so we rely on version-based signaling.
bool signals_opt_in(const CTransaction& tx);

/// Check if a transaction is replaceable, considering inherited signaling.
/// A transaction is replaceable if it signals RBF or any of its
/// unconfirmed ancestors signal RBF.
bool is_replaceable(const CTransaction& tx, const Mempool& mempool);

// ============================================================================
// Replacement validation
// ============================================================================

/// Detailed result of a replacement check.
struct ReplacementResult {
    bool allowed = false;         // whether replacement is permitted
    Amount required_fee = 0;      // minimum absolute fee required
    Amount required_fee_rate = 0; // minimum fee rate (sat/kB) required
    int num_evicted = 0;          // number of transactions to be evicted
    std::vector<uint256> evicted_txids;  // txids that would be removed
    std::string error;            // error message if not allowed
};

/// Full RBF replacement check against the mempool.
/// Validates all five BIP-125 rules:
///   1. Conflicting transactions signal replaceability
///   2. No new unconfirmed inputs
///   3. Higher absolute fee
///   4. Fee increase covers incremental relay fee
///   5. Eviction count within limit
///
/// @param replacement          The proposed replacement transaction.
/// @param mempool              The current mempool state.
/// @param incremental_relay_fee  Minimum incremental fee rate (sat/kB).
/// @return                     Detailed result with fee requirements.
ReplacementResult check_replacement(
    const CTransaction& replacement,
    const Mempool& mempool,
    Amount incremental_relay_fee);

// ============================================================================
// Conflict detection
// ============================================================================

/// Find all mempool transactions that conflict with the given transaction.
/// A conflict occurs when both transactions spend the same outpoint.
/// @param tx       The transaction to check.
/// @param mempool  The current mempool.
/// @return         TXIDs of all directly conflicting transactions.
std::vector<uint256> find_conflicts(const CTransaction& tx,
                                     const Mempool& mempool);

/// Find all transactions that would need to be evicted if the
/// given conflicts are replaced. This includes the conflicts themselves
/// plus all their descendants in the mempool.
/// @param conflicts  Direct conflict txids.
/// @param mempool    The current mempool.
/// @return           All txids to evict (conflicts + descendants).
std::vector<uint256> find_all_evictions(
    const std::vector<uint256>& conflicts,
    const Mempool& mempool);

// ============================================================================
// Fee calculations
// ============================================================================

/// Calculate the total fees of a set of transactions.
/// Returns the sum of fees for all given txids found in the mempool.
Amount calculate_conflict_fees(const std::vector<uint256>& txids,
                                const Mempool& mempool);

/// Calculate the minimum fee required for a replacement to be accepted.
/// This is the max of:
///   1. Total fees of all evicted transactions
///   2. Total fees + incremental relay fee for the replacement size
Amount calculate_required_fee(
    const std::vector<uint256>& evicted_txids,
    const Mempool& mempool,
    size_t replacement_size,
    Amount incremental_relay_fee);

/// Check rule 2: replacement must not introduce new unconfirmed inputs.
/// Returns true if the replacement only spends confirmed UTXOs or
/// UTXOs from transactions already in the conflict set.
bool check_no_new_unconfirmed(
    const CTransaction& replacement,
    const std::vector<uint256>& conflict_set,
    const Mempool& mempool);

// ============================================================================
// Replacement execution
// ============================================================================

/// Attempt to execute a replacement in the mempool.
/// If the replacement passes all checks, the conflicting transactions
/// (and their descendants) are removed and the replacement is added.
/// @param replacement           The replacement transaction.
/// @param mempool               The mempool to modify.
/// @param incremental_relay_fee Minimum incremental fee rate.
/// @return                      Result including evicted txids.
ReplacementResult try_replacement(
    const CTransaction& replacement,
    Mempool& mempool,
    Amount incremental_relay_fee);

} // namespace rbf
} // namespace flow

#endif // FLOWCOIN_POLICY_RBF_H

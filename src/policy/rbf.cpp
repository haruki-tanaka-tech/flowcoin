// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "policy/rbf.h"
#include "policy/policy.h"

#include <algorithm>
#include <set>
#include <unordered_set>

namespace flow {
namespace rbf {

// ============================================================================
// Signal detection
// ============================================================================

bool signals_opt_in(const CTransaction& tx) {
    // Version-based signaling: version >= 2 signals RBF
    if (tx.version >= 2) return true;

    // Coinbase transactions cannot be replaced
    if (tx.is_coinbase()) return false;

    return false;
}

bool is_replaceable(const CTransaction& tx, const Mempool& mempool) {
    // Direct signaling
    if (signals_opt_in(tx)) return true;

    // Check inherited signaling through unconfirmed ancestors
    uint256 txid = tx.get_txid();
    auto ancestors = mempool.get_ancestors(txid);

    for (const auto& ancestor_txid : ancestors) {
        CTransaction ancestor_tx;
        if (mempool.get(ancestor_txid, ancestor_tx)) {
            if (signals_opt_in(ancestor_tx)) {
                return true;
            }
        }
    }

    return false;
}

// ============================================================================
// Conflict detection
// ============================================================================

std::vector<uint256> find_conflicts(const CTransaction& tx,
                                     const Mempool& mempool) {
    std::set<uint256> conflict_set;

    for (const auto& in : tx.vin) {
        if (in.is_coinbase()) continue;

        // Check if this outpoint is already spent by a mempool transaction
        if (mempool.is_spent_by_mempool(in.prevout.txid, in.prevout.index)) {
            // Find which transaction spends it
            auto spending = mempool.get_spending_txids(in.prevout.txid);
            for (const auto& spend_txid : spending) {
                // Verify this specific spending tx uses our outpoint
                CTransaction spend_tx;
                if (mempool.get(spend_txid, spend_tx)) {
                    for (const auto& spend_in : spend_tx.vin) {
                        if (spend_in.prevout.txid == in.prevout.txid &&
                            spend_in.prevout.index == in.prevout.index) {
                            conflict_set.insert(spend_txid);
                            break;
                        }
                    }
                }
            }
        }
    }

    return std::vector<uint256>(conflict_set.begin(), conflict_set.end());
}

std::vector<uint256> find_all_evictions(
    const std::vector<uint256>& conflicts,
    const Mempool& mempool) {
    std::set<uint256> all_evicted;

    // Start with direct conflicts
    for (const auto& txid : conflicts) {
        all_evicted.insert(txid);

        // Add all descendants
        auto descendants = mempool.get_descendants(txid);
        for (const auto& desc : descendants) {
            all_evicted.insert(desc);
        }
    }

    return std::vector<uint256>(all_evicted.begin(), all_evicted.end());
}

// ============================================================================
// Fee calculations
// ============================================================================

Amount calculate_conflict_fees(const std::vector<uint256>& txids,
                                const Mempool& mempool) {
    Amount total = 0;
    for (const auto& txid : txids) {
        MempoolEntry entry;
        if (mempool.get_entry(txid, entry)) {
            total += entry.fee;
        }
    }
    return total;
}

Amount calculate_required_fee(
    const std::vector<uint256>& evicted_txids,
    const Mempool& mempool,
    size_t replacement_size,
    Amount incremental_relay_fee) {
    // Total fees of all evicted transactions
    Amount evicted_fees = calculate_conflict_fees(evicted_txids, mempool);

    // Incremental relay fee for the replacement
    Amount incremental = policy::calculate_fee_from_rate(
        incremental_relay_fee, replacement_size);

    // Must exceed both:
    //   1. Total evicted fees
    //   2. Evicted fees + incremental relay fee
    return evicted_fees + incremental;
}

bool check_no_new_unconfirmed(
    const CTransaction& replacement,
    const std::vector<uint256>& conflict_set,
    const Mempool& mempool) {
    // Build a set of txids that are in the conflict set for quick lookup
    std::set<uint256> conflict_txids(conflict_set.begin(), conflict_set.end());

    for (const auto& in : replacement.vin) {
        if (in.is_coinbase()) continue;

        // If this input spends a mempool transaction that is NOT in
        // the conflict set, it introduces a new unconfirmed dependency
        if (mempool.exists(in.prevout.txid)) {
            if (conflict_txids.find(in.prevout.txid) == conflict_txids.end()) {
                return false;  // New unconfirmed input
            }
        }
    }

    return true;
}

// ============================================================================
// Replacement check
// ============================================================================

ReplacementResult check_replacement(
    const CTransaction& replacement,
    const Mempool& mempool,
    Amount incremental_relay_fee) {
    ReplacementResult result;

    // Find direct conflicts
    auto conflicts = find_conflicts(replacement, mempool);

    if (conflicts.empty()) {
        result.error = "no-conflict";
        return result;
    }

    // Rule 1: All conflicting transactions must signal replaceability
    for (const auto& conflict_txid : conflicts) {
        CTransaction conflict_tx;
        if (!mempool.get(conflict_txid, conflict_tx)) {
            result.error = "conflict-not-found";
            return result;
        }

        if (!is_replaceable(conflict_tx, mempool)) {
            result.error = "txn-mempool-conflict-not-replaceable";
            return result;
        }
    }

    // Find all transactions that would be evicted
    auto all_evicted = find_all_evictions(conflicts, mempool);
    result.evicted_txids = all_evicted;
    result.num_evicted = static_cast<int>(all_evicted.size());

    // Rule 5: Check eviction count
    if (result.num_evicted > MAX_REPLACEMENTS) {
        result.error = "too-many-potential-replacements";
        return result;
    }

    // Rule 2: No new unconfirmed inputs
    if (!check_no_new_unconfirmed(replacement, all_evicted, mempool)) {
        result.error = "replacement-adds-unconfirmed";
        return result;
    }

    // Rules 3 & 4: Fee requirements
    size_t replacement_size = replacement.get_serialize_size();
    result.required_fee = calculate_required_fee(
        all_evicted, mempool, replacement_size, incremental_relay_fee);

    Amount evicted_fees = calculate_conflict_fees(all_evicted, mempool);
    result.required_fee_rate = policy::calculate_fee_rate(
        result.required_fee, replacement_size);

    // The actual fee check is done by the caller since we may not
    // have UTXO context to compute the replacement fee here.
    result.allowed = true;

    return result;
}

// ============================================================================
// Replacement execution
// ============================================================================

ReplacementResult try_replacement(
    const CTransaction& replacement,
    Mempool& mempool,
    Amount incremental_relay_fee) {
    // First, check if replacement is valid
    ReplacementResult result = check_replacement(
        replacement, mempool, incremental_relay_fee);

    if (!result.allowed) {
        return result;
    }

    // Remove all evicted transactions
    for (const auto& txid : result.evicted_txids) {
        mempool.remove(txid);
    }

    // Add the replacement
    auto add_result = mempool.add_transaction(replacement);
    if (!add_result.accepted) {
        result.allowed = false;
        result.error = "replacement-rejected: " + add_result.reject_reason;
        return result;
    }

    return result;
}

} // namespace rbf
} // namespace flow

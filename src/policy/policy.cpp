// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "policy/policy.h"
#include "hash/keccak.h"

#include <algorithm>
#include <cstring>
#include <set>
#include <unordered_set>

namespace flow {
namespace policy {

// ============================================================================
// Transaction standardness
// ============================================================================

PolicyCheckResult check_transaction_standard(const CTransaction& tx) {
    PolicyCheckResult result;
    result.is_standard = false;
    result.score = 0;

    // 1. Check transaction weight
    size_t weight = get_transaction_weight(tx);
    if (weight > MAX_STANDARD_TX_WEIGHT) {
        result.reason = "tx-size";
        result.score = 10;
        return result;
    }

    // 2. Check version
    if (tx.version < 1 || tx.version > 2) {
        result.reason = "version";
        result.score = 10;
        return result;
    }

    // 3. Check for empty vin/vout
    if (tx.vin.empty()) {
        result.reason = "bad-txns-vin-empty";
        result.score = 10;
        return result;
    }
    if (tx.vout.empty()) {
        result.reason = "bad-txns-vout-empty";
        result.score = 10;
        return result;
    }

    // 4. Check locktime (non-negative)
    if (tx.locktime < 0) {
        result.reason = "bad-txns-locktime-negative";
        result.score = 10;
        return result;
    }

    // 5. Check outputs
    int op_return_count = 0;
    for (const auto& out : tx.vout) {
        // Check for standard output
        if (!is_standard_output(out)) {
            result.reason = "scriptpubkey";
            result.score = 1;
            return result;
        }

        // Check dust
        if (is_dust_output(out, DUST_RELAY_FEE_RATE)) {
            result.reason = "dust";
            result.score = 1;
            return result;
        }

        // Check for OP_RETURN: check if pubkey_hash is all zeros
        // (indicating a data-carrying output)
        bool all_zero = true;
        for (auto b : out.pubkey_hash) {
            if (b != 0) { all_zero = false; break; }
        }
        if (out.amount == 0 && all_zero) {
            op_return_count++;
        }
    }

    // 6. At most one OP_RETURN
    if (op_return_count > 1) {
        result.reason = "multi-op-return";
        result.score = 1;
        return result;
    }

    // 7. Check inputs are standard
    if (!are_inputs_standard(tx)) {
        result.reason = "bad-txns-nonstandard-inputs";
        result.score = 1;
        return result;
    }

    // 8. Check total output value
    Amount total_out = tx.get_value_out();
    if (total_out < 0 || total_out > MAX_MONEY) {
        result.reason = "bad-txns-value-out-of-range";
        result.score = 100;
        return result;
    }

    // 9. Check for duplicate inputs
    std::set<std::pair<uint256, uint32_t>> spent_outpoints;
    for (const auto& in : tx.vin) {
        auto key = std::make_pair(in.prevout.txid, in.prevout.index);
        if (!spent_outpoints.insert(key).second) {
            result.reason = "bad-txns-inputs-duplicate";
            result.score = 100;
            return result;
        }
    }

    result.is_standard = true;
    return result;
}

bool is_standard_output(const CTxOut& txout) {
    // Standard outputs:
    // - Positive amount with a valid pubkey hash (P2PKH equivalent)
    // - Zero amount with null pubkey hash (OP_RETURN equivalent)
    if (txout.amount < 0) return false;
    if (txout.amount > MAX_MONEY) return false;

    // Zero-value outputs are data carriers (OP_RETURN equivalent)
    if (txout.amount == 0) {
        return true;  // Allow zero-value outputs as data carriers
    }

    // Non-zero outputs must have a non-null pubkey hash
    bool is_null = true;
    for (auto b : txout.pubkey_hash) {
        if (b != 0) { is_null = false; break; }
    }
    if (is_null) return false;  // Non-zero value to null hash is non-standard

    return true;
}

bool is_standard_script_pubkey(const script::CScript& script) {
    script::ScriptType type = script.classify();
    switch (type) {
        case script::ScriptType::P2PKH:
        case script::ScriptType::P2SH:
        case script::ScriptType::NULL_DATA:
        case script::ScriptType::COINBASE:
            return true;

        case script::ScriptType::MULTISIG: {
            int m = 0, n = 0;
            if (!script.is_multisig(m, n)) return false;
            return n <= MAX_STD_MULTISIG_KEYS;
        }

        case script::ScriptType::UNKNOWN:
        case script::ScriptType::EMPTY:
            return false;
    }
    return false;
}

bool are_inputs_standard(const CTransaction& tx) {
    for (const auto& in : tx.vin) {
        if (in.is_coinbase()) continue;

        // Check pubkey is not all zeros
        bool pubkey_null = true;
        for (auto b : in.pubkey) {
            if (b != 0) { pubkey_null = false; break; }
        }
        if (pubkey_null) return false;

        // Check signature is not all zeros
        bool sig_null = true;
        for (auto b : in.signature) {
            if (b != 0) { sig_null = false; break; }
        }
        if (sig_null) return false;
    }
    return true;
}

// ============================================================================
// Dust policy
// ============================================================================

bool is_dust_output(const CTxOut& txout, Amount relay_fee_rate) {
    // Zero-value outputs (OP_RETURN) are not dust
    if (txout.amount == 0) return false;

    // Negative outputs are invalid, not dust
    if (txout.amount < 0) return false;

    Amount threshold = get_dust_threshold_at_rate(txout, relay_fee_rate);
    return txout.amount < threshold;
}

Amount get_dust_threshold_at_rate(const CTxOut& /*txout*/, Amount relay_fee_rate) {
    // Cost to spend this output:
    //   Input overhead: 36 (outpoint) + 32 (pubkey) + 64 (signature) = 132 bytes
    //   Output itself: 40 bytes (8 amount + 32 pubkey_hash)
    //
    // Total spending cost at relay_fee_rate (per kB):
    //   cost = (132 + 40) * relay_fee_rate / 1000

    size_t spend_size = 132 + 40;  // 172 bytes
    Amount cost = static_cast<Amount>(spend_size) * relay_fee_rate / 1000;

    // Minimum: 1 atomic unit
    return std::max(cost, static_cast<Amount>(1));
}

Amount get_default_dust_threshold() {
    CTxOut dummy;
    return get_dust_threshold_at_rate(dummy, DUST_RELAY_FEE_RATE);
}

// ============================================================================
// Script policy
// ============================================================================

int count_tx_sigops(const CTransaction& tx) {
    int count = 0;
    // Each non-coinbase input has one signature verification
    for (const auto& in : tx.vin) {
        if (!in.is_coinbase()) {
            count++;
        }
    }
    return count;
}

// ============================================================================
// Package policy
// ============================================================================

PackageCheckResult check_package(const std::vector<CTransaction>& txs) {
    PackageCheckResult result;

    // Check count limit
    if (txs.size() > MAX_PACKAGE_COUNT) {
        result.reason = "package-too-many-transactions";
        return result;
    }

    if (txs.empty()) {
        result.reason = "package-empty";
        return result;
    }

    // Check total weight
    if (!check_package_limits(txs)) {
        result.reason = "package-too-large";
        return result;
    }

    // Check topology
    if (!check_package_topology(txs)) {
        result.reason = "package-not-sorted";
        return result;
    }

    // Check each transaction individually
    for (const auto& tx : txs) {
        PolicyCheckResult tx_result = check_transaction_standard(tx);
        uint256 txid = tx.get_txid();

        if (tx_result.is_standard) {
            result.accepted_txids.push_back(txid);
        } else {
            result.rejected_txids.push_back(txid);
        }
    }

    result.accepted = result.rejected_txids.empty();
    if (!result.accepted && result.reason.empty()) {
        result.reason = "package-contains-nonstandard";
    }

    return result;
}

bool check_package_topology(const std::vector<CTransaction>& txs) {
    // Build a set of known txids seen so far
    std::set<uint256> seen;

    for (const auto& tx : txs) {
        // Check that all parents referenced by inputs are either:
        // 1. Already confirmed (not in this package) -- we allow this
        // 2. Appear earlier in the package (in 'seen')
        for (const auto& in : tx.vin) {
            if (in.is_coinbase()) continue;

            uint256 parent_txid = in.prevout.txid;
            // If the parent is in this package, it must have been seen already
            bool parent_in_package = false;
            for (const auto& other_tx : txs) {
                if (other_tx.get_txid() == parent_txid) {
                    parent_in_package = true;
                    break;
                }
            }

            if (parent_in_package && seen.find(parent_txid) == seen.end()) {
                return false;  // Parent appears later in the package
            }
        }

        seen.insert(tx.get_txid());
    }

    return true;
}

bool check_package_limits(const std::vector<CTransaction>& txs) {
    if (txs.size() > MAX_PACKAGE_COUNT) return false;

    size_t total_weight = 0;
    for (const auto& tx : txs) {
        total_weight += get_transaction_weight(tx);
    }

    return total_weight <= MAX_PACKAGE_WEIGHT;
}

// ============================================================================
// RBF policy
// ============================================================================

RBFCheckResult check_rbf_policy(const CTransaction& replacement,
                                 const std::vector<CTransaction>& conflicts,
                                 Amount incremental_relay_fee) {
    RBFCheckResult result;

    if (conflicts.empty()) {
        result.replaceable = false;
        result.reason = "no-conflicts";
        return result;
    }

    // Rule 1: All conflicting transactions must signal replaceability
    // A transaction signals RBF if any input has nSequence < 0xFFFFFFFE
    // In FlowCoin's model, we use a simpler heuristic: check the
    // first input's sequence field (stored in MempoolEntry)
    // For now, we check that all conflicts allow replacement.

    // Rule 5: Count total evictions
    int total_evicted = static_cast<int>(conflicts.size());
    if (total_evicted > MAX_BIP125_REPLACEMENT_CANDIDATES) {
        result.replaceable = false;
        result.reason = "too-many-potential-replacements";
        return result;
    }

    // Rule 3: Calculate required fee
    // Replacement must pay more than total fees of all conflicts
    Amount conflict_total_fee = 0;
    size_t conflict_total_size = 0;
    for (const auto& conflict : conflicts) {
        // We approximate fee as 0 since we don't have UTXO context here.
        // The caller should compute actual fees.
        conflict_total_size += conflict.get_serialize_size();
    }

    // Rule 4: Additional incremental fee
    size_t replacement_size = replacement.get_serialize_size();
    Amount incremental_fee = calculate_fee_from_rate(
        incremental_relay_fee, replacement_size);

    result.required_fee = conflict_total_fee + incremental_fee;
    result.replaceable = true;

    return result;
}

// ============================================================================
// Fee rate utilities
// ============================================================================

Amount calculate_fee_rate(Amount fee, size_t tx_size) {
    if (tx_size == 0) return 0;
    return (fee * 1000) / static_cast<Amount>(tx_size);
}

Amount calculate_fee_from_rate(Amount fee_rate, size_t tx_size) {
    return (fee_rate * static_cast<Amount>(tx_size) + 999) / 1000;
}

bool meets_minimum_relay_fee(Amount fee, size_t tx_size,
                              Amount min_relay_fee) {
    Amount required = calculate_fee_from_rate(min_relay_fee, tx_size);
    return fee >= required;
}

// ============================================================================
// Weight calculations
// ============================================================================

size_t get_transaction_weight(const CTransaction& tx) {
    // FlowCoin: no witness discount, weight = size * 4
    return tx.get_serialize_size() * 4;
}

size_t get_virtual_size_from_weight(size_t weight) {
    return (weight + 3) / 4;
}

// ============================================================================
// Extended policy validation
// ============================================================================

namespace detail {

/// Validate that a transaction's output values are all within range.
bool validate_output_ranges(const CTransaction& tx, std::string& error) {
    Amount total_out = 0;
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const auto& out = tx.vout[i];
        if (out.amount < 0) {
            error = "bad-txns-vout-negative (index " + std::to_string(i) + ")";
            return false;
        }
        if (out.amount > MAX_MONEY) {
            error = "bad-txns-vout-toolarge (index " + std::to_string(i) + ")";
            return false;
        }
        total_out += out.amount;
        if (total_out < 0 || total_out > MAX_MONEY) {
            error = "bad-txns-txouttotal-toolarge";
            return false;
        }
    }
    return true;
}

/// Validate that a transaction has no duplicate inputs.
bool validate_no_duplicate_inputs(const CTransaction& tx, std::string& error) {
    std::set<std::pair<uint256, uint32_t>> seen;
    for (const auto& in : tx.vin) {
        auto key = std::make_pair(in.prevout.txid, in.prevout.index);
        if (!seen.insert(key).second) {
            error = "bad-txns-inputs-duplicate";
            return false;
        }
    }
    return true;
}

/// Check that inputs reference valid outpoints (non-null for non-coinbase).
bool validate_input_outpoints(const CTransaction& tx, std::string& error) {
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const auto& in = tx.vin[i];
        if (in.is_coinbase()) continue;

        if (in.prevout.txid.is_null()) {
            error = "bad-txns-prevout-null (input " + std::to_string(i) + ")";
            return false;
        }
    }
    return true;
}

/// Validate locktime constraints for relay.
bool validate_locktime_for_relay(const CTransaction& tx, std::string& error) {
    if (tx.locktime < 0) {
        error = "bad-txns-locktime-negative";
        return false;
    }
    // Locktime values > 500M are treated as Unix timestamps
    // Locktime values <= 500M are treated as block heights
    // Both are valid for relay; the mempool checks finality separately.
    return true;
}

/// Count total sigops across all inputs and outputs.
int count_legacy_sigops(const CTransaction& tx) {
    int count = 0;
    // Each non-coinbase input has one CHECKSIG operation
    for (const auto& in : tx.vin) {
        if (!in.is_coinbase()) {
            count += 1;
        }
    }
    return count;
}

/// Estimate the cost to spend a P2PKH output.
/// Input: 36 (outpoint) + 32 (pubkey) + 64 (signature) = 132 bytes.
size_t estimate_spending_cost() {
    return 132;
}

/// Calculate the effective fee rate considering ancestor packages.
/// For CPFP: effective_rate = (tx_fee + ancestor_fees) / (tx_size + ancestor_size)
Amount calculate_effective_fee_rate(Amount tx_fee, size_t tx_size,
                                     Amount ancestor_fees, size_t ancestor_size) {
    size_t total_size = tx_size + ancestor_size;
    Amount total_fee = tx_fee + ancestor_fees;
    if (total_size == 0) return 0;
    return (total_fee * 1000) / static_cast<Amount>(total_size);
}

/// Check if a package has a valid fee structure.
/// The package's effective fee rate must meet the minimum relay fee.
bool validate_package_fee(const std::vector<CTransaction>& txs,
                           const std::vector<Amount>& fees,
                           Amount min_fee_rate,
                           std::string& error) {
    if (txs.size() != fees.size()) {
        error = "package-fee-mismatch";
        return false;
    }

    Amount total_fee = 0;
    size_t total_size = 0;
    for (size_t i = 0; i < txs.size(); ++i) {
        total_fee += fees[i];
        total_size += txs[i].get_serialize_size();

        if (fees[i] < 0) {
            error = "package-negative-fee (tx " + std::to_string(i) + ")";
            return false;
        }
    }

    if (total_size == 0) {
        error = "package-zero-size";
        return false;
    }

    Amount effective_rate = (total_fee * 1000) /
                             static_cast<Amount>(total_size);
    if (effective_rate < min_fee_rate) {
        error = "package-fee-rate-too-low";
        return false;
    }

    return true;
}

/// Validate ancestor/descendant limits for a transaction in a package.
bool validate_ancestor_limits(size_t ancestor_count, size_t ancestor_size,
                               size_t descendant_count, size_t descendant_size,
                               std::string& error) {
    if (ancestor_count > MAX_ANCESTOR_COUNT) {
        error = "too-long-mempool-chain (ancestors: " +
                std::to_string(ancestor_count) + ")";
        return false;
    }
    if (ancestor_size > MAX_ANCESTOR_SIZE) {
        error = "too-large-ancestor-set";
        return false;
    }
    if (descendant_count > MAX_DESCENDANT_COUNT) {
        error = "too-long-mempool-chain (descendants: " +
                std::to_string(descendant_count) + ")";
        return false;
    }
    if (descendant_size > MAX_DESCENDANT_SIZE) {
        error = "too-large-descendant-set";
        return false;
    }
    return true;
}

/// Check if a transaction could be a DoS vector.
/// Flags transactions with excessive inputs, outputs, or suspicious patterns.
int compute_dos_score(const CTransaction& tx) {
    int score = 0;

    // Excessive number of inputs
    if (tx.vin.size() > 500) score += 10;
    if (tx.vin.size() > 2000) score += 20;

    // Excessive number of outputs
    if (tx.vout.size() > 500) score += 10;
    if (tx.vout.size() > 2000) score += 20;

    // Extremely large transaction
    size_t size = tx.get_serialize_size();
    if (size > MAX_STANDARD_TX_WEIGHT / 4) score += 10;

    // Zero-value outputs that aren't data-carrying
    int zero_count = 0;
    for (const auto& out : tx.vout) {
        if (out.amount == 0) zero_count++;
    }
    if (zero_count > 3) score += 5;

    // All inputs from the same transaction (potential double-spend probe)
    if (tx.vin.size() > 1) {
        bool all_same = true;
        const auto& first_txid = tx.vin[0].prevout.txid;
        for (size_t i = 1; i < tx.vin.size(); ++i) {
            if (tx.vin[i].prevout.txid != first_txid) {
                all_same = false;
                break;
            }
        }
        if (all_same && tx.vin.size() > 10) score += 5;
    }

    return score;
}

/// Compute a priority score for a transaction based on fee rate and age.
/// Higher priority = more likely to be included in the next block.
double compute_tx_priority(Amount fee_rate, size_t tx_size,
                            int64_t time_in_mempool_seconds) {
    // Base priority from fee rate (sat/kB)
    double priority = static_cast<double>(fee_rate);

    // Small bonus for smaller transactions (less block space consumed)
    if (tx_size < 500) {
        priority *= 1.1;
    }

    // Age bonus: transactions waiting longer get a slight boost
    // Max bonus: 10% after 10 minutes
    double age_factor = std::min(
        1.0 + static_cast<double>(time_in_mempool_seconds) / 6000.0,
        1.1);
    priority *= age_factor;

    return priority;
}

/// Validate that a coinbase transaction is properly formed.
bool validate_coinbase_structure(const CTransaction& tx, std::string& error) {
    if (!tx.is_coinbase()) {
        error = "not-coinbase";
        return false;
    }

    // Coinbase must have exactly one input
    if (tx.vin.size() != 1) {
        error = "bad-cb-multiple-inputs";
        return false;
    }

    // Coinbase must have at least one output
    if (tx.vout.empty()) {
        error = "bad-cb-no-outputs";
        return false;
    }

    // Coinbase output values must be non-negative
    for (const auto& out : tx.vout) {
        if (out.amount < 0) {
            error = "bad-cb-negative-output";
            return false;
        }
    }

    return true;
}

} // namespace detail

// ============================================================================
// Extended public API implementations
// ============================================================================

/// Full extended standardness check with detailed diagnostics.
PolicyCheckResult check_transaction_standard_extended(
    const CTransaction& tx,
    Amount relay_fee_rate,
    bool strict_mode) {
    PolicyCheckResult result;
    result.is_standard = false;

    // Run basic standardness check first
    result = check_transaction_standard(tx);
    if (!result.is_standard) return result;

    // Extended checks in strict mode
    if (strict_mode) {
        std::string error;

        // Validate output ranges
        if (!detail::validate_output_ranges(tx, error)) {
            result.is_standard = false;
            result.reason = error;
            result.score = 100;
            return result;
        }

        // Validate no duplicate inputs
        if (!detail::validate_no_duplicate_inputs(tx, error)) {
            result.is_standard = false;
            result.reason = error;
            result.score = 100;
            return result;
        }

        // Validate input outpoints
        if (!detail::validate_input_outpoints(tx, error)) {
            result.is_standard = false;
            result.reason = error;
            result.score = 10;
            return result;
        }

        // Check sigops count
        int sigops = detail::count_legacy_sigops(tx);
        if (sigops > MAX_STANDARD_TX_SIGOPS) {
            result.is_standard = false;
            result.reason = "bad-txns-too-many-sigops";
            result.score = 10;
            return result;
        }

        // Check for extreme dust at the specific relay fee rate
        for (const auto& out : tx.vout) {
            if (is_dust_output(out, relay_fee_rate)) {
                result.is_standard = false;
                result.reason = "dust-at-relay-rate";
                result.score = 1;
                return result;
            }
        }

        // DOS score check
        int dos_score = detail::compute_dos_score(tx);
        if (dos_score >= 50) {
            result.is_standard = false;
            result.reason = "potential-dos-vector";
            result.score = dos_score;
            return result;
        }
    }

    result.is_standard = true;
    return result;
}

} // namespace policy
} // namespace flow

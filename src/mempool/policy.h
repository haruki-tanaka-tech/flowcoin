// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Transaction relay policy: non-consensus rules for deciding which
// transactions to relay and accept into the mempool. These checks
// are applied before consensus validation to filter out non-standard
// transactions that would waste bandwidth or create problems.

#ifndef FLOWCOIN_MEMPOOL_POLICY_H
#define FLOWCOIN_MEMPOOL_POLICY_H

#include "primitives/transaction.h"
#include "util/types.h"

#include <cstdint>
#include <string>

namespace flow {
namespace policy {

// ---------------------------------------------------------------------------
// Policy constants
// ---------------------------------------------------------------------------

/// Maximum standard transaction size (100 KB)
constexpr size_t MAX_STANDARD_TX_SIZE = 100'000;

/// Maximum OP_RETURN data size (80 bytes)
constexpr size_t MAX_OP_RETURN_SIZE = 80;

/// Dust threshold: outputs below this are considered uneconomical to spend
constexpr Amount DUST_THRESHOLD = 546;

/// Minimum relay fee in atomic units per byte
constexpr Amount MIN_RELAY_FEE = 1;

/// Maximum number of signers in a bare multisig output
constexpr int MAX_STANDARD_MULTISIG_N = 3;

/// Maximum number of inputs in a standard transaction
constexpr size_t MAX_STANDARD_TX_INPUTS = 500;

/// Maximum number of outputs in a standard transaction
constexpr size_t MAX_STANDARD_TX_OUTPUTS = 500;

/// Maximum locktime in the past to accept (0 = no restriction)
constexpr int64_t MAX_LOCKTIME_PAST = 0;

/// Minimum transaction version
constexpr uint32_t MIN_TX_VERSION = 1;

/// Maximum transaction version
constexpr uint32_t MAX_TX_VERSION = 2;

/// Maximum total value of all outputs (prevent overflow attacks)
constexpr Amount MAX_TOTAL_OUTPUT = 21'000'000LL * 100'000'000LL;

// ---------------------------------------------------------------------------
// Policy result
// ---------------------------------------------------------------------------

struct PolicyResult {
    bool acceptable;
    std::string reason;
};

// ---------------------------------------------------------------------------
// Policy check functions
// ---------------------------------------------------------------------------

/// Check if a transaction is standard for relay.
/// This applies non-consensus relay policy rules including:
///   - Transaction size within MAX_STANDARD_TX_SIZE
///   - Transaction version within [MIN_TX_VERSION, MAX_TX_VERSION]
///   - Number of inputs/outputs within limits
///   - No dust outputs (below DUST_THRESHOLD)
///   - Non-negative locktime
///   - No empty inputs or outputs
///   - Total output value within range
///   - Fee rate meets minimum relay fee
PolicyResult check_standard(const CTransaction& tx);

/// Check if a transaction output is dust.
/// An output is dust if spending it would cost more in fees than
/// the output is worth. Uses the given fee rate to calculate the
/// cost of spending (input serialization overhead).
bool is_dust(const CTxOut& output, Amount fee_rate);

/// Calculate the dust threshold at a given fee rate.
/// Returns the minimum output value that is not considered dust.
/// Spending an output requires at least one input (132 bytes for
/// FlowCoin: 32 txid + 4 index + 32 pubkey + 64 signature),
/// so dust_threshold = fee_rate * 132.
Amount get_dust_threshold(Amount fee_rate);

/// Check if a transaction's fee rate is at least the minimum relay fee.
/// Returns true if the fee rate is acceptable.
bool meets_min_relay_fee(const CTransaction& tx, Amount fee);

/// Check if a single output is standard.
/// - Amount must be non-negative
/// - Amount must be <= MAX_TOTAL_OUTPUT
/// - Must not be dust (unless zero for data-carrying outputs)
PolicyResult check_output_standard(const CTxOut& output);

/// Check if a single input is standard.
/// - Must not be coinbase
/// - Pubkey must not be all zeros
/// - Signature must not be all zeros (unsigned txs are not relayed)
PolicyResult check_input_standard(const CTxIn& input);

/// Calculate the virtual size of a transaction.
/// For FlowCoin, vsize = serialized size (no witness discount).
size_t get_virtual_size(const CTransaction& tx);

/// Check if the locktime on a transaction is acceptable for relay.
/// Transactions with locktime far in the future are rejected.
bool is_locktime_acceptable(int64_t locktime, int64_t current_time,
                             uint64_t current_height);

// ---------------------------------------------------------------------------
// Advanced policy checks
// ---------------------------------------------------------------------------

/// Check the fee rate against a dynamic minimum that increases when
/// the mempool is congested.
bool check_dynamic_min_fee(const CTransaction& tx, Amount fee,
                            size_t mempool_size_bytes,
                            size_t max_mempool_bytes);

/// Check if a transaction has reasonable total weight.
bool check_weight(const CTransaction& tx, size_t max_weight);

/// Validate the locktime policy of a transaction.
PolicyResult check_locktime_policy(const CTransaction& tx,
                                    int64_t current_time,
                                    uint64_t current_height);

/// Full relay policy check combining standardness, locktime, fee rate,
/// and dust checks against the current mempool state.
PolicyResult check_relay_policy(const CTransaction& tx, Amount fee,
                                 size_t mempool_size_bytes,
                                 size_t max_mempool_bytes,
                                 int64_t current_time,
                                 uint64_t current_height);

/// Calculate the minimum fee required for a given transaction size
/// under current mempool conditions.
Amount calculate_min_fee(size_t tx_size, size_t mempool_size_bytes,
                          size_t max_mempool_bytes);

/// Check if a transaction could be part of a DoS attack.
bool is_potentially_malicious(const CTransaction& tx);

/// Compute the priority of a transaction based on coin age.
/// input_info: pairs of (value, confirmation_height) for each input.
double compute_priority(const CTransaction& tx,
                         const std::vector<std::pair<Amount, uint64_t>>& input_info,
                         uint64_t current_height);

} // namespace policy
} // namespace flow

#endif // FLOWCOIN_MEMPOOL_POLICY_H

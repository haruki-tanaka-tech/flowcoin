// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// UTXO coin selection for wallet transactions.
// Provides multiple algorithms: smallest-first, largest-first,
// knapsack (random walk), and branch-and-bound (exact match).
// The auto_select function tries multiple algorithms and picks the best.

#pragma once

#include "util/types.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace flow {

/// A single UTXO that the wallet can spend.
struct CoinToSpend {
    uint256 txid;
    uint32_t vout;
    Amount value;
    std::array<uint8_t, 32> pubkey;   // public key needed to sign this input
    uint64_t height;                   // block height where this UTXO was confirmed
    bool is_coinbase;                  // whether this comes from a coinbase tx
    int confirmations;                 // number of confirmations
};

/// Result of coin selection.
struct CoinSelection {
    std::vector<CoinToSpend> selected;
    Amount total_selected;
    Amount fee;
    Amount change;
    bool success;
    std::string algorithm_used;
    std::string error;
};

namespace coinselect {

// ---------------------------------------------------------------------------
// Core algorithms
// ---------------------------------------------------------------------------

/// Algorithm 1: Smallest-first (simple greedy).
/// Sort coins by value ascending, take until target + fee is met.
/// Minimizes dust and UTXO fragmentation by spending small coins first.
CoinSelection smallest_first(const std::vector<CoinToSpend>& available,
                              Amount target, Amount fee_per_input = 1000);

/// Algorithm 2: Largest-first (minimize number of inputs).
/// Sort coins by value descending, take until target + fee is met.
/// Produces fewer inputs (lower fees) but may leave small UTXOs unspent.
CoinSelection largest_first(const std::vector<CoinToSpend>& available,
                             Amount target, Amount fee_per_input = 1000);

/// Algorithm 3: Knapsack (Bitcoin Core's original algorithm).
/// Tries to find an exact match using random walk approximation.
/// Falls back to smallest-first if no close match is found.
/// Produces good results in most cases and avoids creating change
/// outputs when possible.
CoinSelection knapsack(const std::vector<CoinToSpend>& available,
                        Amount target, Amount fee_per_input = 1000);

/// Algorithm 4: Branch and Bound (Bitcoin Core BnB).
/// Searches for an exact combination of coins that matches the target
/// plus fees without requiring a change output. When successful, this
/// saves the cost of creating and later spending a change output.
/// cost_of_change: the fee cost of creating and spending a change output.
CoinSelection branch_and_bound(const std::vector<CoinToSpend>& available,
                                Amount target, Amount fee_per_input = 1000,
                                Amount cost_of_change = 2000);

/// Auto-select: tries branch_and_bound first (for exact match, no change),
/// then knapsack, then smallest_first as a fallback.
/// Returns the best result that succeeds.
CoinSelection auto_select(const std::vector<CoinToSpend>& available,
                           Amount target, Amount fee_per_input = 1000);

// ---------------------------------------------------------------------------
// Fee estimation helpers
// ---------------------------------------------------------------------------

/// Estimate the fee for a transaction with the given number of inputs
/// and outputs, at the specified fee rate per input.
Amount estimate_fee(int num_inputs, int num_outputs,
                    Amount fee_per_input = 1000);

/// Estimate the serialized transaction size in bytes.
/// Each input is 132 bytes (32 txid + 4 index + 32 pubkey + 64 sig).
/// Each output is 40 bytes (8 amount + 32 pubkey_hash).
/// Overhead: 4 (version) + 1 (vin_count) + 1 (vout_count) + 8 (locktime) = 14.
size_t estimate_tx_size(int num_inputs, int num_outputs);

/// Estimate the fee using a per-byte fee rate instead of per-input.
Amount estimate_fee_by_size(int num_inputs, int num_outputs,
                             Amount fee_rate_per_byte);

// ---------------------------------------------------------------------------
// UTXO filtering
// ---------------------------------------------------------------------------

/// Filter out unspendable coins (immature coinbase, zero value, etc.).
/// tip_height: current chain tip height for coinbase maturity check.
/// coinbase_maturity: number of confirmations required for coinbase.
std::vector<CoinToSpend> filter_spendable(
    const std::vector<CoinToSpend>& coins,
    uint64_t tip_height,
    int coinbase_maturity = 100);

/// Sort coins by effective value (value minus cost to spend).
/// Coins that cost more to spend than they're worth are excluded.
std::vector<CoinToSpend> sort_by_effective_value(
    const std::vector<CoinToSpend>& coins,
    Amount fee_per_input);

/// Calculate the total value of a set of coins.
Amount total_value(const std::vector<CoinToSpend>& coins);

/// Group coins by address (pubkey) for privacy-aware selection.
std::vector<std::vector<CoinToSpend>> group_by_address(
    const std::vector<CoinToSpend>& coins);

} // namespace coinselect

// ---------------------------------------------------------------------------
// Coin selection analysis
// ---------------------------------------------------------------------------

/// Analyze the waste of a coin selection compared to alternatives.
/// Waste = change_cost + excess (if no change) + input_fees - long_term_fee_savings
/// Lower waste is better.
struct WasteAnalysis {
    Amount waste;
    Amount change_cost;
    Amount excess;
    Amount input_fees;
    int num_inputs;
    bool has_change;
};

/// Calculate the waste metric for a given selection.
WasteAnalysis calculate_waste(const CoinSelection& selection,
                               Amount target,
                               Amount fee_per_input,
                               Amount cost_of_change = 2000);

/// Find the selection with minimum waste across all algorithms.
CoinSelection select_min_waste(const std::vector<CoinToSpend>& available,
                                Amount target, Amount fee_per_input = 1000);

// Backward-compatible interface
CoinSelection select_coins(const std::vector<CoinToSpend>& available,
                            Amount target, Amount fee_per_input = 1000);

} // namespace flow

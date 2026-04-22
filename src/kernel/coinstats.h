// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// UTXO set statistics computation.
// Used by the gettxoutsetinfo RPC and the CoinStatsIndex to provide
// a summary of the current UTXO set: total supply, number of UTXOs,
// hash commitment, and distribution statistics.
//
// The UTXO hash is computed as:
//   hash = keccak256(sorted(keccak256(outpoint || entry) for each UTXO))
// This provides a deterministic commitment to the full UTXO set state.

#ifndef FLOWCOIN_KERNEL_COINSTATS_H
#define FLOWCOIN_KERNEL_COINSTATS_H

#include "chain/utxo.h"
#include "util/types.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace flow::kernel {

// ============================================================================
// CoinStats result
// ============================================================================

struct CoinStats {
    /// Block height at which these stats were computed.
    uint64_t height = 0;

    /// Hash of the block at this height.
    uint256 block_hash;

    /// Total number of unspent transaction outputs.
    uint64_t utxo_count = 0;

    /// Total number of transactions that have unspent outputs.
    uint64_t tx_count = 0;

    /// Total value of all unspent outputs (in atomic units).
    Amount total_amount = 0;

    /// Total value of all coinbase outputs that are still unspent.
    Amount total_coinbase_amount = 0;

    /// Number of unspent coinbase outputs.
    uint64_t coinbase_utxo_count = 0;

    /// Deterministic hash commitment to the UTXO set.
    uint256 utxo_hash;

    /// Total serialized size of all UTXOs (bytes).
    uint64_t total_size = 0;

    /// Size of the UTXO database on disk (bytes).
    uint64_t disk_size = 0;

    /// Average UTXO value (atomic units).
    double avg_value = 0.0;

    /// Median UTXO value (atomic units). Only computed if requested.
    Amount median_value = 0;

    /// Distribution: count of UTXOs by value range.
    /// Buckets (in FLC, not atomic units):
    ///   [0, 0.001), [0.001, 0.01), [0.01, 0.1), [0.1, 1),
    ///   [1, 10), [10, 100), [100, 1000), [1000, 10000), [10000, inf)
    std::vector<uint64_t> value_distribution;

    /// Whether the statistics have been successfully computed.
    bool valid = false;

    /// Error message if computation failed.
    std::string error;

    /// Format as a human-readable string.
    std::string to_string() const;
};

// ============================================================================
// Computation options
// ============================================================================

struct CoinStatsOptions {
    /// Compute the UTXO hash (can be slow for large UTXO sets).
    bool compute_hash = true;

    /// Compute value distribution histogram.
    bool compute_distribution = false;

    /// Compute median value (requires sorting all values).
    bool compute_median = false;

    /// Include disk size in the stats.
    bool include_disk_size = false;
};

// ============================================================================
// Computation functions
// ============================================================================

/// Compute UTXO set statistics at the current chain tip.
///
/// @param utxo     The UTXO set to analyze.
/// @param height   The current chain height.
/// @param hash     The current tip block hash.
/// @param options  Which statistics to compute.
/// @return         The computed statistics.
CoinStats compute_coin_stats(const UTXOSet& utxo,
                              uint64_t height,
                              const uint256& hash,
                              const CoinStatsOptions& options = {});

/// Compute just the UTXO hash commitment.
/// This is faster than full stats when only the hash is needed.
///
/// @param utxo  The UTXO set.
/// @return      The deterministic hash commitment.
uint256 compute_utxo_hash(const UTXOSet& utxo);

} // namespace flow::kernel

#endif // FLOWCOIN_KERNEL_COINSTATS_H

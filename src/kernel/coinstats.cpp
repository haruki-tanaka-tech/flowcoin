// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "kernel/coinstats.h"
#include "hash/keccak.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <numeric>
#include <set>
#include <sstream>
#include <vector>

namespace flow::kernel {

// ============================================================================
// CoinStats::to_string
// ============================================================================

std::string CoinStats::to_string() const {
    if (!valid) {
        return "CoinStats: invalid (" + error + ")";
    }

    std::ostringstream ss;
    ss << "UTXO Statistics at height " << height << ":\n";
    ss << "  Block hash:     " << block_hash.to_hex() << "\n";
    ss << "  UTXO count:     " << utxo_count << "\n";
    ss << "  TX count:       " << tx_count << "\n";

    // Format amounts as FLOW (8 decimal places)
    auto format_flow = [](Amount atomic) -> std::string {
        char buf[64];
        int64_t whole = atomic / 100'000'000LL;
        int64_t frac = atomic % 100'000'000LL;
        if (frac < 0) frac = -frac;
        std::snprintf(buf, sizeof(buf), "%lld.%08lld",
                      static_cast<long long>(whole),
                      static_cast<long long>(frac));
        return buf;
    };

    ss << "  Total amount:   " << format_flow(total_amount) << " FLOW\n";
    ss << "  Avg value:      " << format_flow(static_cast<Amount>(avg_value)) << " FLOW\n";

    if (median_value > 0) {
        ss << "  Median value:   " << format_flow(median_value) << " FLOW\n";
    }

    ss << "  Coinbase UTXOs: " << coinbase_utxo_count << " ("
       << format_flow(total_coinbase_amount) << " FLOW)\n";

    if (total_size > 0) {
        ss << "  Total size:     " << total_size << " bytes\n";
    }
    if (disk_size > 0) {
        ss << "  Disk size:      " << disk_size << " bytes\n";
    }

    ss << "  UTXO hash:      " << utxo_hash.to_hex() << "\n";

    if (!value_distribution.empty()) {
        ss << "  Value distribution:\n";
        const char* labels[] = {
            "    [0, 0.001)",
            "    [0.001, 0.01)",
            "    [0.01, 0.1)",
            "    [0.1, 1)",
            "    [1, 10)",
            "    [10, 100)",
            "    [100, 1000)",
            "    [1000, 10000)",
            "    [10000, inf)",
        };
        for (size_t i = 0; i < value_distribution.size() && i < 9; ++i) {
            ss << labels[i] << ": " << value_distribution[i] << "\n";
        }
    }

    return ss.str();
}

// ============================================================================
// UTXO hash computation
// ============================================================================

uint256 compute_utxo_hash(const UTXOSet& utxo) {
    // Iterate all UTXOs, hash each one, collect all hashes, sort, and
    // compute a final hash over the sorted list.
    //
    // For each UTXO:
    //   entry_hash = keccak256(txid || le32(vout) || le64(value) ||
    //                          pubkey_hash || le64(height) || is_coinbase)
    //
    // Final hash = keccak256(sorted entry hashes concatenated)

    std::vector<uint256> entry_hashes;

    // Use the iterator interface to walk all UTXOs
    auto all_utxos = utxo.get_all();
    entry_hashes.reserve(all_utxos.size());

    for (const auto& [outpoint, entry] : all_utxos) {
        // Build the preimage for this UTXO entry
        std::vector<uint8_t> preimage;
        preimage.reserve(32 + 4 + 8 + 32 + 8 + 1); // 85 bytes

        // txid (32 bytes)
        preimage.insert(preimage.end(),
                        outpoint.first.begin(), outpoint.first.end());

        // vout (4 bytes LE)
        uint32_t vout = outpoint.second;
        preimage.push_back(static_cast<uint8_t>(vout));
        preimage.push_back(static_cast<uint8_t>(vout >> 8));
        preimage.push_back(static_cast<uint8_t>(vout >> 16));
        preimage.push_back(static_cast<uint8_t>(vout >> 24));

        // value (8 bytes LE)
        uint64_t val = static_cast<uint64_t>(entry.value);
        for (int b = 0; b < 8; ++b) {
            preimage.push_back(static_cast<uint8_t>(val >> (b * 8)));
        }

        // pubkey_hash (32 bytes)
        preimage.insert(preimage.end(),
                        entry.pubkey_hash.begin(), entry.pubkey_hash.end());

        // height (8 bytes LE)
        for (int b = 0; b < 8; ++b) {
            preimage.push_back(static_cast<uint8_t>(entry.height >> (b * 8)));
        }

        // is_coinbase (1 byte)
        preimage.push_back(entry.is_coinbase ? 1 : 0);

        // Hash the entry
        entry_hashes.push_back(keccak256(preimage.data(), preimage.size()));
    }

    // Sort hashes for deterministic ordering
    std::sort(entry_hashes.begin(), entry_hashes.end());

    // Compute final hash over all sorted entry hashes
    if (entry_hashes.empty()) {
        // Empty UTXO set: hash of nothing
        return keccak256(nullptr, 0);
    }

    std::vector<uint8_t> combined;
    combined.reserve(entry_hashes.size() * 32);
    for (const auto& h : entry_hashes) {
        combined.insert(combined.end(), h.begin(), h.end());
    }

    return keccak256(combined.data(), combined.size());
}

// ============================================================================
// Full statistics computation
// ============================================================================

CoinStats compute_coin_stats(const UTXOSet& utxo,
                              uint64_t height,
                              const uint256& block_hash,
                              const CoinStatsOptions& options) {
    CoinStats stats;
    stats.height = height;
    stats.block_hash = block_hash;

    auto all_utxos = utxo.get_all();
    stats.utxo_count = all_utxos.size();

    // Track unique transaction IDs
    std::set<uint256> tx_set;
    std::vector<Amount> values;

    if (options.compute_median || options.compute_distribution) {
        values.reserve(all_utxos.size());
    }

    // Value distribution buckets (in atomic units)
    // [0, 100K), [100K, 1M), [1M, 10M), [10M, 100M),
    // [100M, 1B), [1B, 10B), [10B, 100B), [100B, 1T), [1T, inf)
    static const Amount bucket_boundaries[] = {
        100'000LL,          // 0.001 FLOW
        1'000'000LL,        // 0.01 FLOW
        10'000'000LL,       // 0.1 FLOW
        100'000'000LL,      // 1 FLOW
        1'000'000'000LL,    // 10 FLOW
        10'000'000'000LL,   // 100 FLOW
        100'000'000'000LL,  // 1000 FLOW
        1'000'000'000'000LL, // 10000 FLOW
    };
    constexpr int num_buckets = 9;
    std::vector<uint64_t> distribution(num_buckets, 0);

    for (const auto& [outpoint, entry] : all_utxos) {
        stats.total_amount += entry.value;
        tx_set.insert(outpoint.first);

        if (entry.is_coinbase) {
            stats.coinbase_utxo_count++;
            stats.total_coinbase_amount += entry.value;
        }

        if (options.compute_median || options.compute_distribution) {
            values.push_back(entry.value);
        }

        if (options.compute_distribution) {
            int bucket = num_buckets - 1; // Default: last bucket
            for (int i = 0; i < num_buckets - 1; ++i) {
                if (entry.value < bucket_boundaries[i]) {
                    bucket = i;
                    break;
                }
            }
            distribution[bucket]++;
        }

        // Estimate serialized size: outpoint (36) + value (8) + script (34)
        stats.total_size += 78;
    }

    stats.tx_count = tx_set.size();

    if (stats.utxo_count > 0) {
        stats.avg_value = static_cast<double>(stats.total_amount) /
                          static_cast<double>(stats.utxo_count);
    }

    if (options.compute_median && !values.empty()) {
        std::sort(values.begin(), values.end());
        stats.median_value = values[values.size() / 2];
    }

    if (options.compute_distribution) {
        stats.value_distribution = distribution;
    }

    if (options.compute_hash) {
        stats.utxo_hash = compute_utxo_hash(utxo);
    }

    stats.valid = true;
    return stats;
}

} // namespace flow::kernel

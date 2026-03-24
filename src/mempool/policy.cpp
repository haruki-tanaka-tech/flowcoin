// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "mempool/policy.h"

#include <algorithm>
#include <cstring>

namespace flow {
namespace policy {

// ---------------------------------------------------------------------------
// Dust calculation
// ---------------------------------------------------------------------------

Amount get_dust_threshold(Amount fee_rate) {
    // Spending an input in FlowCoin requires serializing:
    //   - 32 bytes: prevout txid
    //   - 4 bytes:  prevout index
    //   - 32 bytes: pubkey
    //   - 64 bytes: Ed25519 signature
    // Total: 132 bytes per input
    //
    // An output is dust if its value is less than the cost of the
    // input needed to spend it:
    //   dust_threshold = fee_rate * input_overhead_bytes
    constexpr size_t INPUT_OVERHEAD = 132;

    if (fee_rate <= 0) return DUST_THRESHOLD;

    Amount threshold = fee_rate * static_cast<Amount>(INPUT_OVERHEAD);

    // Enforce a minimum dust threshold
    if (threshold < DUST_THRESHOLD) {
        threshold = DUST_THRESHOLD;
    }

    return threshold;
}

bool is_dust(const CTxOut& output, Amount fee_rate) {
    // Zero-value outputs used for data carrying are not dust
    if (output.amount == 0) return false;

    // Negative amounts are always invalid (caught by consensus)
    if (output.amount < 0) return true;

    Amount threshold = get_dust_threshold(fee_rate);
    return output.amount < threshold;
}

// ---------------------------------------------------------------------------
// Output checks
// ---------------------------------------------------------------------------

PolicyResult check_output_standard(const CTxOut& output) {
    // Check for negative amount
    if (output.amount < 0) {
        return {false, "bad-txns-vout-negative"};
    }

    // Check maximum single output value
    if (output.amount > MAX_TOTAL_OUTPUT) {
        return {false, "bad-txns-vout-toolarge"};
    }

    // Check for dust (outputs that cost more to spend than they are worth)
    if (output.amount > 0 && output.amount < DUST_THRESHOLD) {
        return {false, "dust"};
    }

    // Check that the pubkey_hash is not all zeros (except for zero-value outputs)
    if (output.amount > 0) {
        bool all_zero = true;
        for (size_t i = 0; i < 32; ++i) {
            if (output.pubkey_hash[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            return {false, "bad-txns-vout-null-pubkey-hash"};
        }
    }

    return {true, ""};
}

// ---------------------------------------------------------------------------
// Input checks
// ---------------------------------------------------------------------------

PolicyResult check_input_standard(const CTxIn& input) {
    // Coinbase inputs are never standard in the mempool
    if (input.is_coinbase()) {
        return {false, "bad-txns-coinbase-in-mempool"};
    }

    // Check that the pubkey is not all zeros
    bool pubkey_zero = true;
    for (size_t i = 0; i < 32; ++i) {
        if (input.pubkey[i] != 0) {
            pubkey_zero = false;
            break;
        }
    }
    if (pubkey_zero) {
        return {false, "bad-txns-vin-null-pubkey"};
    }

    // Check that the signature is not all zeros (unsigned txs not relayed)
    bool sig_zero = true;
    for (size_t i = 0; i < 64; ++i) {
        if (input.signature[i] != 0) {
            sig_zero = false;
            break;
        }
    }
    if (sig_zero) {
        return {false, "bad-txns-vin-unsigned"};
    }

    // Check that the prevout txid is not null
    if (input.prevout.txid.is_null()) {
        return {false, "bad-txns-vin-null-prevout"};
    }

    return {true, ""};
}

// ---------------------------------------------------------------------------
// Transaction-level standard check
// ---------------------------------------------------------------------------

PolicyResult check_standard(const CTransaction& tx) {
    // Version check
    if (tx.version < MIN_TX_VERSION || tx.version > MAX_TX_VERSION) {
        return {false, "version"};
    }

    // Must have inputs and outputs
    if (tx.vin.empty()) {
        return {false, "bad-txns-vin-empty"};
    }
    if (tx.vout.empty()) {
        return {false, "bad-txns-vout-empty"};
    }

    // Input count limit
    if (tx.vin.size() > MAX_STANDARD_TX_INPUTS) {
        return {false, "bad-txns-too-many-inputs"};
    }

    // Output count limit
    if (tx.vout.size() > MAX_STANDARD_TX_OUTPUTS) {
        return {false, "bad-txns-too-many-outputs"};
    }

    // Serialized size check
    std::vector<uint8_t> serialized = tx.serialize();
    size_t tx_size = serialized.size();
    if (tx_size > MAX_STANDARD_TX_SIZE) {
        return {false, "tx-size"};
    }

    // Locktime check: must be non-negative
    if (tx.locktime < 0) {
        return {false, "bad-txns-locktime-negative"};
    }

    // Check each input
    for (const auto& in : tx.vin) {
        PolicyResult in_result = check_input_standard(in);
        if (!in_result.acceptable) {
            return in_result;
        }
    }

    // Check each output and track total value
    Amount total_out = 0;
    int zero_value_outputs = 0;

    for (const auto& out : tx.vout) {
        PolicyResult out_result = check_output_standard(out);
        if (!out_result.acceptable) {
            return out_result;
        }

        if (out.amount == 0) {
            zero_value_outputs++;
        }

        total_out += out.amount;
        if (total_out < 0 || total_out > MAX_TOTAL_OUTPUT) {
            return {false, "bad-txns-txouttotal-toolarge"};
        }
    }

    // Allow at most one zero-value (data-carrying) output
    if (zero_value_outputs > 1) {
        return {false, "multi-op-return"};
    }

    // Check for duplicate inputs
    {
        std::set<std::pair<uint256, uint32_t>> seen;
        for (const auto& in : tx.vin) {
            auto key = std::make_pair(in.prevout.txid, in.prevout.index);
            if (!seen.insert(key).second) {
                return {false, "bad-txns-inputs-duplicate"};
            }
        }
    }

    return {true, ""};
}

// ---------------------------------------------------------------------------
// Fee checks
// ---------------------------------------------------------------------------

bool meets_min_relay_fee(const CTransaction& tx, Amount fee) {
    auto serialized = tx.serialize();
    size_t tx_size = serialized.size();
    if (tx_size == 0) return false;

    double fee_rate = static_cast<double>(fee) / static_cast<double>(tx_size);
    return fee_rate >= static_cast<double>(MIN_RELAY_FEE);
}

// ---------------------------------------------------------------------------
// Virtual size
// ---------------------------------------------------------------------------

size_t get_virtual_size(const CTransaction& tx) {
    auto serialized = tx.serialize();
    return serialized.size();
}

// ---------------------------------------------------------------------------
// Locktime check
// ---------------------------------------------------------------------------

bool is_locktime_acceptable(int64_t locktime, int64_t current_time,
                             uint64_t current_height) {
    if (locktime == 0) return true;

    // Locktime < 500,000,000 is interpreted as a block height
    if (locktime < 500'000'000) {
        return static_cast<uint64_t>(locktime) <= current_height;
    }

    // Locktime >= 500,000,000 is a unix timestamp
    return locktime <= current_time;
}

// ---------------------------------------------------------------------------
// Advanced policy checks
// ---------------------------------------------------------------------------

/// Validate the fee rate of a transaction against a dynamic minimum.
/// The dynamic minimum can increase when the mempool is congested.
/// mempool_size_bytes: current total bytes in the mempool.
/// max_mempool_bytes: maximum mempool capacity.
bool check_dynamic_min_fee(const CTransaction& tx, Amount fee,
                            size_t mempool_size_bytes,
                            size_t max_mempool_bytes) {
    auto serialized = tx.serialize();
    size_t tx_size = serialized.size();
    if (tx_size == 0) return false;

    double base_rate = static_cast<double>(MIN_RELAY_FEE);

    // If the mempool is more than 75% full, start increasing the
    // minimum fee rate exponentially to deter low-fee spam
    if (max_mempool_bytes > 0 && mempool_size_bytes > 0) {
        double fullness = static_cast<double>(mempool_size_bytes) /
                          static_cast<double>(max_mempool_bytes);

        if (fullness > 0.75) {
            // Scale from 1x at 75% to 16x at 100%
            double excess = (fullness - 0.75) / 0.25; // 0..1
            double multiplier = 1.0 + 15.0 * excess * excess;
            base_rate *= multiplier;
        }
    }

    double fee_rate = static_cast<double>(fee) / static_cast<double>(tx_size);
    return fee_rate >= base_rate;
}

/// Check if a transaction has reasonable total weight.
/// Weight = serialized size in FlowCoin (no segwit discount).
bool check_weight(const CTransaction& tx, size_t max_weight) {
    auto serialized = tx.serialize();
    return serialized.size() <= max_weight;
}

/// Validate the nLockTime semantics of a transaction.
/// Returns a policy result indicating whether the transaction's locktime
/// is acceptable at the current chain state.
PolicyResult check_locktime_policy(const CTransaction& tx,
                                    int64_t current_time,
                                    uint64_t current_height) {
    if (tx.locktime == 0) {
        return {true, ""};
    }

    if (tx.locktime < 0) {
        return {false, "locktime-negative"};
    }

    // Future locktime: reject if more than 2 hours in the future (time-based)
    // or more than 100 blocks in the future (height-based)
    if (tx.locktime < 500'000'000) {
        // Height-based locktime
        if (static_cast<uint64_t>(tx.locktime) > current_height + 100) {
            return {false, "locktime-too-far-in-future"};
        }
        if (static_cast<uint64_t>(tx.locktime) > current_height) {
            return {false, "non-final"};
        }
    } else {
        // Time-based locktime
        int64_t max_future = current_time + 7200; // 2 hours
        if (tx.locktime > max_future) {
            return {false, "locktime-too-far-in-future"};
        }
        if (tx.locktime > current_time) {
            return {false, "non-final"};
        }
    }

    return {true, ""};
}

/// Validate a transaction for relay considering the full mempool context.
/// This combines check_standard with additional dynamic checks.
PolicyResult check_relay_policy(const CTransaction& tx, Amount fee,
                                 size_t mempool_size_bytes,
                                 size_t max_mempool_bytes,
                                 int64_t current_time,
                                 uint64_t current_height) {
    // Basic standardness check
    PolicyResult std_result = check_standard(tx);
    if (!std_result.acceptable) {
        return std_result;
    }

    // Locktime policy check
    PolicyResult lt_result = check_locktime_policy(tx, current_time, current_height);
    if (!lt_result.acceptable) {
        return lt_result;
    }

    // Dynamic minimum fee check
    if (!check_dynamic_min_fee(tx, fee, mempool_size_bytes, max_mempool_bytes)) {
        return {false, "mempool-min-fee-not-met"};
    }

    // Fee rate must meet the basic minimum relay fee
    if (!meets_min_relay_fee(tx, fee)) {
        return {false, "min-relay-fee-not-met"};
    }

    // Dust check: verify all non-zero outputs are above dust threshold
    Amount effective_rate = MIN_RELAY_FEE;
    for (const auto& out : tx.vout) {
        if (is_dust(out, effective_rate)) {
            return {false, "dust"};
        }
    }

    return {true, ""};
}

/// Calculate the minimum fee required for a transaction of the given size.
/// Takes into account dynamic mempool conditions.
Amount calculate_min_fee(size_t tx_size, size_t mempool_size_bytes,
                          size_t max_mempool_bytes) {
    double base_rate = static_cast<double>(MIN_RELAY_FEE);

    if (max_mempool_bytes > 0 && mempool_size_bytes > 0) {
        double fullness = static_cast<double>(mempool_size_bytes) /
                          static_cast<double>(max_mempool_bytes);

        if (fullness > 0.75) {
            double excess = (fullness - 0.75) / 0.25;
            double multiplier = 1.0 + 15.0 * excess * excess;
            base_rate *= multiplier;
        }
    }

    return static_cast<Amount>(base_rate * static_cast<double>(tx_size) + 0.5);
}

/// Check if a transaction could potentially be part of a DoS attack.
/// Returns true if the transaction appears suspicious.
bool is_potentially_malicious(const CTransaction& tx) {
    // Extremely high number of inputs relative to outputs
    if (tx.vin.size() > 100 && tx.vout.size() == 1) {
        // Could be a consolidation, but flag for review
        return false; // Allow consolidations
    }

    // Extremely high number of outputs (fan-out)
    if (tx.vout.size() > 200) {
        return true;
    }

    // Check for outputs with identical pubkey_hash (creates many UTXOs
    // to the same address, possible fragmentation attack)
    if (tx.vout.size() > 20) {
        std::map<std::array<uint8_t, 32>, int> pkh_counts;
        for (const auto& out : tx.vout) {
            pkh_counts[out.pubkey_hash]++;
            if (pkh_counts[out.pubkey_hash] > 10) {
                return true;
            }
        }
    }

    // Very small outputs (near dust) with many outputs
    if (tx.vout.size() > 50) {
        int near_dust_count = 0;
        for (const auto& out : tx.vout) {
            if (out.amount > 0 && out.amount < DUST_THRESHOLD * 2) {
                near_dust_count++;
            }
        }
        if (near_dust_count > 30) {
            return true;
        }
    }

    return false;
}

/// Compute the "priority" of a transaction based on coin age.
/// Higher priority transactions may be included in blocks even with
/// lower fee rates (deprecated in Bitcoin, but useful for FlowCoin's
/// early network where blocks are sparsely filled).
double compute_priority(const CTransaction& tx,
                         const std::vector<std::pair<Amount, uint64_t>>& input_info,
                         uint64_t current_height) {
    // Priority = sum(value_in_atomic * (current_height - input_height)) / tx_size
    double priority = 0.0;

    for (const auto& [value, height] : input_info) {
        uint64_t coin_age = (current_height > height) ? (current_height - height) : 0;
        priority += static_cast<double>(value) * static_cast<double>(coin_age);
    }

    auto serialized = tx.serialize();
    size_t tx_size = serialized.size();
    if (tx_size > 0) {
        priority /= static_cast<double>(tx_size);
    }

    return priority;
}

} // namespace policy
} // namespace flow

// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "coinselect.h"
#include <algorithm>

namespace flow {

// Estimate transaction size:
// version(4) + compact(vin_count) + vin_count*(32+4+64+32) + compact(vout_count) + vout_count*(8+20)
static size_t estimate_tx_size(size_t num_inputs, size_t num_outputs) {
    return 4 + 1 + num_inputs * 132 + 1 + num_outputs * 28;
}

Result<CoinSelection> select_coins(const std::vector<CoinEntry>& available,
                                    Amount target,
                                    int64_t fee_per_byte) {
    if (available.empty()) {
        return Error{"no coins available"};
    }

    // Sort by amount ascending (take smallest coins first to reduce dust)
    auto sorted = available;
    std::sort(sorted.begin(), sorted.end(),
        [](const CoinEntry& a, const CoinEntry& b) {
            return a.amount.value < b.amount.value;
        });

    CoinSelection result;
    result.total = Amount{0};

    // Estimate fee for 1 output + change output
    // We'll refine after selecting inputs
    size_t est_outputs = 2; // destination + change

    for (const auto& coin : sorted) {
        result.selected.push_back(coin);
        result.total += coin.amount;

        // Estimate fee with current number of inputs
        size_t est_size = estimate_tx_size(result.selected.size(), est_outputs);
        result.fee = Amount{static_cast<int64_t>(est_size) * fee_per_byte};

        Amount needed = target + result.fee;
        if (result.total >= needed) {
            result.change = result.total - target - result.fee;

            // If change is dust (< fee to spend it), add to fee instead
            size_t change_spend_cost = 132 * fee_per_byte;
            if (result.change.value > 0 &&
                result.change.value < static_cast<int64_t>(change_spend_cost)) {
                result.fee += result.change;
                result.change = Amount{0};
            }

            return result;
        }
    }

    return Error{"insufficient funds: need " +
                  std::to_string((target + result.fee).value) +
                  " have " + std::to_string(result.total.value)};
}

} // namespace flow

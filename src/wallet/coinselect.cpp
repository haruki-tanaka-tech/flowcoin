// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "wallet/coinselect.h"

#include <algorithm>

namespace flow {

CoinSelection select_coins(const std::vector<CoinToSpend>& available,
                            Amount target, Amount fee_per_input) {
    CoinSelection result;
    result.total_selected = 0;
    result.fee = 0;
    result.change = 0;
    result.success = false;

    if (target <= 0) {
        return result;
    }

    // Sort a copy of available UTXOs by value ascending (smallest first).
    // This minimizes the number of inputs when possible while preferring
    // to consume small UTXOs and reduce fragmentation.
    std::vector<CoinToSpend> sorted = available;
    std::sort(sorted.begin(), sorted.end(),
              [](const CoinToSpend& a, const CoinToSpend& b) {
                  return a.value < b.value;
              });

    // Accumulate coins until we cover target + fee.
    // Fee grows as we add inputs, so we re-check after each addition.
    Amount accumulated = 0;
    std::vector<CoinToSpend> selected;

    for (const auto& coin : sorted) {
        selected.push_back(coin);
        accumulated += coin.value;

        Amount fee = fee_per_input * static_cast<Amount>(selected.size());
        Amount needed = target + fee;

        if (accumulated >= needed) {
            result.selected = std::move(selected);
            result.total_selected = accumulated;
            result.fee = fee;
            result.change = accumulated - target - fee;
            result.success = true;
            return result;
        }
    }

    // Could not cover the target + fee with all available coins.
    // Return failure with the best attempt for diagnostics.
    result.selected = std::move(selected);
    result.total_selected = accumulated;
    result.fee = fee_per_input * static_cast<Amount>(result.selected.size());
    result.change = 0;
    result.success = false;
    return result;
}

} // namespace flow

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// UTXO coin selection for wallet transactions.
// Uses a smallest-first accumulation strategy.

#pragma once

#include "util/types.h"

#include <array>
#include <cstdint>
#include <vector>

namespace flow {

/// A single UTXO that the wallet can spend.
struct CoinToSpend {
    uint256 txid;
    uint32_t vout;
    Amount value;
    std::array<uint8_t, 32> pubkey;   // public key needed to sign this input
};

/// Result of coin selection.
struct CoinSelection {
    std::vector<CoinToSpend> selected;
    Amount total_selected;
    Amount fee;
    Amount change;
    bool success;
};

/// Select the smallest set of coins that covers (target + fees).
/// Fee model: fee_per_input * number_of_inputs_selected.
/// Returns success=false if insufficient funds.
CoinSelection select_coins(const std::vector<CoinToSpend>& available,
                            Amount target, Amount fee_per_input = 1000);

} // namespace flow

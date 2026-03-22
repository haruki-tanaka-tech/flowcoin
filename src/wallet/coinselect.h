// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Coin selection: pick UTXOs to cover a target amount + fee.
// Simple strategy: sort by amount, take smallest that cover target.

#pragma once

#include "core/types.h"
#include "primitives/transaction.h"
#include "chain/utxo.h"

#include <vector>

namespace flow {

struct CoinEntry {
    COutPoint outpoint;
    Amount amount;
    Blob<20> pubkey_hash;
};

struct CoinSelection {
    std::vector<CoinEntry> selected;
    Amount total;
    Amount fee;
    Amount change; // total - target - fee
};

// Select coins to cover target + fee.
// fee_per_byte: fee rate in atomic units per byte of transaction.
// Returns error if insufficient funds.
Result<CoinSelection> select_coins(const std::vector<CoinEntry>& available,
                                    Amount target,
                                    int64_t fee_per_byte = 1);

} // namespace flow

// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Block assembler: builds candidate blocks for mining.
// Each block gets a new address from the wallet (never reuse).

#pragma once

#include "primitives/block.h"
#include "chain/chainstate.h"
#include "mempool/mempool.h"
#include "wallet/wallet.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "consensus/growth.h"
#include "consensus/difficulty.h"

namespace flow::mining {

struct BlockTemplate {
    CBlock block;
    Amount total_fees;
    std::string miner_address;
};

// Build a candidate block template on top of the current chain tip.
// Uses wallet.get_mining_address() for a fresh coinbase address.
// Includes top-fee transactions from mempool.
BlockTemplate assemble_block(ChainState& chain,
                              Mempool& mempool,
                              Wallet& wallet,
                              size_t max_txs = 1000);

// Attempt to mine (find valid delta_hash) for a block template.
// For v0.1: brute-force search without real ggml training.
// Returns true if a valid hash was found within max_attempts.
bool try_mine(CBlock& block, uint32_t max_attempts = 1'000'000);

} // namespace flow::mining

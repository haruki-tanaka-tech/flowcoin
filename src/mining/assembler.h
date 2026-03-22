// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Block assembler: builds candidate blocks for mining.
// Each block gets a new address from the wallet (never reuse).
// Mining = training the model via ggml, not brute-force hashing.

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
BlockTemplate assemble_block(ChainState& chain,
                              Mempool& mempool,
                              Wallet& wallet,
                              size_t max_txs = 1000);

// Brute-force nonce search (regtest only). Real mining is in flowminer.py.
bool mine_brute_force(CBlock& block, uint32_t max_attempts = 1'000'000);

} // namespace flow::mining

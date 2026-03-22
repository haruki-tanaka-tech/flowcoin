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
#include "trainer.h"
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

// Mine a block using real training (Proof-of-Training).
// Each training step produces a new delta_hash. If H = Keccak256(D||V) < target,
// the block is valid. Training improves the model AND searches for valid hash.
// Returns true if a valid block was produced within max_steps.
bool mine_with_training(CBlock& block, Trainer& trainer,
                         const std::vector<int32_t>& training_data,
                         uint32_t max_steps = 10'000);

// Fallback: brute-force nonce search (no real training, for regtest only).
bool mine_brute_force(CBlock& block, uint32_t max_attempts = 1'000'000);

} // namespace flow::mining

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Block reward calculation with Bitcoin-identical halving schedule.
//
// Subsidy schedule:
//   Blocks      0 - 209,999:  50   FLOW  (era 0)
//   Blocks 210,000 - 419,999:  25   FLOW  (era 1)
//   Blocks 420,000 - 629,999:  12.5 FLOW  (era 2)
//   ...
//   Era N: INITIAL_REWARD >> N
//
// The subsidy halves every HALVING_INTERVAL (210,000) blocks until it
// reaches MIN_REWARD (1 atomic unit), after which it stays at 1.
// Total supply converges to MAX_SUPPLY (21,000,000 FLOW = 2.1 * 10^15 atomic units).
//
// Geometric series proof:
//   Total = 210,000 * (50 + 25 + 12.5 + ...) * COIN
//         = 210,000 * 100 * COIN
//         = 21,000,000 * COIN = MAX_SUPPLY

#ifndef FLOWCOIN_CONSENSUS_REWARD_H
#define FLOWCOIN_CONSENSUS_REWARD_H

#include "../util/types.h"
#include <cstdint>

namespace flow::consensus {

/// Compute the block subsidy (miner reward) at a given block height.
///
/// @param height  Block height (0-indexed; genesis block is height 0).
/// @return        Reward in atomic units (1 FLOW = 10^8 atomic units).
///                Returns 0 when the subsidy has been fully exhausted.
Amount compute_block_reward(uint64_t height);

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_REWARD_H

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Keccak-256d Proof-of-Work verification.
// Analogous to Bitcoin Core's pow.h.

#ifndef FLOWCOIN_CONSENSUS_POW_H
#define FLOWCOIN_CONSENSUS_POW_H

#include "difficulty.h"
#include "params.h"
#include "../primitives/block.h"
#include "../util/arith_uint256.h"
#include "../util/types.h"

#include <cstdint>

namespace flow::consensus {

/// Check the Proof-of-Work for a block header.
/// Verifies keccak256d(header[0..91]) <= target from nbits.
bool CheckProofOfWork(const CBlockHeader& header);

/// Get the powLimit as an arith_uint256.
arith_uint256 GetPowLimit();

/// Get human-readable difficulty from compact nbits.
double GetDifficulty(uint32_t nbits);

/// Check if minimum difficulty blocks are allowed (regtest only).
bool AllowMinDifficultyBlocks(bool regtest);

/// Get the next required work target for a child block.
uint32_t GetNextWorkRequired(uint64_t parent_height, uint32_t parent_nbits,
                              int64_t parent_timestamp, int64_t first_block_time,
                              bool regtest = false);

/// Estimate network hashrate from difficulty.
double EstimateNetworkHashrate(double difficulty);

/// Compute the work contribution of a single block.
arith_uint256 GetBlockProof(uint32_t nbits);

/// Convert difficulty to compact target.
uint32_t DifficultyToTarget(double difficulty);

/// Format a 256-bit target as a hex string.
std::string FormatTarget(uint32_t nbits);

/// Estimate time to find a block.
double EstimateTimeToBlock(double difficulty, double local_hashrate);

/// Get retarget period boundaries.
void GetRetargetPeriod(uint64_t height, uint64_t& period_start,
                        uint64_t& period_end);

/// Check if a height is a retarget boundary.
inline bool IsRetargetHeight(uint64_t height) {
    return height > 0 && (height % RETARGET_INTERVAL == 0);
}

/// Blocks until next retarget.
inline uint64_t BlocksUntilRetarget(uint64_t height) {
    return RETARGET_INTERVAL - (height % RETARGET_INTERVAL);
}

/// Difficulty progress info.
struct DifficultyProgress {
    double blocks_in_period;
    double period_progress_pct;
    double estimated_adjustment;
    uint64_t blocks_until_retarget;
    double current_difficulty;
    double estimated_hashrate;
};

DifficultyProgress GetDifficultyProgress(uint64_t current_height,
                                          uint32_t current_nbits,
                                          int64_t period_start_time,
                                          int64_t current_time);

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_POW_H

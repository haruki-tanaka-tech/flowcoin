// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Keccak-256d Proof-of-Work: verification and difficulty math.
//
// PoW hash is keccak256d(header[0..91]) — the same as the block ID hash.
// CheckProofOfWork simply verifies that block_id <= target(nbits).

#ifndef FLOWCOIN_CONSENSUS_POW_H
#define FLOWCOIN_CONSENSUS_POW_H

#include "difficulty.h"
#include "params.h"
#include "../primitives/block.h"
#include "../util/arith_uint256.h"
#include "../util/types.h"

#include <cstdint>
#include <string>

namespace flow::consensus {

// ---------------------------------------------------------------------------
// PoW verification
// ---------------------------------------------------------------------------

/// Verify the Proof-of-Work: keccak256d(header[0..91]) <= target(nbits).
bool CheckProofOfWork(const CBlockHeader& header);

// ---------------------------------------------------------------------------
// Difficulty math
// ---------------------------------------------------------------------------

/// Return the powLimit as an arith_uint256.
arith_uint256 GetPowLimit();

/// Human-readable difficulty from compact nbits.
double GetDifficulty(uint32_t nbits);

/// Whether minimum-difficulty blocks are allowed (regtest only).
bool AllowMinDifficultyBlocks(bool regtest);

/// Next required work target for a child block.
uint32_t GetNextWorkRequired(uint64_t parent_height, uint32_t parent_nbits,
                              int64_t parent_timestamp, int64_t first_block_time,
                              bool regtest = false);

/// Estimated network hashrate from difficulty.
double EstimateNetworkHashrate(double difficulty);

/// Work contribution of a single block.
arith_uint256 GetBlockProof(uint32_t nbits);

/// Convert difficulty to compact target.
uint32_t DifficultyToTarget(double difficulty);

/// Format a 256-bit target as a hex string.
std::string FormatTarget(uint32_t nbits);

/// Expected time to find a block at the given local hashrate.
double EstimateTimeToBlock(double difficulty, double local_hashrate);

/// Retarget period boundaries for `height`.
void GetRetargetPeriod(uint64_t height, uint64_t& period_start,
                        uint64_t& period_end);

/// Whether `height` is a retarget boundary.
inline bool IsRetargetHeight(uint64_t height) {
    return height > 0 && (height % RETARGET_INTERVAL == 0);
}

/// Blocks until the next retarget.
inline uint64_t BlocksUntilRetarget(uint64_t height) {
    return RETARGET_INTERVAL - (height % RETARGET_INTERVAL);
}

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

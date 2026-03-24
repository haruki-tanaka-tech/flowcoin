// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Proof-of-Training verification wrapper.
// Analogous to Bitcoin Core's pow.h, this module provides high-level
// functions that combine difficulty checking, training hash verification,
// and human-readable difficulty computation.
//
// In FlowCoin, "proof of work" is replaced by "proof of training":
// miners train a neural network and the training hash (derived from
// the block hash) must meet a difficulty target. The difficulty adjustment
// follows Bitcoin's exact algorithm (retarget every 2016 blocks).

#ifndef FLOWCOIN_CONSENSUS_POW_H
#define FLOWCOIN_CONSENSUS_POW_H

#include "difficulty.h"
#include "params.h"
#include "../primitives/block.h"
#include "../util/arith_uint256.h"
#include "../util/types.h"

#include <cstdint>

namespace flow::consensus {

/// Check the full proof-of-training for a block header.
///
/// Combines:
///   1. Decode nbits to a target value (reject invalid encodings)
///   2. Compute the training hash from the header
///   3. Verify training_hash <= target
///
/// This is the top-level PoT check used during header validation.
///
/// @param header  The block header to verify.
/// @return        true if the header's training hash meets its difficulty target.
bool CheckProofOfTraining(const CBlockHeader& header);

/// Get the powLimit as an arith_uint256.
/// This is the maximum allowed target (minimum difficulty = 1).
/// Decoded from INITIAL_NBITS (0x1f00ffff).
arith_uint256 GetPowLimit();

/// Get the human-readable difficulty value from compact nbits.
///
/// Difficulty is defined as: powLimit_target / current_target.
/// At minimum difficulty (nbits == INITIAL_NBITS), difficulty is 1.0.
/// Higher difficulty means a smaller target (harder to find valid hash).
///
/// @param nbits  The compact target encoding.
/// @return       Difficulty as a floating-point number (>= 1.0).
///               Returns 0.0 if nbits is invalid.
double GetDifficulty(uint32_t nbits);

// GetDifficulty(CBlockIndex) is in chain/ to avoid circular dependency

/// Check if minimum difficulty blocks are allowed.
/// In regtest mode, blocks can use the easiest possible difficulty
/// regardless of what the retarget algorithm would normally require.
///
/// @param regtest  true if running in regtest mode.
/// @return         true if min-difficulty blocks are allowed.
bool AllowMinDifficultyBlocks(bool regtest);

/// Get the next required proof-of-training target for a child block.
///
/// Wrapper around get_next_work_required() that handles:
///   - Non-retarget blocks (return parent nbits unchanged)
///   - Retarget blocks (compute new target from period timestamps)
///   - Min-difficulty override for regtest
///
/// @param parent_height      Height of the parent block.
/// @param parent_nbits       Compact target of the parent block.
/// @param parent_timestamp   Timestamp of the parent block.
/// @param first_block_time   Timestamp of the first block in the current
///                            retarget period (height % 2016 == 0).
/// @param regtest            true if running in regtest mode.
/// @return                   Compact target for the child block.
uint32_t GetNextWorkRequired(uint64_t parent_height, uint32_t parent_nbits,
                              int64_t parent_timestamp, int64_t first_block_time,
                              bool regtest = false);

/// Compute the estimated network hashrate (training rate) from difficulty.
///
/// hashrate = difficulty * 2^32 / TARGET_BLOCK_TIME
///
/// This gives an approximation of how much training work per second
/// the network is collectively performing.
///
/// @param difficulty  The current difficulty value.
/// @return            Estimated training operations per second.
double EstimateNetworkHashrate(double difficulty);

/// Compute the "chainwork" contribution of a single block.
///
/// Work for a block is defined as: 2^256 / (target + 1).
/// This represents the expected number of hash attempts needed
/// to find a block at this difficulty level.
///
/// @param nbits  Compact target of the block.
/// @return       Work contribution as a 256-bit integer.
arith_uint256 GetBlockProof(uint32_t nbits);

/// Compute cumulative chainwork from genesis to a given block.
/// Sums GetBlockProof() for each block in the chain.
///
/// @param tip  The block index at the tip of the chain.
/// @return     Total cumulative work as a 256-bit integer.
// GetChainWork(CBlockIndex*) is in chain/ to avoid circular dependency

/// Convert a difficulty value to the corresponding compact target (nbits).
///
/// Inverse of GetDifficulty(): given a difficulty value, compute the
/// compact target encoding that would produce that difficulty.
///
/// @param difficulty  The desired difficulty.
/// @return            Compact target encoding (nbits).
uint32_t DifficultyToTarget(double difficulty);

/// Format a 256-bit target as a hex string for display.
///
/// @param nbits  Compact target to format.
/// @return       Hex string representation of the full 256-bit target.
std::string FormatTarget(uint32_t nbits);

/// Estimate time to find a block at the current difficulty.
///
/// @param difficulty     Current network difficulty.
/// @param local_hashrate Local training operations per second.
/// @return               Expected seconds to find a block.
double EstimateTimeToBlock(double difficulty, double local_hashrate);

/// Calculate the retarget period boundaries for a given height.
///
/// @param height          Block height.
/// @param period_start    [out] Height of first block in this retarget period.
/// @param period_end      [out] Height of last block in this retarget period.
void GetRetargetPeriod(uint64_t height, uint64_t& period_start,
                        uint64_t& period_end);

/// Check if a height is a retarget boundary.
///
/// @param height  Block height to check.
/// @return        true if height % RETARGET_INTERVAL == 0.
inline bool IsRetargetHeight(uint64_t height) {
    return height > 0 && (height % RETARGET_INTERVAL == 0);
}

/// Get the number of blocks remaining until the next retarget.
///
/// @param height  Current block height.
/// @return        Blocks until next retarget boundary.
inline uint64_t BlocksUntilRetarget(uint64_t height) {
    return RETARGET_INTERVAL - (height % RETARGET_INTERVAL);
}

/// Verify the complete proof-of-training for a block, including
/// architecture and difficulty consistency checks.
///
/// This is a higher-level check than CheckProofOfTraining that also
/// validates the training hash is computed correctly from the block
/// header fields (not just that it meets the target).
///
/// @param header        The block header.
/// @param parent_nbits  The parent block's compact target.
/// @param child_height  Expected height for this block.
/// @return              true if all PoT checks pass.
bool VerifyFullProofOfTraining(const CBlockHeader& header,
                                uint32_t parent_nbits,
                                uint64_t child_height);

/// Compute a difficulty progress string for display.
/// Shows what percentage of the retarget period has elapsed
/// and the estimated adjustment at the next retarget.
///
/// @param current_height   Current chain height.
/// @param current_nbits    Current difficulty target.
/// @param period_start_time Timestamp of first block in current period.
/// @param current_time      Current time.
/// @return                  Human-readable difficulty progress info.
struct DifficultyProgress {
    double blocks_in_period;     // Blocks completed in current retarget period
    double period_progress_pct;  // Percentage of period completed
    double estimated_adjustment; // Estimated difficulty change at next retarget
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

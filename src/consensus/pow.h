// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// RandomX Proof-of-Work: verification, runtime management, difficulty math.
//
// PoW hash is RandomX(header_bytes, seed), where seed is the block hash at
// `rx_seed_height(current_height)`. The block ID hash (keccak256d of the
// unsigned header) is unchanged — only the target comparison uses RandomX.
//
// Seed rotation follows the Monero pattern: rotates every SEEDHASH_EPOCH_BLOCKS
// blocks with a SEEDHASH_EPOCH_LAG-block delay so nodes agree on the seed
// before it takes effect and reorgs near the boundary do not thrash caches.

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
// RandomX seed rotation
// ---------------------------------------------------------------------------

/// Seed rotates every 2048 blocks (~14 days at a 10-minute target).
constexpr uint64_t SEEDHASH_EPOCH_BLOCKS = 2048;

/// 64-block lag so the new cache is warm before rotation kicks in.
constexpr uint64_t SEEDHASH_EPOCH_LAG = 64;

/// Height of the block whose hash is the RandomX seed for `height`.
/// Matches Monero's `rx_seedheight`.
uint64_t rx_seed_height(uint64_t height);

// ---------------------------------------------------------------------------
// RandomX runtime
// ---------------------------------------------------------------------------

/// Configure RandomX runtime. Must be called before the first hash
/// computation; subsequent calls are no-ops.
///
/// @param full_mem     Allocate the 2 GB dataset for fast mining. Otherwise
///                     only the 256 MB cache is used (verifier mode).
/// @param large_pages  Request huge pages. Falls back silently if denied.
void ConfigureRandomX(bool full_mem, bool large_pages);

/// Pre-initialise the cache for `seed` so the first PoW verification does
/// not pay the cache init cost (~40 ms).
void WarmUpRandomX(const uint256& seed);

/// Release all caches, dataset, and thread-local VMs. Call on shutdown.
void ShutdownRandomX();

/// Compute RandomX PoW hash of `data` using `seed` as the cache key.
uint256 ComputePowHash(const uint8_t* data, size_t len, const uint256& seed);

// ---------------------------------------------------------------------------
// PoW verification
// ---------------------------------------------------------------------------

/// Verify the Proof-of-Work: RandomX(header[0..91], seed) <= target(nbits).
bool CheckProofOfWork(const CBlockHeader& header, const uint256& seed);

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

// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Difficulty adjustment for FlowCoin's Proof-of-Useful-Training.
// Implements Bitcoin's exact retarget algorithm: every 2016 blocks,
// the target is adjusted based on actual vs expected timespan,
// clamped to a 4x factor in either direction.
//
// The "training hash" (keccak256(delta_hash || dataset_hash)) must be
// numerically less than or equal to the current target for a block
// to be accepted. This ties difficulty to the quality/quantity of
// training work: better training produces lower-entropy deltas that
// are more likely to meet a tighter target.

#ifndef FLOWCOIN_CONSENSUS_DIFFICULTY_H
#define FLOWCOIN_CONSENSUS_DIFFICULTY_H

#include "../util/arith_uint256.h"
#include "../util/types.h"
#include <cstdint>

namespace flow::consensus {

/// Decode the compact nBits format into a full 256-bit target value.
///
/// nBits encoding (same as Bitcoin):
///   byte 3:     exponent (number of bytes in the target)
///   bytes 2-0:  mantissa (top 3 bytes of the target value)
///   target = mantissa << (8 * (exponent - 3))
///
/// @param nbits   The compact target encoding.
/// @param target  [out] The decoded 256-bit target.
/// @return        false if nbits encodes a negative value, overflows, or
///                exceeds the powLimit (INITIAL_NBITS). true otherwise.
bool derive_target(uint32_t nbits, arith_uint256& target);

/// Check whether a training hash meets the difficulty target.
///
/// The training hash is interpreted as a little-endian 256-bit unsigned
/// integer. It must be <= the target decoded from nbits.
///
/// @param training_hash  keccak256(delta_hash || dataset_hash)
/// @param nbits          Compact target for this block.
/// @return               true if hash <= target, false otherwise.
bool check_proof_of_training(const uint256& training_hash, uint32_t nbits);

/// Calculate the next required work target (called every RETARGET_INTERVAL blocks).
///
/// Algorithm (identical to Bitcoin's CalculateNextWorkRequired):
///   1. If height is not at a retarget boundary (height % 2016 != 0),
///      return parent_nbits unchanged.
///   2. Compute actual_timespan = last_block_time - first_block_time.
///   3. Clamp actual_timespan to [RETARGET_TIMESPAN/4, RETARGET_TIMESPAN*4].
///   4. new_target = old_target * actual_timespan / RETARGET_TIMESPAN.
///   5. If new_target > powLimit, clamp to powLimit.
///   6. Return new_target.GetCompact().
///
/// @param height            Height of the block being validated.
/// @param parent_nbits      Compact target of the parent block.
/// @param first_block_time  Timestamp of the first block in this retarget period
///                          (block at height - RETARGET_INTERVAL).
/// @param last_block_time   Timestamp of the last block in this retarget period
///                          (the parent block).
/// @return                  New compact target for the next retarget period.
uint32_t get_next_work_required(uint64_t height, uint32_t parent_nbits,
                                int64_t first_block_time, int64_t last_block_time);

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_DIFFICULTY_H

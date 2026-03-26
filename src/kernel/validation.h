// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Pure consensus validation functions for the kernel library.
// These functions take ONLY inputs and return results — no global state,
// no side effects, no database access. This makes them suitable for
// testing, fuzzing, and external validation tools.
//
// The kernel validation layer wraps the lower-level consensus module
// (consensus/validation.h) with a cleaner API that doesn't require
// assembling context objects.

#ifndef FLOWCOIN_KERNEL_VALIDATION_H
#define FLOWCOIN_KERNEL_VALIDATION_H

#include "chain/utxo.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/arith_uint256.h"
#include "util/types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace flow::kernel {

// ============================================================================
// Transaction validation (pure functions)
// ============================================================================

/// Result of validating a single transaction.
struct TxValidationResult {
    bool valid = false;
    std::string error;          // Empty if valid
    std::string debug_message;  // Additional diagnostic info
    Amount fee = 0;             // Total fee (inputs - outputs), 0 if invalid
    int sigops = 0;             // Signature operations count
    Amount total_in = 0;        // Sum of input values
    Amount total_out = 0;       // Sum of output values
};

/// Validate a non-coinbase transaction against the UTXO set.
///
/// Checks:
///   1. Transaction is not empty (has inputs and outputs)
///   2. Transaction size <= MAX_TX_SIZE
///   3. All inputs exist in the UTXO set
///   4. No double-spends within the transaction
///   5. Input values are in valid range (0, MAX_SUPPLY]
///   6. Output values are in valid range [0, MAX_SUPPLY]
///   7. Sum of outputs <= sum of inputs (fee >= 0)
///   8. No overflow in value sums
///   9. Coinbase inputs are mature (>= COINBASE_MATURITY confirmations)
///  10. Ed25519 signatures verify against input pubkey hashes
///
/// @param tx       The transaction to validate.
/// @param utxo     The current UTXO set for input lookups.
/// @param height   The height at which this transaction would be included.
/// @return         Validation result with fee and error info.
TxValidationResult validate_transaction(
    const CTransaction& tx,
    const UTXOSet& utxo,
    uint64_t height);

/// Validate a coinbase transaction.
///
/// Checks:
///   1. Exactly one input with null prevout
///   2. Coinbase script size within limits
///   3. Output value <= max_value (block reward + total fees)
///   4. Output values are non-negative
///   5. No overflow in output sum
///
/// @param tx         The coinbase transaction to validate.
/// @param height     The block height.
/// @param max_value  Maximum allowed output (reward + fees).
/// @return           Validation result.
TxValidationResult validate_coinbase(
    const CTransaction& tx,
    uint64_t height,
    Amount max_value);

// ============================================================================
// Block subsidy (pure functions)
// ============================================================================

/// Compute the block subsidy (miner reward) at a given height.
/// This is a pure function of height with no external dependencies.
///
/// @param height  Block height (genesis = 0).
/// @return        Reward in atomic units.
Amount get_block_subsidy(uint64_t height);

/// Compute the total supply minted through a given height.
/// Sum of all block subsidies from height 0 to the given height.
Amount get_total_supply(uint64_t height);

// ============================================================================
// Difficulty (pure functions)
// ============================================================================

/// Compute the next required work target.
///
/// Called every RETARGET_INTERVAL blocks. Adjusts the target based on
/// the ratio of actual timespan to expected timespan, clamped to a
/// MAX_RETARGET_FACTOR change in either direction.
///
/// @param prev_nbits        Current compact target.
/// @param actual_timespan   Actual time for the last retarget period (seconds).
/// @param allow_min_difficulty  If true, allow minimum difficulty (regtest).
/// @return                  New compact target.
uint32_t compute_next_work(uint32_t prev_nbits,
                            int64_t actual_timespan,
                            bool allow_min_difficulty = false);

/// Get the powLimit as an arith_uint256.
arith_uint256 get_pow_limit();

/// Get difficulty as a floating-point number from compact nbits.
double get_difficulty(uint32_t nbits);

// ============================================================================
// Keccak-256d Proof-of-Work (pure functions)
// ============================================================================

/// Check if a training hash meets the difficulty target.
///
/// @param training_hash  keccak256(delta_hash || dataset_hash)
/// @param nbits          Compact target for this block.
/// @return               true if hash <= target.
bool check_proof_of_training(const uint256& training_hash, uint32_t nbits);

/// Compute the training hash from component hashes.
///
/// training_hash = keccak256(delta_hash || dataset_hash)
///
/// @param delta_hash    Hash of the compressed weight delta.
/// @param dataset_hash  Hash of the evaluation dataset.
/// @return              The training hash.
uint256 compute_training_hash(const uint256& delta_hash,
                               const uint256& dataset_hash);

/// Verify the Ed25519 block signature.
///
/// Verifies that miner_sig is a valid Ed25519 signature over
/// the unsigned header bytes (0..243) under miner_pubkey.
///
/// @param header  The block header to verify.
/// @return        true if the signature is valid.
bool verify_block_signature(const CBlockHeader& header);

// ============================================================================
// Model dimensions (pure functions)
// ============================================================================

/// Compute the consensus model dimensions for a given block height.
///
/// Dimensions grow deterministically with height:
///   d_model:  512 + height  (capped at 1024)
///   n_layers: 8 + height/32 (capped at 24)
///   n_slots:  1024 + height * SLOT_GROWTH_PER_BLOCK (no cap)
///   n_heads:  d_model / 64
///   d_ff:     2 * d_model
///   gru_dim:  d_model
///
/// @param height  Block height.
/// @return        Model dimensions struct.


/// Compute the expected total parameter count for given dimensions.


} // namespace flow::kernel

#endif // FLOWCOIN_KERNEL_VALIDATION_H

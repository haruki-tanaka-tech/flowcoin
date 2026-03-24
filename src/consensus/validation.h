// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Consensus validation for FlowCoin blocks and headers.
//
// Implements all 16 consensus checks:
//
// CHECK  FIELD              RULE                                    ERROR CODE
// ─────  ─────────────────  ──────────────────────────────────────  ──────────
//  1     prev_hash          == parent_hash (from context)           bad-prevblk
//  2     height             == parent_height + 1                    bad-height
//  3     timestamp          > parent_timestamp                      time-too-old
//  4     timestamp          >= parent_timestamp + MIN_BLOCK_INTERVAL bad-time-spacing
//  5     timestamp          <= adjusted_time + MAX_FUTURE_TIME      time-too-new
//  6     val_loss           isfinite() && val_loss > 0              bad-val-loss
//  7     val_loss           < MAX_VAL_LOSS                          val-loss-range
//  8     prev_val_loss      == parent_val_loss (bit-identical)      bad-prev-loss
//  9     val_loss           <= MAX_LOSS_INCREASE * parent_val_loss  loss-regression
// 10     training_hash      < target from nbits                     high-hash
// 11     nbits              == get_next_work_required(...)           bad-diffbits
// 12     dataset_hash       == computed dataset hash                 bad-dataset-hash
// 13     growth fields      == compute_growth(height, improving)    bad-growth
// 14     miner_sig          Ed25519Verify(pubkey, header[0..243])   bad-signature
// 15     val_loss           == ForwardEval(model+delta, val_data)   bad-eval-loss
// 16     train_steps        >= compute_min_steps(height)            insufficient-training
//
// check_header() validates checks 1-11, 13-14 (no block body needed).
// check_block() validates all 16 checks plus coinbase, merkle root, and
// transaction signatures.

#ifndef FLOWCOIN_CONSENSUS_VALIDATION_H
#define FLOWCOIN_CONSENSUS_VALIDATION_H

#include "params.h"
#include "../util/types.h"
#include "../primitives/block.h"

#include <cstdint>
#include <string>
#include <vector>

namespace flow::consensus {

// ---------------------------------------------------------------------------
// Validation result codes
// ---------------------------------------------------------------------------

enum class ValidationResult {
    OK = 0,
    HEADER_INVALID,
    BLOCK_INVALID,
    TX_INVALID,
    DUPLICATE,
    INTERNAL_ERROR,
};

// ---------------------------------------------------------------------------
// ValidationState — accumulates error information during validation
// ---------------------------------------------------------------------------

class ValidationState {
public:
    ValidationState() = default;

    bool is_valid() const { return result_ == ValidationResult::OK; }
    bool is_invalid() const {
        return result_ == ValidationResult::HEADER_INVALID
            || result_ == ValidationResult::BLOCK_INVALID
            || result_ == ValidationResult::TX_INVALID;
    }
    bool is_error() const { return result_ == ValidationResult::INTERNAL_ERROR; }

    ValidationResult result() const { return result_; }
    const std::string& reject_reason() const { return reject_reason_; }
    const std::string& debug_message() const { return debug_message_; }

    /** Mark as invalid with a result code, reject reason, and optional debug message. */
    bool invalid(ValidationResult result, const std::string& reject_reason,
                 const std::string& debug_msg = "") {
        result_ = result;
        reject_reason_ = reject_reason;
        debug_message_ = debug_msg;
        return false;
    }

    /** Convenience for internal errors. */
    bool error(const std::string& reject_reason) {
        return invalid(ValidationResult::INTERNAL_ERROR, reject_reason);
    }

    /** Reset to valid state. */
    void clear() {
        result_ = ValidationResult::OK;
        reject_reason_.clear();
        debug_message_.clear();
    }

    /** Human-readable summary. */
    std::string to_string() const {
        if (is_valid()) return "valid";
        std::string s = reject_reason_;
        if (!debug_message_.empty()) {
            s += " (" + debug_message_ + ")";
        }
        return s;
    }

private:
    ValidationResult result_ = ValidationResult::OK;
    std::string reject_reason_;
    std::string debug_message_;
};

// ---------------------------------------------------------------------------
// BlockContext — parent-chain state needed for validation
// ---------------------------------------------------------------------------

struct BlockContext {
    // Parent block info
    uint256     prev_hash;                //!< Parent's block hash
    uint64_t    prev_height    = 0;       //!< Parent's height
    int64_t     prev_timestamp = 0;       //!< Parent's timestamp
    float       prev_val_loss  = 0.0f;    //!< Parent's val_loss
    uint32_t    prev_nbits     = 0;       //!< Parent's difficulty bits

    // Expected model dimensions for the child block (from compute_growth)
    ModelDimensions expected_dims{};

    // Cumulative count of improving blocks at the parent
    uint32_t    improving_blocks = 0;

    // Current network-adjusted time
    int64_t     adjusted_time = 0;

    // Expected minimum training steps for the child height
    uint32_t    min_train_steps = 0;

    // Expected difficulty bits for the child block (from get_next_work_required)
    uint32_t    expected_nbits = 0;

    // Timestamp of block at start of current retarget period
    // (block at height: floor(prev_height / 2016) * 2016)
    int64_t     retarget_first_time = 0;

    // True if we are validating the genesis block (no parent exists).
    // When true, checks 1-5, 8-9, 11 are skipped.
    bool        is_genesis = false;
};

// ---------------------------------------------------------------------------
// EvalFunction — callback for forward evaluation (check 15)
// ---------------------------------------------------------------------------

/** Callback for forward model evaluation.
 *  Takes the compressed delta payload and dataset hash, returns computed val_loss.
 *  If nullptr and delta is non-empty, check 15 is skipped (used during IBD). */
using EvalFunction = float(*)(const std::vector<uint8_t>& delta_payload,
                               const uint256& dataset_hash);

// ---------------------------------------------------------------------------
// check_header — header-only validation (checks 1-11, 13-14)
// ---------------------------------------------------------------------------

/** Validate a block header against its parent context.
 *
 *  Implements checks 1-11 and 13-14. Skips checks requiring the block body
 *  (12, 15, 16). For the genesis block (ctx.is_genesis), chain-relative
 *  checks (1-5, 8-9, 11) are skipped.
 *
 *  @param header  The block header to validate.
 *  @param ctx     Parent context.
 *  @param state   [out] Validation state with reject reason on failure.
 *  @return        true if the header passes all applicable checks.
 */
bool check_header(const CBlockHeader& header, const BlockContext& ctx,
                  ValidationState& state);

// ---------------------------------------------------------------------------
// check_block — full block validation (all 16 checks)
// ---------------------------------------------------------------------------

/** Validate a complete block (header + transactions + delta).
 *
 *  Calls check_header() first, then validates:
 *  - Check 12: dataset_hash integrity (non-null)
 *  - Check 15: forward evaluation (if eval_fn provided and delta non-empty)
 *  - Check 16: minimum training steps
 *  - Coinbase reward matches compute_block_reward()
 *  - Transaction signature validation
 *  - Merkle root verification
 *  - Block size limits
 *
 *  @param block    The full block to validate.
 *  @param ctx      Parent context.
 *  @param state    [out] Validation state with reject reason on failure.
 *  @param eval_fn  Optional callback for forward evaluation. If nullptr and
 *                  delta is non-empty, check 15 is skipped.
 *  @return         true if the block passes all checks.
 */
bool check_block(const CBlock& block, const BlockContext& ctx,
                 ValidationState& state, EvalFunction eval_fn = nullptr);

// ---------------------------------------------------------------------------
// check_block_transactions — detailed per-transaction validation
// ---------------------------------------------------------------------------

/** Validate all transactions in a block with detailed checks.
 *
 *  Called during ConnectBlock when UTXO access is available.
 *  Performs:
 *  - Block size estimate check (MAX_BLOCK_SIZE)
 *  - Total sigops count (MAX_BLOCK_SIGOPS)
 *  - Duplicate txid detection within the block
 *  - Per-transaction structure validation:
 *    - No null prevouts in non-coinbase transactions
 *    - Transaction size limits (MAX_TX_SIZE)
 *    - Output value sanity (non-negative, no overflow)
 *
 *  @param block  The full block.
 *  @param ctx    Parent context.
 *  @param state  [out] Validation state with reject reason on failure.
 *  @return       true if all transaction-level checks pass.
 */
bool check_block_transactions(const CBlock& block, const BlockContext& ctx,
                               ValidationState& state);

// ---------------------------------------------------------------------------
// check_coinbase — detailed coinbase validation
// ---------------------------------------------------------------------------

/** Validate the coinbase transaction against consensus rules.
 *
 *  Checks:
 *  - Is a valid coinbase (single null input)
 *  - Has at least one output
 *  - Total output value <= max_allowed (subsidy + fees)
 *  - All outputs have non-negative values
 *
 *  @param coinbase     The coinbase transaction.
 *  @param height       Block height (for BIP34 check).
 *  @param max_allowed  Maximum allowed coinbase value (subsidy + fees).
 *  @param state        [out] Validation state.
 *  @return             true if the coinbase passes all checks.
 */
bool check_coinbase(const CTransaction& coinbase, uint64_t height,
                     Amount max_allowed, ValidationState& state);

// ---------------------------------------------------------------------------
// compute_block_fees — total fees for non-coinbase transactions
// ---------------------------------------------------------------------------

/** Compute total fees for all non-coinbase transactions in a block.
 *
 *  @param block           The full block.
 *  @param tx_input_sums   Pre-computed input value sums for each transaction.
 *                          tx_input_sums[0] corresponds to the coinbase (0).
 *  @return                Total fees in atomic units.
 */
Amount compute_block_fees(const CBlock& block,
                           const std::vector<Amount>& tx_input_sums);

// ---------------------------------------------------------------------------
// check_transaction — standalone transaction validation
// ---------------------------------------------------------------------------

/** Validate a single transaction in isolation (no UTXO context).
 *
 *  Checks:
 *  - Has at least one input and one output
 *  - All output values non-negative and don't exceed MAX_SUPPLY
 *  - Total output value doesn't overflow
 *  - No duplicate inputs within the transaction
 *  - Transaction is not coinbase (use check_coinbase for that)
 *  - Signature verification on all inputs
 *
 *  @param tx     The transaction to validate.
 *  @param state  [out] Validation state.
 *  @return       true if the transaction passes all checks.
 */
bool check_transaction(const CTransaction& tx, ValidationState& state);

// ---------------------------------------------------------------------------
// check_block_weight — validate block weight/size limits
// ---------------------------------------------------------------------------

/** Validate block weight against consensus limits.
 *
 *  Computes the effective block weight as:
 *    weight = header_size + sum(tx_sizes) + delta_payload_size
 *
 *  @param block  The full block.
 *  @param state  [out] Validation state.
 *  @return       true if block weight is within limits.
 */
bool check_block_weight(const CBlock& block, ValidationState& state);

// ---------------------------------------------------------------------------
// ValidationFlags — fine-grained control over which checks to run
// ---------------------------------------------------------------------------

struct ValidationFlags {
    bool check_header = true;
    bool check_transactions = true;
    bool check_merkle = true;
    bool check_signatures = true;
    bool check_eval = true;
    bool check_difficulty = true;
    bool check_timestamp = true;

    /// Default: all checks enabled
    static ValidationFlags all() { return ValidationFlags{}; }

    /// Minimal checks (for IBD headers-first)
    static ValidationFlags header_only() {
        ValidationFlags f{};
        f.check_transactions = false;
        f.check_merkle = false;
        f.check_eval = false;
        return f;
    }

    /// Skip expensive checks (for assume-valid)
    static ValidationFlags assume_valid() {
        ValidationFlags f{};
        f.check_eval = false;
        f.check_signatures = false;
        return f;
    }
};

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_VALIDATION_H

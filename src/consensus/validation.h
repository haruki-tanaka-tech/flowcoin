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

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_VALIDATION_H

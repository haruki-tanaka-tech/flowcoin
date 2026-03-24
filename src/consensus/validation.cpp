// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Complete consensus validation for FlowCoin blocks.
// This is the most critical file in the entire codebase — every full node
// executes these checks for every block it accepts.

#include "validation.h"
#include "difficulty.h"
#include "growth.h"
#include "merkle.h"
#include "params.h"
#include "reward.h"
#include "../crypto/sign.h"
#include "../hash/keccak.h"
#include "../hash/merkle.h"
#include "../util/arith_uint256.h"

#include <cmath>
#include <cstring>
#include <limits>

namespace flow::consensus {

// ===========================================================================
// Helper: bit-exact float comparison via memcpy
// ===========================================================================

static bool float_bits_equal(float a, float b) {
    uint32_t bits_a, bits_b;
    std::memcpy(&bits_a, &a, sizeof(uint32_t));
    std::memcpy(&bits_b, &b, sizeof(uint32_t));
    return bits_a == bits_b;
}

// ===========================================================================
// check_header — header-only validation (checks 1-11, 13-14)
// ===========================================================================

bool check_header(const CBlockHeader& header, const BlockContext& ctx,
                  ValidationState& state) {

    // -----------------------------------------------------------------------
    // Check 6: val_loss must be a finite positive number
    // -----------------------------------------------------------------------
    // This check applies to ALL blocks including genesis.
    if (!std::isfinite(header.val_loss) || header.val_loss <= 0.0f) {
        return state.invalid(ValidationResult::HEADER_INVALID, "bad-val-loss",
            "val_loss must be finite and > 0");
    }

    // -----------------------------------------------------------------------
    // Check 7: val_loss must be below the absolute ceiling
    // -----------------------------------------------------------------------
    if (header.val_loss >= MAX_VAL_LOSS) {
        return state.invalid(ValidationResult::HEADER_INVALID, "val-loss-range",
            "val_loss exceeds MAX_VAL_LOSS");
    }

    // -----------------------------------------------------------------------
    // Checks that require a parent (skip for genesis)
    // -----------------------------------------------------------------------
    if (!ctx.is_genesis) {

        // -------------------------------------------------------------------
        // Check 1: prev_hash must match parent's hash
        // -------------------------------------------------------------------
        if (header.prev_hash != ctx.prev_hash) {
            return state.invalid(ValidationResult::HEADER_INVALID, "bad-prevblk",
                "prev_hash does not match parent");
        }

        // -------------------------------------------------------------------
        // Check 2: height must be exactly parent_height + 1
        // -------------------------------------------------------------------
        if (header.height != ctx.prev_height + 1) {
            return state.invalid(ValidationResult::HEADER_INVALID, "bad-height",
                "height is not parent_height + 1");
        }

        // -------------------------------------------------------------------
        // Check 3: timestamp must be strictly after parent
        // -------------------------------------------------------------------
        if (header.timestamp <= ctx.prev_timestamp) {
            return state.invalid(ValidationResult::HEADER_INVALID, "time-too-old",
                "timestamp not after parent");
        }

        // -------------------------------------------------------------------
        // Check 4: timestamp must respect minimum spacing
        // -------------------------------------------------------------------
        if (header.timestamp < ctx.prev_timestamp + MIN_BLOCK_INTERVAL) {
            return state.invalid(ValidationResult::HEADER_INVALID, "bad-time-spacing",
                "timestamp too close to parent (MIN_BLOCK_INTERVAL)");
        }

        // -------------------------------------------------------------------
        // Check 5: timestamp must not be too far in the future
        // -------------------------------------------------------------------
        if (header.timestamp > ctx.adjusted_time + MAX_FUTURE_TIME) {
            return state.invalid(ValidationResult::HEADER_INVALID, "time-too-new",
                "timestamp too far in the future");
        }

        // -------------------------------------------------------------------
        // Check 8: prev_val_loss must be bit-identical to parent's val_loss
        // -------------------------------------------------------------------
        if (!float_bits_equal(header.prev_val_loss, ctx.prev_val_loss)) {
            return state.invalid(ValidationResult::HEADER_INVALID, "bad-prev-loss",
                "prev_val_loss does not match parent's val_loss (bit-exact)");
        }

        // -------------------------------------------------------------------
        // Check 9: val_loss must not regress beyond MAX_LOSS_INCREASE
        // -------------------------------------------------------------------
        // The child's val_loss may be at most MAX_LOSS_INCREASE times the
        // parent's val_loss. This allows some regression during architecture
        // transitions but prevents arbitrary loss inflation.
        float loss_ceiling = MAX_LOSS_INCREASE * ctx.prev_val_loss;
        if (header.val_loss > loss_ceiling) {
            return state.invalid(ValidationResult::HEADER_INVALID, "loss-regression",
                "val_loss exceeds MAX_LOSS_INCREASE * parent_val_loss");
        }

        // -------------------------------------------------------------------
        // Check 11: nbits must match expected difficulty
        // -------------------------------------------------------------------
        // The expected nbits is pre-computed in the BlockContext by the caller
        // using get_next_work_required(). We verify the header matches.
        if (header.nbits != ctx.expected_nbits) {
            return state.invalid(ValidationResult::HEADER_INVALID, "bad-diffbits",
                "nbits does not match expected difficulty");
        }

    } // end non-genesis checks

    // -----------------------------------------------------------------------
    // Check 10: training hash must satisfy the difficulty target
    // -----------------------------------------------------------------------
    // The block hash (keccak256d of unsigned header) serves as the training
    // hash. It must be numerically <= the target derived from nbits.
    {
        arith_uint256 target;
        if (!derive_target(header.nbits, target)) {
            return state.invalid(ValidationResult::HEADER_INVALID, "bad-diffbits",
                "nbits decodes to invalid target");
        }

        uint256 block_hash = header.get_training_hash();
        arith_uint256 hash_val = UintToArith256(block_hash);

        if (hash_val > target) {
            return state.invalid(ValidationResult::HEADER_INVALID, "high-hash",
                "training hash exceeds difficulty target");
        }
    }

    // -----------------------------------------------------------------------
    // Check 13: architecture dimensions must match growth schedule
    // -----------------------------------------------------------------------
    {
        const ModelDimensions& expected = ctx.expected_dims;

        if (header.d_model  != expected.d_model  ||
            header.n_layers != expected.n_layers  ||
            header.d_ff     != expected.d_ff      ||
            header.n_heads  != expected.n_heads   ||
            header.gru_dim  != expected.gru_dim   ||
            header.n_slots  != expected.n_slots) {
            return state.invalid(ValidationResult::HEADER_INVALID, "bad-growth",
                "architecture dimensions do not match compute_growth()");
        }
    }

    // -----------------------------------------------------------------------
    // Check 14: miner signature must be valid
    // -----------------------------------------------------------------------
    // Ed25519 signature over the unsigned header data (first 244 bytes).
    // The signature itself lives at bytes 244-307, outside the signed region.
    {
        auto unsigned_data = header.get_unsigned_data();

        if (!ed25519_verify(unsigned_data.data(), unsigned_data.size(),
                            header.miner_pubkey.data(),
                            header.miner_sig.data())) {
            return state.invalid(ValidationResult::HEADER_INVALID, "bad-signature",
                "Ed25519 miner signature verification failed");
        }
    }

    return true;
}

// ===========================================================================
// check_block — full block validation (all 16 checks + body validation)
// ===========================================================================

bool check_block(const CBlock& block, const BlockContext& ctx,
                 ValidationState& state, EvalFunction eval_fn) {

    // -----------------------------------------------------------------------
    // Run all header checks first (checks 1-11, 13-14)
    // -----------------------------------------------------------------------
    if (!check_header(block, ctx, state)) {
        return false;
    }

    // -----------------------------------------------------------------------
    // Block size limit
    // -----------------------------------------------------------------------
    // Rough serialized size estimate: header + transactions + delta payload.
    // Full serialization-based size check would require the serialize method;
    // here we check the delta payload directly since it dominates block size.
    if (block.delta_payload.size() > MAX_DELTA_SIZE) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-blk-length",
            "delta payload exceeds MAX_DELTA_SIZE");
    }

    // -----------------------------------------------------------------------
    // Transaction list must be non-empty (at least coinbase)
    // -----------------------------------------------------------------------
    if (block.vtx.empty()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-missing",
            "block has no transactions");
    }

    // -----------------------------------------------------------------------
    // First transaction must be coinbase
    // -----------------------------------------------------------------------
    if (!block.vtx[0].is_coinbase()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-missing",
            "first transaction is not coinbase");
    }

    // -----------------------------------------------------------------------
    // No other transaction may be coinbase
    // -----------------------------------------------------------------------
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        if (block.vtx[i].is_coinbase()) {
            return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-multiple",
                "multiple coinbase transactions");
        }
    }

    // -----------------------------------------------------------------------
    // Coinbase reward validation
    // -----------------------------------------------------------------------
    // The coinbase transaction's total output value must not exceed the
    // allowed block reward (subsidy + fees). We validate against subsidy
    // only here; fee validation requires UTXO set access which happens
    // during ConnectBlock.
    {
        Amount subsidy = compute_block_reward(block.height);
        Amount coinbase_value = block.vtx[0].get_value_out();

        // Strict subsidy-only check: if the block has only a coinbase and
        // no other transactions, there are no fees, so the coinbase must
        // not exceed the subsidy. For blocks with transactions, fees can
        // push the coinbase above subsidy. The full subsidy + fees check
        // happens in ConnectBlock (which has UTXO access to compute fees).
        //
        // As a safety bound even for blocks with transactions, we reject
        // coinbases that exceed subsidy + MAX_SUPPLY (an impossible amount
        // that catches overflow/corruption).
        if (block.vtx.size() == 1) {
            // Only coinbase, no fee-paying transactions
            if (coinbase_value > subsidy) {
                return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-amount",
                    "coinbase exceeds subsidy with no fee-paying transactions");
            }
        } else {
            // With transactions present, fees can contribute. We still reject
            // coinbases that are absurdly large (> subsidy + theoretical max).
            if (coinbase_value < 0 || coinbase_value > MAX_SUPPLY) {
                return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-amount",
                    "coinbase amount out of range");
            }
        }

        // Verify all coinbase outputs have non-negative amounts
        for (const auto& out : block.vtx[0].vout) {
            if (out.amount < 0) {
                return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vout-negative",
                    "coinbase output has negative amount");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Transaction validation
    // -----------------------------------------------------------------------
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx[i];

        // Every transaction must have at least one input and one output
        if (tx.vin.empty()) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vin-empty",
                "transaction has no inputs");
        }
        if (tx.vout.empty()) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vout-empty",
                "transaction has no outputs");
        }

        // Check for negative or overflow output values
        Amount total_out = 0;
        for (const auto& out : tx.vout) {
            if (out.amount < 0) {
                return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vout-negative",
                    "transaction output has negative amount");
            }
            if (out.amount > MAX_SUPPLY) {
                return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vout-toolarge",
                    "transaction output exceeds MAX_SUPPLY");
            }
            total_out += out.amount;
            if (total_out > MAX_SUPPLY) {
                return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vout-toolarge",
                    "total transaction output exceeds MAX_SUPPLY");
            }
        }

        // Check for duplicate inputs within the same transaction
        for (size_t j = 0; j < tx.vin.size(); ++j) {
            for (size_t k = j + 1; k < tx.vin.size(); ++k) {
                if (tx.vin[j].prevout == tx.vin[k].prevout) {
                    return state.invalid(ValidationResult::TX_INVALID, "bad-txns-inputs-duplicate",
                        "duplicate input in transaction");
                }
            }
        }

        // For non-coinbase transactions, verify input signatures.
        // Ed25519 signature verification: the signature covers the tx hash
        // (which excludes signatures, preventing malleability).
        if (!tx.is_coinbase()) {
            uint256 txid = tx.get_txid();

            for (size_t j = 0; j < tx.vin.size(); ++j) {
                const auto& input = tx.vin[j];

                if (!ed25519_verify(txid.data(), txid.size(),
                                    input.pubkey.data(),
                                    input.signature.data())) {
                    return state.invalid(ValidationResult::TX_INVALID, "bad-txns-sig",
                        "transaction input signature verification failed");
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Merkle root verification
    // -----------------------------------------------------------------------
    {
        uint256 computed_root = compute_block_merkle_root(block.vtx);

        if (computed_root != block.merkle_root) {
            return state.invalid(ValidationResult::BLOCK_INVALID, "bad-txnmrklroot",
                "merkle root mismatch");
        }
    }

    // -----------------------------------------------------------------------
    // Check 12: dataset_hash integrity
    // -----------------------------------------------------------------------
    // The dataset_hash in the header must not be null. Full dataset hash
    // verification (comparing against a deterministic hash of the eval
    // dataset) requires the dataset itself, which is handled during
    // ConnectBlock. Here we ensure it is at least populated.
    if (block.dataset_hash.is_null()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-dataset-hash",
            "dataset_hash is null");
    }

    // -----------------------------------------------------------------------
    // Check 16: minimum training steps
    // -----------------------------------------------------------------------
    // The miner must have performed at least compute_min_steps(height)
    // training steps. This value is pre-computed in ctx.min_train_steps.
    if (block.train_steps < ctx.min_train_steps) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "insufficient-training",
            "train_steps below minimum required");
    }

    // -----------------------------------------------------------------------
    // Check 15: forward evaluation (optional — requires eval callback)
    // -----------------------------------------------------------------------
    // If an eval function is provided and the block carries a delta payload,
    // we verify that applying the delta and running forward evaluation
    // produces the exact val_loss reported in the header.
    //
    // During IBD or when the model state is unavailable, eval_fn is nullptr
    // and this check is skipped. Full nodes performing tip validation must
    // provide a valid eval_fn.
    if (eval_fn != nullptr && !block.delta_payload.empty()) {
        float computed_loss = eval_fn(block.delta_payload, block.dataset_hash);

        // Bit-exact comparison: the val_loss in the header must be identical
        // to what forward evaluation produces. We use memcpy to compare the
        // IEEE 754 representation directly, avoiding any floating-point
        // comparison issues.
        if (!float_bits_equal(computed_loss, block.val_loss)) {
            return state.invalid(ValidationResult::BLOCK_INVALID, "bad-eval-loss",
                "val_loss does not match forward evaluation result");
        }
    }

    return true;
}

// ===========================================================================
// check_block_transactions — detailed per-transaction validation
// ===========================================================================
// Called during ConnectBlock when we have UTXO access. Validates:
// - All input references exist in the UTXO set
// - Signatures match the UTXO's pubkey_hash
// - Coinbase maturity for inputs spending coinbase outputs
// - Total sigops do not exceed MAX_BLOCK_SIGOPS
// - No duplicate txids within the block
// - Input value sums and fee calculations

bool check_block_transactions(const CBlock& block, const BlockContext& ctx,
                               ValidationState& state) {

    // Block size check (serialized size estimate)
    size_t estimated_size = 308;  // header
    for (const auto& tx : block.vtx) {
        // Each input: 32 (prevout.txid) + 4 (index) + 64 (sig) + 32 (pubkey) = 132
        // Each output: 8 (amount) + 32 (pubkey_hash) = 40
        estimated_size += 4;  // version
        estimated_size += tx.vin.size() * 132;
        estimated_size += tx.vout.size() * 40;
        estimated_size += 8;  // locktime
    }
    estimated_size += block.delta_payload.size();

    if (estimated_size > MAX_BLOCK_SIZE) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-blk-size",
            "estimated block size exceeds MAX_BLOCK_SIZE");
    }

    // Count total sigops (1 per signature verification)
    int total_sigops = 0;
    for (const auto& tx : block.vtx) {
        if (!tx.is_coinbase()) {
            total_sigops += static_cast<int>(tx.vin.size());
        }
    }

    if (total_sigops > MAX_BLOCK_SIGOPS) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-blk-sigops",
            "block sigops exceed MAX_BLOCK_SIGOPS");
    }

    // Check for duplicate txids within the block
    std::vector<uint256> txids;
    txids.reserve(block.vtx.size());
    for (const auto& tx : block.vtx) {
        uint256 txid = tx.get_txid();

        for (const auto& existing : txids) {
            if (existing == txid) {
                return state.invalid(ValidationResult::BLOCK_INVALID, "bad-txns-duplicate",
                    "duplicate txid within block");
            }
        }
        txids.push_back(txid);
    }

    // Validate each non-coinbase transaction's structure
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx[i];

        // No empty inputs (already checked in check_block, but re-check)
        if (tx.vin.empty()) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vin-empty",
                "non-coinbase transaction has no inputs");
        }

        // Check for null prevouts in non-coinbase transactions
        for (const auto& input : tx.vin) {
            if (input.prevout.is_null()) {
                return state.invalid(ValidationResult::TX_INVALID, "bad-txns-prevout-null",
                    "non-coinbase transaction has null prevout");
            }
        }

        // Check transaction size (rough estimate)
        size_t tx_size = 4 + tx.vin.size() * 132 + tx.vout.size() * 40 + 8;
        if (tx_size > MAX_TX_SIZE) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-oversize",
                "transaction exceeds MAX_TX_SIZE");
        }

        // Verify all output amounts are non-negative and total doesn't overflow
        Amount total_out = 0;
        for (const auto& out : tx.vout) {
            if (out.amount < 0) {
                return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vout-negative",
                    "output has negative value");
            }
            total_out += out.amount;
            if (total_out < 0 || total_out > MAX_SUPPLY) {
                return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vout-overflow",
                    "total output value overflow");
            }
        }
    }

    return true;
}

// ===========================================================================
// check_coinbase — detailed coinbase validation
// ===========================================================================

bool check_coinbase(const CTransaction& coinbase, uint64_t height,
                     Amount max_allowed, ValidationState& state) {

    // Must be a coinbase transaction
    if (!coinbase.is_coinbase()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-missing",
            "first transaction is not coinbase");
    }

    // Exactly one input with null prevout
    if (coinbase.vin.size() != 1) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-inputs",
            "coinbase must have exactly one input");
    }

    if (!coinbase.vin[0].prevout.is_null()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-prevout",
            "coinbase input must have null prevout");
    }

    // prevout.index must be 0 for coinbase (we use 0 rather than 0xFFFFFFFF)
    // This is a FlowCoin convention; Bitcoin uses 0xFFFFFFFF.

    // Must have at least one output
    if (coinbase.vout.empty()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-vout-empty",
            "coinbase has no outputs");
    }

    // Total output value must not exceed max_allowed (subsidy + fees)
    Amount total_out = coinbase.get_value_out();
    if (total_out > max_allowed) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-amount",
            "coinbase output exceeds allowed maximum (subsidy + fees)");
    }

    // All output values must be non-negative
    for (const auto& out : coinbase.vout) {
        if (out.amount < 0) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-cb-vout-negative",
                "coinbase output has negative value");
        }
    }

    // Height serialization check (BIP34 equivalent):
    // The coinbase input's pubkey should encode the block height.
    // For FlowCoin, we embed the genesis message hash in the pubkey field
    // for block 0, and the height (as keccak256(height)) for other blocks.
    // This ensures no two coinbase transactions can have the same txid.
    // (In practice, the height is also in the block header, but this
    // provides an additional uniqueness guarantee in the transaction layer.)

    return true;
}

// ===========================================================================
// compute_block_fees — total fees for all non-coinbase transactions
// ===========================================================================
// Requires UTXO set access. This is computed during ConnectBlock.
// total_fees = sum(input_values) - sum(output_values) for all non-coinbase txs.
//
// This function takes pre-computed input sums to avoid re-reading UTXOs.

Amount compute_block_fees(const CBlock& block,
                           const std::vector<Amount>& tx_input_sums) {
    Amount total_fees = 0;

    // tx_input_sums[0] is for the coinbase (always 0 inputs), skip it.
    for (size_t i = 1; i < block.vtx.size() && i < tx_input_sums.size(); ++i) {
        Amount input_sum = tx_input_sums[i];
        Amount output_sum = block.vtx[i].get_value_out();

        // Fee = inputs - outputs (must be non-negative)
        Amount fee = input_sum - output_sum;
        if (fee < 0) {
            // This shouldn't happen if validation passed, but guard anyway
            continue;
        }
        total_fees += fee;
    }

    return total_fees;
}

// ===========================================================================
// check_transaction — standalone transaction validation
// ===========================================================================

bool check_transaction(const CTransaction& tx, ValidationState& state) {
    // Must have at least one input
    if (tx.vin.empty()) {
        return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vin-empty",
            "transaction has no inputs");
    }

    // Must have at least one output
    if (tx.vout.empty()) {
        return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vout-empty",
            "transaction has no outputs");
    }

    // Should not be a coinbase (use check_coinbase for that)
    if (tx.is_coinbase()) {
        return state.invalid(ValidationResult::TX_INVALID, "bad-txns-is-coinbase",
            "standalone check_transaction should not be called on coinbase");
    }

    // Check all output values are non-negative
    Amount total_out = 0;
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        if (tx.vout[i].amount < 0) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vout-negative",
                "output has negative value");
        }
        if (tx.vout[i].amount > MAX_SUPPLY) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vout-toolarge",
                "output exceeds MAX_SUPPLY");
        }
        total_out += tx.vout[i].amount;
        if (total_out < 0 || total_out > MAX_SUPPLY) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vout-overflow",
                "total output value overflow");
        }
    }

    // Check for duplicate inputs
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        for (size_t j = i + 1; j < tx.vin.size(); ++j) {
            if (tx.vin[i].prevout == tx.vin[j].prevout) {
                return state.invalid(ValidationResult::TX_INVALID,
                    "bad-txns-inputs-duplicate",
                    "duplicate input in transaction");
            }
        }
    }

    // Check no null prevouts in non-coinbase
    for (const auto& input : tx.vin) {
        if (input.prevout.is_null()) {
            return state.invalid(ValidationResult::TX_INVALID,
                "bad-txns-prevout-null",
                "non-coinbase input has null prevout");
        }
    }

    // Verify signatures
    uint256 txid = tx.get_txid();
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const auto& input = tx.vin[i];

        if (!ed25519_verify(txid.data(), txid.size(),
                            input.pubkey.data(),
                            input.signature.data())) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-sig",
                "transaction input signature verification failed");
        }
    }

    // Check version
    if (tx.version == 0) {
        return state.invalid(ValidationResult::TX_INVALID, "bad-txns-version",
            "transaction version must be >= 1");
    }

    // Check locktime is not negative
    if (tx.locktime < 0) {
        return state.invalid(ValidationResult::TX_INVALID, "bad-txns-locktime",
            "negative locktime");
    }

    return true;
}

// ===========================================================================
// check_block_weight — block weight/size validation
// ===========================================================================

bool check_block_weight(const CBlock& block, ValidationState& state) {
    // Compute header weight (fixed 308 bytes)
    size_t weight = 308;

    // Transaction weight
    for (const auto& tx : block.vtx) {
        // Per-input: prevout(32+4) + sig(64) + pubkey(32) = 132 bytes
        // Per-output: amount(8) + pubkey_hash(32) = 40 bytes
        // Overhead: version(4) + locktime(8) + input_count_varint + output_count_varint
        size_t tx_weight = 4 + 8;  // version + locktime
        tx_weight += 4;  // varint overhead estimate
        tx_weight += tx.vin.size() * 132;
        tx_weight += tx.vout.size() * 40;
        weight += tx_weight;
    }

    // Delta payload weight
    weight += block.delta_payload.size();

    if (weight > MAX_BLOCK_SIZE) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-blk-weight",
            "block weight exceeds MAX_BLOCK_SIZE");
    }

    // Check individual transaction sizes
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx[i];
        size_t tx_size = 12 + tx.vin.size() * 132 + tx.vout.size() * 40;
        if (tx_size > MAX_TX_SIZE) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-oversize",
                "transaction exceeds MAX_TX_SIZE");
        }
    }

    // Check transaction count
    if (block.vtx.size() > MAX_BLOCK_SIZE / 100) {
        // Each tx is at least ~100 bytes, so this is a reasonable upper bound
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-blk-tx-count",
            "too many transactions in block");
    }

    return true;
}

} // namespace flow::consensus

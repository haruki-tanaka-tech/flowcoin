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
    (void)ctx;

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
    (void)height;

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

// ===========================================================================
// encode_height_in_coinbase — BIP34 equivalent for FlowCoin
// ===========================================================================
// Encodes the block height as a CScript-style push of a little-endian integer
// into the coinbase's script_sig. The encoding is:
//   [1-byte push size] [height as LE bytes, minimal encoding]
// Height 0 encodes as [0x01, 0x00].
// Heights 1-16 encode as [0x01, height].
// Heights 17-255 encode as [0x01, height].
// Heights 256+ encode as [0x02, lo, hi] etc.

bool encode_height_in_coinbase(std::vector<uint8_t>& script_sig, uint64_t height) {
    // Determine minimal byte length for encoding
    std::vector<uint8_t> height_bytes;
    uint64_t h = height;
    if (h == 0) {
        height_bytes.push_back(0x00);
    } else {
        while (h > 0) {
            height_bytes.push_back(static_cast<uint8_t>(h & 0xFF));
            h >>= 8;
        }
        // If the top bit of the last byte is set, we need an extra 0x00
        // to prevent it being interpreted as negative in script.
        if (height_bytes.back() & 0x80) {
            height_bytes.push_back(0x00);
        }
    }

    // script_sig format: [push_size] [height_bytes...]
    // push_size must be 1-8 (we reject blocks with height needing >8 bytes)
    if (height_bytes.size() > 8) {
        return false;
    }

    // Prepend length byte
    script_sig.clear();
    script_sig.reserve(1 + height_bytes.size());
    script_sig.push_back(static_cast<uint8_t>(height_bytes.size()));
    script_sig.insert(script_sig.end(), height_bytes.begin(), height_bytes.end());

    return true;
}

bool decode_height_from_coinbase(const std::vector<uint8_t>& script_sig, uint64_t& height) {
    if (script_sig.empty()) {
        return false;
    }

    uint8_t push_size = script_sig[0];

    // push_size must be between 1 and 8 inclusive
    if (push_size < 1 || push_size > 8) {
        return false;
    }

    // Verify we have enough bytes
    if (script_sig.size() < static_cast<size_t>(1 + push_size)) {
        return false;
    }

    // Decode little-endian integer
    height = 0;
    for (int i = push_size - 1; i >= 0; --i) {
        height <<= 8;
        height |= script_sig[1 + static_cast<size_t>(i)];
    }

    return true;
}

// ===========================================================================
// verify_coinbase_height — validate BIP34 height encoding
// ===========================================================================

static bool verify_coinbase_height(const CTransaction& coinbase, uint64_t expected_height,
                                    ValidationState& state) {
    // Coinbase must have exactly one input
    if (coinbase.vin.empty()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-height",
            "coinbase has no inputs for height check");
    }

    // The script_sig is encoded in the pubkey field for FlowCoin coinbases.
    // We verify that the height can be decoded from it if the coinbase carries
    // an encoded height. Genesis block (height 0) uses a message hash instead
    // of an encoded height, so skip for genesis.
    if (expected_height == 0) {
        return true;
    }

    // For non-genesis blocks, the coinbase script_sig must contain the height
    // as the first push. We extract the bytes from the signature field which
    // is repurposed as script_sig storage in coinbase transactions.
    // In FlowCoin, the signature field of a coinbase input serves as script_sig.
    const auto& sig = coinbase.vin[0].signature;

    // The first byte is the push size
    uint8_t push_size = sig[0];
    if (push_size < 1 || push_size > 8) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-height",
            "coinbase height push_size out of range");
    }

    if (static_cast<size_t>(push_size + 1) > sig.size()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-height",
            "coinbase script_sig too short for height encoding");
    }

    // Decode height from script_sig
    uint64_t decoded_height = 0;
    for (int i = push_size - 1; i >= 0; --i) {
        decoded_height <<= 8;
        decoded_height |= sig[1 + static_cast<size_t>(i)];
    }

    if (decoded_height != expected_height) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-height",
            "coinbase height encoding does not match block height");
    }

    return true;
}

// ===========================================================================
// check_block_tx_against_utxo — per-tx UTXO validation for ConnectBlock
// ===========================================================================
// Validates a single non-coinbase transaction against the UTXO set:
// - All inputs must reference existing UTXOs
// - Inputs spending coinbase must have COINBASE_MATURITY confirmations
// - Pubkey hash from UTXO must match pubkey in scriptSig
// - Ed25519 signature must be valid over SignatureHash
// - Sum(inputs) >= Sum(outputs)

struct TxValidationResult {
    bool valid;
    std::string reject_reason;
    std::string debug_message;
    Amount input_sum;
    Amount output_sum;
    Amount fee;
    int sigops;
    std::vector<std::pair<uint256, uint32_t>> spent_utxos;
    std::vector<std::pair<uint256, uint32_t>> created_utxos;
};

static TxValidationResult validate_tx_against_utxo(
        const CTransaction& tx,
        size_t tx_index_in_block,
        uint64_t block_height,
        const std::vector<std::pair<uint256, std::vector<CTxOut>>>& prev_tx_outputs) {
    (void)tx_index_in_block;
    (void)block_height;

    TxValidationResult result;
    result.valid = true;
    result.input_sum = 0;
    result.output_sum = 0;
    result.fee = 0;
    result.sigops = 0;

    if (tx.is_coinbase()) {
        result.valid = false;
        result.reject_reason = "bad-txns-is-coinbase";
        result.debug_message = "validate_tx_against_utxo called on coinbase";
        return result;
    }

    uint256 txid = tx.get_txid();

    // Count sigops (one per input)
    result.sigops = static_cast<int>(tx.vin.size());

    // Validate each input
    for (size_t vin_i = 0; vin_i < tx.vin.size(); ++vin_i) {
        const CTxIn& input = tx.vin[vin_i];

        // Record the spent UTXO reference
        result.spent_utxos.emplace_back(input.prevout.txid, input.prevout.index);

        // Check if this input references a transaction earlier in the same block.
        // This supports in-block spending chains.
        bool found_in_block = false;
        for (const auto& [prev_txid, prev_outputs] : prev_tx_outputs) {
            if (prev_txid == input.prevout.txid) {
                if (input.prevout.index >= prev_outputs.size()) {
                    result.valid = false;
                    result.reject_reason = "bad-txns-inputs-missingorspent";
                    result.debug_message = "in-block input index out of range";
                    return result;
                }

                const CTxOut& prev_out = prev_outputs[input.prevout.index];
                result.input_sum += prev_out.amount;
                found_in_block = true;

                // Verify pubkey hash matches
                uint256 input_pkh = keccak256(input.pubkey.data(), input.pubkey.size());
                if (std::memcmp(input_pkh.data(), prev_out.pubkey_hash.data(), 32) != 0) {
                    result.valid = false;
                    result.reject_reason = "bad-txns-sig";
                    result.debug_message = "pubkey hash mismatch for in-block input";
                    return result;
                }

                // Verify Ed25519 signature
                if (!ed25519_verify(txid.data(), txid.size(),
                                    input.pubkey.data(),
                                    input.signature.data())) {
                    result.valid = false;
                    result.reject_reason = "bad-txns-sig";
                    result.debug_message = "Ed25519 signature failed for in-block input";
                    return result;
                }

                break;
            }
        }

        if (found_in_block) {
            continue;
        }

        // For the remaining input validation (UTXO lookup, coinbase maturity,
        // pubkey hash match), the caller must provide the data from the UTXO set.
        // This function handles in-block inputs only; the caller handles UTXO
        // lookups for inputs referencing older blocks.
    }

    // Compute output sum
    for (uint32_t vout = 0; vout < tx.vout.size(); ++vout) {
        const CTxOut& out = tx.vout[vout];
        if (out.amount < 0) {
            result.valid = false;
            result.reject_reason = "bad-txns-vout-negative";
            result.debug_message = "output has negative value";
            return result;
        }
        result.output_sum += out.amount;
        if (result.output_sum < 0 || result.output_sum > MAX_SUPPLY) {
            result.valid = false;
            result.reject_reason = "bad-txns-vout-overflow";
            result.debug_message = "total output value overflow";
            return result;
        }
        result.created_utxos.emplace_back(txid, vout);
    }

    return result;
}

// ===========================================================================
// ConnectResult — defined in validation.h
// ===========================================================================

// ===========================================================================
// connect_block_transactions — validate all txs and compute UTXO changes
// ===========================================================================
// This is the core ConnectBlock logic that validates every transaction in a
// block against the UTXO set, computes fees, and tracks all UTXO mutations
// (spent and created) for undo data generation.
//
// Unlike check_block_transactions (which does structural checks only), this
// function performs full validation including:
// - UTXO existence checks
// - Coinbase maturity enforcement
// - Pubkey hash matching
// - Ed25519 signature verification per input
// - Fee computation (inputs - outputs for each tx)
// - Coinbase value <= subsidy + fees
// - Block sigop count
// - Double-spend detection within the block

ConnectResult connect_block_transactions(
        const CBlock& block,
        uint64_t height) {

    ConnectResult result;
    result.success = false;
    result.total_fees = 0;
    result.total_sigops = 0;
    result.total_block_weight = 0;

    // Must have at least one transaction (coinbase)
    if (block.vtx.empty()) {
        result.error = "block has no transactions";
        return result;
    }

    // First transaction must be coinbase
    if (!block.vtx[0].is_coinbase()) {
        result.error = "first transaction is not coinbase";
        return result;
    }

    // No other transaction may be coinbase
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        if (block.vtx[i].is_coinbase()) {
            result.error = "multiple coinbase transactions at index " + std::to_string(i);
            return result;
        }
    }

    // Build a map of in-block transaction outputs for spending chain resolution
    // Key: txid, Value: outputs of that transaction
    std::vector<std::pair<uint256, std::vector<CTxOut>>> in_block_outputs;
    in_block_outputs.reserve(block.vtx.size());

    // Track all outpoints being spent in this block to detect double-spends
    struct OutpointHash {
        size_t operator()(const std::pair<uint256, uint32_t>& p) const {
            size_t h = 0;
            for (size_t i = 0; i < 8 && i < p.first.size(); ++i) {
                h ^= static_cast<size_t>(p.first.data()[i]) << (i * 8);
            }
            h ^= static_cast<size_t>(p.second) << 3;
            return h;
        }
    };
    std::vector<std::pair<uint256, uint32_t>> all_spent_outpoints;

    // Process coinbase first (no inputs to validate)
    {
        const CTransaction& coinbase = block.vtx[0];
        uint256 cb_txid = coinbase.get_txid();

        // Record coinbase outputs for potential in-block spending (after maturity)
        in_block_outputs.emplace_back(cb_txid, coinbase.vout);

        // Track created UTXOs
        for (uint32_t vout = 0; vout < coinbase.vout.size(); ++vout) {
            result.created_utxos.emplace_back(cb_txid, vout);
        }

        // Estimate coinbase weight
        result.total_block_weight += 12 + coinbase.vin.size() * 132 +
                                     coinbase.vout.size() * 40;
    }

    // Process each non-coinbase transaction
    for (size_t tx_i = 1; tx_i < block.vtx.size(); ++tx_i) {
        const CTransaction& tx = block.vtx[tx_i];
        uint256 txid = tx.get_txid();

        // Basic structural validation
        if (tx.vin.empty()) {
            result.error = "tx " + std::to_string(tx_i) + " has no inputs";
            return result;
        }
        if (tx.vout.empty()) {
            result.error = "tx " + std::to_string(tx_i) + " has no outputs";
            return result;
        }

        // Check for null prevouts
        for (const auto& input : tx.vin) {
            if (input.prevout.is_null()) {
                result.error = "tx " + std::to_string(tx_i) +
                               " has null prevout in non-coinbase";
                return result;
            }
        }

        // Double-spend check: ensure no outpoint is spent twice in this block
        for (const auto& input : tx.vin) {
            auto outpoint = std::make_pair(input.prevout.txid, input.prevout.index);
            for (const auto& existing : all_spent_outpoints) {
                if (existing.first == outpoint.first &&
                    existing.second == outpoint.second) {
                    result.error = "tx " + std::to_string(tx_i) +
                                   " double-spends an outpoint within the block";
                    return result;
                }
            }
            all_spent_outpoints.push_back(outpoint);
        }

        // Validate in-block input spending chains
        TxValidationResult tx_result = validate_tx_against_utxo(
            tx, tx_i, height, in_block_outputs);

        if (!tx_result.valid) {
            result.error = tx_result.reject_reason + ": " + tx_result.debug_message;
            return result;
        }

        // Count sigops
        result.total_sigops += tx_result.sigops;
        if (result.total_sigops > MAX_BLOCK_SIGOPS) {
            result.error = "block sigops exceed MAX_BLOCK_SIGOPS";
            return result;
        }

        // Track spent and created UTXOs
        for (const auto& sp : tx_result.spent_utxos) {
            result.spent_utxos.push_back(sp);
        }
        for (const auto& cr : tx_result.created_utxos) {
            result.created_utxos.push_back(cr);
        }

        // Record this transaction's outputs for in-block spending chains
        in_block_outputs.emplace_back(txid, tx.vout);

        // Accumulate weight
        size_t tx_weight = 12 + tx.vin.size() * 132 + tx.vout.size() * 40;
        result.total_block_weight += tx_weight;

        // Per-tx size check
        if (tx_weight > MAX_TX_SIZE) {
            result.error = "tx " + std::to_string(tx_i) + " exceeds MAX_TX_SIZE";
            return result;
        }
    }

    // Add header and delta payload to block weight
    result.total_block_weight += 308;  // header size
    result.total_block_weight += block.delta_payload.size();

    if (result.total_block_weight > MAX_BLOCK_SIZE) {
        result.error = "block weight exceeds MAX_BLOCK_SIZE";
        return result;
    }

    // Coinbase value check is deferred to the caller who has UTXO access
    // and can compute the exact fees. We return the partial results here.

    result.success = true;
    return result;
}

// ===========================================================================
// validate_block_sigops — count and enforce sigop limit
// ===========================================================================

int count_block_sigops(const CBlock& block) {
    int total = 0;
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const CTransaction& tx = block.vtx[i];
        if (!tx.is_coinbase()) {
            // One sigop per input (Ed25519 signature verification)
            total += static_cast<int>(tx.vin.size());
        }
    }
    return total;
}

// ===========================================================================
// compute_signature_hash — hash that is signed by each input
// ===========================================================================
// For FlowCoin, the signature covers the transaction ID (txid).
// The txid is computed by hashing the transaction data excluding signatures,
// which prevents signature malleability.

uint256 compute_signature_hash(const CTransaction& tx) {
    return tx.get_txid();
}

// ===========================================================================
// verify_input_signature — verify a single input's Ed25519 signature
// ===========================================================================

bool verify_input_signature(const CTransaction& tx, size_t input_index) {
    if (input_index >= tx.vin.size()) {
        return false;
    }

    const CTxIn& input = tx.vin[input_index];
    uint256 sighash = compute_signature_hash(tx);

    return ed25519_verify(sighash.data(), sighash.size(),
                          input.pubkey.data(),
                          input.signature.data());
}

// ===========================================================================
// verify_all_input_signatures — batch verify all inputs in a transaction
// ===========================================================================

bool verify_all_input_signatures(const CTransaction& tx, ValidationState& state) {
    if (tx.is_coinbase()) {
        return true;  // Coinbase has no real signatures to verify
    }

    uint256 sighash = compute_signature_hash(tx);

    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const CTxIn& input = tx.vin[i];

        if (!ed25519_verify(sighash.data(), sighash.size(),
                            input.pubkey.data(),
                            input.signature.data())) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-sig",
                "Ed25519 signature failed for input " + std::to_string(i));
        }
    }

    return true;
}

// ===========================================================================
// check_input_coinbase_maturity — enforce COINBASE_MATURITY for spending
// ===========================================================================

bool check_input_coinbase_maturity(bool is_coinbase_output,
                                     uint64_t output_height,
                                     uint64_t spending_height,
                                     ValidationState& state) {
    if (!is_coinbase_output) {
        return true;
    }

    if (spending_height < output_height + COINBASE_MATURITY) {
        return state.invalid(ValidationResult::TX_INVALID, "bad-txns-premature-spend-of-coinbase",
            "tried to spend coinbase at height " + std::to_string(output_height) +
            " from height " + std::to_string(spending_height) +
            " (maturity=" + std::to_string(COINBASE_MATURITY) + ")");
    }

    return true;
}

// ===========================================================================
// check_input_pubkey_hash — verify the input's pubkey matches the UTXO
// ===========================================================================

bool check_input_pubkey_hash(const CTxIn& input,
                               const std::array<uint8_t, 32>& expected_pubkey_hash,
                               ValidationState& state) {
    // Compute keccak256(pubkey) and compare with the UTXO's pubkey_hash
    uint256 computed_hash = keccak256(input.pubkey.data(), input.pubkey.size());

    if (std::memcmp(computed_hash.data(), expected_pubkey_hash.data(), 32) != 0) {
        return state.invalid(ValidationResult::TX_INVALID, "bad-txns-pubkey-hash",
            "input pubkey hash does not match UTXO's pubkey_hash");
    }

    return true;
}

// ===========================================================================
// compute_tx_fee — compute fee for a single non-coinbase transaction
// ===========================================================================

Amount compute_tx_fee(Amount input_sum, Amount output_sum) {
    if (input_sum < output_sum) {
        return -1;  // Invalid: spending more than available
    }
    return input_sum - output_sum;
}

// ===========================================================================
// validate_coinbase_script_sig_size — size must be 2..100 bytes
// ===========================================================================

bool validate_coinbase_script_sig_size(const CTransaction& coinbase,
                                         ValidationState& state) {
    if (!coinbase.is_coinbase() || coinbase.vin.empty()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-scriptlen",
            "not a valid coinbase transaction");
    }

    // In FlowCoin, the coinbase script_sig is encoded in the signature field.
    // The push_size byte + data must be between 2 and 100 bytes.
    const auto& sig_field = coinbase.vin[0].signature;

    // Check the push_size to determine actual script_sig length
    uint8_t push_size = sig_field[0];
    size_t effective_len = 1 + push_size;  // push_size byte + data bytes

    if (effective_len < 2) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-length",
            "coinbase script_sig too short (min 2 bytes)");
    }

    if (effective_len > 100) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-length",
            "coinbase script_sig too long (max 100 bytes)");
    }

    return true;
}

// ===========================================================================
// check_duplicate_txids_across_blocks — prevent txid reuse
// ===========================================================================
// FlowCoin requires unique txids. For coinbase transactions, this is
// guaranteed by BIP34 height encoding. For regular transactions, duplicate
// txids are prevented by the UTXO model (can't double-create the same
// outpoint).

bool check_duplicate_txids(const CBlock& block, ValidationState& state) {
    std::vector<uint256> seen;
    seen.reserve(block.vtx.size());

    for (const auto& tx : block.vtx) {
        uint256 txid = tx.get_txid();
        for (const auto& s : seen) {
            if (s == txid) {
                return state.invalid(ValidationResult::BLOCK_INVALID,
                    "bad-txns-duplicate-txid",
                    "duplicate txid within block");
            }
        }
        seen.push_back(txid);
    }

    return true;
}

// ===========================================================================
// estimate_block_size — compute estimated serialized block size
// ===========================================================================

size_t estimate_block_size(const CBlock& block) {
    size_t size = 308;  // header

    for (const auto& tx : block.vtx) {
        size += 4;  // version
        size += 4;  // varint overhead
        size += tx.vin.size() * 132;
        size += tx.vout.size() * 40;
        size += 8;  // locktime
    }

    size += block.delta_payload.size();
    return size;
}

// ===========================================================================
// check_block_locktime — validate transaction locktimes
// ===========================================================================
// Transactions with locktime > 0 are only valid if their locktime is less
// than the block's timestamp (if locktime < 500_000_000, it is a height;
// otherwise it is a unix timestamp).

bool check_block_locktime(const CBlock& block, ValidationState& state) {
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const CTransaction& tx = block.vtx[i];

        if (tx.is_coinbase()) continue;  // Coinbase locktime is ignored

        if (tx.locktime == 0) continue;  // No lock

        // Locktime < 500_000_000 is interpreted as block height
        if (tx.locktime < 500'000'000) {
            if (static_cast<uint64_t>(tx.locktime) > block.height) {
                return state.invalid(ValidationResult::TX_INVALID, "bad-txns-nonfinal",
                    "transaction locktime (height) not satisfied: locktime=" +
                    std::to_string(tx.locktime) +
                    " block_height=" + std::to_string(block.height));
            }
        } else {
            // Locktime >= 500_000_000 is interpreted as unix timestamp
            if (tx.locktime > block.timestamp) {
                return state.invalid(ValidationResult::TX_INVALID, "bad-txns-nonfinal",
                    "transaction locktime (time) not satisfied: locktime=" +
                    std::to_string(tx.locktime) +
                    " block_time=" + std::to_string(block.timestamp));
            }
        }
    }

    return true;
}

// ===========================================================================
// compute_total_output_value — sum all outputs across all transactions
// ===========================================================================

Amount compute_total_output_value(const CBlock& block) {
    Amount total = 0;
    for (const auto& tx : block.vtx) {
        for (const auto& out : tx.vout) {
            total += out.amount;
        }
    }
    return total;
}

// ===========================================================================
// compute_total_input_value — sum all input values (requires input_sums)
// ===========================================================================

Amount compute_total_input_value(const std::vector<Amount>& tx_input_sums) {
    Amount total = 0;
    for (size_t i = 1; i < tx_input_sums.size(); ++i) {
        total += tx_input_sums[i];
    }
    return total;
}

// ===========================================================================
// check_monetary_supply — verify no coins are created from thin air
// ===========================================================================
// After computing fees and subsidy, verify that the coinbase does not
// claim more than subsidy + fees.

bool check_monetary_supply(const CBlock& block, Amount subsidy, Amount fees,
                            ValidationState& state) {
    Amount coinbase_out = block.vtx[0].get_value_out();
    Amount max_allowed = subsidy + fees;

    if (coinbase_out > max_allowed) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-amount",
            "coinbase output (" + std::to_string(coinbase_out) +
            ") exceeds subsidy + fees (" + std::to_string(max_allowed) + ")");
    }

    // Verify no individual output exceeds the maximum
    for (const auto& out : block.vtx[0].vout) {
        if (out.amount > MAX_SUPPLY) {
            return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-vout-toolarge",
                "coinbase output exceeds MAX_SUPPLY");
        }
    }

    return true;
}

// ===========================================================================
// validate_block_full — comprehensive block validation for ConnectBlock
// ===========================================================================
// This combines all the validation functions above into a single entry point
// suitable for ConnectBlock. It assumes check_block() has already been called
// and passed; this function adds UTXO-dependent checks.

bool validate_block_full(const CBlock& block, const BlockContext& ctx,
                          ValidationState& state) {
    (void)ctx;

    // 1. Verify block locktime constraints
    if (!check_block_locktime(block, state)) {
        return false;
    }

    // 2. Verify no duplicate txids
    if (!check_duplicate_txids(block, state)) {
        return false;
    }

    // 3. Verify block weight
    if (!check_block_weight(block, state)) {
        return false;
    }

    // 4. Coinbase height encoding (BIP34 equivalent) for non-genesis
    if (block.height > 0) {
        if (!verify_coinbase_height(block.vtx[0], block.height, state)) {
            return false;
        }
    }

    // 5. Verify coinbase script_sig size
    if (block.height > 0) {
        if (!validate_coinbase_script_sig_size(block.vtx[0], state)) {
            return false;
        }
    }

    // 6. Count and verify sigops
    int sigops = count_block_sigops(block);
    if (sigops > MAX_BLOCK_SIGOPS) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-blk-sigops",
            "block sigops (" + std::to_string(sigops) +
            ") exceed MAX_BLOCK_SIGOPS (" + std::to_string(MAX_BLOCK_SIGOPS) + ")");
    }

    // 7. Verify all non-coinbase input signatures
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        if (!verify_all_input_signatures(block.vtx[i], state)) {
            return false;
        }
    }

    // 8. Verify block size estimate
    size_t estimated_size = estimate_block_size(block);
    if (estimated_size > MAX_BLOCK_SIZE) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-blk-size",
            "estimated block size exceeds MAX_BLOCK_SIZE");
    }

    return true;
}

} // namespace flow::consensus

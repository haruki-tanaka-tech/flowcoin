// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Complete consensus validation for FlowCoin blocks.
// Keccak-256d Proof-of-Work consensus.

#include "validation.h"
#include "difficulty.h"
#include "merkle.h"
#include "params.h"
#include "pow.h"
#include "reward.h"
#include "../crypto/sign.h"
#include "../hash/keccak.h"
#include "../hash/merkle.h"
#include "../util/arith_uint256.h"
#include "../util/strencodings.h"
#include "../logging.h"

#include <cmath>
#include <cstring>
#include <limits>

namespace flow::consensus {

// ===========================================================================
// check_header -- header-only validation (checks 1-8)
// ===========================================================================

bool check_header(const CBlockHeader& header, const BlockContext& ctx,
                  ValidationState& state) {

    // -----------------------------------------------------------------------
    // Checks that require a parent (skip for genesis)
    // -----------------------------------------------------------------------
    if (!ctx.is_genesis) {

        // Check 1: prev_hash must match parent's hash
        if (header.prev_hash != ctx.prev_hash) {
            return state.invalid(ValidationResult::HEADER_INVALID, "bad-prevblk",
                "prev_hash does not match parent");
        }

        // Check 2: height must be exactly parent_height + 1
        if (header.height != ctx.prev_height + 1) {
            return state.invalid(ValidationResult::HEADER_INVALID, "bad-height",
                "height is not parent_height + 1");
        }

        // Check 3: timestamp must be strictly after the Median Time Past
        // of the last 11 blocks (Bitcoin Core's rule). Comparing against
        // the immediate parent rejected siblings that landed in the same
        // wall-clock second under rapid mining; MTP still prevents
        // large-scale time reversals.
        if (header.timestamp <= ctx.median_time_past) {
            return state.invalid(ValidationResult::HEADER_INVALID, "time-too-old",
                "timestamp at or before median-time-past");
        }

        // Check 4: timestamp must not be too far in the future
        if (header.timestamp > ctx.adjusted_time + MAX_FUTURE_TIME) {
            return state.invalid(ValidationResult::HEADER_INVALID, "time-too-new",
                "timestamp too far in the future");
        }

        // Check 5: nbits must match expected difficulty
        if (header.nbits != ctx.expected_nbits) {
            return state.invalid(ValidationResult::HEADER_INVALID, "bad-diffbits",
                "nbits does not match expected difficulty");
        }

    } // end non-genesis checks

    // -----------------------------------------------------------------------
    // Check 6: Proof-of-Work -- keccak256d(header[0..91]) <= target
    // -----------------------------------------------------------------------
    if (!CheckProofOfWork(header)) {
        LogWarn("consensus", "PoW check FAILED at height %lu nbits=0x%08x",
                (unsigned long)header.height, header.nbits);
        return state.invalid(ValidationResult::HEADER_INVALID, "high-hash",
            "hash exceeds difficulty target");
    }

    // -----------------------------------------------------------------------
    // Check 7: miner signature must be valid
    // -----------------------------------------------------------------------
    // Ed25519 signature over the unsigned header data (first 92 bytes).
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
// check_block -- full block validation (header + body)
// ===========================================================================

bool check_block(const CBlock& block, const BlockContext& ctx,
                 ValidationState& state) {

    // Run all header checks first
    if (!check_header(block, ctx, state)) {
        return false;
    }

    // Transaction list must be non-empty (at least coinbase)
    if (block.vtx.empty()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-missing",
            "block has no transactions");
    }

    // First transaction must be coinbase
    if (!block.vtx[0].is_coinbase()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-missing",
            "first transaction is not coinbase");
    }

    // No other transaction may be coinbase
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        if (block.vtx[i].is_coinbase()) {
            return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-multiple",
                "multiple coinbase transactions");
        }
    }

    // Coinbase reward validation
    {
        Amount subsidy = compute_block_reward(block.height);
        Amount coinbase_value = block.vtx[0].get_value_out();

        if (block.vtx.size() == 1) {
            if (coinbase_value > subsidy) {
                return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-amount",
                    "coinbase exceeds subsidy with no fee-paying transactions");
            }
        } else {
            if (coinbase_value < 0 || coinbase_value > MAX_SUPPLY) {
                return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-amount",
                    "coinbase amount out of range");
            }
        }

        for (const auto& out : block.vtx[0].vout) {
            if (out.amount < 0) {
                return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vout-negative",
                    "coinbase output has negative amount");
            }
        }
    }

    // Transaction validation
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx[i];

        if (tx.vin.empty()) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vin-empty",
                "transaction has no inputs");
        }
        if (tx.vout.empty()) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vout-empty",
                "transaction has no outputs");
        }

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

        for (size_t j = 0; j < tx.vin.size(); ++j) {
            for (size_t k = j + 1; k < tx.vin.size(); ++k) {
                if (tx.vin[j].prevout == tx.vin[k].prevout) {
                    return state.invalid(ValidationResult::TX_INVALID, "bad-txns-inputs-duplicate",
                        "duplicate input in transaction");
                }
            }
        }

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

    // Merkle root verification
    {
        uint256 computed_root = compute_block_merkle_root(block.vtx);

        if (computed_root != block.merkle_root) {
            return state.invalid(ValidationResult::BLOCK_INVALID, "bad-txnmrklroot",
                "merkle root mismatch");
        }
    }

    return true;
}

// ===========================================================================
// check_block_transactions
// ===========================================================================

bool check_block_transactions(const CBlock& block, const BlockContext& ctx,
                               ValidationState& state) {
    (void)ctx;

    // Block size check
    size_t estimated_size = BLOCK_HEADER_SIZE;
    for (const auto& tx : block.vtx) {
        estimated_size += 4;
        estimated_size += tx.vin.size() * 132;
        estimated_size += tx.vout.size() * 40;
        estimated_size += 8;
    }

    if (estimated_size > MAX_BLOCK_SIZE) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-blk-size",
            "estimated block size exceeds MAX_BLOCK_SIZE");
    }

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

    for (size_t i = 1; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx[i];

        if (tx.vin.empty()) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vin-empty",
                "non-coinbase transaction has no inputs");
        }

        for (const auto& input : tx.vin) {
            if (input.prevout.is_null()) {
                return state.invalid(ValidationResult::TX_INVALID, "bad-txns-prevout-null",
                    "non-coinbase transaction has null prevout");
            }
        }

        size_t tx_size = 4 + tx.vin.size() * 132 + tx.vout.size() * 40 + 8;
        if (tx_size > MAX_TX_SIZE) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-oversize",
                "transaction exceeds MAX_TX_SIZE");
        }

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
// check_coinbase
// ===========================================================================

bool check_coinbase(const CTransaction& coinbase, uint64_t height,
                     Amount max_allowed, ValidationState& state) {
    (void)height;

    if (!coinbase.is_coinbase()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-missing",
            "first transaction is not coinbase");
    }

    if (coinbase.vin.size() != 1) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-inputs",
            "coinbase must have exactly one input");
    }

    if (!coinbase.vin[0].prevout.is_null()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-prevout",
            "coinbase input must have null prevout");
    }

    if (coinbase.vout.empty()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-vout-empty",
            "coinbase has no outputs");
    }

    Amount total_out = coinbase.get_value_out();
    if (total_out > max_allowed) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-amount",
            "coinbase output exceeds allowed maximum (subsidy + fees)");
    }

    for (const auto& out : coinbase.vout) {
        if (out.amount < 0) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-cb-vout-negative",
                "coinbase output has negative value");
        }
    }

    return true;
}

// ===========================================================================
// compute_block_fees
// ===========================================================================

Amount compute_block_fees(const CBlock& block,
                           const std::vector<Amount>& tx_input_sums) {
    Amount total_fees = 0;

    for (size_t i = 1; i < block.vtx.size() && i < tx_input_sums.size(); ++i) {
        Amount input_sum = tx_input_sums[i];
        Amount output_sum = block.vtx[i].get_value_out();

        Amount fee = input_sum - output_sum;
        if (fee < 0) {
            continue;
        }
        total_fees += fee;
    }

    return total_fees;
}

// ===========================================================================
// check_transaction
// ===========================================================================

bool check_transaction(const CTransaction& tx, ValidationState& state) {
    if (tx.vin.empty()) {
        return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vin-empty",
            "transaction has no inputs");
    }

    if (tx.vout.empty()) {
        return state.invalid(ValidationResult::TX_INVALID, "bad-txns-vout-empty",
            "transaction has no outputs");
    }

    if (tx.is_coinbase()) {
        return state.invalid(ValidationResult::TX_INVALID, "bad-txns-is-coinbase",
            "standalone check_transaction should not be called on coinbase");
    }

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

    for (size_t i = 0; i < tx.vin.size(); ++i) {
        for (size_t j = i + 1; j < tx.vin.size(); ++j) {
            if (tx.vin[i].prevout == tx.vin[j].prevout) {
                return state.invalid(ValidationResult::TX_INVALID,
                    "bad-txns-inputs-duplicate",
                    "duplicate input in transaction");
            }
        }
    }

    for (const auto& input : tx.vin) {
        if (input.prevout.is_null()) {
            return state.invalid(ValidationResult::TX_INVALID,
                "bad-txns-prevout-null",
                "non-coinbase input has null prevout");
        }
    }

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

    if (tx.version == 0) {
        return state.invalid(ValidationResult::TX_INVALID, "bad-txns-version",
            "transaction version must be >= 1");
    }

    if (tx.locktime < 0) {
        return state.invalid(ValidationResult::TX_INVALID, "bad-txns-locktime",
            "negative locktime");
    }

    return true;
}

// ===========================================================================
// check_block_weight
// ===========================================================================

bool check_block_weight(const CBlock& block, ValidationState& state) {
    size_t weight = BLOCK_HEADER_SIZE;

    for (const auto& tx : block.vtx) {
        size_t tx_weight = 4 + 8;
        tx_weight += 4;
        tx_weight += tx.vin.size() * 132;
        tx_weight += tx.vout.size() * 40;
        weight += tx_weight;
    }

    if (weight > MAX_BLOCK_SIZE) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-blk-weight",
            "block weight exceeds MAX_BLOCK_SIZE");
    }

    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx[i];
        size_t tx_size = 12 + tx.vin.size() * 132 + tx.vout.size() * 40;
        if (tx_size > MAX_TX_SIZE) {
            return state.invalid(ValidationResult::TX_INVALID, "bad-txns-oversize",
                "transaction exceeds MAX_TX_SIZE");
        }
    }

    if (block.vtx.size() > MAX_BLOCK_SIZE / 100) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-blk-tx-count",
            "too many transactions in block");
    }

    return true;
}

// ===========================================================================
// BIP34 height encoding
// ===========================================================================

bool encode_height_in_coinbase(std::vector<uint8_t>& script_sig, uint64_t height) {
    std::vector<uint8_t> height_bytes;
    uint64_t h = height;
    if (h == 0) {
        height_bytes.push_back(0x00);
    } else {
        while (h > 0) {
            height_bytes.push_back(static_cast<uint8_t>(h & 0xFF));
            h >>= 8;
        }
        if (height_bytes.back() & 0x80) {
            height_bytes.push_back(0x00);
        }
    }

    if (height_bytes.size() > 8) {
        return false;
    }

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

    if (push_size < 1 || push_size > 8) {
        return false;
    }

    if (script_sig.size() < static_cast<size_t>(1 + push_size)) {
        return false;
    }

    height = 0;
    for (int i = push_size - 1; i >= 0; --i) {
        height <<= 8;
        height |= script_sig[1 + static_cast<size_t>(i)];
    }

    return true;
}

// ===========================================================================
// Helper: verify_coinbase_height
// ===========================================================================

static bool verify_coinbase_height(const CTransaction& coinbase, uint64_t expected_height,
                                    ValidationState& state) {
    if (coinbase.vin.empty()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-height",
            "coinbase has no inputs for height check");
    }

    if (expected_height == 0) {
        return true;
    }

    const auto& sig = coinbase.vin[0].signature;

    uint8_t push_size = sig[0];
    if (push_size < 1 || push_size > 8) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-height",
            "coinbase height push_size out of range");
    }

    if (static_cast<size_t>(push_size + 1) > sig.size()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-height",
            "coinbase script_sig too short for height encoding");
    }

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
// UTXO validation helpers
// ===========================================================================

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

    result.sigops = static_cast<int>(tx.vin.size());

    for (size_t vin_i = 0; vin_i < tx.vin.size(); ++vin_i) {
        const CTxIn& input = tx.vin[vin_i];

        result.spent_utxos.emplace_back(input.prevout.txid, input.prevout.index);

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

                uint256 input_pkh = keccak256(input.pubkey.data(), input.pubkey.size());
                if (std::memcmp(input_pkh.data(), prev_out.pubkey_hash.data(), 32) != 0) {
                    result.valid = false;
                    result.reject_reason = "bad-txns-sig";
                    result.debug_message = "pubkey hash mismatch for in-block input";
                    return result;
                }

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
    }

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
// connect_block_transactions
// ===========================================================================

ConnectResult connect_block_transactions(
        const CBlock& block,
        uint64_t height) {

    ConnectResult result;
    result.success = false;
    result.total_fees = 0;
    result.total_sigops = 0;
    result.total_block_weight = 0;

    if (block.vtx.empty()) {
        result.error = "block has no transactions";
        return result;
    }

    if (!block.vtx[0].is_coinbase()) {
        result.error = "first transaction is not coinbase";
        return result;
    }

    for (size_t i = 1; i < block.vtx.size(); ++i) {
        if (block.vtx[i].is_coinbase()) {
            result.error = "multiple coinbase transactions at index " + std::to_string(i);
            return result;
        }
    }

    std::vector<std::pair<uint256, std::vector<CTxOut>>> in_block_outputs;
    in_block_outputs.reserve(block.vtx.size());

    std::vector<std::pair<uint256, uint32_t>> all_spent_outpoints;

    {
        const CTransaction& coinbase = block.vtx[0];
        uint256 cb_txid = coinbase.get_txid();

        in_block_outputs.emplace_back(cb_txid, coinbase.vout);

        for (uint32_t vout = 0; vout < coinbase.vout.size(); ++vout) {
            result.created_utxos.emplace_back(cb_txid, vout);
        }

        result.total_block_weight += 12 + coinbase.vin.size() * 132 +
                                     coinbase.vout.size() * 40;
    }

    for (size_t tx_i = 1; tx_i < block.vtx.size(); ++tx_i) {
        const CTransaction& tx = block.vtx[tx_i];
        uint256 txid = tx.get_txid();

        if (tx.vin.empty()) {
            result.error = "tx " + std::to_string(tx_i) + " has no inputs";
            return result;
        }
        if (tx.vout.empty()) {
            result.error = "tx " + std::to_string(tx_i) + " has no outputs";
            return result;
        }

        for (const auto& input : tx.vin) {
            if (input.prevout.is_null()) {
                result.error = "tx " + std::to_string(tx_i) +
                               " has null prevout in non-coinbase";
                return result;
            }
        }

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

        TxValidationResult tx_result = validate_tx_against_utxo(
            tx, tx_i, height, in_block_outputs);

        if (!tx_result.valid) {
            result.error = tx_result.reject_reason + ": " + tx_result.debug_message;
            return result;
        }

        result.total_sigops += tx_result.sigops;
        if (result.total_sigops > MAX_BLOCK_SIGOPS) {
            result.error = "block sigops exceed MAX_BLOCK_SIGOPS";
            return result;
        }

        for (const auto& sp : tx_result.spent_utxos) {
            result.spent_utxos.push_back(sp);
        }
        for (const auto& cr : tx_result.created_utxos) {
            result.created_utxos.push_back(cr);
        }

        in_block_outputs.emplace_back(txid, tx.vout);

        size_t tx_weight = 12 + tx.vin.size() * 132 + tx.vout.size() * 40;
        result.total_block_weight += tx_weight;

        if (tx_weight > MAX_TX_SIZE) {
            result.error = "tx " + std::to_string(tx_i) + " exceeds MAX_TX_SIZE";
            return result;
        }
    }

    result.total_block_weight += BLOCK_HEADER_SIZE;

    if (result.total_block_weight > MAX_BLOCK_SIZE) {
        result.error = "block weight exceeds MAX_BLOCK_SIZE";
        return result;
    }

    result.success = true;
    return result;
}

// ===========================================================================
// Remaining validation helpers
// ===========================================================================

int count_block_sigops(const CBlock& block) {
    int total = 0;
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const CTransaction& tx = block.vtx[i];
        if (!tx.is_coinbase()) {
            total += static_cast<int>(tx.vin.size());
        }
    }
    return total;
}

uint256 compute_signature_hash(const CTransaction& tx) {
    return tx.get_txid();
}

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

bool verify_all_input_signatures(const CTransaction& tx, ValidationState& state) {
    if (tx.is_coinbase()) {
        return true;
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

bool check_input_pubkey_hash(const CTxIn& input,
                               const std::array<uint8_t, 32>& expected_pubkey_hash,
                               ValidationState& state) {
    uint256 computed_hash = keccak256(input.pubkey.data(), input.pubkey.size());

    if (std::memcmp(computed_hash.data(), expected_pubkey_hash.data(), 32) != 0) {
        return state.invalid(ValidationResult::TX_INVALID, "bad-txns-pubkey-hash",
            "input pubkey hash does not match UTXO's pubkey_hash");
    }

    return true;
}

Amount compute_tx_fee(Amount input_sum, Amount output_sum) {
    if (input_sum < output_sum) {
        return -1;
    }
    return input_sum - output_sum;
}

bool validate_coinbase_script_sig_size(const CTransaction& coinbase,
                                         ValidationState& state) {
    if (!coinbase.is_coinbase() || coinbase.vin.empty()) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-scriptlen",
            "not a valid coinbase transaction");
    }

    const auto& sig_field = coinbase.vin[0].signature;

    uint8_t push_size = sig_field[0];
    size_t effective_len = 1 + push_size;

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

size_t estimate_block_size(const CBlock& block) {
    size_t size = BLOCK_HEADER_SIZE;

    for (const auto& tx : block.vtx) {
        size += 4;
        size += 4;
        size += tx.vin.size() * 132;
        size += tx.vout.size() * 40;
        size += 8;
    }

    return size;
}

bool check_block_locktime(const CBlock& block, ValidationState& state) {
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const CTransaction& tx = block.vtx[i];

        if (tx.is_coinbase()) continue;
        if (tx.locktime == 0) continue;

        if (tx.locktime < 500'000'000) {
            if (static_cast<uint64_t>(tx.locktime) > block.height) {
                return state.invalid(ValidationResult::TX_INVALID, "bad-txns-nonfinal",
                    "transaction locktime (height) not satisfied");
            }
        } else {
            if (tx.locktime > block.timestamp) {
                return state.invalid(ValidationResult::TX_INVALID, "bad-txns-nonfinal",
                    "transaction locktime (time) not satisfied");
            }
        }
    }

    return true;
}

Amount compute_total_output_value(const CBlock& block) {
    Amount total = 0;
    for (const auto& tx : block.vtx) {
        for (const auto& out : tx.vout) {
            total += out.amount;
        }
    }
    return total;
}

Amount compute_total_input_value(const std::vector<Amount>& tx_input_sums) {
    Amount total = 0;
    for (size_t i = 1; i < tx_input_sums.size(); ++i) {
        total += tx_input_sums[i];
    }
    return total;
}

bool check_monetary_supply(const CBlock& block, Amount subsidy, Amount fees,
                            ValidationState& state) {
    Amount coinbase_out = block.vtx[0].get_value_out();
    Amount max_allowed = subsidy + fees;

    if (coinbase_out > max_allowed) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-amount",
            "coinbase output (" + std::to_string(coinbase_out) +
            ") exceeds subsidy + fees (" + std::to_string(max_allowed) + ")");
    }

    for (const auto& out : block.vtx[0].vout) {
        if (out.amount > MAX_SUPPLY) {
            return state.invalid(ValidationResult::BLOCK_INVALID, "bad-cb-vout-toolarge",
                "coinbase output exceeds MAX_SUPPLY");
        }
    }

    return true;
}

bool validate_block_full(const CBlock& block, const BlockContext& ctx,
                          ValidationState& state) {
    (void)ctx;

    if (!check_block_locktime(block, state)) {
        return false;
    }

    if (!check_duplicate_txids(block, state)) {
        return false;
    }

    if (!check_block_weight(block, state)) {
        return false;
    }

    if (block.height > 0) {
        if (!verify_coinbase_height(block.vtx[0], block.height, state)) {
            return false;
        }
    }

    if (block.height > 0) {
        if (!validate_coinbase_script_sig_size(block.vtx[0], state)) {
            return false;
        }
    }

    int sigops = count_block_sigops(block);
    if (sigops > MAX_BLOCK_SIGOPS) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-blk-sigops",
            "block sigops (" + std::to_string(sigops) +
            ") exceed MAX_BLOCK_SIGOPS (" + std::to_string(MAX_BLOCK_SIGOPS) + ")");
    }

    for (size_t i = 1; i < block.vtx.size(); ++i) {
        if (!verify_all_input_signatures(block.vtx[i], state)) {
            return false;
        }
    }

    size_t estimated_size = estimate_block_size(block);
    if (estimated_size > MAX_BLOCK_SIZE) {
        return state.invalid(ValidationResult::BLOCK_INVALID, "bad-blk-size",
            "estimated block size exceeds MAX_BLOCK_SIZE");
    }

    return true;
}

} // namespace flow::consensus

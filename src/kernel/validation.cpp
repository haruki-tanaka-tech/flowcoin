// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "kernel/validation.h"
#include "consensus/difficulty.h"
#include "consensus/growth.h"
#include "consensus/pow.h"
#include "consensus/reward.h"
#include "crypto/sign.h"
#include "hash/keccak.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace flow::kernel {

// ============================================================================
// Transaction validation
// ============================================================================

TxValidationResult validate_transaction(
    const CTransaction& tx,
    const UTXOSet& utxo,
    uint64_t height) {

    TxValidationResult result;

    // Check 1: non-empty
    if (tx.vin.empty()) {
        result.error = "bad-txns-vin-empty";
        return result;
    }
    if (tx.vout.empty()) {
        result.error = "bad-txns-vout-empty";
        return result;
    }

    // Check 2: size limit
    auto serialized = tx.serialize();
    if (serialized.size() > consensus::MAX_TX_SIZE) {
        result.error = "bad-txns-oversize";
        return result;
    }

    // Check 3-5: inputs exist and are valid
    Amount total_in = 0;
    std::vector<std::pair<uint256, uint32_t>> spent_outpoints;
    int sigops = 0;

    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const auto& input = tx.vin[i];

        // Check for duplicate inputs (double-spend within same tx)
        auto outpoint = std::make_pair(input.prevout.txid, input.prevout.index);
        for (const auto& prev : spent_outpoints) {
            if (prev.first == outpoint.first && prev.second == outpoint.second) {
                result.error = "bad-txns-inputs-duplicate";
                return result;
            }
        }
        spent_outpoints.push_back(outpoint);

        // Look up the UTXO
        UTXOEntry entry;
        if (!utxo.get(input.prevout.txid, input.prevout.index, entry)) {
            result.error = "bad-txns-inputs-missingorspent";
            result.debug_message = "Input " + std::to_string(i) + " not found in UTXO set";
            return result;
        }

        // Coinbase maturity check
        if (entry.is_coinbase) {
            if (height < entry.height + consensus::COINBASE_MATURITY) {
                result.error = "bad-txns-premature-spend-of-coinbase";
                result.debug_message = "Coinbase output at height " +
                    std::to_string(entry.height) + " not mature at height " +
                    std::to_string(height) + " (needs " +
                    std::to_string(consensus::COINBASE_MATURITY) + " confirmations)";
                return result;
            }
        }

        // Value range check
        if (entry.value < 0 || entry.value > consensus::MAX_SUPPLY) {
            result.error = "bad-txns-inputvalues-outofrange";
            return result;
        }

        // Overflow check
        if (total_in + entry.value < total_in) {
            result.error = "bad-txns-inputvalues-overflow";
            return result;
        }
        total_in += entry.value;

        // Signature verification: one Ed25519 verify per input
        sigops++;
    }

    // Check 6-8: outputs
    Amount total_out = 0;
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const auto& output = tx.vout[i];

        if (output.amount < 0) {
            result.error = "bad-txns-vout-negative";
            return result;
        }
        if (output.amount > consensus::MAX_SUPPLY) {
            result.error = "bad-txns-vout-toolarge";
            return result;
        }
        if (total_out + output.amount < total_out) {
            result.error = "bad-txns-txouttotal-toolarge";
            return result;
        }
        total_out += output.amount;
    }

    // Fee must be non-negative
    if (total_in < total_out) {
        result.error = "bad-txns-in-belowout";
        result.debug_message = "total_in=" + std::to_string(total_in) +
                               " total_out=" + std::to_string(total_out);
        return result;
    }

    // Check 10: signature verification
    // Each input's signature must verify against the pubkey whose hash
    // matches the UTXO's pubkey_hash.
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const auto& input = tx.vin[i];

        UTXOEntry entry;
        utxo.get(input.prevout.txid, input.prevout.index, entry);

        // Verify the signature over the transaction's signing hash
        uint256 sighash = tx.signature_hash(static_cast<uint32_t>(i));

        // Check that the pubkey hashes to the expected pubkey_hash
        uint256 computed_hash = keccak256(input.pubkey.data(), input.pubkey.size());
        if (std::memcmp(computed_hash.data(), entry.pubkey_hash.data(), 32) != 0) {
            result.error = "bad-txns-pubkey-hash-mismatch";
            result.debug_message = "Input " + std::to_string(i);
            return result;
        }

        // Verify Ed25519 signature
        if (!ed25519_verify(sighash.data(), sighash.size(),
                                     input.pubkey.data(),
                                     input.signature.data())) {
            result.error = "bad-txns-signature-invalid";
            result.debug_message = "Input " + std::to_string(i);
            return result;
        }
    }

    result.valid = true;
    result.fee = total_in - total_out;
    result.sigops = sigops;
    result.total_in = total_in;
    result.total_out = total_out;
    return result;
}

TxValidationResult validate_coinbase(
    const CTransaction& tx,
    uint64_t height,
    Amount max_value) {

    TxValidationResult result;

    // Must have exactly one input
    if (tx.vin.size() != 1) {
        result.error = "bad-cb-multiple-inputs";
        return result;
    }

    // Coinbase input must have null prevout
    const auto& input = tx.vin[0];
    if (!input.prevout.txid.is_null() || input.prevout.index != 0xFFFFFFFF) {
        result.error = "bad-cb-missing-null-prevout";
        return result;
    }

    // Must have at least one output
    if (tx.vout.empty()) {
        result.error = "bad-cb-no-outputs";
        return result;
    }

    // Coinbase identity: pubkey must not be all zeros
    // (In FlowCoin, coinbase uses pubkey field for miner identity)
    {
        bool all_zero = true;
        for (size_t j = 0; j < input.pubkey.size(); ++j) {
            if (input.pubkey[j] != 0) { all_zero = false; break; }
        }
        if (all_zero) {
            result.error = "bad-cb-no-pubkey";
            return result;
        }
    }

    // Sum of outputs must not exceed max_value
    Amount total_out = 0;
    for (const auto& output : tx.vout) {
        if (output.amount < 0) {
            result.error = "bad-cb-vout-negative";
            return result;
        }
        if (total_out + output.amount < total_out) {
            result.error = "bad-cb-txouttotal-toolarge";
            return result;
        }
        total_out += output.amount;
    }

    if (total_out > max_value) {
        result.error = "bad-cb-amount";
        result.debug_message = "coinbase output " + std::to_string(total_out) +
                               " exceeds max " + std::to_string(max_value);
        return result;
    }

    result.valid = true;
    result.total_out = total_out;
    return result;
}

// ============================================================================
// Block subsidy
// ============================================================================

Amount get_block_subsidy(uint64_t height) {
    return consensus::compute_block_reward(height);
}

Amount get_total_supply(uint64_t height) {
    return consensus::compute_total_supply(height);
}

// ============================================================================
// Difficulty
// ============================================================================

uint32_t compute_next_work(uint32_t prev_nbits,
                            int64_t actual_timespan,
                            bool allow_min_difficulty) {
    // Clamp timespan to [timespan/4, timespan*4]
    int64_t target_timespan = consensus::RETARGET_TIMESPAN;
    int64_t min_timespan = target_timespan / consensus::MAX_RETARGET_FACTOR;
    int64_t max_timespan = target_timespan * consensus::MAX_RETARGET_FACTOR;

    int64_t clamped = actual_timespan;
    if (clamped < min_timespan) clamped = min_timespan;
    if (clamped > max_timespan) clamped = max_timespan;

    // Decode current target
    arith_uint256 target;
    if (!consensus::derive_target(prev_nbits, target)) {
        return prev_nbits;
    }

    // Adjust: new_target = old_target * actual_timespan / target_timespan
    target *= static_cast<uint32_t>(clamped);
    target /= static_cast<uint32_t>(target_timespan);

    // Clamp to powLimit
    arith_uint256 pow_limit = consensus::GetPowLimit();
    if (target > pow_limit) {
        target = pow_limit;
    }

    // Allow minimum difficulty for regtest
    if (allow_min_difficulty) {
        return consensus::INITIAL_NBITS;
    }

    return target.GetCompact();
}

arith_uint256 get_pow_limit() {
    return consensus::GetPowLimit();
}

double get_difficulty(uint32_t nbits) {
    return consensus::GetDifficulty(nbits);
}

// ============================================================================
// Proof-of-Training
// ============================================================================

bool check_proof_of_training(const uint256& training_hash, uint32_t nbits) {
    return consensus::check_proof_of_training(training_hash, nbits);
}

uint256 compute_training_hash(const uint256& delta_hash,
                               const uint256& dataset_hash) {
    // training_hash = keccak256(delta_hash || dataset_hash)
    uint8_t combined[64];
    std::memcpy(combined, delta_hash.data(), 32);
    std::memcpy(combined + 32, dataset_hash.data(), 32);
    return keccak256(combined, 64);
}

bool verify_block_signature(const CBlockHeader& header) {
    // Serialize the unsigned portion (bytes 0..243)
    auto header_bytes = header.serialize();
    if (header_bytes.size() < BLOCK_HEADER_UNSIGNED_SIZE) {
        return false;
    }

    // Verify Ed25519 signature
    return ed25519_verify(
        header_bytes.data(),
        BLOCK_HEADER_UNSIGNED_SIZE,
        header.miner_pubkey.data(),
        header.miner_sig.data());
}

// ============================================================================
// Model dimensions
// ============================================================================

consensus::ModelDimensions get_model_dims(uint64_t height) {
    return consensus::compute_growth(height);
}

size_t compute_param_count(const consensus::ModelDimensions& dims) {
    return consensus::estimate_param_count(
        dims.d_model, dims.n_layers, dims.d_ff, dims.n_slots);
}

} // namespace flow::kernel

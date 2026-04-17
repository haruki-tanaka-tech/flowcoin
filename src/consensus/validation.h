// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Consensus validation for FlowCoin blocks and headers.
//
// Implements RandomX Proof-of-Work consensus checks:
//
// CHECK  FIELD              RULE                                     ERROR CODE
// -----  -----------------  ---------------------------------------  ----------
//  1     prev_hash          == parent_hash (from context)            bad-prevblk
//  2     height             == parent_height + 1                     bad-height
//  3     timestamp          > parent_timestamp                       time-too-old
//  4     timestamp          >= parent_timestamp + MIN_BLOCK_INTERVAL bad-time-spacing
//  5     timestamp          <= adjusted_time + MAX_FUTURE_TIME       time-too-new
//  6     nbits              == get_next_work_required(...)            bad-diffbits
//  7     PoW                RandomX(header[0..91], pow_seed) <= tgt  high-hash
//  8     miner_sig          Ed25519Verify(pubkey, header[0..91])     bad-signature
//
// check_header() validates checks 1-8 (no block body needed).
// check_block() validates header + coinbase, merkle root, transactions.

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
    VALID = 0,
    HEADER_INVALID,
    BLOCK_INVALID,
    TX_INVALID,
    ALREADY_HAVE,
    INTERNAL_ERR,
};

// ---------------------------------------------------------------------------
// ValidationState
// ---------------------------------------------------------------------------

class ValidationState {
public:
    ValidationState() = default;

    bool is_valid() const { return result_ == ValidationResult::VALID; }
    bool is_invalid() const {
        return result_ == ValidationResult::HEADER_INVALID
            || result_ == ValidationResult::BLOCK_INVALID
            || result_ == ValidationResult::TX_INVALID;
    }
    bool is_error() const { return result_ == ValidationResult::INTERNAL_ERR; }

    ValidationResult result() const { return result_; }
    const std::string& reject_reason() const { return reject_reason_; }
    const std::string& debug_message() const { return debug_message_; }

    bool invalid(ValidationResult result, const std::string& reject_reason,
                 const std::string& debug_msg = "") {
        result_ = result;
        reject_reason_ = reject_reason;
        debug_message_ = debug_msg;
        return false;
    }

    bool error(const std::string& reject_reason) {
        return invalid(ValidationResult::INTERNAL_ERR, reject_reason);
    }

    void clear() {
        result_ = ValidationResult::VALID;
        reject_reason_.clear();
        debug_message_.clear();
    }

    std::string to_string() const {
        if (is_valid()) return "valid";
        std::string s = reject_reason_;
        if (!debug_message_.empty()) {
            s += " (" + debug_message_ + ")";
        }
        return s;
    }

private:
    ValidationResult result_ = ValidationResult::VALID;
    std::string reject_reason_;
    std::string debug_message_;
};

// ---------------------------------------------------------------------------
// BlockContext -- parent-chain state needed for validation
// ---------------------------------------------------------------------------

struct BlockContext {
    // Parent block info
    uint256     prev_hash;
    uint64_t    prev_height    = 0;
    int64_t     prev_timestamp = 0;
    uint32_t    prev_nbits     = 0;

    // Current network-adjusted time
    int64_t     adjusted_time = 0;

    // Expected difficulty bits for the child block
    uint32_t    expected_nbits = 0;

    // Timestamp of block at start of current retarget period
    int64_t     retarget_first_time = 0;

    // RandomX PoW seed: block hash at rx_seed_height(header.height).
    // Caller looks this up from the block index before validation.
    uint256     pow_seed;

    // True if we are validating the genesis block (no parent exists).
    bool        is_genesis = false;
};

// ---------------------------------------------------------------------------
// check_header -- header-only validation (checks 1-8)
// ---------------------------------------------------------------------------

bool check_header(const CBlockHeader& header, const BlockContext& ctx,
                  ValidationState& state);

// ---------------------------------------------------------------------------
// check_block -- full block validation (header + body)
// ---------------------------------------------------------------------------

bool check_block(const CBlock& block, const BlockContext& ctx,
                 ValidationState& state);

// ---------------------------------------------------------------------------
// check_block_transactions
// ---------------------------------------------------------------------------

bool check_block_transactions(const CBlock& block, const BlockContext& ctx,
                               ValidationState& state);

// ---------------------------------------------------------------------------
// check_coinbase
// ---------------------------------------------------------------------------

bool check_coinbase(const CTransaction& coinbase, uint64_t height,
                     Amount max_allowed, ValidationState& state);

// ---------------------------------------------------------------------------
// compute_block_fees
// ---------------------------------------------------------------------------

Amount compute_block_fees(const CBlock& block,
                           const std::vector<Amount>& tx_input_sums);

// ---------------------------------------------------------------------------
// check_transaction
// ---------------------------------------------------------------------------

bool check_transaction(const CTransaction& tx, ValidationState& state);

// ---------------------------------------------------------------------------
// check_block_weight
// ---------------------------------------------------------------------------

bool check_block_weight(const CBlock& block, ValidationState& state);

// ---------------------------------------------------------------------------
// ValidationFlags
// ---------------------------------------------------------------------------

struct ValidationFlags {
    bool check_header = true;
    bool check_transactions = true;
    bool check_merkle = true;
    bool check_signatures = true;
    bool check_difficulty = true;
    bool check_timestamp = true;

    static ValidationFlags all() { return ValidationFlags{}; }

    static ValidationFlags header_only() {
        ValidationFlags f{};
        f.check_transactions = false;
        f.check_merkle = false;
        return f;
    }

    static ValidationFlags assume_valid() {
        ValidationFlags f{};
        f.check_signatures = false;
        return f;
    }
};

// ---------------------------------------------------------------------------
// BIP34 height encoding in coinbase
// ---------------------------------------------------------------------------

bool encode_height_in_coinbase(std::vector<uint8_t>& script_sig, uint64_t height);
bool decode_height_from_coinbase(const std::vector<uint8_t>& script_sig, uint64_t& height);

// ---------------------------------------------------------------------------
// ConnectResult
// ---------------------------------------------------------------------------

struct ConnectResult {
    bool success;
    std::string error;
    Amount total_fees;
    std::vector<std::pair<uint256, uint32_t>> spent_utxos;
    std::vector<std::pair<uint256, uint32_t>> created_utxos;
    int total_sigops;
    size_t total_block_weight;
};

ConnectResult connect_block_transactions(const CBlock& block, uint64_t height);

// ---------------------------------------------------------------------------
// Additional validation helpers
// ---------------------------------------------------------------------------

int count_block_sigops(const CBlock& block);
uint256 compute_signature_hash(const CTransaction& tx);
bool verify_input_signature(const CTransaction& tx, size_t input_index);
bool verify_all_input_signatures(const CTransaction& tx, ValidationState& state);

bool check_input_coinbase_maturity(bool is_coinbase_output,
                                     uint64_t output_height,
                                     uint64_t spending_height,
                                     ValidationState& state);

bool check_input_pubkey_hash(const CTxIn& input,
                               const std::array<uint8_t, 32>& expected_pubkey_hash,
                               ValidationState& state);

Amount compute_tx_fee(Amount input_sum, Amount output_sum);
bool validate_coinbase_script_sig_size(const CTransaction& coinbase,
                                         ValidationState& state);
bool check_duplicate_txids(const CBlock& block, ValidationState& state);
size_t estimate_block_size(const CBlock& block);
bool check_block_locktime(const CBlock& block, ValidationState& state);
Amount compute_total_output_value(const CBlock& block);
Amount compute_total_input_value(const std::vector<Amount>& tx_input_sums);
bool check_monetary_supply(const CBlock& block, Amount subsidy, Amount fees,
                            ValidationState& state);
bool validate_block_full(const CBlock& block, const BlockContext& ctx,
                          ValidationState& state);

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_VALIDATION_H

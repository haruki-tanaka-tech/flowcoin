// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "wallet/txbuilder.h"
#include "hash/keccak.h"

#include <algorithm>
#include <cstring>
#include <numeric>

namespace flow {

// ---------------------------------------------------------------------------
// Wire format sizes (must match transaction.cpp serialization)
// ---------------------------------------------------------------------------

// version: 4 bytes
// varint for input/output counts: 1-9 bytes each (use 1 for estimates < 253)
// per input: prevout_txid(32) + prevout_index(4) + pubkey(32) + signature(64) = 132
// per output: amount(8) + pubkey_hash(32) = 40
// locktime: 8 bytes

static constexpr size_t TX_OVERHEAD = 4 + 1 + 1 + 8;  // version + vin_count + vout_count + locktime
static constexpr size_t INPUT_SIZE = 32 + 4 + 32 + 64;  // = 132
static constexpr size_t OUTPUT_SIZE = 8 + 32;             // = 40

// ---------------------------------------------------------------------------
// Builder methods
// ---------------------------------------------------------------------------

TxBuilder& TxBuilder::add_input(const uint256& txid, uint32_t vout,
                                  Amount value,
                                  const std::array<uint8_t, 32>& pubkey) {
    InputInfo info;
    info.txid = txid;
    info.vout = vout;
    info.value = value;
    info.pubkey = pubkey;
    inputs_.push_back(info);
    return *this;
}

TxBuilder& TxBuilder::add_output(const std::vector<uint8_t>& pubkey_hash,
                                   Amount value) {
    OutputInfo info;
    info.pubkey_hash = {};
    size_t copy_len = std::min(pubkey_hash.size(), static_cast<size_t>(32));
    std::memcpy(info.pubkey_hash.data(), pubkey_hash.data(), copy_len);
    info.value = value;
    outputs_.push_back(info);
    return *this;
}

TxBuilder& TxBuilder::add_output(const std::array<uint8_t, 32>& pubkey_hash,
                                   Amount value) {
    OutputInfo info;
    info.pubkey_hash = pubkey_hash;
    info.value = value;
    outputs_.push_back(info);
    return *this;
}

TxBuilder& TxBuilder::set_change_address(
        const std::vector<uint8_t>& change_pubkey_hash) {
    change_pubkey_hash_ = {};
    size_t copy_len = std::min(change_pubkey_hash.size(), static_cast<size_t>(32));
    std::memcpy(change_pubkey_hash_.data(), change_pubkey_hash.data(), copy_len);
    has_change_address_ = true;
    return *this;
}

TxBuilder& TxBuilder::set_fee_rate(Amount fee_rate) {
    fee_rate_ = std::max(fee_rate, static_cast<Amount>(1));
    return *this;
}

// ---------------------------------------------------------------------------
// Size estimation
// ---------------------------------------------------------------------------

size_t TxBuilder::estimate_size() const {
    // varint encoding: for counts < 253, it's 1 byte
    size_t vin_varint = (inputs_.size() < 253) ? 1 :
                        (inputs_.size() <= 0xFFFF) ? 3 : 5;
    size_t vout_varint = (outputs_.size() < 253) ? 1 :
                         (outputs_.size() <= 0xFFFF) ? 3 : 5;

    return 4  // version
         + vin_varint
         + inputs_.size() * INPUT_SIZE
         + vout_varint
         + outputs_.size() * OUTPUT_SIZE
         + 8; // locktime
}

size_t TxBuilder::estimate_size_with_change() const {
    size_t num_outputs = outputs_.size() + 1;
    size_t vin_varint = (inputs_.size() < 253) ? 1 :
                        (inputs_.size() <= 0xFFFF) ? 3 : 5;
    size_t vout_varint = (num_outputs < 253) ? 1 :
                         (num_outputs <= 0xFFFF) ? 3 : 5;

    return 4
         + vin_varint
         + inputs_.size() * INPUT_SIZE
         + vout_varint
         + num_outputs * OUTPUT_SIZE
         + 8;
}

// ---------------------------------------------------------------------------
// Totals
// ---------------------------------------------------------------------------

Amount TxBuilder::total_input_value() const {
    Amount total = 0;
    for (const auto& in : inputs_) {
        total += in.value;
    }
    return total;
}

Amount TxBuilder::total_output_value() const {
    Amount total = 0;
    for (const auto& out : outputs_) {
        total += out.value;
    }
    return total;
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

TxBuilder::BuildResult TxBuilder::build() const {
    BuildResult result;
    result.fee = 0;
    result.change = 0;
    result.success = false;

    // Validate inputs
    if (inputs_.empty()) {
        result.error = "no inputs specified";
        return result;
    }

    if (outputs_.empty()) {
        result.error = "no outputs specified";
        return result;
    }

    Amount total_in = total_input_value();
    Amount total_out = total_output_value();

    if (total_in <= 0) {
        result.error = "total input value must be positive";
        return result;
    }

    if (total_out <= 0) {
        result.error = "total output value must be positive";
        return result;
    }

    // Check for dust outputs
    for (const auto& out : outputs_) {
        if (out.value < DUST_THRESHOLD && out.value != 0) {
            result.error = "output value " + std::to_string(out.value)
                         + " is below dust threshold ("
                         + std::to_string(DUST_THRESHOLD) + ")";
            return result;
        }
    }

    // First pass: estimate fee without change output
    size_t estimated_size = estimate_size();
    Amount fee_no_change = fee_rate_ * static_cast<Amount>(estimated_size);
    if (fee_no_change < 1000) fee_no_change = 1000;

    Amount remainder = total_in - total_out - fee_no_change;

    if (remainder < 0) {
        result.error = "insufficient funds: need "
                     + std::to_string(total_out + fee_no_change)
                     + " but have " + std::to_string(total_in);
        return result;
    }

    // Decide whether to add a change output
    bool add_change = false;
    Amount change_amount = 0;
    Amount final_fee = fee_no_change;

    if (remainder > DUST_THRESHOLD && has_change_address_) {
        // Re-estimate with change output
        size_t size_with_change = estimate_size_with_change();
        Amount fee_with_change = fee_rate_ * static_cast<Amount>(size_with_change);
        if (fee_with_change < 1000) fee_with_change = 1000;

        change_amount = total_in - total_out - fee_with_change;

        if (change_amount > DUST_THRESHOLD) {
            add_change = true;
            final_fee = fee_with_change;
        } else {
            // Change would be dust after accounting for the extra output fee;
            // donate the remainder to miners
            final_fee = total_in - total_out;
            change_amount = 0;
        }
    } else if (remainder > 0 && !has_change_address_) {
        // No change address: remainder becomes fee
        final_fee = total_in - total_out;
        change_amount = 0;
    } else {
        // Remainder is dust: donate to miners
        final_fee = total_in - total_out;
        change_amount = 0;
    }

    // Build the CTransaction
    CTransaction tx;
    tx.version = 1;
    tx.locktime = 0;

    // Inputs (signatures zeroed)
    for (const auto& in : inputs_) {
        CTxIn txin;
        txin.prevout = COutPoint(in.txid, in.vout);
        txin.pubkey = in.pubkey;
        txin.signature = {};
        tx.vin.push_back(txin);
    }

    // Explicit outputs
    for (const auto& out : outputs_) {
        tx.vout.emplace_back(out.value, out.pubkey_hash);
    }

    // Change output
    if (add_change) {
        tx.vout.emplace_back(change_amount, change_pubkey_hash_);
    }

    result.tx = std::move(tx);
    result.fee = final_fee;
    result.change = change_amount;
    result.success = true;
    return result;
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

bool TxBuilder::sign(CTransaction& tx, SignFunc sign_func) const {
    if (!sign_func) return false;

    // Compute the signing hash (excludes signatures)
    std::vector<uint8_t> sighash_data = tx.serialize_for_hash();
    uint256 tx_hash = keccak256d(sighash_data.data(), sighash_data.size());

    for (size_t i = 0; i < tx.vin.size(); ++i) {
        try {
            std::array<uint8_t, 64> sig =
                sign_func(tx_hash, tx.vin[i].pubkey);
            tx.vin[i].signature = sig;
        } catch (...) {
            return false;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Clear
// ---------------------------------------------------------------------------

void TxBuilder::clear() {
    inputs_.clear();
    outputs_.clear();
    change_pubkey_hash_ = {};
    has_change_address_ = false;
    fee_rate_ = 1;
}

} // namespace flow

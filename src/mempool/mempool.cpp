// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "mempool/mempool.h"
#include "chain/utxo.h"
#include "consensus/params.h"
#include "crypto/sign.h"
#include "hash/keccak.h"

#include <algorithm>
#include <chrono>
#include <set>

namespace flow {

Mempool::Mempool(const UTXOSet& utxo) : utxo_(utxo) {}

Mempool::AddResult Mempool::add_transaction(const CTransaction& tx) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Compute txid
    uint256 txid = tx.get_txid();

    // Reject if already in mempool
    if (txs_.count(txid)) {
        return {false, "txn-already-in-mempool"};
    }

    // Coinbase transactions cannot enter the mempool
    if (tx.is_coinbase()) {
        return {false, "coinbase"};
    }

    // Must have at least one input and one output
    if (tx.vin.empty()) {
        return {false, "bad-txns-vin-empty"};
    }
    if (tx.vout.empty()) {
        return {false, "bad-txns-vout-empty"};
    }

    // Check serialized size
    std::vector<uint8_t> serialized = tx.serialize();
    size_t tx_size = serialized.size();
    if (tx_size > consensus::MAX_TX_SIZE) {
        return {false, "bad-txns-oversize"};
    }

    // Check for duplicate inputs within the transaction
    {
        std::set<std::pair<uint256, uint32_t>> seen_inputs;
        for (const auto& in : tx.vin) {
            auto key = std::make_pair(in.prevout.txid, in.prevout.index);
            if (!seen_inputs.insert(key).second) {
                return {false, "bad-txns-inputs-duplicate"};
            }
        }
    }

    // Check no double-spend within mempool
    for (const auto& in : tx.vin) {
        auto key = std::make_pair(in.prevout.txid, in.prevout.index);
        auto it = spent_outpoints_.find(key);
        if (it != spent_outpoints_.end()) {
            return {false, "txn-mempool-conflict"};
        }
    }

    // Validate inputs (UTXO existence, signatures, compute fee)
    Amount fee = 0;
    std::string error;
    if (!validate_inputs(tx, fee, error)) {
        return {false, error};
    }

    // Fee must be non-negative
    if (fee < 0) {
        return {false, "bad-txns-fee-negative"};
    }

    // Check minimum fee rate
    double fee_rate = static_cast<double>(fee) / static_cast<double>(tx_size);
    if (fee_rate < MIN_FEE_RATE) {
        return {false, "min-fee-not-met"};
    }

    // Check output values are non-negative and don't overflow
    Amount total_out = 0;
    for (const auto& out : tx.vout) {
        if (out.amount < 0) {
            return {false, "bad-txns-vout-negative"};
        }
        if (out.amount > consensus::MAX_SUPPLY) {
            return {false, "bad-txns-vout-toolarge"};
        }
        total_out += out.amount;
        if (total_out > consensus::MAX_SUPPLY) {
            return {false, "bad-txns-txouttotal-toolarge"};
        }
    }

    // All checks passed. Add to mempool.
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    MempoolEntry entry;
    entry.tx = tx;
    entry.txid = txid;
    entry.fee = fee;
    entry.tx_size = tx_size;
    entry.fee_rate = fee_rate;
    entry.time_added = now;

    txs_.emplace(txid, std::move(entry));
    by_fee_rate_.emplace(fee_rate, txid);
    total_bytes_ += tx_size;

    // Track spent outpoints
    for (const auto& in : tx.vin) {
        auto key = std::make_pair(in.prevout.txid, in.prevout.index);
        spent_outpoints_.emplace(key, txid);
    }

    return {true, ""};
}

void Mempool::remove(const uint256& txid) {
    std::lock_guard<std::mutex> lock(mutex_);
    remove_locked(txid);
}

void Mempool::remove_locked(const uint256& txid) {
    auto it = txs_.find(txid);
    if (it == txs_.end()) return;

    const MempoolEntry& entry = it->second;

    // Remove from fee-rate index
    auto range = by_fee_rate_.equal_range(entry.fee_rate);
    for (auto fi = range.first; fi != range.second; ++fi) {
        if (fi->second == txid) {
            by_fee_rate_.erase(fi);
            break;
        }
    }

    // Remove spent outpoints
    for (const auto& in : entry.tx.vin) {
        auto key = std::make_pair(in.prevout.txid, in.prevout.index);
        spent_outpoints_.erase(key);
    }

    total_bytes_ -= entry.tx_size;
    txs_.erase(it);
}

void Mempool::remove_for_block(const std::vector<CTransaction>& block_txs) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Collect all outpoints spent by the block
    std::set<std::pair<uint256, uint32_t>> block_spent;
    for (const auto& tx : block_txs) {
        for (const auto& in : tx.vin) {
            if (!in.is_coinbase()) {
                block_spent.emplace(in.prevout.txid, in.prevout.index);
            }
        }
    }

    // Remove block transactions from mempool
    for (const auto& tx : block_txs) {
        uint256 txid = tx.get_txid();
        remove_locked(txid);
    }

    // Remove any remaining mempool transactions that conflict
    // (spend the same inputs as the block's transactions)
    std::vector<uint256> to_remove;
    for (const auto& [txid, entry] : txs_) {
        for (const auto& in : entry.tx.vin) {
            auto key = std::make_pair(in.prevout.txid, in.prevout.index);
            if (block_spent.count(key)) {
                to_remove.push_back(txid);
                break;
            }
        }
    }
    for (const auto& txid : to_remove) {
        remove_locked(txid);
    }
}

bool Mempool::exists(const uint256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return txs_.count(txid) > 0;
}

bool Mempool::get(const uint256& txid, CTransaction& tx) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = txs_.find(txid);
    if (it == txs_.end()) return false;
    tx = it->second.tx;
    return true;
}

std::vector<CTransaction> Mempool::get_sorted_transactions(size_t max_count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<CTransaction> result;
    result.reserve(max_count > 0 ? std::min(max_count, txs_.size()) : txs_.size());

    for (const auto& [fee_rate, txid] : by_fee_rate_) {
        if (max_count > 0 && result.size() >= max_count) break;
        auto it = txs_.find(txid);
        if (it != txs_.end()) {
            result.push_back(it->second.tx);
        }
    }

    return result;
}

std::vector<uint256> Mempool::get_txids() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<uint256> ids;
    ids.reserve(txs_.size());
    for (const auto& [txid, entry] : txs_) {
        ids.push_back(txid);
    }
    return ids;
}

size_t Mempool::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return txs_.size();
}

size_t Mempool::total_bytes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_bytes_;
}

void Mempool::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    txs_.clear();
    by_fee_rate_.clear();
    spent_outpoints_.clear();
    total_bytes_ = 0;
}

bool Mempool::is_spent_by_mempool(const uint256& txid, uint32_t vout) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = std::make_pair(txid, vout);
    return spent_outpoints_.count(key) > 0;
}

bool Mempool::validate_inputs(const CTransaction& tx, Amount& fee_out,
                               std::string& error) const {
    // Compute the signing hash (serialized tx without signatures)
    std::vector<uint8_t> hash_preimage = tx.serialize_for_hash();
    uint256 tx_hash = keccak256d(hash_preimage);

    Amount total_in = 0;
    Amount total_out = 0;

    for (const auto& in : tx.vin) {
        // Look up the output being spent: first in UTXO set, then mempool
        Amount input_value = 0;
        std::array<uint8_t, 32> expected_pubkey_hash{};

        UTXOEntry utxo_entry;
        if (utxo_.get(in.prevout.txid, in.prevout.index, utxo_entry)) {
            input_value = utxo_entry.value;
            expected_pubkey_hash = utxo_entry.pubkey_hash;
        } else {
            // Check if the parent transaction is in the mempool
            auto parent_it = txs_.find(in.prevout.txid);
            if (parent_it == txs_.end()) {
                error = "missing-inputs";
                return false;
            }
            const CTransaction& parent_tx = parent_it->second.tx;
            if (in.prevout.index >= parent_tx.vout.size()) {
                error = "missing-inputs";
                return false;
            }
            const CTxOut& parent_out = parent_tx.vout[in.prevout.index];
            input_value = parent_out.amount;
            expected_pubkey_hash = parent_out.pubkey_hash;
        }

        // Verify pubkey hash: keccak256d(pubkey)[0..31] == expected
        uint256 pk_hash = keccak256d(in.pubkey.data(), 32);
        if (std::memcmp(pk_hash.data(), expected_pubkey_hash.data(), 32) != 0) {
            error = "bad-txns-pubkey-hash-mismatch";
            return false;
        }

        // Verify Ed25519 signature over the transaction hash
        if (!ed25519_verify(tx_hash.data(), 32, in.pubkey.data(),
                            in.signature.data())) {
            error = "bad-txns-signature-invalid";
            return false;
        }

        total_in += input_value;
    }

    // Sum outputs
    for (const auto& out : tx.vout) {
        total_out += out.amount;
    }

    // Fee = inputs - outputs
    fee_out = total_in - total_out;
    if (fee_out < 0) {
        error = "bad-txns-in-belowout";
        return false;
    }

    return true;
}

} // namespace flow

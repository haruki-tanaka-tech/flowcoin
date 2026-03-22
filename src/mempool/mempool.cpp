// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "mempool.h"
#include "core/time.h"

#include <algorithm>

namespace flow {

Mempool::Mempool(size_t max_size_bytes) : max_size_bytes_(max_size_bytes) {}

std::string Mempool::outpoint_key(const COutPoint& op) {
    return op.txid.to_hex() + ":" + std::to_string(op.vout);
}

Result<Ok> Mempool::add(const CTransaction& tx, Amount fee) {
    std::lock_guard lock(mu_);

    Hash256 txid = tx.get_hash();
    std::string txid_hex = txid.to_hex();

    // Reject duplicates
    if (entries_.count(txid_hex)) {
        return Error{"tx-already-in-mempool"};
    }

    // Reject if any input is already spent by another mempool tx
    for (const auto& in : tx.vin) {
        if (in.is_coinbase()) {
            return Error{"coinbase-in-mempool"};
        }
        auto key = outpoint_key(in.prevout);
        if (spent_outpoints_.count(key)) {
            return Error{"txn-mempool-conflict"};
        }
    }

    // Reject negative or zero fee
    if (fee.value < 0) {
        return Error{"negative-fee"};
    }

    auto serialized = tx.serialize();
    size_t tx_size = serialized.size();

    // Evict lowest fee-rate txs if over capacity
    while (current_size_bytes_ + tx_size > max_size_bytes_ && !entries_.empty()) {
        evict_lowest();
    }

    MempoolEntry entry;
    entry.tx = tx;
    entry.txid = txid;
    entry.fee = fee;
    entry.size = tx_size;
    entry.time = get_time();

    double rate = entry.fee_rate();

    // Track spent outpoints
    for (const auto& in : tx.vin) {
        spent_outpoints_[outpoint_key(in.prevout)] = txid_hex;
    }

    by_fee_rate_.emplace(rate, txid_hex);
    entries_.emplace(txid_hex, std::move(entry));
    current_size_bytes_ += tx_size;

    return Ok{};
}

bool Mempool::remove(const Hash256& txid) {
    std::lock_guard lock(mu_);

    std::string txid_hex = txid.to_hex();
    auto it = entries_.find(txid_hex);
    if (it == entries_.end()) return false;

    const auto& entry = it->second;

    // Remove from spent outpoints
    for (const auto& in : entry.tx.vin) {
        spent_outpoints_.erase(outpoint_key(in.prevout));
    }

    // Remove from fee rate index
    double rate = entry.fee_rate();
    auto range = by_fee_rate_.equal_range(rate);
    for (auto fi = range.first; fi != range.second; ++fi) {
        if (fi->second == txid_hex) {
            by_fee_rate_.erase(fi);
            break;
        }
    }

    current_size_bytes_ -= entry.size;
    entries_.erase(it);
    return true;
}

void Mempool::remove_for_block(const std::vector<CTransaction>& txs) {
    for (const auto& tx : txs) {
        remove(tx.get_hash());
    }
}

bool Mempool::has(const Hash256& txid) const {
    std::lock_guard lock(mu_);
    return entries_.count(txid.to_hex()) > 0;
}

std::optional<MempoolEntry> Mempool::get(const Hash256& txid) const {
    std::lock_guard lock(mu_);
    auto it = entries_.find(txid.to_hex());
    if (it == entries_.end()) return std::nullopt;
    return it->second;
}

std::vector<CTransaction> Mempool::get_sorted(size_t max_count) const {
    std::lock_guard lock(mu_);

    std::vector<CTransaction> result;
    result.reserve(std::min(max_count, entries_.size()));

    for (const auto& [rate, txid_hex] : by_fee_rate_) {
        if (result.size() >= max_count) break;
        auto it = entries_.find(txid_hex);
        if (it != entries_.end()) {
            result.push_back(it->second.tx);
        }
    }

    return result;
}

bool Mempool::is_spent(const COutPoint& outpoint) const {
    std::lock_guard lock(mu_);
    return spent_outpoints_.count(outpoint_key(outpoint)) > 0;
}

size_t Mempool::size() const {
    std::lock_guard lock(mu_);
    return entries_.size();
}

void Mempool::evict_lowest() {
    // Remove the lowest fee-rate transaction (last in the multimap)
    if (by_fee_rate_.empty()) return;

    auto lowest = std::prev(by_fee_rate_.end());
    std::string txid_hex = lowest->second;
    by_fee_rate_.erase(lowest);

    auto it = entries_.find(txid_hex);
    if (it != entries_.end()) {
        for (const auto& in : it->second.tx.vin) {
            spent_outpoints_.erase(outpoint_key(in.prevout));
        }
        current_size_bytes_ -= it->second.size;
        entries_.erase(it);
    }
}

} // namespace flow

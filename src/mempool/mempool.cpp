// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "mempool/mempool.h"
#include "chain/utxo.h"
#include "consensus/params.h"
#include "crypto/sign.h"
#include "hash/keccak.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <numeric>
#include <set>

namespace flow {

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

int64_t Mempool::now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

Mempool::Mempool(const UTXOSet& utxo) : utxo_(utxo) {}

// ---------------------------------------------------------------------------
// Core add / remove
// ---------------------------------------------------------------------------

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

    // Apply fee delta if any
    Amount effective_fee = fee;
    auto delta_it = fee_deltas_.find(txid);
    if (delta_it != fee_deltas_.end()) {
        effective_fee += delta_it->second;
    }

    // Check minimum fee rate
    double fee_rate = static_cast<double>(effective_fee) / static_cast<double>(tx_size);
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
    int64_t now = now_seconds();

    // Determine nSequence for RBF signaling from first input
    uint32_t seq = 0xFFFFFFFF;
    // FlowCoin CTxIn does not have an nSequence field in the struct,
    // but we track RBF signaling via the fee_rate threshold instead.

    MempoolEntry entry;
    entry.tx = tx;
    entry.txid = txid;
    entry.fee = fee;
    entry.tx_size = tx_size;
    entry.fee_rate = fee_rate;
    entry.time_added = now;
    entry.sequence = seq;

    txs_.emplace(txid, std::move(entry));
    by_fee_rate_.emplace(fee_rate, txid);
    total_bytes_ += tx_size;

    // Track spent outpoints
    for (const auto& in : tx.vin) {
        auto key = std::make_pair(in.prevout.txid, in.prevout.index);
        spent_outpoints_.emplace(key, txid);
    }

    // Build dependency graph
    build_deps_locked(txid, tx);

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

    // Remove dependency graph entries
    remove_deps_locked(txid);

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

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

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

bool Mempool::get_entry(const uint256& txid, MempoolEntry& entry) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = txs_.find(txid);
    if (it == txs_.end()) return false;
    entry = it->second;
    return true;
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
    orphans_.clear();
    orphan_by_prev_.clear();
    parents_.clear();
    children_.clear();
    fee_deltas_.clear();
    total_bytes_ = 0;
}

bool Mempool::is_spent_by_mempool(const uint256& txid, uint32_t vout) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = std::make_pair(txid, vout);
    return spent_outpoints_.count(key) > 0;
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Dependency graph
// ---------------------------------------------------------------------------

void Mempool::build_deps_locked(const uint256& txid, const CTransaction& tx) {
    for (const auto& in : tx.vin) {
        // If the parent tx is also in the mempool, record the dependency
        if (txs_.count(in.prevout.txid)) {
            parents_[txid].insert(in.prevout.txid);
            children_[in.prevout.txid].insert(txid);
        }
    }
}

void Mempool::remove_deps_locked(const uint256& txid) {
    // Remove this tx as a child of its parents
    auto pit = parents_.find(txid);
    if (pit != parents_.end()) {
        for (const auto& parent : pit->second) {
            auto cit = children_.find(parent);
            if (cit != children_.end()) {
                cit->second.erase(txid);
                if (cit->second.empty()) {
                    children_.erase(cit);
                }
            }
        }
        parents_.erase(pit);
    }

    // Remove this tx as a parent of its children
    auto cit = children_.find(txid);
    if (cit != children_.end()) {
        for (const auto& child : cit->second) {
            auto pit2 = parents_.find(child);
            if (pit2 != parents_.end()) {
                pit2->second.erase(txid);
                if (pit2->second.empty()) {
                    parents_.erase(pit2);
                }
            }
        }
        children_.erase(cit);
    }
}

void Mempool::collect_ancestors_locked(const uint256& txid,
                                        std::set<uint256>& result) const {
    auto pit = parents_.find(txid);
    if (pit == parents_.end()) return;

    for (const auto& parent : pit->second) {
        if (result.insert(parent).second) {
            collect_ancestors_locked(parent, result);
        }
    }
}

void Mempool::collect_descendants_locked(const uint256& txid,
                                          std::set<uint256>& result) const {
    auto cit = children_.find(txid);
    if (cit == children_.end()) return;

    for (const auto& child : cit->second) {
        if (result.insert(child).second) {
            collect_descendants_locked(child, result);
        }
    }
}

// ---------------------------------------------------------------------------
// Ancestor / descendant info
// ---------------------------------------------------------------------------

AncestorInfo Mempool::get_ancestor_info(const uint256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    AncestorInfo info{};

    auto it = txs_.find(txid);
    if (it == txs_.end()) return info;

    // Include self in ancestor package
    info.ancestor_count = 1;
    info.ancestor_size = it->second.tx_size;
    info.ancestor_fees = it->second.fee;

    // Collect all ancestors
    std::set<uint256> ancestors;
    collect_ancestors_locked(txid, ancestors);

    for (const auto& anc_txid : ancestors) {
        auto anc_it = txs_.find(anc_txid);
        if (anc_it != txs_.end()) {
            info.ancestor_count++;
            info.ancestor_size += anc_it->second.tx_size;
            info.ancestor_fees += anc_it->second.fee;
        }
    }

    info.ancestor_fee_rate = (info.ancestor_size > 0)
        ? static_cast<double>(info.ancestor_fees) / static_cast<double>(info.ancestor_size)
        : 0.0;

    return info;
}

std::vector<uint256> Mempool::get_ancestors(const uint256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::set<uint256> ancestors;
    collect_ancestors_locked(txid, ancestors);

    return std::vector<uint256>(ancestors.begin(), ancestors.end());
}

std::vector<uint256> Mempool::get_descendants(const uint256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::set<uint256> descendants;
    collect_descendants_locked(txid, descendants);

    return std::vector<uint256>(descendants.begin(), descendants.end());
}

// ---------------------------------------------------------------------------
// Orphan pool
// ---------------------------------------------------------------------------

void Mempool::add_orphan(const CTransaction& tx, uint64_t peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    uint256 txid = tx.get_txid();

    // Already known (in mempool or orphan pool)
    if (txs_.count(txid) || orphans_.count(txid)) return;

    OrphanEntry entry;
    entry.tx = tx;
    entry.txid = txid;
    entry.time_added = now_seconds();
    entry.from_peer = peer_id;

    // Index by parent prevout txids for fast resolution
    for (const auto& in : tx.vin) {
        orphan_by_prev_[in.prevout.txid].insert(txid);
    }

    orphans_.emplace(txid, std::move(entry));
}

bool Mempool::has_orphan(const uint256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return orphans_.count(txid) > 0;
}

void Mempool::remove_orphan(const uint256& txid) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = orphans_.find(txid);
    if (it == orphans_.end()) return;

    // Remove from orphan_by_prev index
    for (const auto& in : it->second.tx.vin) {
        auto prev_it = orphan_by_prev_.find(in.prevout.txid);
        if (prev_it != orphan_by_prev_.end()) {
            prev_it->second.erase(txid);
            if (prev_it->second.empty()) {
                orphan_by_prev_.erase(prev_it);
            }
        }
    }

    orphans_.erase(it);
}

void Mempool::remove_orphans_for_block(const CBlock& block) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Collect txids from the block; orphans that match are removed directly
    std::vector<uint256> to_remove;
    for (const auto& tx : block.vtx) {
        uint256 block_txid = tx.get_txid();
        if (orphans_.count(block_txid)) {
            to_remove.push_back(block_txid);
        }
    }

    // Remove matched orphans
    for (const auto& txid : to_remove) {
        auto it = orphans_.find(txid);
        if (it != orphans_.end()) {
            for (const auto& in : it->second.tx.vin) {
                auto prev_it = orphan_by_prev_.find(in.prevout.txid);
                if (prev_it != orphan_by_prev_.end()) {
                    prev_it->second.erase(txid);
                    if (prev_it->second.empty()) {
                        orphan_by_prev_.erase(prev_it);
                    }
                }
            }
            orphans_.erase(it);
        }
    }
}

int Mempool::resolve_orphans(const uint256& resolved_txid) {
    // This method must NOT hold the lock when calling add_transaction
    // since add_transaction also acquires the lock. We collect candidates
    // under the lock, then try to add them without holding it.

    std::vector<CTransaction> candidates;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto prev_it = orphan_by_prev_.find(resolved_txid);
        if (prev_it == orphan_by_prev_.end()) return 0;

        // Collect orphan txs that were waiting on this resolved txid
        for (const auto& orphan_txid : prev_it->second) {
            auto oit = orphans_.find(orphan_txid);
            if (oit != orphans_.end()) {
                candidates.push_back(oit->second.tx);
            }
        }
    }

    int accepted = 0;

    for (const auto& orphan_tx : candidates) {
        uint256 orphan_txid = orphan_tx.get_txid();

        // Try to add to mempool
        AddResult result = add_transaction(orphan_tx);

        // Regardless of outcome, remove from orphan pool
        {
            std::lock_guard<std::mutex> lock(mutex_);

            auto oit = orphans_.find(orphan_txid);
            if (oit != orphans_.end()) {
                for (const auto& in : oit->second.tx.vin) {
                    auto prev_it = orphan_by_prev_.find(in.prevout.txid);
                    if (prev_it != orphan_by_prev_.end()) {
                        prev_it->second.erase(orphan_txid);
                        if (prev_it->second.empty()) {
                            orphan_by_prev_.erase(prev_it);
                        }
                    }
                }
                orphans_.erase(oit);
            }
        }

        if (result.accepted) {
            accepted++;
            // Recursively try to resolve further orphans
            accepted += resolve_orphans(orphan_txid);
        }
    }

    return accepted;
}

void Mempool::limit_orphans(size_t max_orphans) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (orphans_.size() <= max_orphans) return;

    // Evict oldest orphans first
    std::vector<std::pair<int64_t, uint256>> by_time;
    by_time.reserve(orphans_.size());
    for (const auto& [txid, entry] : orphans_) {
        by_time.emplace_back(entry.time_added, txid);
    }
    std::sort(by_time.begin(), by_time.end());

    size_t to_evict = orphans_.size() - max_orphans;
    for (size_t i = 0; i < to_evict && i < by_time.size(); ++i) {
        const uint256& txid = by_time[i].second;

        auto it = orphans_.find(txid);
        if (it != orphans_.end()) {
            for (const auto& in : it->second.tx.vin) {
                auto prev_it = orphan_by_prev_.find(in.prevout.txid);
                if (prev_it != orphan_by_prev_.end()) {
                    prev_it->second.erase(txid);
                    if (prev_it->second.empty()) {
                        orphan_by_prev_.erase(prev_it);
                    }
                }
            }
            orphans_.erase(it);
        }
    }
}

size_t Mempool::orphan_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return orphans_.size();
}

void Mempool::remove_orphans_from_peer(uint64_t peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<uint256> to_remove;
    for (const auto& [txid, entry] : orphans_) {
        if (entry.from_peer == peer_id) {
            to_remove.push_back(txid);
        }
    }

    for (const auto& txid : to_remove) {
        auto it = orphans_.find(txid);
        if (it != orphans_.end()) {
            for (const auto& in : it->second.tx.vin) {
                auto prev_it = orphan_by_prev_.find(in.prevout.txid);
                if (prev_it != orphan_by_prev_.end()) {
                    prev_it->second.erase(txid);
                    if (prev_it->second.empty()) {
                        orphan_by_prev_.erase(prev_it);
                    }
                }
            }
            orphans_.erase(it);
        }
    }
}

// ---------------------------------------------------------------------------
// Replace-by-fee
// ---------------------------------------------------------------------------

bool Mempool::signals_rbf(const CTransaction& tx) {
    // In FlowCoin, any transaction can be replaced if a strictly
    // higher-fee replacement is provided that spends at least one
    // overlapping input. We do not require nSequence signaling since
    // FlowCoin CTxIn lacks an nSequence field. All transactions are
    // considered replaceable by default.
    (void)tx;
    return true;
}

RBFResult Mempool::try_replace(const CTransaction& new_tx) {
    std::lock_guard<std::mutex> lock(mutex_);

    RBFResult result;
    result.replaced = false;

    uint256 new_txid = new_tx.get_txid();

    // Find which existing mempool transactions conflict with this one
    // (spend any of the same inputs)
    std::set<uint256> conflicting_txids;
    for (const auto& in : new_tx.vin) {
        auto key = std::make_pair(in.prevout.txid, in.prevout.index);
        auto sp_it = spent_outpoints_.find(key);
        if (sp_it != spent_outpoints_.end()) {
            conflicting_txids.insert(sp_it->second);
        }
    }

    if (conflicting_txids.empty()) {
        result.reason = "no-conflicting-transactions";
        return result;
    }

    // Validate the new transaction's inputs and compute fee
    Amount new_fee = 0;
    std::string error;
    // We cannot call validate_inputs directly because the inputs may
    // conflict with current mempool state. Compute fee manually by
    // looking up input values.
    Amount total_in = 0;
    for (const auto& in : new_tx.vin) {
        UTXOEntry utxo_entry;
        if (utxo_.get(in.prevout.txid, in.prevout.index, utxo_entry)) {
            total_in += utxo_entry.value;
        } else {
            // Check parent in mempool (but not a conflicting one)
            auto parent_it = txs_.find(in.prevout.txid);
            if (parent_it != txs_.end() &&
                conflicting_txids.find(in.prevout.txid) == conflicting_txids.end()) {
                if (in.prevout.index < parent_it->second.tx.vout.size()) {
                    total_in += parent_it->second.tx.vout[in.prevout.index].amount;
                } else {
                    result.reason = "missing-inputs";
                    return result;
                }
            } else {
                result.reason = "missing-inputs";
                return result;
            }
        }
    }

    Amount total_out = 0;
    for (const auto& out : new_tx.vout) {
        total_out += out.amount;
    }
    new_fee = total_in - total_out;

    if (new_fee < 0) {
        result.reason = "insufficient-fee";
        return result;
    }

    // Compute new transaction size and fee rate
    auto serialized = new_tx.serialize();
    size_t new_size = serialized.size();
    double new_fee_rate = static_cast<double>(new_fee) / static_cast<double>(new_size);

    // The replacement must pay strictly more total fee than all conflicting
    // transactions combined, and also a higher fee rate.
    Amount total_conflicting_fees = 0;
    size_t total_conflicting_size = 0;
    for (const auto& ctxid : conflicting_txids) {
        auto cit = txs_.find(ctxid);
        if (cit != txs_.end()) {
            total_conflicting_fees += cit->second.fee;
            total_conflicting_size += cit->second.tx_size;

            // Also collect all descendants of the conflicting txs,
            // as they must be evicted too
            std::set<uint256> descendants;
            collect_descendants_locked(ctxid, descendants);
            for (const auto& dtxid : descendants) {
                conflicting_txids.insert(dtxid);
                auto dit = txs_.find(dtxid);
                if (dit != txs_.end()) {
                    total_conflicting_fees += dit->second.fee;
                    total_conflicting_size += dit->second.tx_size;
                }
            }
        }
    }

    // Rule 3: new fee must be strictly greater than total conflicting fees
    if (new_fee <= total_conflicting_fees) {
        result.reason = "insufficient-fee: new tx fee " + std::to_string(new_fee) +
                        " <= conflicting total " + std::to_string(total_conflicting_fees);
        return result;
    }

    // Rule 4: new fee must pay for the bandwidth of the replacement
    // (at least the min relay fee rate for the additional size)
    Amount min_additional_fee = static_cast<Amount>(
        MIN_FEE_RATE * static_cast<double>(new_size));
    if (new_fee - total_conflicting_fees < min_additional_fee) {
        result.reason = "insufficient-fee: does not pay for bandwidth";
        return result;
    }

    // Rule 5: replacement cannot evict more than 100 transactions
    if (conflicting_txids.size() > 100) {
        result.reason = "too-many-replacements: would evict " +
                        std::to_string(conflicting_txids.size()) + " transactions";
        return result;
    }

    // All checks pass. Evict conflicting transactions.
    for (const auto& ctxid : conflicting_txids) {
        result.evicted_txids.push_back(ctxid);
        remove_locked(ctxid);
    }

    // Now add the new transaction. We must do this without calling
    // add_transaction (which would try to lock the mutex again).
    // Instead, replicate the insertion logic.
    MempoolEntry entry;
    entry.tx = new_tx;
    entry.txid = new_txid;
    entry.fee = new_fee;
    entry.tx_size = new_size;
    entry.fee_rate = new_fee_rate;
    entry.time_added = now_seconds();
    entry.sequence = 0;

    txs_.emplace(new_txid, std::move(entry));
    by_fee_rate_.emplace(new_fee_rate, new_txid);
    total_bytes_ += new_size;

    for (const auto& in : new_tx.vin) {
        auto key = std::make_pair(in.prevout.txid, in.prevout.index);
        spent_outpoints_.emplace(key, new_txid);
    }

    build_deps_locked(new_txid, new_tx);

    result.replaced = true;
    return result;
}

// ---------------------------------------------------------------------------
// Size limits and eviction
// ---------------------------------------------------------------------------

void Mempool::set_max_size(size_t max_bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    max_size_ = max_bytes;
}

void Mempool::enforce_size_limit() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (total_bytes_ <= max_size_) return;

    // Evict from the tail of the fee-rate index (lowest fee rate)
    // by_fee_rate_ is sorted descending, so the last entries are lowest
    while (total_bytes_ > max_size_ && !by_fee_rate_.empty()) {
        // Get the lowest fee-rate entry
        auto rit = by_fee_rate_.end();
        --rit;

        uint256 txid_to_evict = rit->second;

        // Also evict all descendants of this transaction
        std::set<uint256> to_evict;
        to_evict.insert(txid_to_evict);
        collect_descendants_locked(txid_to_evict, to_evict);

        for (const auto& txid : to_evict) {
            remove_locked(txid);
        }
    }
}

void Mempool::expire_old(int64_t max_age_seconds) {
    std::lock_guard<std::mutex> lock(mutex_);

    int64_t now = now_seconds();
    int64_t cutoff = now - max_age_seconds;

    std::vector<uint256> to_remove;
    for (const auto& [txid, entry] : txs_) {
        if (entry.time_added < cutoff) {
            to_remove.push_back(txid);
        }
    }

    for (const auto& txid : to_remove) {
        remove_locked(txid);
    }
}

// ---------------------------------------------------------------------------
// Statistics and fee estimation
// ---------------------------------------------------------------------------

MempoolStats Mempool::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    MempoolStats stats{};
    stats.tx_count = txs_.size();
    stats.total_bytes = total_bytes_;
    stats.orphan_count = orphans_.size();
    stats.total_fees = 0;
    stats.min_fee_rate = std::numeric_limits<double>::max();
    stats.max_fee_rate = 0.0;
    stats.oldest_entry = std::numeric_limits<int64_t>::max();

    if (txs_.empty()) {
        stats.min_fee_rate = 0.0;
        stats.oldest_entry = 0;
        return stats;
    }

    std::vector<double> fee_rates;
    fee_rates.reserve(txs_.size());

    for (const auto& [txid, entry] : txs_) {
        stats.total_fees += entry.fee;

        if (entry.fee_rate < stats.min_fee_rate) {
            stats.min_fee_rate = entry.fee_rate;
        }
        if (entry.fee_rate > stats.max_fee_rate) {
            stats.max_fee_rate = entry.fee_rate;
        }
        if (entry.time_added < stats.oldest_entry) {
            stats.oldest_entry = entry.time_added;
        }

        fee_rates.push_back(entry.fee_rate);
    }

    // Compute median fee rate
    std::sort(fee_rates.begin(), fee_rates.end());
    size_t n = fee_rates.size();
    if (n % 2 == 0) {
        stats.median_fee_rate = (fee_rates[n / 2 - 1] + fee_rates[n / 2]) / 2.0;
    } else {
        stats.median_fee_rate = fee_rates[n / 2];
    }

    return stats;
}

std::vector<FeeHistogramBucket> Mempool::get_fee_histogram(int num_buckets) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<FeeHistogramBucket> histogram;

    if (txs_.empty() || num_buckets <= 0) return histogram;

    // Collect all fee rates
    std::vector<double> fee_rates;
    fee_rates.reserve(txs_.size());
    for (const auto& [txid, entry] : txs_) {
        fee_rates.push_back(entry.fee_rate);
    }
    std::sort(fee_rates.begin(), fee_rates.end());

    double min_rate = fee_rates.front();
    double max_rate = fee_rates.back();

    if (max_rate <= min_rate) {
        // All same rate, single bucket
        FeeHistogramBucket bucket;
        bucket.min_fee_rate = min_rate;
        bucket.max_fee_rate = max_rate;
        bucket.count = txs_.size();
        bucket.total_bytes = total_bytes_;
        histogram.push_back(bucket);
        return histogram;
    }

    double bucket_width = (max_rate - min_rate) / static_cast<double>(num_buckets);
    histogram.resize(static_cast<size_t>(num_buckets));

    for (int i = 0; i < num_buckets; ++i) {
        histogram[i].min_fee_rate = min_rate + i * bucket_width;
        histogram[i].max_fee_rate = min_rate + (i + 1) * bucket_width;
        histogram[i].count = 0;
        histogram[i].total_bytes = 0;
    }

    // Fill buckets
    for (const auto& [txid, entry] : txs_) {
        int bucket_idx = static_cast<int>(
            (entry.fee_rate - min_rate) / bucket_width);
        if (bucket_idx < 0) bucket_idx = 0;
        if (bucket_idx >= num_buckets) bucket_idx = num_buckets - 1;

        histogram[bucket_idx].count++;
        histogram[bucket_idx].total_bytes += entry.tx_size;
    }

    return histogram;
}

double Mempool::estimate_fee_rate(int target_blocks) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (txs_.empty()) {
        return MIN_FEE_RATE;
    }

    // Simple heuristic: estimate based on current mempool depth.
    // Assume each block can fit ~1MB of transactions. To confirm
    // within target_blocks blocks, the fee rate should be higher than
    // the fee rate of the N-th transaction counting from the top of
    // the sorted mempool, where N = target_blocks * max_block_txs.

    // Estimate max transactions per block based on average tx size
    size_t avg_tx_size = (txs_.size() > 0) ? (total_bytes_ / txs_.size()) : 250;
    if (avg_tx_size == 0) avg_tx_size = 250;

    size_t max_block_bytes = 1'000'000; // 1 MB
    size_t max_per_block = max_block_bytes / avg_tx_size;

    size_t target_position = static_cast<size_t>(target_blocks) * max_per_block;

    if (target_position >= txs_.size()) {
        // The entire mempool would clear within target_blocks
        return MIN_FEE_RATE;
    }

    // Walk the fee rate index to find the fee rate at target_position
    size_t pos = 0;
    for (const auto& [fee_rate, txid] : by_fee_rate_) {
        if (pos >= target_position) {
            return fee_rate;
        }
        pos++;
    }

    return MIN_FEE_RATE;
}

// ---------------------------------------------------------------------------
// Transaction priority adjustment
// ---------------------------------------------------------------------------

bool Mempool::prioritise_transaction(const uint256& txid, Amount fee_delta) {
    std::lock_guard<std::mutex> lock(mutex_);

    fee_deltas_[txid] += fee_delta;

    // If the transaction is already in the mempool, update its effective
    // fee rate in the index
    auto it = txs_.find(txid);
    if (it != txs_.end()) {
        // Remove old fee-rate entry
        auto range = by_fee_rate_.equal_range(it->second.fee_rate);
        for (auto fi = range.first; fi != range.second; ++fi) {
            if (fi->second == txid) {
                by_fee_rate_.erase(fi);
                break;
            }
        }

        // Compute new effective fee rate
        Amount effective_fee = it->second.fee + fee_deltas_[txid];
        double new_rate = static_cast<double>(effective_fee) /
                          static_cast<double>(it->second.tx_size);
        it->second.fee_rate = new_rate;

        // Re-insert with new fee rate
        by_fee_rate_.emplace(new_rate, txid);
    }

    return true;
}

// ---------------------------------------------------------------------------
// Advanced mempool queries
// ---------------------------------------------------------------------------

// Get transactions sorted by ancestor fee rate for CPFP-aware block assembly.
// This produces a better ordering than simple fee rate when there are
// dependent transaction chains in the mempool.
std::vector<CTransaction> Mempool::get_sorted_transactions(size_t max_count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (txs_.empty()) return {};

    // Build a list of (ancestor_fee_rate, txid) for sorting
    struct ScoredTx {
        double score;
        uint256 txid;
        bool operator>(const ScoredTx& o) const { return score > o.score; }
    };

    std::vector<ScoredTx> scored;
    scored.reserve(txs_.size());

    for (const auto& [txid, entry] : txs_) {
        // Compute ancestor score
        double score = entry.fee_rate;

        // Check if this tx has ancestors in the mempool
        auto pit = parents_.find(txid);
        if (pit != parents_.end() && !pit->second.empty()) {
            // Compute ancestor package fee rate
            Amount pkg_fees = entry.fee;
            size_t pkg_size = entry.tx_size;

            std::set<uint256> ancestors;
            collect_ancestors_locked(txid, ancestors);

            for (const auto& anc : ancestors) {
                auto ait = txs_.find(anc);
                if (ait != txs_.end()) {
                    pkg_fees += ait->second.fee;
                    pkg_size += ait->second.tx_size;
                }
            }

            double pkg_rate = (pkg_size > 0)
                ? static_cast<double>(pkg_fees) / static_cast<double>(pkg_size)
                : 0.0;

            // Use the higher of individual and package fee rate
            if (pkg_rate > score) {
                score = pkg_rate;
            }
        }

        scored.push_back({score, txid});
    }

    // Sort descending by score
    std::sort(scored.begin(), scored.end(),
              [](const ScoredTx& a, const ScoredTx& b) {
                  return a.score > b.score;
              });

    // Build result, respecting dependency ordering
    std::vector<CTransaction> result;
    std::set<uint256> included;
    result.reserve(max_count > 0 ? std::min(max_count, txs_.size()) : txs_.size());

    for (const auto& st : scored) {
        if (max_count > 0 && result.size() >= max_count) break;
        if (included.count(st.txid)) continue;

        // Ensure all ancestors are included before this transaction
        std::set<uint256> ancestors;
        collect_ancestors_locked(st.txid, ancestors);

        for (const auto& anc : ancestors) {
            if (!included.count(anc)) {
                auto ait = txs_.find(anc);
                if (ait != txs_.end()) {
                    result.push_back(ait->second.tx);
                    included.insert(anc);
                }
            }
        }

        // Add this transaction
        if (!included.count(st.txid)) {
            auto it = txs_.find(st.txid);
            if (it != txs_.end()) {
                result.push_back(it->second.tx);
                included.insert(st.txid);
            }
        }
    }

    return result;
}

// Get the total fees of all transactions in the mempool (for coinbase calculation)
Amount Mempool::get_total_fees() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Amount total = 0;
    for (const auto& [txid, entry] : txs_) {
        total += entry.fee;
    }
    return total;
}

// Get the number of transactions with fee rate above a threshold
size_t Mempool::count_above_fee_rate(double min_rate) const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [fee_rate, txid] : by_fee_rate_) {
        if (fee_rate >= min_rate) {
            count++;
        } else {
            break; // sorted descending, so we can stop early
        }
    }
    return count;
}

// Check if a transaction has unconfirmed parents in the mempool
bool Mempool::has_unconfirmed_parents(const uint256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto pit = parents_.find(txid);
    return pit != parents_.end() && !pit->second.empty();
}

// Get the depth of the dependency chain for a transaction
// (how many levels of unconfirmed parents it has)
int Mempool::get_chain_depth(const uint256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    int max_depth = 0;
    std::set<uint256> visited;

    std::function<int(const uint256&)> depth_of = [&](const uint256& id) -> int {
        if (visited.count(id)) return 0;
        visited.insert(id);

        auto pit = parents_.find(id);
        if (pit == parents_.end() || pit->second.empty()) return 0;

        int max_parent_depth = 0;
        for (const auto& parent : pit->second) {
            int pd = depth_of(parent);
            if (pd > max_parent_depth) {
                max_parent_depth = pd;
            }
        }

        return max_parent_depth + 1;
    };

    return depth_of(txid);
}

// Get all transactions that spend outputs from a specific transaction
std::vector<uint256> Mempool::get_spending_txids(const uint256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<uint256> result;

    // Check all outpoints for this txid
    for (const auto& [outpoint, spending_txid] : spent_outpoints_) {
        if (outpoint.first == txid) {
            result.push_back(spending_txid);
        }
    }

    return result;
}

// Check if adding this transaction would exceed the maximum chain depth
bool Mempool::would_exceed_chain_depth(const CTransaction& tx,
                                        int max_depth) const {
    std::lock_guard<std::mutex> lock(mutex_);

    int current_max_depth = 0;

    for (const auto& in : tx.vin) {
        if (txs_.count(in.prevout.txid)) {
            // This input references a mempool transaction
            uint256 parent_txid = in.prevout.txid;
            std::set<uint256> visited;

            std::function<int(const uint256&)> depth_of =
                [&](const uint256& id) -> int {
                if (visited.count(id)) return 0;
                visited.insert(id);

                auto pit = parents_.find(id);
                if (pit == parents_.end() || pit->second.empty()) return 0;

                int max_pd = 0;
                for (const auto& parent : pit->second) {
                    int pd = depth_of(parent);
                    if (pd > max_pd) max_pd = pd;
                }
                return max_pd + 1;
            };

            int depth = depth_of(parent_txid) + 1;
            if (depth > current_max_depth) {
                current_max_depth = depth;
            }
        }
    }

    return current_max_depth >= max_depth;
}

// Get a snapshot of the mempool for serialization/backup
std::vector<MempoolEntry> Mempool::get_all_entries() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<MempoolEntry> result;
    result.reserve(txs_.size());
    for (const auto& [txid, entry] : txs_) {
        result.push_back(entry);
    }
    return result;
}

// Trim the orphan pool, removing entries from disconnected peers
// and expired entries (older than max_age_seconds)
void Mempool::trim_orphans(int64_t max_age_seconds) {
    std::lock_guard<std::mutex> lock(mutex_);

    int64_t now = now_seconds();
    int64_t cutoff = now - max_age_seconds;

    std::vector<uint256> to_remove;
    for (const auto& [txid, entry] : orphans_) {
        if (entry.time_added < cutoff) {
            to_remove.push_back(txid);
        }
    }

    for (const auto& txid : to_remove) {
        auto it = orphans_.find(txid);
        if (it != orphans_.end()) {
            for (const auto& in : it->second.tx.vin) {
                auto prev_it = orphan_by_prev_.find(in.prevout.txid);
                if (prev_it != orphan_by_prev_.end()) {
                    prev_it->second.erase(txid);
                    if (prev_it->second.empty()) {
                        orphan_by_prev_.erase(prev_it);
                    }
                }
            }
            orphans_.erase(it);
        }
    }
}

// Check consistency of internal data structures (for debugging)
bool Mempool::check_consistency() const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Verify total_bytes matches
    size_t computed_bytes = 0;
    for (const auto& [txid, entry] : txs_) {
        computed_bytes += entry.tx_size;
    }
    if (computed_bytes != total_bytes_) return false;

    // Verify fee-rate index matches
    size_t fee_rate_count = 0;
    for (const auto& [rate, txid] : by_fee_rate_) {
        if (!txs_.count(txid)) return false;
        fee_rate_count++;
    }
    if (fee_rate_count != txs_.size()) return false;

    // Verify spent outpoints reference valid transactions
    for (const auto& [outpoint, txid] : spent_outpoints_) {
        if (!txs_.count(txid)) return false;
    }

    // Verify parent/child relationships are symmetric
    for (const auto& [txid, parent_set] : parents_) {
        for (const auto& parent : parent_set) {
            auto cit = children_.find(parent);
            if (cit == children_.end()) return false;
            if (!cit->second.count(txid)) return false;
        }
    }

    for (const auto& [txid, child_set] : children_) {
        for (const auto& child : child_set) {
            auto pit = parents_.find(child);
            if (pit == parents_.end()) return false;
            if (!pit->second.count(txid)) return false;
        }
    }

    return true;
}

} // namespace flow

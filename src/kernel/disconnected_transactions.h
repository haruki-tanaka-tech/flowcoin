// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// DisconnectedBlockTransactions: temporary storage for transactions
// that were removed from the chain during a block disconnection (reorg).
// These transactions need to be re-added to the mempool if they are
// still valid under the new chain tip.
//
// During a reorg from chain A to chain B:
//   1. Disconnect blocks from A back to the fork point
//   2. Each disconnected block's transactions go into DisconnectedTxs
//   3. Connect blocks from fork point to B tip
//   4. Add DisconnectedTxs back to mempool (minus those in B blocks)
//
// This module prevents transaction loss during reorgs.

#ifndef FLOWCOIN_KERNEL_DISCONNECTED_TRANSACTIONS_H
#define FLOWCOIN_KERNEL_DISCONNECTED_TRANSACTIONS_H

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/types.h"

#include <cstdint>
#include <list>
#include <map>
#include <set>
#include <vector>

namespace flow::kernel {

// ============================================================================
// DisconnectedBlockTransactions
// ============================================================================

class DisconnectedBlockTransactions {
public:
    DisconnectedBlockTransactions() = default;

    /// Add all transactions from a disconnected block.
    /// Transactions are stored in reverse block order (last block first)
    /// so that when re-adding to the mempool, dependencies are respected.
    /// Coinbase transactions are excluded (they become invalid after disconnect).
    void add_block(const CBlock& block) {
        // Skip coinbase (index 0), add all other transactions
        for (size_t i = 1; i < block.vtx.size(); ++i) {
            const CTransaction& tx = block.vtx[i];
            uint256 txid = tx.get_txid();

            // Don't add duplicates
            if (tx_ids_.count(txid)) continue;

            tx_ids_.insert(txid);
            transactions_.push_front(tx);
        }

        ++blocks_disconnected_;
    }

    /// Remove a transaction (e.g., because it was included in a newly
    /// connected block on the alternative chain).
    void remove_tx(const uint256& txid) {
        if (tx_ids_.erase(txid) == 0) return;

        transactions_.remove_if([&txid](const CTransaction& tx) {
            return tx.get_txid() == txid;
        });
    }

    /// Remove all transactions that appear in a connected block.
    /// Called when connecting blocks on the new chain after a reorg.
    void remove_for_block(const CBlock& block) {
        for (const auto& tx : block.vtx) {
            remove_tx(tx.get_txid());
        }
    }

    /// Get all remaining disconnected transactions.
    /// These should be re-validated and added to the mempool.
    /// Returns transactions in dependency order (parents before children).
    const std::list<CTransaction>& get_transactions() const {
        return transactions_;
    }

    /// Get the number of remaining transactions.
    size_t size() const { return transactions_.size(); }

    /// Check if empty.
    bool empty() const { return transactions_.empty(); }

    /// Get the number of blocks that were disconnected.
    size_t blocks_disconnected() const { return blocks_disconnected_; }

    /// Clear all stored transactions.
    void clear() {
        transactions_.clear();
        tx_ids_.clear();
        blocks_disconnected_ = 0;
    }

    /// Check if a specific transaction is in the disconnected set.
    bool contains(const uint256& txid) const {
        return tx_ids_.count(txid) > 0;
    }

    /// Get the total serialized size of all stored transactions.
    size_t get_total_size() const {
        size_t total = 0;
        for (const auto& tx : transactions_) {
            total += tx.serialize().size();
        }
        return total;
    }

    /// Enforce a memory limit. If total size exceeds max_bytes,
    /// drop the oldest transactions (from the tail of the list).
    /// Returns the number of transactions dropped.
    size_t limit_memory(size_t max_bytes) {
        size_t dropped = 0;
        while (!transactions_.empty() && get_total_size() > max_bytes) {
            uint256 txid = transactions_.back().get_txid();
            tx_ids_.erase(txid);
            transactions_.pop_back();
            ++dropped;
        }
        return dropped;
    }

private:
    /// Transactions in reverse-block order (most recently disconnected first).
    std::list<CTransaction> transactions_;

    /// Fast lookup set for txids.
    std::set<uint256> tx_ids_;

    /// Number of blocks that contributed transactions.
    size_t blocks_disconnected_ = 0;
};

} // namespace flow::kernel

#endif // FLOWCOIN_KERNEL_DISCONNECTED_TRANSACTIONS_H

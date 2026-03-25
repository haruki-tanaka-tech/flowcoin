// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Transaction mempool: holds unconfirmed transactions awaiting inclusion
// in a block. Provides fee-rate sorting for block assembly, double-spend
// detection within the pool, full input validation against the UTXO set,
// orphan transaction management, ancestor/descendant tracking for CPFP,
// replace-by-fee (RBF) support, size-based eviction, and fee estimation.

#ifndef FLOWCOIN_MEMPOOL_H
#define FLOWCOIN_MEMPOOL_H

#include "util/types.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "chain/blockindex.h"  // Uint256Hasher

#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace flow {

class UTXOSet;

// ---------------------------------------------------------------------------
// Mempool entry: a single transaction in the pool
// ---------------------------------------------------------------------------

struct MempoolEntry {
    CTransaction tx;
    uint256 txid;
    Amount fee;           // total input - total output
    size_t tx_size;       // serialized size in bytes
    double fee_rate;      // fee / size (atomic units per byte)
    int64_t time_added;   // unix timestamp when added to mempool
    uint32_t sequence;    // nSequence of the first input (for RBF signaling)
};

// ---------------------------------------------------------------------------
// Orphan entry: transaction whose inputs are not yet available
// ---------------------------------------------------------------------------

struct OrphanEntry {
    CTransaction tx;
    uint256 txid;
    int64_t time_added;
    uint64_t from_peer;   // which peer sent this transaction
};

// ---------------------------------------------------------------------------
// Ancestor/descendant information (for CPFP fee calculations)
// ---------------------------------------------------------------------------

struct AncestorInfo {
    size_t ancestor_count;
    size_t ancestor_size;     // total serialized bytes
    Amount ancestor_fees;     // total fees across all ancestors
    double ancestor_fee_rate; // fees/size across all ancestors
};

// ---------------------------------------------------------------------------
// Replace-by-fee result
// ---------------------------------------------------------------------------

struct RBFResult {
    bool replaced;
    std::vector<uint256> evicted_txids;
    std::string reason;   // if not replaced, the reason why
};

// ---------------------------------------------------------------------------
// Mempool statistics
// ---------------------------------------------------------------------------

struct MempoolStats {
    size_t tx_count;
    size_t total_bytes;
    Amount total_fees;
    double min_fee_rate;
    double median_fee_rate;
    double max_fee_rate;
    size_t orphan_count;
    int64_t oldest_entry;
};

// ---------------------------------------------------------------------------
// Fee histogram bucket for fee estimation
// ---------------------------------------------------------------------------

struct FeeHistogramBucket {
    double min_fee_rate;
    double max_fee_rate;
    size_t count;
    size_t total_bytes;
};

// ---------------------------------------------------------------------------
// Mempool
// ---------------------------------------------------------------------------

class Mempool {
public:
    explicit Mempool(const UTXOSet& utxo);

    // Result of attempting to add a transaction
    struct AddResult {
        bool accepted;
        std::string reject_reason;
    };

    // Add a transaction to the mempool.
    // Validates: not duplicate, not coinbase, size limit, inputs exist
    // (UTXO or other mempool tx), no double-spends within mempool,
    // signatures valid, fee >= minimum.
    AddResult add_transaction(const CTransaction& tx);

    // Remove a transaction by txid (when included in a block)
    void remove(const uint256& txid);

    // Remove transactions that conflict with a confirmed block's transactions.
    // Removes both the block's transactions and any mempool transactions
    // that spend the same inputs.
    void remove_for_block(const std::vector<CTransaction>& block_txs);

    // Check if a transaction is in the mempool
    bool exists(const uint256& txid) const;

    // Get a transaction from the mempool
    bool get(const uint256& txid, CTransaction& tx) const;

    // Get a full entry (including fee info) from the mempool
    bool get_entry(const uint256& txid, MempoolEntry& entry) const;

    // Get the fee for a transaction in the mempool (returns 0 if not found)
    Amount get_fee(const uint256& txid) const {
        MempoolEntry entry;
        if (get_entry(txid, entry)) return entry.fee;
        return 0;
    }

    // Get transactions sorted by fee rate (highest first) for block assembly
    std::vector<CTransaction> get_sorted_transactions(size_t max_count = 0) const;

    // Get all transaction IDs
    std::vector<uint256> get_txids() const;

    // Get mempool size (number of transactions)
    size_t size() const;

    // Get total serialized bytes of all transactions in mempool
    size_t total_bytes() const;
    size_t bytes() const { return total_bytes(); }

    // Clear all transactions
    void clear();

    // Check if an outpoint is spent by any mempool transaction
    bool is_spent_by_mempool(const uint256& txid, uint32_t vout) const;

    // -------------------------------------------------------------------
    // Orphan pool management
    // -------------------------------------------------------------------

    // Add an orphan transaction (inputs not yet available)
    void add_orphan(const CTransaction& tx, uint64_t peer_id);

    // Check if a transaction is in the orphan pool
    bool has_orphan(const uint256& txid) const;

    // Remove an orphan by txid
    void remove_orphan(const uint256& txid);

    // Remove orphans whose inputs are resolved by a newly confirmed block.
    // Returns the number of orphans removed.
    void remove_orphans_for_block(const CBlock& block);

    // Try to accept orphans that depended on a newly confirmed or
    // newly accepted mempool transaction. Returns the number of
    // orphans that were successfully moved into the mempool.
    int resolve_orphans(const uint256& resolved_txid);

    // Evict oldest orphans until the orphan pool is at most max_orphans entries.
    void limit_orphans(size_t max_orphans = 100);

    // Get the number of orphan transactions
    size_t orphan_count() const;

    // Remove all orphans from a specific peer
    void remove_orphans_from_peer(uint64_t peer_id);

    // -------------------------------------------------------------------
    // Ancestor / descendant tracking (CPFP)
    // -------------------------------------------------------------------

    // Get aggregate ancestor info for a transaction (for CPFP evaluation)
    AncestorInfo get_ancestor_info(const uint256& txid) const;

    // Get the list of ancestor txids for a mempool transaction
    std::vector<uint256> get_ancestors(const uint256& txid) const;

    // Get the list of descendant txids for a mempool transaction
    std::vector<uint256> get_descendants(const uint256& txid) const;

    // -------------------------------------------------------------------
    // Replace-by-fee (RBF)
    // -------------------------------------------------------------------

    // Attempt to replace an existing mempool transaction with a higher-fee version.
    // The new transaction must spend at least one of the same inputs,
    // and must pay strictly higher total fees and higher fee rate.
    RBFResult try_replace(const CTransaction& new_tx);

    // Check if a transaction signals replaceability (nSequence < 0xFFFFFFFE)
    static bool signals_rbf(const CTransaction& tx);

    // -------------------------------------------------------------------
    // Size limits and eviction
    // -------------------------------------------------------------------

    // Set the maximum mempool size in bytes (default 300MB)
    void set_max_size(size_t max_bytes);

    // Evict lowest fee-rate transactions until the mempool is under the size limit
    void enforce_size_limit();

    // Remove transactions older than max_age_seconds (default 14 days)
    void expire_old(int64_t max_age_seconds = 336 * 3600);

    // -------------------------------------------------------------------
    // Statistics and fee estimation
    // -------------------------------------------------------------------

    // Get aggregate mempool statistics
    MempoolStats get_stats() const;

    // Build a fee histogram for fee estimation
    std::vector<FeeHistogramBucket> get_fee_histogram(int num_buckets = 20) const;

    // Estimate the fee rate needed for confirmation within N blocks.
    // Returns the fee rate in atomic units per byte.
    double estimate_fee_rate(int target_blocks) const;

    // -------------------------------------------------------------------
    // Transaction priority adjustment
    // -------------------------------------------------------------------

    // Adjust the effective fee delta for a transaction.
    // Positive delta increases priority, negative decreases it.
    bool prioritise_transaction(const uint256& txid, Amount fee_delta);

    // -------------------------------------------------------------------
    // Advanced queries
    // -------------------------------------------------------------------

    // Get total fees of all transactions in the mempool
    Amount get_total_fees() const;

    // Count transactions with fee rate above a threshold
    size_t count_above_fee_rate(double min_rate) const;

    // Check if a transaction has unconfirmed parents in the mempool
    bool has_unconfirmed_parents(const uint256& txid) const;

    // Get the depth of the dependency chain for a transaction
    int get_chain_depth(const uint256& txid) const;

    // Get all transactions spending outputs from a specific tx
    std::vector<uint256> get_spending_txids(const uint256& txid) const;

    // Check if adding a transaction would exceed max chain depth
    bool would_exceed_chain_depth(const CTransaction& tx,
                                   int max_depth = 25) const;

    // Get a snapshot of all mempool entries
    std::vector<MempoolEntry> get_all_entries() const;

    // Trim expired orphans (older than max_age_seconds)
    void trim_orphans(int64_t max_age_seconds = 1200);

    // Check internal consistency (for debugging)
    bool check_consistency() const;

private:
    const UTXOSet& utxo_;

    mutable std::mutex mutex_;

    // Primary storage: txid -> entry
    std::unordered_map<uint256, MempoolEntry, Uint256Hasher> txs_;

    // Fee-rate index for transaction selection (sorted descending)
    std::multimap<double, uint256, std::greater<double>> by_fee_rate_;

    // Spent outpoints tracker: (prev_txid, prev_vout) -> spending txid
    // Prevents double-spends within mempool
    struct OutpointHasher {
        size_t operator()(const std::pair<uint256, uint32_t>& p) const {
            uint64_t val;
            std::memcpy(&val, p.first.data(), 8);
            return val ^ std::hash<uint32_t>{}(p.second);
        }
    };
    std::unordered_map<std::pair<uint256, uint32_t>, uint256, OutpointHasher> spent_outpoints_;

    size_t total_bytes_ = 0;
    size_t max_size_ = 300 * 1024 * 1024; // 300 MB default

    // Minimum fee rate in atomic units per byte
    static constexpr double MIN_FEE_RATE = 1.0;

    // Orphan pool
    std::unordered_map<uint256, OrphanEntry, Uint256Hasher> orphans_;

    // Orphan index: (prev_txid) -> set of orphan txids that spend outputs from it
    std::unordered_map<uint256, std::unordered_set<uint256, Uint256Hasher>, Uint256Hasher> orphan_by_prev_;

    // Dependency graph: txid -> set of parent txids that are in the mempool
    std::unordered_map<uint256, std::unordered_set<uint256, Uint256Hasher>, Uint256Hasher> parents_;

    // Reverse dependency: txid -> set of child txids in the mempool
    std::unordered_map<uint256, std::unordered_set<uint256, Uint256Hasher>, Uint256Hasher> children_;

    // Fee priority deltas (from prioritisetransaction RPC)
    std::unordered_map<uint256, Amount, Uint256Hasher> fee_deltas_;

    // Validate transaction inputs and compute fee.
    // Checks UTXO existence (or parent in mempool), pubkey hash match,
    // and Ed25519 signature verification.
    bool validate_inputs(const CTransaction& tx, Amount& fee_out,
                         std::string& error) const;

    // Remove a single transaction from all internal indexes (no lock)
    void remove_locked(const uint256& txid);

    // Build the parent/child dependency graph entry for a transaction
    void build_deps_locked(const uint256& txid, const CTransaction& tx);

    // Remove dependency graph entries for a transaction
    void remove_deps_locked(const uint256& txid);

    // Collect ancestors recursively (internal, no lock)
    void collect_ancestors_locked(const uint256& txid,
                                   std::set<uint256>& result) const;

    // Collect descendants recursively (internal, no lock)
    void collect_descendants_locked(const uint256& txid,
                                     std::set<uint256>& result) const;

    // Get current timestamp
    static int64_t now_seconds();
};

} // namespace flow

#endif // FLOWCOIN_MEMPOOL_H

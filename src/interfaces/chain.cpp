// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "interfaces/chain.h"
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "chain/blockstore.h"
#include "chain/txindex.h"
#include "mempool/mempool.h"

#include <chrono>
#include <cmath>
#include <cstring>

namespace flow::interfaces {

// ============================================================================
// ChainLock: RAII chain state lock
// ============================================================================

class ChainLockImpl : public Chain::Lock {
public:
    explicit ChainLockImpl(ChainState& chain)
        : chain_(chain) {}

    uint64_t get_height() override {
        return chain_.height();
    }

    uint256 get_tip_hash() override {
        auto* tip = chain_.tip();
        return tip ? tip->hash : uint256();
    }

    int64_t get_median_time_past() override {
        // Compute MTP from the last 11 blocks
        auto* tip = chain_.tip();
        if (!tip) return 0;

        std::vector<int64_t> times;
        auto* idx = tip;
        for (int i = 0; i < 11 && idx; ++i) {
            times.push_back(idx->timestamp);
            idx = idx->prev;
        }

        if (times.empty()) return 0;
        std::sort(times.begin(), times.end());
        return times[times.size() / 2];
    }

private:
    ChainState& chain_;
};

// ============================================================================
// ChainImpl: concrete implementation wrapping ChainState + Mempool
// ============================================================================

class ChainImpl : public Chain {
public:
    ChainImpl(ChainState& chain, Mempool* mempool)
        : chain_(chain), mempool_(mempool) {}

    ~ChainImpl() override = default;

    // ---- Block information -------------------------------------------------

    uint64_t get_height() override {
        return chain_.height();
    }

    uint256 get_block_hash(uint64_t height) override {
        auto* idx = chain_.get_block_index_at_height(height);
        if (idx) return idx->hash;
        return uint256();
    }

    bool get_block(const uint256& hash, CBlock& block) override {
        // Look up the block index
        auto& tree = chain_.block_tree();
        auto* idx = tree.find(hash);
        if (!idx) return false;

        // Read from block store
        return chain_.get_block_at_height(idx->height, block);
    }

    bool get_block_header(const uint256& hash, CBlockHeader& header) override {
        auto& tree = chain_.block_tree();
        auto* idx = tree.find(hash);
        if (!idx) return false;

        // Construct header from block index
        CBlock block;
        if (!chain_.get_block_at_height(idx->height, block)) return false;
        header = block.get_header();
        return true;
    }

    bool get_block_header_at_height(uint64_t height,
                                     CBlockHeader& header) override {
        CBlock block;
        if (!chain_.get_block_at_height(height, block)) return false;
        header = block.get_header();
        return true;
    }

    bool have_block(const uint256& hash) override {
        auto& tree = chain_.block_tree();
        return tree.find(hash) != nullptr;
    }

    int get_block_confirmations(const uint256& hash) override {
        auto& tree = chain_.block_tree();
        auto* idx = tree.find(hash);
        if (!idx) return -1;

        uint64_t tip_height = chain_.height();
        if (tip_height < idx->height) return 0;
        return static_cast<int>(tip_height - idx->height + 1);
    }

    int64_t get_block_time(const uint256& hash) override {
        auto& tree = chain_.block_tree();
        auto* idx = tree.find(hash);
        return idx ? idx->timestamp : 0;
    }

    int64_t get_block_height(const uint256& hash) override {
        auto& tree = chain_.block_tree();
        auto* idx = tree.find(hash);
        return idx ? static_cast<int64_t>(idx->height) : -1;
    }

    // ---- UTXO queries ------------------------------------------------------

    bool get_utxo(const uint256& txid, uint32_t vout,
                   UTXOEntry& entry) override {
        return chain_.utxo_set().get(txid, vout, entry);
    }

    bool have_utxo(const uint256& txid, uint32_t vout) override {
        return chain_.utxo_set().exists(txid, vout);
    }

    size_t get_utxo_count() override {
        return chain_.utxo_set().total_count();
    }

    Amount get_utxo_total_value() override {
        return chain_.utxo_set().total_value();
    }

    // ---- Mempool -----------------------------------------------------------

    bool is_in_mempool(const uint256& txid) override {
        if (!mempool_) return false;
        return mempool_->exists(txid);
    }

    bool submit_transaction(const CTransaction& tx,
                             std::string& error) override {
        if (!mempool_) {
            error = "mempool-not-available";
            return false;
        }

        auto result = mempool_->add_transaction(tx);
        if (!result.accepted) {
            error = result.reject_reason;
            return false;
        }
        return true;
    }

    bool get_mempool_tx(const uint256& txid, CTransaction& tx) override {
        if (!mempool_) return false;
        return mempool_->get(txid, tx);
    }

    size_t get_mempool_size() override {
        if (!mempool_) return 0;
        return mempool_->size();
    }

    // ---- Chain state -------------------------------------------------------

    int64_t get_adjusted_time() override {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }

    uint32_t get_next_nbits() override {
        auto* tip = chain_.tip();
        return tip ? tip->nbits : 0;
    }

    Amount get_min_relay_fee() override {
        return 1000;  // 1 sat/byte
    }

    int64_t get_median_time_past() override {
        auto* tip = chain_.tip();
        if (!tip) return 0;

        std::vector<int64_t> times;
        auto* idx = tip;
        for (int i = 0; i < 11 && idx; ++i) {
            times.push_back(idx->timestamp);
            idx = idx->prev;
        }

        if (times.empty()) return 0;
        std::sort(times.begin(), times.end());
        return times[times.size() / 2];
    }

    bool is_initial_block_download() override {
        auto* tip = chain_.tip();
        if (!tip) return true;

        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        return (now - tip->timestamp) > 86400;
    }

    // ---- Transaction lookup ------------------------------------------------

    bool find_tx(const uint256& txid, CTransaction& tx,
                  uint256& block_hash, uint64_t& block_height) override {
        auto* txindex = chain_.tx_index();
        if (!txindex) return false;

        auto loc = txindex->find(txid);
        if (!loc.found) return false;

        block_hash = loc.block_hash;
        block_height = loc.block_height;

        // Read the block and find the transaction
        CBlock block;
        if (!chain_.get_block_at_height(block_height, block)) return false;

        if (loc.tx_index < block.vtx.size()) {
            tx = block.vtx[loc.tx_index];
            return true;
        }

        return false;
    }

    // ---- Notifications -----------------------------------------------------

    void register_block_callback(BlockCallback cb) override {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        block_callbacks_.push_back(std::move(cb));
    }

    void register_tx_callback(TxCallback cb) override {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        tx_callbacks_.push_back(std::move(cb));
    }

    // ---- Chain lock --------------------------------------------------------

    std::unique_ptr<Lock> lock() override {
        return std::make_unique<ChainLockImpl>(chain_);
    }

    // ---- Chain tips --------------------------------------------------------

    uint256 get_tip_hash() override {
        auto* tip = chain_.tip();
        return tip ? tip->hash : uint256();
    }

    uint256 get_genesis_hash() override {
        auto* idx = chain_.get_block_index_at_height(0);
        return idx ? idx->hash : uint256();
    }

private:
    ChainState& chain_;
    Mempool* mempool_;

    std::mutex cb_mutex_;
    std::vector<BlockCallback> block_callbacks_;
    std::vector<TxCallback> tx_callbacks_;
};

// ============================================================================
// Chain utility functions
// ============================================================================

namespace chain_util {

/// Compute the estimated network hash rate from recent blocks.
/// Uses the last n_blocks to calculate average block time and difficulty.
double estimate_network_hashrate(ChainState& chain, int n_blocks) {
    auto* tip = chain.tip();
    if (!tip || n_blocks <= 0) return 0.0;

    // Walk back n_blocks to get the time span
    auto* start = tip;
    int count = 0;
    while (start && start->prev && count < n_blocks) {
        start = start->prev;
        count++;
    }

    if (count == 0 || start == tip) return 0.0;

    int64_t time_span = tip->timestamp - start->timestamp;
    if (time_span <= 0) return 0.0;

    // Average time per block
    double avg_block_time = static_cast<double>(time_span) /
                             static_cast<double>(count);

    // Difficulty from tip's nbits
    uint32_t nbits = tip->nbits;
    int exp = static_cast<int>((nbits >> 24) & 0xFF);
    uint32_t mantissa = nbits & 0x007FFFFF;
    if (mantissa == 0) return 0.0;

    double target = static_cast<double>(mantissa) *
                    std::pow(256.0, exp - 3);
    double max_target = static_cast<double>(0x00FFFFFF) *
                        std::pow(256.0, 0x20 - 3);

    if (target == 0.0) return 0.0;
    double difficulty = max_target / target;

    // hashrate = difficulty * 2^32 / avg_block_time
    return difficulty * 4294967296.0 / avg_block_time;
}

/// Get the chain's total verified transaction count.
uint64_t get_chain_tx_count(ChainState& chain) {
    uint64_t count = 0;
    auto* tip = chain.tip();
    auto* idx = tip;
    while (idx) {
        count += static_cast<uint64_t>(idx->n_tx);
        idx = idx->prev;
    }
    return count;
}

/// Check if the chain is making progress (not stalled).
bool is_chain_progressing(ChainState& chain, int64_t max_stall_seconds) {
    auto* tip = chain.tip();
    if (!tip) return false;

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    return (now - tip->timestamp) < max_stall_seconds;
}

/// Find the common ancestor of two blocks at different heights.
uint256 find_common_ancestor(ChainState& chain,
                              const uint256& hash_a,
                              const uint256& hash_b) {
    auto& tree = chain.block_tree();
    auto* idx_a = tree.find(hash_a);
    auto* idx_b = tree.find(hash_b);

    if (!idx_a || !idx_b) return uint256();

    // Walk back the higher block to the same height
    while (idx_a->height > idx_b->height && idx_a->prev) {
        idx_a = idx_a->prev;
    }
    while (idx_b->height > idx_a->height && idx_b->prev) {
        idx_b = idx_b->prev;
    }

    // Walk both back until they meet
    while (idx_a && idx_b && idx_a != idx_b) {
        idx_a = idx_a->prev;
        idx_b = idx_b->prev;
    }

    return (idx_a && idx_b) ? idx_a->hash : uint256();
}

/// Get the chain of block hashes from start_height to end_height.
std::vector<uint256> get_block_hash_range(ChainState& chain,
                                           uint64_t start_height,
                                           uint64_t end_height) {
    std::vector<uint256> result;
    if (start_height > end_height) return result;
    if (end_height > chain.height()) end_height = chain.height();

    result.reserve(end_height - start_height + 1);
    for (uint64_t h = start_height; h <= end_height; ++h) {
        auto* idx = chain.get_block_index_at_height(h);
        if (idx) {
            result.push_back(idx->hash);
        }
    }

    return result;
}

/// Compute average block interval over the last n blocks.
double average_block_interval(ChainState& chain, int n_blocks) {
    auto* tip = chain.tip();
    if (!tip || n_blocks <= 0) return 0.0;

    std::vector<int64_t> intervals;
    auto* current = tip;

    for (int i = 0; i < n_blocks && current && current->prev; ++i) {
        int64_t interval = current->timestamp - current->prev->timestamp;
        intervals.push_back(interval);
        current = current->prev;
    }

    if (intervals.empty()) return 0.0;

    double sum = 0.0;
    for (int64_t t : intervals) {
        sum += static_cast<double>(t);
    }

    return sum / static_cast<double>(intervals.size());
}

/// Compute the model improvement rate over the last n blocks.
double model_improvement_rate(ChainState& chain, int n_blocks) {
    auto* tip = chain.tip();
    if (!tip || n_blocks <= 0) return 0.0;


    auto* current = tip;

    for (int i = 0; i < n_blocks && current && current->prev; ++i) {
        current = current->prev;
    }

    if (!current || current == tip) return 0.0;




    return 0.0;  // PoW: no model loss tracking
}

} // namespace chain_util

// ============================================================================
// Factory functions
// ============================================================================

std::unique_ptr<Chain> make_chain(ChainState& chainstate) {
    return std::make_unique<ChainImpl>(chainstate, nullptr);
}

std::unique_ptr<Chain> make_chain(ChainState& chainstate, Mempool& mempool) {
    return std::make_unique<ChainImpl>(chainstate, &mempool);
}

} // namespace flow::interfaces

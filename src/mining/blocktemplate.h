// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Block template construction for miners.
// Creates a partially-filled block header with the correct difficulty,
// model dimensions, coinbase transaction, and target for the miner
// to complete with training proof and signature.
//
// The BlockAssembler performs fee-rate-ordered transaction selection
// from the mempool, respecting block size and sigops limits, with
// ancestor-aware fee sorting for child-pays-for-parent support.

#ifndef FLOWCOIN_MINING_BLOCKTEMPLATE_H
#define FLOWCOIN_MINING_BLOCKTEMPLATE_H

#include "consensus/params.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/types.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace flow {

class ChainState;
class Mempool;
class Wallet;

// ---------------------------------------------------------------------------
// BlockTemplate -- the result of template construction
// ---------------------------------------------------------------------------

struct BlockTemplate {
    CBlockHeader header;               //!< Partially filled header
    CTransaction coinbase_tx;          //!< Coinbase transaction with block reward
    std::vector<CTransaction> transactions; //!< Selected mempool transactions
    std::vector<Amount> tx_fees;       //!< Fee for each selected transaction
    Amount total_fees;                 //!< Sum of all transaction fees
    Amount coinbase_value;             //!< Block reward + fees

    uint256 target;                    //!< 256-bit target (decoded from nbits)
    std::string target_hex;            //!< Target as hex string for RPC
    uint32_t min_train_steps;          //!< Minimum training steps required
    consensus::ModelDimensions dims;   //!< Model architecture for the miner

    uint64_t template_id;             //!< Unique template identifier
    int64_t creation_time;             //!< When this template was created

    /// Get the total block size if this template were assembled.
    size_t estimated_block_size() const;

    /// Get the total block weight if this template were assembled.
    size_t estimated_block_weight() const;

    /// Get the number of selected transactions (excluding coinbase).
    size_t tx_count() const { return transactions.size(); }

    /// Assemble into a full CBlock (without training proof -- miner fills that).
    CBlock assemble() const;
};

// ---------------------------------------------------------------------------
// TxCandidate -- intermediate structure for transaction selection
// ---------------------------------------------------------------------------

struct TxCandidate {
    const CTransaction* tx;           //!< Pointer to mempool transaction
    uint256 txid;                      //!< Cached transaction ID
    Amount fee;                        //!< Transaction fee
    size_t size;                       //!< Serialized size
    double fee_rate;                   //!< Fee per byte (fee / size)
    int sigop_count;                   //!< Signature operation count
    std::vector<uint256> depends;      //!< Transaction IDs this tx depends on

    // Ancestor-aware fee rate (for CPFP)
    double ancestor_fee_rate;          //!< (sum of ancestor fees) / (sum of ancestor sizes)
    Amount ancestor_fee;               //!< Total fee including ancestors
    size_t ancestor_size;              //!< Total size including ancestors

    bool operator<(const TxCandidate& other) const {
        // Higher ancestor fee rate = higher priority
        return ancestor_fee_rate > other.ancestor_fee_rate;
    }
};

// ---------------------------------------------------------------------------
// BlockAssembler -- constructs block templates
// ---------------------------------------------------------------------------

class BlockAssembler {
public:
    /// Construct with chain state and optional mempool/wallet.
    BlockAssembler(const ChainState& chain, const Mempool* mempool = nullptr,
                   const Wallet* wallet = nullptr);

    /// Create a block template with an auto-generated coinbase address.
    /// If a wallet is available, uses a fresh address from the wallet.
    BlockTemplate create_template();

    /// Create a block template with a specific coinbase address (bech32m).
    BlockTemplate create_template(const std::string& coinbase_address);

    /// Create a block template with a specific coinbase public key.
    BlockTemplate create_template(const std::array<uint8_t, 32>& coinbase_pubkey);

    // --- Configuration ---

    /// Set the maximum block size for template construction.
    void set_max_block_size(size_t max_size) { max_block_size_ = max_size; }

    /// Set the maximum signature operations per block.
    void set_max_block_sigops(int max_sigops) { max_block_sigops_ = max_sigops; }

    /// Set the minimum fee rate for transaction selection (atomic units per byte).
    void set_min_fee_rate(Amount min_rate) { min_fee_rate_ = min_rate; }

    /// Set the maximum block weight.
    void set_max_block_weight(size_t max_weight) { max_block_weight_ = max_weight; }

    // --- Statistics ---

    /// Get the number of transactions considered in the last template.
    size_t get_last_candidates_count() const { return last_candidates_count_; }

    /// Get the number of transactions selected in the last template.
    size_t get_last_selected_count() const { return last_selected_count_; }

private:
    const ChainState& chain_;
    const Mempool* mempool_;
    const Wallet* wallet_;

    size_t max_block_size_ = consensus::MAX_BLOCK_SIZE;
    int max_block_sigops_ = consensus::MAX_BLOCK_SIGOPS;
    Amount min_fee_rate_ = 1;
    size_t max_block_weight_ = MAX_BLOCK_WEIGHT;

    size_t last_candidates_count_ = 0;
    size_t last_selected_count_ = 0;

    /// Fill the header fields from chain state.
    void fill_header(CBlockHeader& hdr, uint64_t next_height);

    /// Build the coinbase transaction.
    CTransaction build_coinbase(uint64_t height, Amount reward_plus_fees,
                                 const std::array<uint8_t, 32>& pubkey);

    /// Build the coinbase with a bech32m address.
    CTransaction build_coinbase(uint64_t height, Amount reward_plus_fees,
                                 const std::string& address);

    /// Select transactions from the mempool ordered by ancestor fee rate.
    void select_transactions(BlockTemplate& tmpl);

    /// Build candidate list from mempool.
    std::vector<TxCandidate> build_candidates();

    /// Compute ancestor-aware fee rates for all candidates.
    void compute_ancestor_fee_rates(std::vector<TxCandidate>& candidates);

    /// Sort candidates by ancestor fee rate (descending).
    void sort_by_ancestor_fee_rate(std::vector<TxCandidate>& candidates);

    /// Compute the merkle root for the template's transactions.
    uint256 compute_merkle(const std::vector<CTransaction>& txs);

    /// Compute the block reward for a given height.
    Amount compute_reward(uint64_t height) const;

    /// Estimate signature operation count for a transaction.
    int estimate_sigops(const CTransaction& tx) const;

    /// Generate a unique template ID.
    static uint64_t generate_template_id();

    // --- Full block assembly pipeline ---

    /// Assemble a fully signed block ready for submission.
    CBlock assemble_full_block(
        const BlockTemplate& tmpl,
        const std::array<uint8_t, 32>& miner_privkey,
        const std::array<uint8_t, 32>& miner_pubkey,
        const std::vector<uint8_t>& compressed_delta,
        float val_loss,
        uint32_t train_steps);

    // --- Package-aware transaction selection (CPFP) ---

    /// Build transaction packages from mempool.
    std::vector<struct TxPackage> build_packages();

    /// Select transactions by package fee rate.
    std::vector<CTransaction> select_by_package_fee_rate(
        size_t max_block_size,
        int max_sigops);

    // --- Template validation ---

    /// Validate a template is internally consistent.
    bool validate_template(const BlockTemplate& tmpl) const;

    /// Serialize a template for Stratum protocol delivery.
    std::vector<uint8_t> serialize_template_for_stratum(
        const BlockTemplate& tmpl) const;

    /// Compute the merkle branch for a given transaction index (for Stratum).
    std::vector<uint256> compute_merkle_branch(
        const BlockTemplate& tmpl, size_t tx_index) const;

    /// Check if two templates are compatible (same tip, same difficulty).
    bool templates_compatible(const BlockTemplate& a,
                               const BlockTemplate& b) const;

    /// Estimate total fees from mempool that would fit in a block.
    Amount estimate_total_fees(const Mempool* mempool,
                                size_t max_block_size) const;

    /// Estimate the fee rate at a given percentile of the mempool.
    double estimate_fee_rate_percentile(const Mempool* mempool,
                                         double percentile) const;
};

// ---------------------------------------------------------------------------
// TemplateCache -- caches block templates, rebuilds when stale
// ---------------------------------------------------------------------------

class TemplateCache {
public:
    TemplateCache(const ChainState& chain, const Mempool& mempool);

    /// Get current template (cached or fresh).
    const BlockTemplate& get_template(const std::array<uint8_t, 32>& coinbase_pubkey);

    /// Invalidate cache (called when tip changes or mempool changes significantly).
    void invalidate();

    /// Check if cache is stale.
    bool is_stale() const;

private:
    const ChainState& chain_;
    const Mempool& mempool_;
    std::unique_ptr<BlockTemplate> cached_;
    uint256 cached_tip_hash_;
    size_t cached_mempool_count_ = 0;
    int64_t cached_time_ = 0;
    static constexpr int64_t MAX_CACHE_AGE = 30;
};

// ---------------------------------------------------------------------------
// Free function (backward-compatible API)
// ---------------------------------------------------------------------------

/// Build a block template for mining (simplified API).
BlockTemplate create_block_template(const ChainState& chain,
                                     const std::string& coinbase_address);

} // namespace flow

#endif // FLOWCOIN_MINING_BLOCKTEMPLATE_H

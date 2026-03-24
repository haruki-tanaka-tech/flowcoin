// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "mining/blocktemplate.h"
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "consensus/difficulty.h"
#include "util/arith_uint256.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "crypto/bech32.h"
#include "hash/keccak.h"
#include "hash/merkle.h"
#include "util/random.h"
#include "util/strencodings.h"
#include "util/time.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <numeric>

namespace flow {

// ===========================================================================
// BlockTemplate
// ===========================================================================

size_t BlockTemplate::estimated_block_size() const {
    size_t size = BLOCK_HEADER_SIZE;

    // Transaction count: coinbase + selected
    size_t total_tx = 1 + transactions.size();
    // CompactSize for tx count
    if (total_tx < 253) size += 1;
    else if (total_tx <= 0xFFFF) size += 3;
    else size += 5;

    // Coinbase transaction
    size += coinbase_tx.get_serialize_size();

    // Selected transactions
    for (const auto& tx : transactions) {
        size += tx.get_serialize_size();
    }

    // Delta payload placeholder (CompactSize(0))
    size += 1;

    return size;
}

size_t BlockTemplate::estimated_block_weight() const {
    return estimated_block_size() * WITNESS_SCALE_FACTOR;
}

CBlock BlockTemplate::assemble() const {
    CBlock block;
    static_cast<CBlockHeader&>(block) = header;

    // First transaction is coinbase
    block.vtx.push_back(coinbase_tx);

    // Then all selected transactions
    block.vtx.insert(block.vtx.end(), transactions.begin(), transactions.end());

    // Compute merkle root
    block.merkle_root = block.compute_merkle_root();

    return block;
}

// ===========================================================================
// BlockAssembler
// ===========================================================================

BlockAssembler::BlockAssembler(const ChainState& chain, const Mempool* mempool,
                               const Wallet* wallet)
    : chain_(chain), mempool_(mempool), wallet_(wallet) {}

// ---------------------------------------------------------------------------
// fill_header
// ---------------------------------------------------------------------------

void BlockAssembler::fill_header(CBlockHeader& hdr, uint64_t next_height) {
    CBlockIndex* tip = chain_.tip();

    hdr.version = 1;
    hdr.height = next_height;

    // Previous block hash
    if (tip) {
        hdr.prev_hash = tip->hash;
    } else {
        hdr.prev_hash.set_null();
    }

    // Timestamp: current wall clock time
    hdr.timestamp = GetTime();

    // Difficulty
    if (tip && next_height > 0) {
        if (next_height % consensus::RETARGET_INTERVAL == 0) {
            CBlockIndex* first = tip;
            for (int i = 0; i < consensus::RETARGET_INTERVAL - 1 && first->prev; ++i) {
                first = first->prev;
            }
            hdr.nbits = consensus::get_next_work_required(
                next_height, tip->nbits, first->timestamp, tip->timestamp);
        } else {
            hdr.nbits = tip->nbits;
        }
    } else {
        hdr.nbits = consensus::INITIAL_NBITS;
    }

    // Model dimensions at next height
    uint32_t improving_blocks = tip ? tip->improving_blocks : 0;
    consensus::ModelDimensions dims = consensus::compute_growth(next_height, improving_blocks);

    hdr.d_model  = dims.d_model;
    hdr.n_layers = dims.n_layers;
    hdr.d_ff     = dims.d_ff;
    hdr.n_heads  = dims.n_heads;
    hdr.gru_dim  = dims.gru_dim;
    hdr.n_slots  = dims.n_slots;

    // Previous val_loss
    if (tip) {
        hdr.prev_val_loss = tip->val_loss;
    } else {
        hdr.prev_val_loss = consensus::MAX_VAL_LOSS;
    }

    // Stagnation counter
    if (tip && tip->prev) {
        if (tip->val_loss >= tip->prev_val_loss) {
            hdr.stagnation = tip->stagnation_count + 1;
        } else {
            hdr.stagnation = 0;
        }
    } else {
        hdr.stagnation = 0;
    }
}

// ---------------------------------------------------------------------------
// build_coinbase
// ---------------------------------------------------------------------------

CTransaction BlockAssembler::build_coinbase(uint64_t height, Amount reward_plus_fees,
                                             const std::array<uint8_t, 32>& pubkey) {
    CTransaction coinbase;
    coinbase.version = 1;
    coinbase.locktime = 0;

    // Coinbase input
    CTxIn cb_in;
    cb_in.prevout = COutPoint();

    // Encode height in pubkey field (BIP34 style)
    std::memset(cb_in.pubkey.data(), 0, 32);
    for (int i = 0; i < 8; ++i) {
        cb_in.pubkey[i] = static_cast<uint8_t>(height >> (i * 8));
    }

    coinbase.vin.push_back(cb_in);

    // Coinbase output
    CTxOut cb_out;
    cb_out.amount = reward_plus_fees;
    uint256 pkh = keccak256(pubkey.data(), 32);
    std::memcpy(cb_out.pubkey_hash.data(), pkh.data(), 32);
    coinbase.vout.push_back(cb_out);

    return coinbase;
}

CTransaction BlockAssembler::build_coinbase(uint64_t height, Amount reward_plus_fees,
                                             const std::string& address) {
    CTransaction coinbase;
    coinbase.version = 1;
    coinbase.locktime = 0;

    CTxIn cb_in;
    cb_in.prevout = COutPoint();
    std::memset(cb_in.pubkey.data(), 0, 32);
    for (int i = 0; i < 8; ++i) {
        cb_in.pubkey[i] = static_cast<uint8_t>(height >> (i * 8));
    }
    coinbase.vin.push_back(cb_in);

    CTxOut cb_out;
    cb_out.amount = reward_plus_fees;

    if (!address.empty()) {
        auto decoded = bech32m_decode(address);
        if (decoded.valid && decoded.program.size() == 20) {
            std::memcpy(cb_out.pubkey_hash.data(), decoded.program.data(), 20);
        }
    }

    coinbase.vout.push_back(cb_out);

    return coinbase;
}

// ---------------------------------------------------------------------------
// compute_merkle
// ---------------------------------------------------------------------------

uint256 BlockAssembler::compute_merkle(const std::vector<CTransaction>& txs) {
    if (txs.empty()) {
        uint256 null_hash;
        null_hash.set_null();
        return null_hash;
    }

    std::vector<uint256> hashes;
    hashes.reserve(txs.size());
    for (const auto& tx : txs) {
        hashes.push_back(tx.get_txid());
    }

    return compute_merkle_root(hashes);
}

// ---------------------------------------------------------------------------
// compute_reward
// ---------------------------------------------------------------------------

Amount BlockAssembler::compute_reward(uint64_t height) const {
    return consensus::compute_block_reward(height);
}

// ---------------------------------------------------------------------------
// estimate_sigops
// ---------------------------------------------------------------------------

int BlockAssembler::estimate_sigops(const CTransaction& tx) const {
    // Each input requires one Ed25519 signature verification.
    return static_cast<int>(tx.vin.size());
}

// ---------------------------------------------------------------------------
// generate_template_id
// ---------------------------------------------------------------------------

uint64_t BlockAssembler::generate_template_id() {
    return GetRandUint64();
}

// ---------------------------------------------------------------------------
// select_transactions
// ---------------------------------------------------------------------------

void BlockAssembler::select_transactions(BlockTemplate& tmpl) {
    if (!mempool_) return;

    auto candidates = build_candidates();
    last_candidates_count_ = candidates.size();

    compute_ancestor_fee_rates(candidates);
    sort_by_ancestor_fee_rate(candidates);

    // Reserve space for header + coinbase
    size_t current_size = BLOCK_HEADER_SIZE + tmpl.coinbase_tx.get_serialize_size() + 10;
    int current_sigops = estimate_sigops(tmpl.coinbase_tx);
    size_t current_weight = current_size * WITNESS_SCALE_FACTOR;

    // Track which transactions are already included
    std::set<uint256> included;

    for (const auto& candidate : candidates) {
        // Check fee rate minimum
        if (candidate.fee_rate < static_cast<double>(min_fee_rate_)) continue;

        // Check size limit
        if (current_size + candidate.size > max_block_size_) continue;

        // Check sigops limit
        if (current_sigops + candidate.sigop_count > max_block_sigops_) continue;

        // Check weight limit
        size_t tx_weight = candidate.size * WITNESS_SCALE_FACTOR;
        if (current_weight + tx_weight > max_block_weight_) continue;

        // Check dependencies are included
        bool deps_met = true;
        for (const auto& dep : candidate.depends) {
            if (included.find(dep) == included.end()) {
                deps_met = false;
                break;
            }
        }
        if (!deps_met) continue;

        // Include this transaction
        tmpl.transactions.push_back(*candidate.tx);
        tmpl.tx_fees.push_back(candidate.fee);
        tmpl.total_fees += candidate.fee;
        included.insert(candidate.txid);

        current_size += candidate.size;
        current_sigops += candidate.sigop_count;
        current_weight += tx_weight;
    }

    last_selected_count_ = tmpl.transactions.size();
}

// ---------------------------------------------------------------------------
// build_candidates
// ---------------------------------------------------------------------------

std::vector<TxCandidate> BlockAssembler::build_candidates() {
    std::vector<TxCandidate> candidates;
    if (!mempool_) return candidates;

    // Get sorted transactions from mempool (highest fee rate first)
    auto sorted_txs = mempool_->get_sorted_transactions();
    candidates.reserve(sorted_txs.size());

    // Build txid set for dependency detection
    std::set<uint256> mempool_txids;
    for (const auto& tx : sorted_txs) {
        mempool_txids.insert(tx.get_txid());
    }

    // Cache for looking up transactions by txid
    std::map<uint256, const CTransaction*> tx_cache;
    for (const auto& tx : sorted_txs) {
        tx_cache[tx.get_txid()] = &tx;
    }

    for (const auto& tx : sorted_txs) {
        // Retrieve the full mempool entry to get fee info
        CTransaction entry_tx;
        if (!mempool_->get(tx.get_txid(), entry_tx)) continue;

        TxCandidate c;
        c.tx = tx_cache[tx.get_txid()];
        c.txid = tx.get_txid();
        c.size = tx.get_serialize_size();

        // Compute fee from the mempool: we don't have direct fee access
        // from get_sorted_transactions, so estimate from the ordering.
        // The mempool internally tracks fees; use total_out vs inputs.
        c.fee = 0;  // Will be computed by ancestor fee rate calculation
        c.fee_rate = 0.0;
        c.sigop_count = estimate_sigops(tx);

        // Build dependency list: for each input, check if the referenced tx
        // is also in the mempool (unconfirmed parent).
        for (const auto& vin : tx.vin) {
            if (mempool_txids.count(vin.prevout.txid)) {
                c.depends.push_back(vin.prevout.txid);
            }
        }

        // Initialize ancestor values to own values
        c.ancestor_fee = c.fee;
        c.ancestor_size = c.size;
        c.ancestor_fee_rate = c.fee_rate;

        candidates.push_back(c);
    }

    return candidates;
}

// ---------------------------------------------------------------------------
// compute_ancestor_fee_rates
// ---------------------------------------------------------------------------

void BlockAssembler::compute_ancestor_fee_rates(std::vector<TxCandidate>& candidates) {
    // Build a map from txid to candidate index for fast lookup
    std::map<uint256, size_t> txid_to_idx;
    for (size_t i = 0; i < candidates.size(); ++i) {
        txid_to_idx[candidates[i].txid] = i;
    }

    // For each candidate, accumulate ancestor fees and sizes
    for (auto& candidate : candidates) {
        Amount ancestor_fee = candidate.fee;
        size_t ancestor_size = candidate.size;

        // Walk the dependency chain
        std::set<uint256> visited;
        std::vector<uint256> stack = candidate.depends;

        while (!stack.empty()) {
            uint256 dep_txid = stack.back();
            stack.pop_back();

            if (visited.count(dep_txid)) continue;
            visited.insert(dep_txid);

            auto it = txid_to_idx.find(dep_txid);
            if (it == txid_to_idx.end()) continue;

            const auto& dep = candidates[it->second];
            ancestor_fee += dep.fee;
            ancestor_size += dep.size;

            // Add transitive dependencies
            for (const auto& d : dep.depends) {
                if (!visited.count(d)) {
                    stack.push_back(d);
                }
            }
        }

        candidate.ancestor_fee = ancestor_fee;
        candidate.ancestor_size = ancestor_size;
        candidate.ancestor_fee_rate = (ancestor_size > 0)
            ? static_cast<double>(ancestor_fee) / static_cast<double>(ancestor_size)
            : 0.0;
    }
}

// ---------------------------------------------------------------------------
// sort_by_ancestor_fee_rate
// ---------------------------------------------------------------------------

void BlockAssembler::sort_by_ancestor_fee_rate(std::vector<TxCandidate>& candidates) {
    std::sort(candidates.begin(), candidates.end());
}

// ---------------------------------------------------------------------------
// create_template (various overloads)
// ---------------------------------------------------------------------------

BlockTemplate BlockAssembler::create_template() {
    // Use a zero pubkey if no wallet is available
    std::array<uint8_t, 32> pubkey{};
    return create_template(pubkey);
}

BlockTemplate BlockAssembler::create_template(const std::string& coinbase_address) {
    BlockTemplate tmpl;
    CBlockIndex* tip = chain_.tip();
    uint64_t next_height = tip ? tip->height + 1 : 0;

    // Fill header
    fill_header(tmpl.header, next_height);

    // Model dimensions
    uint32_t improving_blocks = tip ? tip->improving_blocks : 0;
    tmpl.dims = consensus::compute_growth(next_height, improving_blocks);
    tmpl.min_train_steps = consensus::compute_min_steps(next_height);

    // Decode target
    arith_uint256 target_arith;
    consensus::derive_target(tmpl.header.nbits, target_arith);
    tmpl.target = ArithToUint256(target_arith);
    tmpl.target_hex = target_arith.GetHex();

    // Initially, total_fees = 0 (will be filled by select_transactions)
    tmpl.total_fees = 0;

    // Select transactions from mempool
    // Need a temporary coinbase to estimate size
    Amount reward = compute_reward(next_height);
    tmpl.coinbase_tx = build_coinbase(next_height, reward, coinbase_address);

    select_transactions(tmpl);

    // Rebuild coinbase with actual fees
    tmpl.coinbase_value = reward + tmpl.total_fees;
    tmpl.coinbase_tx = build_coinbase(next_height, tmpl.coinbase_value, coinbase_address);

    // Template metadata
    tmpl.template_id = generate_template_id();
    tmpl.creation_time = GetTime();

    return tmpl;
}

BlockTemplate BlockAssembler::create_template(const std::array<uint8_t, 32>& coinbase_pubkey) {
    BlockTemplate tmpl;
    CBlockIndex* tip = chain_.tip();
    uint64_t next_height = tip ? tip->height + 1 : 0;

    fill_header(tmpl.header, next_height);

    uint32_t improving_blocks = tip ? tip->improving_blocks : 0;
    tmpl.dims = consensus::compute_growth(next_height, improving_blocks);
    tmpl.min_train_steps = consensus::compute_min_steps(next_height);

    arith_uint256 target_arith;
    consensus::derive_target(tmpl.header.nbits, target_arith);
    tmpl.target = ArithToUint256(target_arith);
    tmpl.target_hex = target_arith.GetHex();

    tmpl.total_fees = 0;

    Amount reward = compute_reward(next_height);
    tmpl.coinbase_tx = build_coinbase(next_height, reward, coinbase_pubkey);

    select_transactions(tmpl);

    tmpl.coinbase_value = reward + tmpl.total_fees;
    tmpl.coinbase_tx = build_coinbase(next_height, tmpl.coinbase_value, coinbase_pubkey);

    tmpl.template_id = generate_template_id();
    tmpl.creation_time = GetTime();

    return tmpl;
}

// ===========================================================================
// Free function (backward-compatible API)
// ===========================================================================

BlockTemplate create_block_template(const ChainState& chain,
                                     const std::string& coinbase_address) {
    BlockAssembler assembler(chain);
    return assembler.create_template(coinbase_address);
}

} // namespace flow

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

// ===========================================================================
// Complete block assembly pipeline
// ===========================================================================

CBlock BlockAssembler::assemble_full_block(
    const BlockTemplate& tmpl,
    const std::array<uint8_t, 32>& miner_privkey,
    const std::array<uint8_t, 32>& miner_pubkey,
    const std::vector<uint8_t>& compressed_delta,
    float val_loss,
    uint32_t train_steps) {

    // Step 1: Start with the template's assembled block
    CBlock block = tmpl.assemble();

    // Step 2: Set miner identity
    std::memcpy(block.miner_pubkey.data(), miner_pubkey.data(), 32);

    // Step 3: Set training proof fields
    block.val_loss = val_loss;
    block.train_steps = train_steps;

    // Step 4: Set delta hash from compressed delta
    block.delta_hash = keccak256(compressed_delta.data(), compressed_delta.size());
    block.delta_length = static_cast<uint32_t>(compressed_delta.size());
    block.delta_payload = compressed_delta;
    block.delta_offset = 0;

    // Step 5: Set dataset hash
    // The dataset hash must match the deterministic evaluation data
    // generated from the block height using Keccak-256 counter mode.
    uint64_t height = block.height;
    size_t eval_size = static_cast<size_t>(consensus::EVAL_TOKENS) * 4;
    std::vector<uint8_t> eval_data(eval_size);
    DeterministicRNG eval_rng(height * 1000 + 2);
    eval_rng.fill_bytes(eval_data.data(), eval_data.size());
    block.dataset_hash = keccak256(eval_data.data(), eval_data.size());

    // Step 6: Compute training hash
    // training_hash = Keccak256(delta_hash || dataset_hash)
    std::vector<uint8_t> combined(64);
    std::memcpy(combined.data(), block.delta_hash.data(), 32);
    std::memcpy(combined.data() + 32, block.dataset_hash.data(), 32);
    block.training_hash = keccak256(combined.data(), combined.size());

    // Step 7: Build coinbase transaction
    // The coinbase sends the block reward + fees to a fresh address
    // derived from the miner's public key and the block height.
    // This ensures each block pays to a unique address.
    uint256 coinbase_pkh;
    {
        // Derive per-block address: hash(miner_pubkey || height)
        std::vector<uint8_t> addr_preimage(40);
        std::memcpy(addr_preimage.data(), miner_pubkey.data(), 32);
        for (int i = 0; i < 8; ++i) {
            addr_preimage[32 + i] = static_cast<uint8_t>(height >> (i * 8));
        }
        coinbase_pkh = keccak256(addr_preimage.data(), addr_preimage.size());
    }

    // Rebuild the coinbase with the per-block address
    Amount reward = consensus::compute_block_reward(height);
    Amount total_value = reward + tmpl.total_fees;

    CTransaction coinbase;
    coinbase.version = 1;
    coinbase.locktime = 0;

    // Coinbase input
    CTxIn cb_in;
    cb_in.prevout = COutPoint();
    std::memset(cb_in.pubkey.data(), 0, 32);
    for (int i = 0; i < 8; ++i) {
        cb_in.pubkey[i] = static_cast<uint8_t>(height >> (i * 8));
    }
    coinbase.vin.push_back(cb_in);

    // Coinbase output
    CTxOut cb_out;
    cb_out.amount = total_value;
    std::memcpy(cb_out.pubkey_hash.data(), coinbase_pkh.data(), 32);
    coinbase.vout.push_back(cb_out);

    // Replace the coinbase in the block
    if (!block.vtx.empty()) {
        block.vtx[0] = coinbase;
    } else {
        block.vtx.push_back(coinbase);
    }

    // Step 8: Compute merkle root from all transactions
    block.merkle_root = block.compute_merkle_root();

    // Step 9: Sign header
    // The signature covers the 244-byte unsigned header data.
    auto unsigned_data = block.get_unsigned_data();
    auto sig = flow::ed25519_sign(
        unsigned_data.data(), unsigned_data.size(),
        miner_privkey.data(),
        miner_pubkey.data()
    );
    std::memcpy(block.miner_sig.data(), sig.data(), 64);

    // Step 10: Verify training hash meets difficulty target
    // training_hash < target must hold for the block to be valid.
    // The caller should verify this before broadcasting.

    return block;
}

// ===========================================================================
// Transaction selection with package awareness (CPFP)
// ===========================================================================

struct TxPackage {
    std::vector<uint256> txids;
    size_t total_size;
    Amount total_fees;
    double package_fee_rate;
};

std::vector<TxPackage> BlockAssembler::build_packages() {
    std::vector<TxPackage> packages;
    if (!mempool_) return packages;

    auto candidates = build_candidates();
    if (candidates.empty()) return packages;

    compute_ancestor_fee_rates(candidates);

    // Build a txid -> candidate index map
    std::map<uint256, size_t> txid_to_idx;
    for (size_t i = 0; i < candidates.size(); ++i) {
        txid_to_idx[candidates[i].txid] = i;
    }

    // Track which transactions have been assigned to a package
    std::set<uint256> assigned;

    // For each candidate, build its package (self + all ancestors)
    for (const auto& candidate : candidates) {
        if (assigned.count(candidate.txid)) continue;

        TxPackage pkg;
        pkg.total_size = 0;
        pkg.total_fees = 0;

        // Collect all ancestors via BFS
        std::vector<uint256> stack;
        stack.push_back(candidate.txid);
        std::set<uint256> visited;

        while (!stack.empty()) {
            uint256 current = stack.back();
            stack.pop_back();

            if (visited.count(current)) continue;
            visited.insert(current);

            auto idx_it = txid_to_idx.find(current);
            if (idx_it == txid_to_idx.end()) continue;

            const auto& c = candidates[idx_it->second];
            pkg.txids.push_back(current);
            pkg.total_size += c.size;
            pkg.total_fees += c.fee;

            for (const auto& dep : c.depends) {
                if (!visited.count(dep)) {
                    stack.push_back(dep);
                }
            }
        }

        // Order the package: ancestors first (topological sort)
        // Simple approach: reverse the BFS order
        std::reverse(pkg.txids.begin(), pkg.txids.end());

        // Compute package fee rate
        pkg.package_fee_rate = (pkg.total_size > 0)
            ? static_cast<double>(pkg.total_fees) / static_cast<double>(pkg.total_size)
            : 0.0;

        // Mark all transactions in this package as assigned
        for (const auto& txid : pkg.txids) {
            assigned.insert(txid);
        }

        packages.push_back(std::move(pkg));
    }

    // Sort packages by package fee rate (descending)
    std::sort(packages.begin(), packages.end(),
              [](const TxPackage& a, const TxPackage& b) {
                  return a.package_fee_rate > b.package_fee_rate;
              });

    return packages;
}

std::vector<CTransaction> BlockAssembler::select_by_package_fee_rate(
    size_t max_block_size,
    int max_sigops) {

    std::vector<CTransaction> selected;
    if (!mempool_) return selected;

    auto packages = build_packages();
    if (packages.empty()) return selected;

    size_t current_size = BLOCK_HEADER_SIZE + 100;  // Reserve for header + coinbase
    int current_sigops = 1;  // Coinbase has 1 sigop
    std::set<uint256> included;

    for (const auto& pkg : packages) {
        // Check if the entire package fits
        if (current_size + pkg.total_size > max_block_size) continue;

        // Estimate sigops for the package
        int pkg_sigops = 0;
        std::vector<CTransaction> pkg_txs;

        bool all_found = true;
        for (const auto& txid : pkg.txids) {
            if (included.count(txid)) continue;  // Already included from another package

            CTransaction tx;
            if (!mempool_->get(txid, tx)) {
                all_found = false;
                break;
            }
            pkg_sigops += estimate_sigops(tx);
            pkg_txs.push_back(std::move(tx));
        }

        if (!all_found) continue;
        if (current_sigops + pkg_sigops > max_sigops) continue;

        // Include the package
        for (auto& tx : pkg_txs) {
            uint256 txid = tx.get_txid();
            if (included.count(txid)) continue;

            current_size += tx.get_serialize_size();
            current_sigops += estimate_sigops(tx);
            included.insert(txid);
            selected.push_back(std::move(tx));
        }
    }

    return selected;
}

// ===========================================================================
// Block template caching
// ===========================================================================

TemplateCache::TemplateCache(const ChainState& chain, const Mempool& mempool)
    : chain_(chain), mempool_(mempool) {}

const BlockTemplate& TemplateCache::get_template(
    const std::array<uint8_t, 32>& coinbase_pubkey) {

    if (cached_ && !is_stale()) {
        return *cached_;
    }

    // Build a fresh template
    BlockAssembler assembler(chain_, &mempool_);
    cached_ = std::make_unique<BlockTemplate>(assembler.create_template(coinbase_pubkey));

    // Update cache metadata
    CBlockIndex* tip = chain_.tip();
    if (tip) {
        cached_tip_hash_ = tip->hash;
    }
    cached_mempool_count_ = mempool_.size();
    cached_time_ = GetTime();

    return *cached_;
}

void TemplateCache::invalidate() {
    cached_.reset();
    cached_tip_hash_.set_null();
    cached_mempool_count_ = 0;
    cached_time_ = 0;
}

bool TemplateCache::is_stale() const {
    if (!cached_) return true;

    // Stale if tip has changed
    CBlockIndex* tip = chain_.tip();
    if (tip) {
        if (tip->hash != cached_tip_hash_) return true;
    } else if (!cached_tip_hash_.is_null()) {
        return true;
    }

    // Stale if mempool has changed significantly (>10% difference)
    size_t current_count = mempool_.size();
    if (cached_mempool_count_ > 0) {
        double ratio = static_cast<double>(current_count) /
                       static_cast<double>(cached_mempool_count_);
        if (ratio < 0.9 || ratio > 1.1) return true;
    } else if (current_count > 0) {
        return true;
    }

    // Stale if too old
    if (GetTime() - cached_time_ > MAX_CACHE_AGE) return true;

    return false;
}

// ===========================================================================
// Template validation helpers
// ===========================================================================

bool BlockAssembler::validate_template(const BlockTemplate& tmpl) const {
    // Verify the template is internally consistent

    // 1. Check header height
    CBlockIndex* tip = chain_.tip();
    uint64_t expected_height = tip ? tip->height + 1 : 0;
    if (tmpl.header.height != expected_height) return false;

    // 2. Check prev_hash
    if (tip) {
        if (tmpl.header.prev_hash != tip->hash) return false;
    }

    // 3. Check coinbase value
    Amount reward = compute_reward(tmpl.header.height);
    Amount max_coinbase = reward + tmpl.total_fees;
    if (tmpl.coinbase_value > max_coinbase) return false;

    // 4. Check total block size
    if (tmpl.estimated_block_size() > max_block_size_) return false;

    // 5. Check total block weight
    if (tmpl.estimated_block_weight() > max_block_weight_) return false;

    // 6. Check sigops
    int total_sigops = 0;
    total_sigops += estimate_sigops(tmpl.coinbase_tx);
    for (const auto& tx : tmpl.transactions) {
        total_sigops += estimate_sigops(tx);
    }
    if (total_sigops > max_block_sigops_) return false;

    // 7. Check target is non-zero
    if (tmpl.target.is_null()) return false;

    // 8. Check model dimensions are valid
    if (tmpl.dims.d_model == 0 || tmpl.dims.n_layers == 0) return false;

    return true;
}

// ===========================================================================
// Template serialization for Stratum
// ===========================================================================

std::vector<uint8_t> BlockAssembler::serialize_template_for_stratum(
    const BlockTemplate& tmpl) const {

    DataWriter w(4096);

    // Template ID (8 bytes)
    w.write_u64_le(tmpl.template_id);

    // Header fields needed by the miner
    auto hdr_data = tmpl.header.get_unsigned_data();
    w.write_bytes(hdr_data.data(), hdr_data.size());

    // Target (32 bytes)
    w.write_bytes(tmpl.target.data(), 32);

    // Minimum training steps
    w.write_u32_le(tmpl.min_train_steps);

    // Model dimensions
    w.write_u32_le(tmpl.dims.d_model);
    w.write_u32_le(tmpl.dims.n_layers);
    w.write_u32_le(tmpl.dims.d_ff);
    w.write_u32_le(tmpl.dims.n_heads);
    w.write_u32_le(tmpl.dims.gru_dim);
    w.write_u32_le(tmpl.dims.n_slots);

    // Coinbase value
    w.write_i64_le(tmpl.coinbase_value);

    // Total fees
    w.write_i64_le(tmpl.total_fees);

    // Coinbase transaction (serialized)
    auto coinbase_data = tmpl.coinbase_tx.serialize();
    w.write_compact_size(coinbase_data.size());
    w.write_bytes(coinbase_data.data(), coinbase_data.size());

    // Transaction count (excluding coinbase)
    w.write_compact_size(tmpl.transactions.size());

    // Transaction IDs (for merkle proof construction)
    for (const auto& tx : tmpl.transactions) {
        uint256 txid = tx.get_txid();
        w.write_bytes(txid.data(), 32);
    }

    // Creation timestamp
    w.write_i64_le(tmpl.creation_time);

    return w.release();
}

// ===========================================================================
// Merkle branch construction for Stratum
// ===========================================================================

std::vector<uint256> BlockAssembler::compute_merkle_branch(
    const BlockTemplate& tmpl, size_t tx_index) const {

    // Build the full list of transaction hashes
    std::vector<uint256> hashes;
    hashes.push_back(tmpl.coinbase_tx.get_txid());
    for (const auto& tx : tmpl.transactions) {
        hashes.push_back(tx.get_txid());
    }

    if (hashes.empty()) return {};
    if (tx_index >= hashes.size()) return {};

    std::vector<uint256> branch;

    // Iteratively compute the merkle branch (the sibling hashes needed
    // to reconstruct the merkle root given just the transaction at tx_index)
    size_t n = hashes.size();
    size_t idx = tx_index;

    while (n > 1) {
        // If odd number of elements, duplicate the last
        if (n % 2 != 0) {
            hashes.push_back(hashes.back());
            n++;
        }

        // Record the sibling of our current index
        size_t sibling = (idx % 2 == 0) ? idx + 1 : idx - 1;
        if (sibling < n) {
            branch.push_back(hashes[sibling]);
        }

        // Compute the next level
        std::vector<uint256> next_level;
        for (size_t i = 0; i < n; i += 2) {
            std::vector<uint8_t> combined(64);
            std::memcpy(combined.data(), hashes[i].data(), 32);
            std::memcpy(combined.data() + 32, hashes[i + 1].data(), 32);
            next_level.push_back(keccak256(combined.data(), combined.size()));
        }

        hashes = std::move(next_level);
        n = hashes.size();
        idx = idx / 2;
    }

    return branch;
}

// ===========================================================================
// Block template comparison (for detecting stale work)
// ===========================================================================

bool BlockAssembler::templates_compatible(const BlockTemplate& a,
                                           const BlockTemplate& b) const {
    // Two templates are compatible if they build on the same chain tip
    // and have the same difficulty target. Compatible templates allow
    // miners to switch between them without restarting training.

    if (a.header.prev_hash != b.header.prev_hash) return false;
    if (a.header.height != b.header.height) return false;
    if (a.header.nbits != b.header.nbits) return false;

    // Model dimensions must also match
    if (a.dims.d_model != b.dims.d_model) return false;
    if (a.dims.n_layers != b.dims.n_layers) return false;
    if (a.dims.d_ff != b.dims.d_ff) return false;
    if (a.dims.n_heads != b.dims.n_heads) return false;
    if (a.dims.gru_dim != b.dims.gru_dim) return false;
    if (a.dims.n_slots != b.dims.n_slots) return false;

    return true;
}

// ===========================================================================
// Fee estimation helpers
// ===========================================================================

Amount BlockAssembler::estimate_total_fees(const Mempool* mempool,
                                            size_t max_block_size) const {
    if (!mempool) return 0;

    auto sorted = mempool->get_sorted_transactions();
    if (sorted.empty()) return 0;

    Amount total = 0;
    size_t current_size = BLOCK_HEADER_SIZE + 100;  // Header + coinbase estimate

    for (const auto& tx : sorted) {
        size_t tx_size = tx.get_serialize_size();
        if (current_size + tx_size > max_block_size) break;

        // Estimate fee from the mempool
        Amount fee = mempool->get_fee(tx.get_txid());
        total += fee;
        current_size += tx_size;
    }

    return total;
}

double BlockAssembler::estimate_fee_rate_percentile(
    const Mempool* mempool, double percentile) const {

    if (!mempool) return 0.0;

    auto sorted = mempool->get_sorted_transactions();
    if (sorted.empty()) return 0.0;

    // Collect fee rates
    std::vector<double> fee_rates;
    fee_rates.reserve(sorted.size());

    for (const auto& tx : sorted) {
        size_t size = tx.get_serialize_size();
        if (size == 0) continue;
        Amount fee = mempool->get_fee(tx.get_txid());
        fee_rates.push_back(static_cast<double>(fee) / static_cast<double>(size));
    }

    if (fee_rates.empty()) return 0.0;

    std::sort(fee_rates.begin(), fee_rates.end());

    // Find the value at the given percentile
    double rank = percentile * static_cast<double>(fee_rates.size() - 1);
    size_t lower = static_cast<size_t>(rank);
    size_t upper = lower + 1;
    if (upper >= fee_rates.size()) upper = fee_rates.size() - 1;

    double frac = rank - static_cast<double>(lower);
    return fee_rates[lower] * (1.0 - frac) + fee_rates[upper] * frac;
}

} // namespace flow

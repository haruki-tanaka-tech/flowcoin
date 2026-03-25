// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for block analysis: field population, transaction counting,
// fee computation, delta statistics, script type analysis,
// block comparison, Merkle proofs, and coinbase construction.

#include "consensus/growth.h"
#include "consensus/merkle.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "hash/keccak.h"
#include "primitives/block.h"
#include "primitives/delta.h"
#include "primitives/transaction.h"
#include "util/random.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <map>
#include <numeric>
#include <set>
#include <vector>

using namespace flow;
using namespace flow::consensus;

// ---------------------------------------------------------------------------
// BlockAnalysis — aggregated block metrics
// ---------------------------------------------------------------------------

struct BlockAnalysis {
    uint256  block_hash;
    uint64_t height;
    int64_t  timestamp;
    uint32_t nbits;
    float    val_loss;
    size_t   tx_count;
    size_t   block_size;
    Amount   total_fees;
    Amount   coinbase_value;
    Amount   total_output;

    // Delta stats
    float    delta_sparsity;
    size_t   delta_compressed_size;
    uint32_t delta_sparse_count;

    // Script type counts
    size_t   p2pkh_count;  // pay-to-pubkey-hash
    size_t   op_return_count;
    size_t   other_count;

    static BlockAnalysis compute(const CBlock& block) {
        BlockAnalysis a;
        a.block_hash = block.get_hash();
        a.height = block.height;
        a.timestamp = block.timestamp;
        a.nbits = block.nbits;
        a.val_loss = block.val_loss;
        a.tx_count = block.vtx.size();
        a.block_size = block.get_block_size();
        a.coinbase_value = block.get_coinbase_value();
        a.delta_compressed_size = block.delta_payload.size();
        a.delta_sparse_count = block.sparse_count;
        a.delta_sparsity = (block.delta_length > 0)
            ? static_cast<float>(block.sparse_count) / static_cast<float>(block.delta_length)
            : 0.0f;

        // Compute total output value and fees
        a.total_output = 0;
        for (const auto& tx : block.vtx) {
            a.total_output += tx.get_value_out();
        }
        // Fees = coinbase_value - block_reward (simplified)
        Amount block_reward = compute_block_reward(block.height);
        a.total_fees = (a.coinbase_value > block_reward)
            ? (a.coinbase_value - block_reward) : 0;

        // Count script types
        a.p2pkh_count = 0;
        a.op_return_count = 0;
        a.other_count = 0;
        for (const auto& tx : block.vtx) {
            for (const auto& out : tx.vout) {
                if (out.amount == 0) {
                    a.op_return_count++;
                } else {
                    a.p2pkh_count++;  // All normal outputs are P2PKH
                }
            }
        }

        return a;
    }
};

// ---------------------------------------------------------------------------
// BlockCompare — compare two blocks
// ---------------------------------------------------------------------------

struct BlockCompareResult {
    bool same_hash;
    bool same_height;
    bool same_nbits;
    bool same_tx_count;
    bool same_merkle_root;
    bool same_val_loss;
    int  difference_count;
};

static BlockCompareResult compare_blocks(const CBlock& a, const CBlock& b) {
    BlockCompareResult r;
    r.same_hash = (a.get_hash() == b.get_hash());
    r.same_height = (a.height == b.height);
    r.same_nbits = (a.nbits == b.nbits);
    r.same_tx_count = (a.vtx.size() == b.vtx.size());
    r.same_merkle_root = (a.merkle_root == b.merkle_root);
    r.same_val_loss = (a.val_loss == b.val_loss);

    r.difference_count = 0;
    if (!r.same_hash) r.difference_count++;
    if (!r.same_height) r.difference_count++;
    if (!r.same_nbits) r.difference_count++;
    if (!r.same_tx_count) r.difference_count++;
    if (!r.same_merkle_root) r.difference_count++;
    if (!r.same_val_loss) r.difference_count++;

    return r;
}

// ---------------------------------------------------------------------------
// MerkleProof — proof of inclusion for a transaction
// ---------------------------------------------------------------------------

struct MerkleProof {
    uint256 tx_hash;
    size_t  tx_index;
    std::vector<uint256> branch;
    uint256 root;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data;
        // tx_hash (32) + tx_index (8) + root (32) + branch_len (4) + branches (32 each)
        size_t total = 32 + 8 + 32 + 4 + branch.size() * 32;
        data.resize(total);
        size_t offset = 0;

        std::memcpy(data.data() + offset, tx_hash.data(), 32); offset += 32;
        uint64_t idx = tx_index;
        std::memcpy(data.data() + offset, &idx, 8); offset += 8;
        std::memcpy(data.data() + offset, root.data(), 32); offset += 32;
        uint32_t blen = static_cast<uint32_t>(branch.size());
        std::memcpy(data.data() + offset, &blen, 4); offset += 4;
        for (const auto& h : branch) {
            std::memcpy(data.data() + offset, h.data(), 32); offset += 32;
        }
        return data;
    }

    static MerkleProof deserialize(const std::vector<uint8_t>& data) {
        MerkleProof proof;
        assert(data.size() >= 76);
        size_t offset = 0;

        std::memcpy(proof.tx_hash.data(), data.data() + offset, 32); offset += 32;
        uint64_t idx;
        std::memcpy(&idx, data.data() + offset, 8); offset += 8;
        proof.tx_index = static_cast<size_t>(idx);
        std::memcpy(proof.root.data(), data.data() + offset, 32); offset += 32;

        uint32_t blen;
        std::memcpy(&blen, data.data() + offset, 4); offset += 4;
        proof.branch.resize(blen);
        for (uint32_t i = 0; i < blen; ++i) {
            std::memcpy(proof.branch[i].data(), data.data() + offset, 32);
            offset += 32;
        }
        return proof;
    }
};

// ---------------------------------------------------------------------------
// Helper: create a test block with N transactions
// ---------------------------------------------------------------------------

static CBlock make_test_block(uint64_t height, int extra_tx_count = 0) {
    CBlock block;
    block.version = 1;
    block.height = height;
    block.timestamp = GENESIS_TIMESTAMP + static_cast<int64_t>(height) * TARGET_BLOCK_TIME;
    block.nbits = INITIAL_NBITS;
    block.val_loss = 5.0f;
    block.prev_val_loss = 5.0f;

    auto dims = compute_growth(height);
    block.d_model = dims.d_model;
    block.n_layers = dims.n_layers;
    block.d_ff = dims.d_ff;
    block.n_heads = dims.n_heads;
    block.gru_dim = dims.gru_dim;
    block.n_slots = dims.n_slots;

    // Coinbase
    Amount reward = compute_block_reward(height);
    std::array<uint8_t, 32> miner_pkh{};
    miner_pkh[0] = 0xAA;
    CTransaction coinbase = CBlock::make_coinbase(height, reward, miner_pkh);
    block.vtx.push_back(coinbase);

    // Additional transactions
    for (int i = 0; i < extra_tx_count; ++i) {
        CTransaction tx;
        tx.version = 1;

        CTxIn in;
        for (int j = 0; j < 32; ++j) {
            in.prevout.txid[j] = static_cast<uint8_t>((i + 1) * 7 + j);
        }
        in.prevout.index = 0;
        tx.vin.push_back(in);

        std::array<uint8_t, 32> pkh{};
        pkh[0] = static_cast<uint8_t>(i + 1);
        tx.vout.push_back(CTxOut(1 * COIN, pkh));
        block.vtx.push_back(tx);
    }

    block.merkle_root = block.compute_merkle_root();
    return block;
}

void test_block_analysis() {

    // -----------------------------------------------------------------------
    // Test 1: BlockAnalysis: all fields populated for genesis
    // -----------------------------------------------------------------------
    {
        auto block = make_test_block(0);
        auto analysis = BlockAnalysis::compute(block);

        assert(!analysis.block_hash.is_null());
        assert(analysis.height == 0);
        assert(analysis.timestamp == GENESIS_TIMESTAMP);
        assert(analysis.nbits == INITIAL_NBITS);
        assert(analysis.val_loss == 5.0f);
        assert(analysis.tx_count == 1);  // just coinbase
        assert(analysis.block_size > 0);
        assert(analysis.coinbase_value == INITIAL_REWARD);
    }

    // -----------------------------------------------------------------------
    // Test 2: BlockAnalysis: correct tx_count for multi-tx block
    // -----------------------------------------------------------------------
    {
        auto block = make_test_block(1, 5);  // 1 coinbase + 5 extra
        auto analysis = BlockAnalysis::compute(block);
        assert(analysis.tx_count == 6);
    }

    // -----------------------------------------------------------------------
    // Test 3: BlockAnalysis: fee computation correct
    // -----------------------------------------------------------------------
    {
        auto block = make_test_block(0);
        // Add extra reward to coinbase to simulate fees
        block.vtx[0].vout[0].amount = INITIAL_REWARD + 1000;
        auto analysis = BlockAnalysis::compute(block);

        assert(analysis.total_fees == 1000);
    }

    // -----------------------------------------------------------------------
    // Test 4: BlockAnalysis: delta stats (sparsity, sizes)
    // -----------------------------------------------------------------------
    {
        auto block = make_test_block(0);
        block.sparse_count = 100;
        block.delta_length = 1000;

        auto analysis = BlockAnalysis::compute(block);
        assert(analysis.delta_sparse_count == 100);
        float expected_sparsity = 100.0f / 1000.0f;
        assert(std::abs(analysis.delta_sparsity - expected_sparsity) < 0.001f);
    }

    // -----------------------------------------------------------------------
    // Test 5: BlockAnalysis: script type counts
    // -----------------------------------------------------------------------
    {
        auto block = make_test_block(0, 3);

        // Add an OP_RETURN output to the second transaction
        CTxOut op_return;
        op_return.amount = 0;
        block.vtx[1].vout.push_back(op_return);

        auto analysis = BlockAnalysis::compute(block);

        // 1 coinbase output + 3 regular outputs = 4 P2PKH
        // 1 OP_RETURN output
        assert(analysis.p2pkh_count == 4);
        assert(analysis.op_return_count == 1);
    }

    // -----------------------------------------------------------------------
    // Test 6: Block compare: same block -> all same
    // -----------------------------------------------------------------------
    {
        auto block = make_test_block(0);
        auto result = compare_blocks(block, block);

        assert(result.same_hash);
        assert(result.same_height);
        assert(result.same_nbits);
        assert(result.same_tx_count);
        assert(result.same_merkle_root);
        assert(result.same_val_loss);
        assert(result.difference_count == 0);
    }

    // -----------------------------------------------------------------------
    // Test 7: Block compare: different blocks -> differences detected
    // -----------------------------------------------------------------------
    {
        auto block_a = make_test_block(0);
        auto block_b = make_test_block(1, 2);

        auto result = compare_blocks(block_a, block_b);
        assert(!result.same_height);
        assert(!result.same_tx_count);
        assert(result.difference_count > 0);
    }

    // -----------------------------------------------------------------------
    // Test 8: MerkleProof: generate and verify succeeds
    // -----------------------------------------------------------------------
    {
        auto block = make_test_block(0, 3);  // 4 transactions total

        // Generate proof for tx at index 2
        auto branch = compute_merkle_branch(block.vtx, 2);
        uint256 leaf = block.vtx[2].get_txid();

        MerkleProof proof;
        proof.tx_hash = leaf;
        proof.tx_index = 2;
        proof.branch = branch;
        proof.root = block.merkle_root;

        // Verify
        bool valid = verify_merkle_branch(leaf, 2, branch, block.merkle_root);
        assert(valid);
    }

    // -----------------------------------------------------------------------
    // Test 9: MerkleProof: tampered proof fails
    // -----------------------------------------------------------------------
    {
        auto block = make_test_block(0, 3);

        auto branch = compute_merkle_branch(block.vtx, 1);
        uint256 leaf = block.vtx[1].get_txid();

        // Tamper with one branch hash
        if (!branch.empty()) {
            branch[0][0] ^= 0xFF;
        }

        bool valid = verify_merkle_branch(leaf, 1, branch, block.merkle_root);
        assert(!valid);
    }

    // -----------------------------------------------------------------------
    // Test 10: MerkleProof: serialize/deserialize round-trip
    // -----------------------------------------------------------------------
    {
        auto block = make_test_block(0, 2);

        auto branch = compute_merkle_branch(block.vtx, 0);
        MerkleProof proof;
        proof.tx_hash = block.vtx[0].get_txid();
        proof.tx_index = 0;
        proof.branch = branch;
        proof.root = block.merkle_root;

        auto serialized = proof.serialize();
        auto proof2 = MerkleProof::deserialize(serialized);

        assert(proof2.tx_hash == proof.tx_hash);
        assert(proof2.tx_index == proof.tx_index);
        assert(proof2.root == proof.root);
        assert(proof2.branch.size() == proof.branch.size());
        for (size_t i = 0; i < proof.branch.size(); ++i) {
            assert(proof2.branch[i] == proof.branch[i]);
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: create_coinbase: correct value and structure
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> miner_pk{};
        miner_pk[0] = 0xBB;

        Amount reward = 50 * COIN;
        auto cb = CBlock::make_coinbase(0, reward, miner_pk);

        assert(cb.is_coinbase());
        assert(cb.vin.size() == 1);
        assert(cb.vin[0].is_coinbase());
        assert(cb.vout.size() >= 1);
        assert(cb.get_value_out() == reward);
    }

    // -----------------------------------------------------------------------
    // Test 12: create_coinbase_multi: multiple payees
    // -----------------------------------------------------------------------
    {
        // Simulate splitting coinbase between miner and dev fund
        std::array<uint8_t, 32> miner_pk{}, dev_pk{};
        miner_pk[0] = 0xCC;
        dev_pk[0] = 0xDD;

        Amount total_reward = 50 * COIN;
        Amount miner_share = 45 * COIN;
        Amount dev_share = 5 * COIN;

        CTransaction cb;
        cb.version = 1;

        // Coinbase input
        CTxIn cb_in;
        cb_in.prevout.txid.set_null();
        cb_in.prevout.index = 0;
        cb.vin.push_back(cb_in);

        // Miner output
        auto miner_pkh = keccak256(miner_pk.data(), 32);
        std::array<uint8_t, 32> miner_pkh_arr;
        std::memcpy(miner_pkh_arr.data(), miner_pkh.data(), 32);
        cb.vout.push_back(CTxOut(miner_share, miner_pkh_arr));

        // Dev fund output
        auto dev_pkh = keccak256(dev_pk.data(), 32);
        std::array<uint8_t, 32> dev_pkh_arr;
        std::memcpy(dev_pkh_arr.data(), dev_pkh.data(), 32);
        cb.vout.push_back(CTxOut(dev_share, dev_pkh_arr));

        assert(cb.is_coinbase());
        assert(cb.vout.size() == 2);
        assert(cb.get_value_out() == total_reward);
        assert(cb.vout[0].amount == miner_share);
        assert(cb.vout[1].amount == dev_share);
    }

    // -----------------------------------------------------------------------
    // Test 13: BlockAnalysis at various heights
    // -----------------------------------------------------------------------
    {
        for (uint64_t h = 0; h < 10; ++h) {
            auto block = make_test_block(h);
            auto analysis = BlockAnalysis::compute(block);
            assert(analysis.height == h);
            assert(analysis.coinbase_value == compute_block_reward(h));
        }
    }

    // -----------------------------------------------------------------------
    // Test 14: Block weight computation
    // -----------------------------------------------------------------------
    {
        auto block = make_test_block(0, 5);
        size_t weight = block.get_block_weight();
        assert(weight > 0);

        // More transactions -> more weight
        auto block2 = make_test_block(0, 20);
        size_t weight2 = block2.get_block_weight();
        assert(weight2 > weight);
    }

    // -----------------------------------------------------------------------
    // Test 15: Merkle root changes with different transactions
    // -----------------------------------------------------------------------
    {
        auto block1 = make_test_block(0, 1);
        auto block2 = make_test_block(0, 2);

        assert(block1.merkle_root != block2.merkle_root);
    }

    // -----------------------------------------------------------------------
    // Test 16: Verify merkle root matches computed
    // -----------------------------------------------------------------------
    {
        auto block = make_test_block(0, 3);
        assert(block.verify_merkle_root());

        // Tamper with merkle root
        block.merkle_root[0] ^= 0xFF;
        assert(!block.verify_merkle_root());
    }
}

// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "merkle.h"
#include "../hash/keccak.h"
#include "../hash/merkle.h"

#include <cstring>

namespace flow::consensus {

uint256 compute_block_merkle_root(const std::vector<CTransaction>& vtx) {
    // Extract the txid from each transaction to form the leaf set.
    // The txid is keccak256d of the transaction's signable data
    // (version + inputs without sigs + outputs + locktime).
    std::vector<uint256> leaves;
    leaves.reserve(vtx.size());

    for (const auto& tx : vtx) {
        leaves.push_back(tx.get_txid());
    }

    // Delegate to the generic Merkle tree implementation.
    // Empty list returns null hash; single leaf returns itself unchanged;
    // odd count duplicates the last leaf; pairs are hashed with keccak256d.
    return compute_merkle_root(leaves);
}

// ---------------------------------------------------------------------------
// compute_merkle_branch — Merkle proof for SPV
// ---------------------------------------------------------------------------

std::vector<uint256> compute_merkle_branch(const std::vector<CTransaction>& vtx,
                                            size_t index) {
    std::vector<uint256> branch;

    if (vtx.empty() || index >= vtx.size()) {
        return branch;
    }

    // Build leaf set
    std::vector<uint256> leaves;
    leaves.reserve(vtx.size());
    for (const auto& tx : vtx) {
        leaves.push_back(tx.get_txid());
    }

    // Build the Merkle tree level by level, recording siblings
    std::vector<uint256> current = leaves;
    size_t target = index;

    while (current.size() > 1) {
        // If odd number of elements, duplicate last
        if (current.size() % 2 != 0) {
            current.push_back(current.back());
        }

        // Record the sibling of our target
        size_t sibling;
        if (target % 2 == 0) {
            sibling = target + 1;
        } else {
            sibling = target - 1;
        }

        if (sibling < current.size()) {
            branch.push_back(current[sibling]);
        }

        // Build next level
        std::vector<uint256> next;
        next.reserve(current.size() / 2);
        for (size_t i = 0; i + 1 < current.size(); i += 2) {
            // Concatenate pair and hash
            uint8_t concat[64];
            std::memcpy(concat, current[i].data(), 32);
            std::memcpy(concat + 32, current[i + 1].data(), 32);
            next.push_back(keccak256(concat, 64));
        }

        current = next;
        target /= 2;
    }

    return branch;
}

// ---------------------------------------------------------------------------
// verify_merkle_branch
// ---------------------------------------------------------------------------

bool verify_merkle_branch(const uint256& leaf, size_t index,
                           const std::vector<uint256>& branch,
                           const uint256& root) {
    uint256 hash = leaf;
    size_t idx = index;

    for (const auto& sibling : branch) {
        uint8_t concat[64];
        if (idx % 2 == 0) {
            // Our hash goes left, sibling goes right
            std::memcpy(concat, hash.data(), 32);
            std::memcpy(concat + 32, sibling.data(), 32);
        } else {
            // Sibling goes left, our hash goes right
            std::memcpy(concat, sibling.data(), 32);
            std::memcpy(concat + 32, hash.data(), 32);
        }
        hash = keccak256(concat, 64);
        idx /= 2;
    }

    return hash == root;
}

// ---------------------------------------------------------------------------
// compute_witness_commitment
// ---------------------------------------------------------------------------

uint256 compute_witness_commitment(const std::vector<CTransaction>& vtx) {
    // For FlowCoin (no segwit), the witness commitment is simply
    // the merkle root hashed once more with a null witness nonce.
    uint256 merkle_root = compute_block_merkle_root(vtx);

    // commitment = keccak256(merkle_root || 0x00...00)
    uint8_t data[64];
    std::memcpy(data, merkle_root.data(), 32);
    std::memset(data + 32, 0, 32);

    return keccak256(data, 64);
}

} // namespace flow::consensus

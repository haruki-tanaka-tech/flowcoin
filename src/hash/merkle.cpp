// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "merkle.h"
#include "keccak.h"

#include <cstring>

namespace flow {

// ===========================================================================
// Internal helper: hash two nodes together
// ===========================================================================

static uint256 hash_pair(const uint256& left, const uint256& right) {
    uint8_t combined[64];
    std::memcpy(combined, left.data(), 32);
    std::memcpy(combined + 32, right.data(), 32);
    return keccak256d(combined, 64);
}

// ===========================================================================
// Merkle root computation
// ===========================================================================

uint256 compute_merkle_root(const std::vector<uint256>& leaves) {
    return compute_merkle_root(leaves, nullptr);
}

uint256 compute_merkle_root(const std::vector<uint256>& leaves, bool* mutated_out) {
    if (mutated_out) *mutated_out = false;

    if (leaves.empty()) {
        return uint256();  // all zeros
    }

    // Working copy -- reduce in-place each round
    std::vector<uint256> level = leaves;

    while (level.size() > 1) {
        // If odd number of entries, duplicate the last one
        if (level.size() % 2 != 0) {
            if (mutated_out) *mutated_out = true;
            level.push_back(level.back());
        }

        // Check for duplicate adjacent pairs (CVE-2012-2459)
        if (mutated_out) {
            for (size_t i = 0; i < level.size(); i += 2) {
                if (level[i] == level[i + 1]) {
                    *mutated_out = true;
                }
            }
        }

        std::vector<uint256> next;
        next.reserve(level.size() / 2);

        for (size_t i = 0; i < level.size(); i += 2) {
            next.push_back(hash_pair(level[i], level[i + 1]));
        }

        level = std::move(next);
    }

    return level[0];
}

// ===========================================================================
// Merkle proof generation
// ===========================================================================

std::vector<uint256> compute_merkle_branch(const std::vector<uint256>& leaves,
                                            size_t index) {
    std::vector<uint256> branch;

    if (leaves.empty() || index >= leaves.size()) {
        return branch;
    }

    std::vector<uint256> level = leaves;
    size_t idx = index;

    while (level.size() > 1) {
        // Duplicate last element if odd
        if (level.size() % 2 != 0) {
            level.push_back(level.back());
        }

        // The sibling of idx is idx^1 (flip the last bit)
        size_t sibling = idx ^ 1;
        if (sibling < level.size()) {
            branch.push_back(level[sibling]);
        }

        // Move up: compute the next level
        std::vector<uint256> next;
        next.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next.push_back(hash_pair(level[i], level[i + 1]));
        }

        level = std::move(next);
        idx /= 2;
    }

    return branch;
}

// ===========================================================================
// Merkle proof verification
// ===========================================================================

uint256 compute_root_from_branch(const uint256& leaf,
                                  const std::vector<uint256>& branch,
                                  size_t index) {
    uint256 current = leaf;
    size_t idx = index;

    for (const auto& sibling : branch) {
        if (idx & 1) {
            // Current node is on the right, sibling is on the left
            current = hash_pair(sibling, current);
        } else {
            // Current node is on the left, sibling is on the right
            current = hash_pair(current, sibling);
        }
        idx >>= 1;
    }

    return current;
}

bool verify_merkle_branch(const uint256& leaf,
                           const std::vector<uint256>& branch,
                           size_t index,
                           const uint256& root) {
    uint256 computed = compute_root_from_branch(leaf, branch, index);
    return computed == root;
}

// ===========================================================================
// MerkleTree class
// ===========================================================================

MerkleTree::MerkleTree() = default;

bool MerkleTree::compute(const std::vector<uint256>& leaves) {
    tree_.clear();

    if (leaves.empty()) {
        return false;
    }

    // Level 0 = leaves
    tree_.push_back(leaves);

    // Build each subsequent level
    while (tree_.back().size() > 1) {
        const auto& prev = tree_.back();
        std::vector<uint256> next;

        // Copy the level (we may need to add a duplicate)
        std::vector<uint256> level = prev;
        if (level.size() % 2 != 0) {
            level.push_back(level.back());
        }

        next.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next.push_back(hash_pair(level[i], level[i + 1]));
        }

        tree_.push_back(std::move(next));
    }

    return true;
}

uint256 MerkleTree::get_root() const {
    if (tree_.empty()) {
        return uint256();
    }
    return tree_.back()[0];
}

std::vector<uint256> MerkleTree::get_proof(size_t index) const {
    std::vector<uint256> proof;

    if (tree_.empty() || index >= tree_[0].size()) {
        return proof;
    }

    size_t idx = index;

    for (size_t level = 0; level + 1 < tree_.size(); ++level) {
        const auto& nodes = tree_[level];

        // Handle odd-sized level: the last node's sibling is itself
        size_t level_size = nodes.size();
        size_t sibling = idx ^ 1;

        if (sibling < level_size) {
            proof.push_back(nodes[sibling]);
        } else {
            // Sibling is the duplicate of the last node
            proof.push_back(nodes[level_size - 1]);
        }

        idx /= 2;
    }

    return proof;
}

uint256 MerkleTree::get_leaf(size_t index) const {
    if (tree_.empty() || index >= tree_[0].size()) {
        return uint256();
    }
    return tree_[0][index];
}

int MerkleTree::depth() const {
    if (tree_.empty()) return 0;
    return static_cast<int>(tree_.size()) - 1;
}

size_t MerkleTree::leaf_count() const {
    if (tree_.empty()) return 0;
    return tree_[0].size();
}

bool MerkleTree::empty() const {
    return tree_.empty();
}

void MerkleTree::clear() {
    tree_.clear();
}

bool MerkleTree::verify_leaf(const uint256& leaf, size_t index) const {
    if (tree_.empty() || index >= tree_[0].size()) {
        return false;
    }
    return tree_[0][index] == leaf;
}

} // namespace flow

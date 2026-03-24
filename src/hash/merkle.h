// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Merkle tree computation using keccak256d for internal nodes.
// Supports root computation, proof generation, and proof verification.

#pragma once

#include "../util/types.h"
#include <cstdint>
#include <vector>

namespace flow {

// ===========================================================================
// Merkle root computation
// ===========================================================================

/** Compute the Merkle root from a list of leaf hashes.
 *
 *  Algorithm (same structure as Bitcoin):
 *  - Empty list: returns a null hash (all zeros).
 *  - Single leaf: returns that leaf unchanged.
 *  - Odd count: the last leaf is duplicated.
 *  - Each pair of adjacent hashes is combined: keccak256d(left || right).
 *  - Repeat until a single root remains.
 */
uint256 compute_merkle_root(const std::vector<uint256>& leaves);

/** Compute Merkle root with mutation detection.
 *  @param leaves       List of leaf hashes.
 *  @param mutated_out  Set to true if the tree has an even number of leaves
 *                      at any level causing a leaf to be duplicated. This
 *                      indicates potential CVE-2012-2459 vulnerability.
 *  @return             The Merkle root hash.
 */
uint256 compute_merkle_root(const std::vector<uint256>& leaves, bool* mutated_out);

// ===========================================================================
// Merkle proof (SPV verification)
// ===========================================================================

/** Compute the Merkle proof (authentication path) for a leaf at the given index.
 *  The proof consists of sibling hashes needed to reconstruct the root.
 *
 *  @param leaves  All leaf hashes in the tree.
 *  @param index   Index of the leaf to generate a proof for (0-based).
 *  @return        Vector of sibling hashes from leaf to root.
 *                 Empty if index is out of range or leaves is empty.
 */
std::vector<uint256> compute_merkle_branch(const std::vector<uint256>& leaves,
                                            size_t index);

/** Verify a Merkle proof.
 *  Given a leaf hash, its proof (branch), position index, and the expected root,
 *  verify that the leaf is part of the tree.
 *
 *  @param leaf    The leaf hash to verify.
 *  @param branch  The Merkle proof (sibling hashes from leaf to root).
 *  @param index   The position of the leaf (0-based). Used to determine
 *                 whether the proof hash goes on the left or right.
 *  @param root    The expected Merkle root.
 *  @return        true if the proof is valid.
 */
bool verify_merkle_branch(const uint256& leaf,
                           const std::vector<uint256>& branch,
                           size_t index,
                           const uint256& root);

/** Compute the root from a leaf and its Merkle proof.
 *  This is useful for computing the root without knowing it in advance.
 *
 *  @param leaf    The leaf hash.
 *  @param branch  The Merkle proof (sibling hashes).
 *  @param index   The position of the leaf.
 *  @return        The computed Merkle root.
 */
uint256 compute_root_from_branch(const uint256& leaf,
                                  const std::vector<uint256>& branch,
                                  size_t index);

// ===========================================================================
// MerkleTree class: cached tree for repeated queries
// ===========================================================================

/** Full Merkle tree with cached internal nodes.
 *  Stores the complete tree structure for efficient proof generation
 *  and root queries without recomputation.
 */
class MerkleTree {
public:
    MerkleTree();

    /** Build the tree from a list of leaf hashes.
     *  @param leaves  The leaf hashes. Must not be empty.
     *  @return        true on success, false if leaves is empty.
     */
    bool compute(const std::vector<uint256>& leaves);

    /** Get the Merkle root.
     *  @return  The root hash, or a null hash if the tree is empty.
     */
    uint256 get_root() const;

    /** Get the Merkle proof for a leaf at the given index.
     *  @param index  Index of the leaf (0-based).
     *  @return       Vector of sibling hashes from leaf to root.
     *                Empty if index is out of range.
     */
    std::vector<uint256> get_proof(size_t index) const;

    /** Get a leaf hash by index.
     *  @param index  Index of the leaf (0-based).
     *  @return       The leaf hash. Null hash if index is out of range.
     */
    uint256 get_leaf(size_t index) const;

    /** Get the depth of the tree (number of levels above the leaves).
     *  A tree with 1 leaf has depth 0.
     *  A tree with 2 leaves has depth 1.
     *  A tree with 3-4 leaves has depth 2.
     */
    int depth() const;

    /** Get the number of leaves. */
    size_t leaf_count() const;

    /** Check if the tree is empty. */
    bool empty() const;

    /** Clear the tree. */
    void clear();

    /** Verify that a leaf is in the tree.
     *  @param leaf   The leaf hash.
     *  @param index  The expected position.
     *  @return       true if the leaf matches at the given index.
     */
    bool verify_leaf(const uint256& leaf, size_t index) const;

private:
    /** The tree stored level by level.
     *  tree_[0] = leaves
     *  tree_[1] = first level of internal nodes
     *  ...
     *  tree_[depth()] = root (single element)
     */
    std::vector<std::vector<uint256>> tree_;
};

} // namespace flow

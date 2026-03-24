// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Convenience wrapper: compute the Merkle root for a block's transaction list.
// Delegates to the generic hash/merkle.h implementation after extracting txids.

#ifndef FLOWCOIN_CONSENSUS_MERKLE_H
#define FLOWCOIN_CONSENSUS_MERKLE_H

#include "../util/types.h"
#include "../primitives/transaction.h"

#include <vector>

namespace flow::consensus {

/** Compute the Merkle root of a block's transactions.
 *
 *  Extracts the txid (double keccak256) from each transaction, then
 *  computes the Merkle tree root using keccak256d for internal nodes.
 *
 *  @param vtx  The block's transaction list (vtx[0] is coinbase).
 *  @return     The 256-bit Merkle root. Null hash if vtx is empty.
 */
uint256 compute_block_merkle_root(const std::vector<CTransaction>& vtx);

/** Compute the Merkle branch (proof) for a transaction at a given index.
 *
 *  The Merkle branch is the set of sibling hashes needed to reconstruct
 *  the root from the leaf. Used for SPV verification.
 *
 *  @param vtx    The block's transaction list.
 *  @param index  Index of the transaction to prove (0 = coinbase).
 *  @return       Vector of sibling hashes from leaf to root.
 *                Empty if index is out of range.
 */
std::vector<uint256> compute_merkle_branch(const std::vector<CTransaction>& vtx,
                                            size_t index);

/** Verify a Merkle branch against a known root.
 *
 *  Given a leaf hash, its index, and the Merkle branch, reconstruct
 *  the root and compare it to the expected root.
 *
 *  @param leaf    The leaf hash (txid).
 *  @param index   The leaf's position in the tree.
 *  @param branch  The Merkle branch (sibling hashes).
 *  @param root    The expected Merkle root.
 *  @return        true if the branch verifies against the root.
 */
bool verify_merkle_branch(const uint256& leaf, size_t index,
                           const std::vector<uint256>& branch,
                           const uint256& root);

/** Compute the witness commitment hash for a block.
 *
 *  This is the hash of the witness merkle root committed in the
 *  coinbase transaction's output. For FlowCoin, this uses the
 *  same txid-based tree since we don't have segwit.
 *
 *  @param vtx  The block's transaction list.
 *  @return     The witness commitment hash.
 */
uint256 compute_witness_commitment(const std::vector<CTransaction>& vtx);

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_MERKLE_H

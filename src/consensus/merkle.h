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

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_MERKLE_H

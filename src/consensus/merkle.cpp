// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "merkle.h"
#include "../hash/merkle.h"

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

} // namespace flow::consensus

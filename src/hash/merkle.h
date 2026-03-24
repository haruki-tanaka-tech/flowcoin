// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Merkle tree computation using keccak256d for internal nodes.
// Algorithm matches Bitcoin's Merkle tree construction.

#pragma once

#include "../util/types.h"
#include <vector>

namespace flow {

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

} // namespace flow

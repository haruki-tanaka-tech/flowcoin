// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Block submission: accepts a complete block from a miner and validates
// it against the chain state.

#ifndef FLOWCOIN_MINING_SUBMITBLOCK_H
#define FLOWCOIN_MINING_SUBMITBLOCK_H

#include "primitives/block.h"

#include <cstdint>
#include <string>
#include <vector>

namespace flow {

class ChainState;

struct SubmitResult {
    bool accepted;
    std::string reject_reason;
};

/// Submit a fully assembled block to the chain.
/// Calls chain.accept_block() and returns the result.
SubmitResult submit_block(ChainState& chain, const CBlock& block);

/// Deserialize a block from raw bytes (wire format).
/// Returns true on success, populating the block.
bool deserialize_block(const std::vector<uint8_t>& data, CBlock& block);

} // namespace flow

#endif // FLOWCOIN_MINING_SUBMITBLOCK_H

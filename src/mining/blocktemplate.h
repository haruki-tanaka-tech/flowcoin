// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Block template construction for miners.
// Creates a partially-filled block header with the correct difficulty,
// model dimensions, coinbase transaction, and target for the miner
// to complete with training proof and signature.

#ifndef FLOWCOIN_MINING_BLOCKTEMPLATE_H
#define FLOWCOIN_MINING_BLOCKTEMPLATE_H

#include "consensus/params.h"
#include "primitives/block.h"
#include "primitives/transaction.h"

#include <string>

namespace flow {

class ChainState;

struct BlockTemplate {
    CBlockHeader header;               // Partially filled header (miner fills val_loss, delta, sig)
    CTransaction coinbase_tx;          // Coinbase transaction with block reward
    uint256 target;                    // 256-bit target (decoded from nbits)
    consensus::ModelDimensions dims;   // Model architecture for the miner
    uint32_t min_train_steps;          // Minimum training steps required
};

/// Build a block template for mining.
/// The coinbase_address receives the block reward. If empty, the coinbase
/// output is left with a zero pubkey_hash (miner must fill it).
BlockTemplate create_block_template(const ChainState& chain,
                                     const std::string& coinbase_address);

} // namespace flow

#endif // FLOWCOIN_MINING_BLOCKTEMPLATE_H
